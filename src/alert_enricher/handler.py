"""Enriches risky AWS security events and sends a readable alert to Slack.

Flow: CloudTrail -> EventBridge rule -> SQS (with DLQ) -> this Lambda -> Slack.

Design rules:
- Pure functions (classify, format_message) hold all the logic, so they are tested without AWS.
- The secret (the Slack incoming-webhook URL) lives in SSM Parameter Store as a SecureString and is
  read at runtime; they never appear in code, environment variables or Terraform state.
- Every decision is logged as one JSON line (observability and audit trail).
- SQS partial batch failures: one bad message never blocks or re-sends the others.
"""
import json
import os
import urllib.request

# Ports that should never be open to the whole internet.
SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 5678: "n8n", 8080: "HTTP alt",
}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
SEVERITY_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦"}


# ---------- Classification (pure) -------------------------------------------------------

def _items(node):
    """CloudTrail wraps lists as {"items": [...]}; tolerate missing or empty nodes."""
    if isinstance(node, dict):
        return node.get("items") or []
    return node or []


def _actor(detail):
    ident = detail.get("userIdentity") or {}
    if ident.get("type") == "Root":
        return "ROOT account"
    return ident.get("arn") or ident.get("principalId") or ident.get("type") or "unknown"


def _open_ingress(detail):
    """Returns [(from_port, to_port, protocol, cidr)] opened to the whole internet."""
    found = []
    params = detail.get("requestParameters") or {}
    for perm in _items(params.get("ipPermissions")):
        cidrs = [r.get("cidrIp") for r in _items(perm.get("ipRanges"))]
        cidrs += [r.get("cidrIpv6") for r in _items(perm.get("ipv6Ranges"))]
        for cidr in cidrs:
            if cidr in OPEN_CIDRS:
                found.append((perm.get("fromPort"), perm.get("toPort"), perm.get("ipProtocol"), cidr))
    return found


def _port_label(from_port, to_port, protocol):
    if protocol in ("-1", -1, "all"):
        return "ALL ports"
    if from_port is None:
        return "unknown port"
    if from_port == to_port:
        name = SENSITIVE_PORTS.get(from_port)
        return f"{from_port} ({name})" if name else str(from_port)
    return f"{from_port}-{to_port}"


def _touches_sensitive(from_port, to_port, protocol):
    if protocol in ("-1", -1, "all"):
        return True
    if from_port is None or to_port is None:
        return False
    return any(from_port <= p <= to_port for p in SENSITIVE_PORTS)


def classify(detail):
    """Returns an alert dict for a risky CloudTrail event, or None when it is not risky."""
    name = detail.get("eventName", "")
    failed = detail.get("errorCode")
    alert = None

    if name == "AuthorizeSecurityGroupIngress":
        opened = _open_ingress(detail)
        if not opened:
            return None
        sensitive = any(_touches_sensitive(f, t, p) for f, t, p, _ in opened)
        ports = ", ".join(sorted({_port_label(f, t, p) for f, t, p, _ in opened}))
        group = (detail.get("requestParameters") or {}).get("groupId", "unknown group")
        alert = {
            "rule": "sg-open-to-internet",
            "severity": "HIGH" if sensitive else "MEDIUM",
            "title": "Security group opened to the internet",
            "facts": {"Group": group, "Ports": ports, "Source": ", ".join(sorted({c for *_, c in opened}))},
            "advice": "Restrict the source to known IPs, or remove the rule if it is not needed.",
        }

    elif name == "CreateAccessKey":
        target = (detail.get("requestParameters") or {}).get("userName")
        is_root = (detail.get("userIdentity") or {}).get("type") == "Root" and not target
        alert = {
            "rule": "access-key-created",
            "severity": "HIGH" if is_root else "MEDIUM",
            "title": "Root access key created" if is_root else "IAM access key created",
            "facts": {"For user": "ROOT account" if is_root else (target or "caller")},
            "advice": "Confirm it was intended; prefer roles or short-lived credentials over long-lived keys.",
        }

    elif name == "ConsoleLogin" and (detail.get("userIdentity") or {}).get("type") == "Root":
        result = (detail.get("responseElements") or {}).get("ConsoleLogin", "unknown")
        mfa = (detail.get("additionalEventData") or {}).get("MFAUsed", "unknown")
        alert = {
            "rule": "root-console-login",
            "severity": "HIGH",
            "title": "Root account console sign-in",
            "facts": {"Result": result, "MFA used": mfa},
            "advice": "The root account should only be used for billing and account recovery.",
        }

    elif name in ("StopLogging", "DeleteTrail", "UpdateTrail"):
        trail = (detail.get("requestParameters") or {}).get("name", "unknown trail")
        alert = {
            "rule": "audit-logging-changed",
            "severity": "CRITICAL" if name != "UpdateTrail" else "HIGH",
            "title": f"CloudTrail audit logging changed ({name})",
            "facts": {"Trail": trail},
            "advice": "Audit logs are evidence for every other control; verify and restore immediately.",
        }

    if alert is None:
        return None
    alert["facts"] = {
        **alert["facts"],
        "Actor": _actor(detail),
        "Source IP": detail.get("sourceIPAddress", "unknown"),
        "Region": detail.get("awsRegion", "unknown"),
        "Time (UTC)": detail.get("eventTime", "unknown"),
    }
    if failed:
        # The attempt itself is worth knowing about, but it did not take effect.
        alert["severity"] = "LOW"
        alert["title"] += f" (attempt failed: {failed})"
    alert["event_id"] = detail.get("eventID", "")
    return alert


def _esc(value):
    """Slack mrkdwn escaping: only &, < and > are special (they would form links or mentions)."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_message(alert):
    """Slack message in mrkdwn; every dynamic value is escaped."""
    icon = SEVERITY_ICON.get(alert["severity"], "⬜")
    lines = [f"{icon} *{_esc(alert['severity'])} · {_esc(alert['title'])}*", ""]
    for key, value in alert["facts"].items():
        lines.append(f"*{_esc(key)}:* {_esc(value)}")
    lines += ["", f"_{_esc(alert['advice'])}_"]
    if alert.get("event_id"):
        lines.append(f"`event {_esc(alert['event_id'])}`")
    return "\n".join(lines)


# ---------- Side effects (injected, so tests never touch AWS or Slack) ----------------------

_secrets_cache = {}


def load_webhook_url():
    """Reads the Slack webhook URL from SSM once per container (cached for warm invocations)."""
    if "webhook" not in _secrets_cache:
        import boto3  # available in the Lambda runtime; imported lazily so tests need no AWS SDK
        ssm = boto3.client("ssm")
        param = ssm.get_parameter(Name=os.environ["SLACK_WEBHOOK_PARAM"], WithDecryption=True)
        _secrets_cache["webhook"] = param["Parameter"]["Value"]
    return _secrets_cache["webhook"]


def send_slack(text, webhook_url=None):
    url = webhook_url or load_webhook_url()
    body = json.dumps({"text": text, "unfurl_links": False}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:  # raises on HTTP errors (4xx/5xx)
        if resp.status != 200:
            raise RuntimeError(f"Slack answered {resp.status}")


def log(**fields):
    print(json.dumps(fields, default=str))


def lambda_handler(event, context, sender=send_slack):
    """SQS batch -> alerts. Returns the ids of messages that failed, so only those are retried."""
    failures = []
    for record in event.get("Records", []):
        message_id = record.get("messageId")
        try:
            envelope = json.loads(record["body"])          # the EventBridge event
            detail = envelope.get("detail") or {}
            alert = classify(detail)
            if alert is None:
                log(action="ignored", message_id=message_id, event_name=detail.get("eventName"))
                continue
            sender(format_message(alert))
            log(action="alerted", message_id=message_id, rule=alert["rule"], severity=alert["severity"],
                event_id=alert["event_id"])
        except Exception as exc:  # noqa: BLE001 - any failure must be reported back to SQS
            log(action="failed", message_id=message_id, error=repr(exc))
            failures.append({"itemIdentifier": message_id})
    return {"batchItemFailures": failures}
