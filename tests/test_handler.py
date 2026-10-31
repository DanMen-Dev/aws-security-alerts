"""Tests for the alert enricher. No AWS account or network needed: the sender is injected."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "alert_enricher"))

import handler  # noqa: E402

EVENTS = ROOT / "tests" / "events"


def load(name):
    return json.loads((EVENTS / name).read_text())


def sqs_record(envelope, message_id="m-1"):
    return {"messageId": message_id, "body": json.dumps(envelope)}


# --- classify --------------------------------------------------------------------------

def test_ssh_open_to_internet_is_high():
    alert = handler.classify(load("sg_open_ssh.json")["detail"])
    assert alert["rule"] == "sg-open-to-internet"
    assert alert["severity"] == "HIGH"
    assert alert["facts"]["Ports"] == "22 (SSH)"
    assert alert["facts"]["Actor"].endswith("user/terraform-daniel")


def test_private_range_is_ignored():
    assert handler.classify(load("sg_private_range.json")["detail"]) is None


def test_https_open_on_ipv6_is_medium():
    alert = handler.classify(load("sg_open_https_ipv6.json")["detail"])
    assert alert["severity"] == "MEDIUM"
    assert alert["facts"]["Source"] == "::/0"


def test_all_ports_open_is_high():
    detail = load("sg_open_ssh.json")["detail"]
    detail["requestParameters"]["ipPermissions"]["items"][0].update(ipProtocol="-1", fromPort=None, toPort=None)
    alert = handler.classify(detail)
    assert alert["severity"] == "HIGH"
    assert alert["facts"]["Ports"] == "ALL ports"


def test_port_range_covering_a_database_is_high():
    detail = load("sg_open_ssh.json")["detail"]
    detail["requestParameters"]["ipPermissions"]["items"][0].update(fromPort=5000, toPort=6000)
    alert = handler.classify(detail)
    assert alert["severity"] == "HIGH"          # 5432 PostgreSQL is inside the range
    assert alert["facts"]["Ports"] == "5000-6000"


def test_root_console_login():
    alert = handler.classify(load("root_console_login.json")["detail"])
    assert alert["rule"] == "root-console-login"
    assert alert["facts"]["Actor"] == "ROOT account"
    assert alert["facts"]["MFA used"] == "Yes"


def test_access_key_for_another_user_is_medium():
    alert = handler.classify(load("create_access_key.json")["detail"])
    assert alert["severity"] == "MEDIUM"
    assert alert["facts"]["For user"] == "ci-bot"


def test_root_access_key_is_high():
    detail = load("create_access_key.json")["detail"]
    detail["userIdentity"] = {"type": "Root", "arn": "arn:aws:iam::123456789012:root"}
    detail["requestParameters"] = {}
    alert = handler.classify(detail)
    assert alert["severity"] == "HIGH"
    assert alert["title"] == "Root access key created"


def test_failed_attempt_is_reported_as_low():
    alert = handler.classify(load("stop_logging_denied.json")["detail"])
    assert alert["rule"] == "audit-logging-changed"
    assert alert["severity"] == "LOW"
    assert "AccessDenied" in alert["title"]


def test_unrelated_event_is_ignored():
    assert handler.classify({"eventName": "DescribeInstances"}) is None


# --- format_message ----------------------------------------------------------------------

def test_message_escapes_slack_control_characters():
    alert = handler.classify(load("sg_open_ssh.json")["detail"])
    alert["facts"]["Group"] = "<!channel> & <https://evil.example|click>"
    text = handler.format_message(alert)
    assert "<!channel>" not in text          # no mass mention can be injected
    assert "&lt;!channel&gt; &amp; &lt;https://evil.example|click&gt;" in text
    assert text.startswith("🟧 *HIGH · Security group opened to the internet*")


# --- lambda_handler -----------------------------------------------------------------------

def test_handler_sends_only_risky_events():
    sent = []
    event = {"Records": [sqs_record(load("sg_open_ssh.json"), "a"),
                         sqs_record(load("sg_private_range.json"), "b")]}
    result = handler.lambda_handler(event, None, sender=sent.append)
    assert result == {"batchItemFailures": []}
    assert len(sent) == 1 and "SSH" in sent[0]


def test_handler_reports_partial_failures():
    def flaky_sender(text):
        raise RuntimeError("Slack down")

    event = {"Records": [sqs_record(load("sg_open_ssh.json"), "a"),
                         {"messageId": "b", "body": "not json"},
                         sqs_record(load("sg_private_range.json"), "c")]}
    result = handler.lambda_handler(event, None, sender=flaky_sender)
    # "a" failed to send, "b" is malformed; "c" was ignored on purpose and is not retried.
    assert result == {"batchItemFailures": [{"itemIdentifier": "a"}, {"itemIdentifier": "b"}]}
