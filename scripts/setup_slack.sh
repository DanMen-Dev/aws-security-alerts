#!/usr/bin/env bash
# Stores the Slack incoming-webhook URL in SSM Parameter Store as a SecureString.
# The URL is typed without echo and never written to disk, shell history or Terraform state.
set -euo pipefail
PROFILE="${AWS_PROFILE:-aws-alertas}"
REGION="${AWS_REGION:-us-east-2}"

read -rsp "Slack webhook URL: " WEBHOOK; echo
case "$WEBHOOK" in
  https://hooks.slack.com/services/*) ;;
  *) echo "That does not look like a Slack incoming-webhook URL." >&2; exit 1 ;;
esac

aws ssm put-parameter --profile "$PROFILE" --region "$REGION" --overwrite --type SecureString \
  --name /security-alerts/slack-webhook-url --value "$WEBHOOK" >/dev/null
unset WEBHOOK
echo "Stored /security-alerts/slack-webhook-url in SSM."
