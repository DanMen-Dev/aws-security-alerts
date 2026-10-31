#!/usr/bin/env bash
# End-to-end test: opens SSH (port 22) to the whole internet on a throwaway security group,
# waits, then closes and deletes it. A HIGH alert should reach Slack within a few minutes
# (CloudTrail usually delivers the event to EventBridge in 1-5 minutes).
set -euo pipefail
PROFILE="${AWS_PROFILE:-aws-alertas}"
REGION="${AWS_REGION:-us-east-2}"
aws_() { aws --profile "$PROFILE" --region "$REGION" "$@"; }

VPC_ID=$(aws_ ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
SG_ID=$(aws_ ec2 create-security-group --group-name "alerts-test-$(date +%s)" \
  --description "Temporary group to test security alerts" --vpc-id "$VPC_ID" --query GroupId --output text)
echo "Created $SG_ID in $VPC_ID; opening port 22 to 0.0.0.0/0 ..."
aws_ ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null

echo "Waiting 60 s before cleaning up (the alert keeps travelling after the rule is gone) ..."
sleep 60
aws_ ec2 revoke-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
aws_ ec2 delete-security-group --group-id "$SG_ID"
echo "Cleaned up. Check Slack, and the logs with:"
echo "  aws logs tail /aws/lambda/security-alerts-enricher --since 15m --follow --profile $PROFILE --region $REGION"
