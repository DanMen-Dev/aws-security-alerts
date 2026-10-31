variable "region" {
  description = "AWS region. us-east-2 is the region assigned to Americas accounts created with the new AWS sign-up; IAM and console sign-in events are only delivered to EventBridge in us-east-1."
  type        = string
  default     = "us-east-2"
}

variable "aws_profile" {
  description = "Named AWS CLI profile used to deploy."
  type        = string
  default     = "aws-alertas"
}

variable "project" {
  description = "Prefix for every resource name."
  type        = string
  default     = "security-alerts"
}

variable "slack_webhook_param" {
  description = "SSM SecureString holding the Slack incoming-webhook URL (created outside Terraform)."
  type        = string
  default     = "/security-alerts/slack-webhook-url"
}

variable "log_retention_days" {
  description = "How long the Lambda logs are kept."
  type        = number
  default     = 14
}

variable "trail_log_expiration_days" {
  description = "How long CloudTrail files are kept in S3 (short, to stay in the free tier)."
  type        = number
  default     = 7
}
