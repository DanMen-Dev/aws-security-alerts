data "aws_caller_identity" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  function_name = "${var.project}-enricher"
  trail_name    = "${var.project}-trail"
  trail_arn     = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
  # Parameter names start with "/", so they are appended right after "parameter".
  webhook_param_arn = "arn:aws:ssm:${var.region}:${local.account_id}:parameter${var.slack_webhook_param}"
}

# ---------------------------------------------------------------------------------------
# 1. CloudTrail: records management events. EventBridge only receives "AWS API Call via
#    CloudTrail" events while a trail with logging enabled exists.
# ---------------------------------------------------------------------------------------
resource "aws_s3_bucket" "trail" {
  bucket        = "${var.project}-trail-${local.account_id}"
  force_destroy = true # lets `terraform destroy` remove the bucket with its log files
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "expire-trail-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.trail_log_expiration_days
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

resource "aws_cloudtrail" "this" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true # IAM and console sign-in events
  is_multi_region_trail         = false
  enable_logging                = true

  depends_on = [aws_s3_bucket_policy.trail]
}

# ---------------------------------------------------------------------------------------
# 2. SQS buffer with a dead-letter queue: nothing is lost if the Lambda or Slack fails.
# ---------------------------------------------------------------------------------------
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.project}-dlq"
  message_retention_seconds = 1209600 # 14 days to inspect failures
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "alerts" {
  name                       = "${var.project}-queue"
  visibility_timeout_seconds = 120 # >= 6x the Lambda timeout, as AWS recommends
  message_retention_seconds  = 86400
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })
}

# ---------------------------------------------------------------------------------------
# 3. EventBridge rule: only the risky API calls reach the queue.
# ---------------------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "risky" {
  name        = "${var.project}-risky-changes"
  description = "Risky security changes recorded by CloudTrail"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    source        = ["aws.ec2", "aws.iam", "aws.signin", "aws.cloudtrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress", "CreateAccessKey", "ConsoleLogin",
        "StopLogging", "DeleteTrail", "UpdateTrail",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "to_queue" {
  rule      = aws_cloudwatch_event_rule.risky.name
  target_id = "alerts-queue"
  arn       = aws_sqs_queue.alerts.arn
}

data "aws_iam_policy_document" "queue" {
  statement {
    sid       = "AllowEventBridgeRule"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.risky.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "alerts" {
  queue_url = aws_sqs_queue.alerts.id
  policy    = data.aws_iam_policy_document.queue.json
}

# ---------------------------------------------------------------------------------------
# 4. Lambda with a least-privilege role.
# ---------------------------------------------------------------------------------------
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../src/alert_enricher"
  output_path = "${path.module}/build/alert_enricher.zip"
  excludes    = ["__pycache__"]
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid = "ConsumeAlertsQueue"
    actions = [
      "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ChangeMessageVisibility",
    ]
    resources = [aws_sqs_queue.alerts.arn]
  }

  statement {
    sid       = "ReadSlackWebhook"
    actions   = ["ssm:GetParameter"]
    resources = [local.webhook_param_arn]
  }

  statement {
    sid       = "DecryptOnlyThroughSsm"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${local.function_name}-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "enricher" {
  function_name    = local.function_name
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 20
  memory_size      = 128

  environment {
    variables = {
      SLACK_WEBHOOK_PARAM = var.slack_webhook_param
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]
}

resource "aws_lambda_event_source_mapping" "queue" {
  event_source_arn        = aws_sqs_queue.alerts.arn
  function_name           = aws_lambda_function.enricher.arn
  batch_size              = 10
  function_response_types = ["ReportBatchItemFailures"]
}
