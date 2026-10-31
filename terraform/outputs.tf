output "lambda_function" {
  value = aws_lambda_function.enricher.function_name
}

output "alerts_queue_url" {
  value = aws_sqs_queue.alerts.id
}

output "dead_letter_queue_url" {
  value = aws_sqs_queue.dlq.id
}

output "eventbridge_rule" {
  value = aws_cloudwatch_event_rule.risky.name
}

output "trail" {
  value = aws_cloudtrail.this.name
}
