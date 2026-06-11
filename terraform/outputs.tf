# outputs.tf
# Useful identifiers surfaced after `terraform apply` for verification, wiring
# into other stacks, or documentation/screenshots.

output "aws_region" {
  description = "Region the monitoring stack was deployed into."
  value       = local.region
}

output "cloudtrail_name" {
  description = "Name of the multi-region CloudTrail."
  value       = aws_cloudtrail.main.name
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail."
  value       = aws_cloudtrail.main.arn
}

output "cloudtrail_s3_bucket" {
  description = "Name of the S3 bucket storing CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_log_group_name" {
  description = "CloudWatch Logs group receiving CloudTrail events."
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic that fans out security alerts."
  value       = aws_sns_topic.security_alerts.arn
}

output "alert_email" {
  description = "Email subscribed to the SNS topic. Remember to confirm the subscription from your inbox."
  value       = var.alarm_email
}

output "alerting_lambda_name" {
  description = "Name of the alerting Lambda function."
  value       = aws_lambda_function.alerting.function_name
}

output "alerting_lambda_arn" {
  description = "ARN of the alerting Lambda function."
  value       = aws_lambda_function.alerting.arn
}

output "alarm_names" {
  description = "All CloudWatch alarm names created by this stack."
  value       = sort([for a in aws_cloudwatch_metric_alarm.detections : a.alarm_name])
}

output "metric_filter_namespace" {
  description = "CloudWatch metrics namespace used by the metric filters."
  value       = local.metric_namespace
}
