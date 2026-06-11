# lambda.tf
# The alerting Lambda and everything needed to trigger it from CloudWatch Logs:
#   * a build artifact (zip) created from src/lambda/handler.py at plan time,
#   * the function itself,
#   * its own log group (so retention is managed and the exec role can be scoped),
#   * a resource-based permission allowing CloudWatch Logs to invoke it, and
#   * the subscription filter that streams selected CloudTrail events to it.

# Package the handler into a zip. Using archive_file means no manual build step
# and the function is automatically updated when handler.py changes
# (source_code_hash below).
data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/../src/lambda/handler.py"
  output_path = "${path.module}/build/handler.zip"
}

# The Lambda's own log group. Created explicitly (rather than letting Lambda
# auto-create it) so we control retention and can scope the IAM policy to it.
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.lambda_function_name}"
  retention_in_days = var.lambda_log_retention_days
}

resource "aws_lambda_function" "alerting" {
  function_name = local.lambda_function_name
  description   = "Parses CloudTrail security events from CloudWatch Logs and publishes formatted alerts to SNS (and optionally Slack)."

  role    = aws_iam_role.lambda_alerting.arn
  handler = "handler.lambda_handler"
  runtime = var.lambda_runtime

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  timeout     = 30
  memory_size = 128

  environment {
    variables = {
      SNS_TOPIC_ARN     = aws_sns_topic.security_alerts.arn
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      PROJECT_NAME      = var.project_name
      ENVIRONMENT       = var.environment
    }
  }

  # Ensure the log group and permissions exist before the function is created.
  depends_on = [
    aws_iam_role_policy.lambda_alerting,
    aws_cloudwatch_log_group.lambda,
  ]
}

# Allow the CloudWatch Logs service (in this region) to invoke the function.
resource "aws_lambda_permission" "allow_cloudwatch_logs" {
  statement_id  = "AllowInvokeFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alerting.function_name
  principal     = "logs.${local.region}.amazonaws.com"

  # Restrict invocation to our CloudTrail log group only.
  source_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
}

# Stream selected CloudTrail events from the log group to the Lambda. A log group
# may have multiple subscription filters; this one feeds the alerting function.
resource "aws_cloudwatch_log_subscription_filter" "to_lambda" {
  name            = "${local.name_prefix}-to-alerting-lambda"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern  = var.lambda_subscription_filter_pattern
  destination_arn = aws_lambda_function.alerting.arn

  # The invoke permission must exist before the subscription is created.
  depends_on = [aws_lambda_permission.allow_cloudwatch_logs]
}
