# iam.tf
# IAM roles and least-privilege policies for:
#   1. CloudTrail writing into CloudWatch Logs, and
#   2. the alerting Lambda (write its own logs + publish to SNS).

# ---------------------------------------------------------------------------
# 1. CloudTrail -> CloudWatch Logs delivery role
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    # Confused-deputy protection: only our trail may assume this role.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name               = "${local.name_prefix}-cloudtrail-cw-role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
  description        = "Allows CloudTrail to deliver log events to the CloudWatch Logs group."
}

# CloudTrail only needs to create log streams and put events into its group.
data "aws_iam_policy_document" "cloudtrail_to_cloudwatch" {
  statement {
    sid    = "AWSCloudTrailCreateAndWriteLogStreams"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  name   = "cloudtrail-cw-logs-delivery"
  role   = aws_iam_role.cloudtrail_to_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_to_cloudwatch.json
}

# ---------------------------------------------------------------------------
# 2. Alerting Lambda execution role
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_alerting" {
  name               = "${local.name_prefix}-alerting-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  description        = "Execution role for the security alerting Lambda."
}

# Least-privilege: write to its own log group and publish to the SNS topic only.
data "aws_iam_policy_document" "lambda_alerting" {
  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid       = "PublishAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_iam_role_policy" "lambda_alerting" {
  name   = "alerting-lambda-permissions"
  role   = aws_iam_role.lambda_alerting.id
  policy = data.aws_iam_policy_document.lambda_alerting.json
}
