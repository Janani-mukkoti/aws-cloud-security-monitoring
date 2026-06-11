# sns.tf
# SNS topic that fans out every security alert to subscribers. The metric alarms
# publish to it directly (alarm_actions) and the alerting Lambda publishes
# richly-formatted messages to it as well. An email subscription delivers alerts
# to a human.

resource "aws_sns_topic" "security_alerts" {
  name         = "${local.name_prefix}-security-alerts"
  display_name = "SecurityAlerts"

  # NOTE on encryption: enabling SSE here requires a CUSTOMER-MANAGED KMS key
  # whose key policy grants cloudwatch.amazonaws.com kms:GenerateDataKey* and
  # kms:Decrypt. The AWS-managed alias/aws/sns key cannot be used because its
  # policy is not editable and would silently block CloudWatch alarm delivery.
  # See docs/detections.md for the hardening steps.
}

# Email subscription. AWS sends a confirmation link to this address; alerts are
# only delivered after the recipient confirms the subscription.
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# Topic access policy. Setting this REPLACES the default policy, so we must also
# re-grant the topic owner the standard management permissions.
data "aws_iam_policy_document" "sns_topic" {
  # Standard owner permissions (mirrors the default SNS topic policy).
  statement {
    sid    = "DefaultOwnerAccess"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "SNS:GetTopicAttributes",
      "SNS:SetTopicAttributes",
      "SNS:AddPermission",
      "SNS:RemovePermission",
      "SNS:DeleteTopic",
      "SNS:Subscribe",
      "SNS:ListSubscriptionsByTopic",
      "SNS:Publish",
    ]
    resources = [aws_sns_topic.security_alerts.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"
      values   = [local.account_id]
    }
  }

  # Allow CloudWatch alarms in this account to publish notifications.
  statement {
    sid    = "AllowCloudWatchAlarmsToPublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.sns_topic.json
}
