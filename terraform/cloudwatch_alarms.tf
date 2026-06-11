# cloudwatch_alarms.tf
# For each security detection we create:
#   1. a CloudWatch Logs metric filter that increments a custom metric whenever a
#      matching CloudTrail event is seen, and
#   2. a CloudWatch alarm that fires (and notifies SNS) when that metric is >= 1
#      within the evaluation window.
#
# The detections are defined once in a map and expanded with for_each, so adding
# a new detection is a single map entry. The filter patterns follow the CIS AWS
# Foundations Benchmark recommendations. See docs/detections.md for the rationale
# behind each one.

locals {
  detections = {
    root-account-usage = {
      metric_name = "RootAccountUsage"
      description = "Root account credentials were used. The root user should be locked away and almost never used; any usage warrants immediate investigation."
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    }

    unauthorized-api-calls = {
      metric_name = "UnauthorizedAPICalls"
      description = "API calls were denied (UnauthorizedOperation / AccessDenied). A spike can indicate credential misuse, reconnaissance, or privilege escalation attempts."
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    }

    console-signin-without-mfa = {
      metric_name = "ConsoleSignInWithoutMFA"
      description = "An IAM user signed in to the AWS Console successfully without multi-factor authentication. MFA should be enforced for all human users."
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    }

    iam-policy-changes = {
      metric_name = "IAMPolicyChanges"
      description = "An IAM policy was created, deleted, attached, or detached. Unexpected IAM changes can indicate privilege escalation or persistence."
      pattern     = "{ ($.eventName = \"DeleteGroupPolicy\") || ($.eventName = \"DeleteRolePolicy\") || ($.eventName = \"DeleteUserPolicy\") || ($.eventName = \"PutGroupPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"CreatePolicyVersion\") || ($.eventName = \"DeletePolicyVersion\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"DetachRolePolicy\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"DetachUserPolicy\") || ($.eventName = \"AttachGroupPolicy\") || ($.eventName = \"DetachGroupPolicy\") }"
    }

    security-group-changes = {
      metric_name = "SecurityGroupChanges"
      description = "A security group rule was created, deleted, or modified. Attackers often open ingress (e.g. 0.0.0.0/0 on 22/3389) to gain or keep access."
      pattern     = "{ ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"AuthorizeSecurityGroupEgress\") || ($.eventName = \"RevokeSecurityGroupIngress\") || ($.eventName = \"RevokeSecurityGroupEgress\") || ($.eventName = \"CreateSecurityGroup\") || ($.eventName = \"DeleteSecurityGroup\") }"
    }

    network-acl-gateway-changes = {
      metric_name = "NetworkAclGatewayChanges"
      description = "A network ACL or network gateway (Internet/customer gateway) was changed. These control network reachability and are a common target for exfiltration or lateral movement."
      pattern     = "{ ($.eventName = \"CreateNetworkAcl\") || ($.eventName = \"CreateNetworkAclEntry\") || ($.eventName = \"DeleteNetworkAcl\") || ($.eventName = \"DeleteNetworkAclEntry\") || ($.eventName = \"ReplaceNetworkAclEntry\") || ($.eventName = \"ReplaceNetworkAclAssociation\") || ($.eventName = \"CreateCustomerGateway\") || ($.eventName = \"DeleteCustomerGateway\") || ($.eventName = \"AttachInternetGateway\") || ($.eventName = \"CreateInternetGateway\") || ($.eventName = \"DeleteInternetGateway\") || ($.eventName = \"DetachInternetGateway\") }"
    }

    # NOTE: this detection intentionally matches on eventName only (not
    # eventSource) so it captures BOTH bucket-level changes (s3.amazonaws.com)
    # and account-level public-access-block changes (s3-control.amazonaws.com).
    s3-policy-changes = {
      metric_name = "S3PolicyChanges"
      description = "An S3 bucket policy/ACL or a public-access-block setting was changed. This is the classic path to accidental or malicious public data exposure."
      pattern     = "{ ($.eventName = \"PutBucketPolicy\") || ($.eventName = \"DeleteBucketPolicy\") || ($.eventName = \"PutBucketAcl\") || ($.eventName = \"PutBucketPublicAccessBlock\") || ($.eventName = \"DeletePublicAccessBlock\") || ($.eventName = \"PutPublicAccessBlock\") || ($.eventName = \"PutAccountPublicAccessBlock\") || ($.eventName = \"PutBucketCors\") || ($.eventName = \"PutBucketLifecycle\") || ($.eventName = \"PutBucketReplication\") || ($.eventName = \"DeleteBucketCors\") || ($.eventName = \"DeleteBucketLifecycle\") || ($.eventName = \"DeleteBucketReplication\") }"
    }
  }
}

# One metric filter per detection. Each matching CloudTrail event publishes a
# data point of value 1 to the custom metric.
resource "aws_cloudwatch_log_metric_filter" "detections" {
  for_each = local.detections

  name           = "${local.name_prefix}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.value.metric_name
    namespace = local.metric_namespace
    value     = "1"
    # No default_value: the metric only reports when an event matches, and the
    # alarm uses treat_missing_data = "notBreaching" to stay green otherwise.
  }
}

# One alarm per detection. Fires when one or more matching events occur within a
# single evaluation period and notifies the SNS topic.
resource "aws_cloudwatch_metric_alarm" "detections" {
  for_each = local.detections

  alarm_name        = "${local.name_prefix}-${each.key}"
  alarm_description = each.value.description

  namespace   = local.metric_namespace
  metric_name = each.value.metric_name
  statistic   = "Sum"

  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  period              = var.alarm_period_seconds
  evaluation_periods  = var.alarm_evaluation_periods
  treat_missing_data  = "notBreaching"

  # Notify SNS on alarm. We also clear via ok_actions so subscribers know when
  # the condition has returned to normal.
  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]

  # The metric filter must exist first so the metric is known to CloudWatch.
  depends_on = [aws_cloudwatch_log_metric_filter.detections]
}
