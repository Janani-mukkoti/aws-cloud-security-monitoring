# variables.tf
# All tunable inputs for the stack. Sensible, safe defaults are provided so the
# only value you MUST set is `alarm_email`. Copy terraform.tfvars.example to
# terraform.tfvars and edit as needed.

variable "aws_region" {
  description = "AWS region to deploy the monitoring stack into. The CloudTrail is multi-region, so this is simply where the trail, S3 bucket, log group, alarms and Lambda live."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short, lowercase project name used to prefix and tag resources. Must be S3-bucket-name safe (lowercase letters, numbers, hyphens)."
  type        = string
  default     = "cloud-security-monitoring"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,40}$", var.project_name))
    error_message = "project_name must be 3-40 chars, lowercase letters, numbers and hyphens only."
  }
}

variable "environment" {
  description = "Deployment environment name (e.g. dev, staging, prod). Used for tagging and resource naming."
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "Additional tags to merge onto every resource (cost center, owner, etc.)."
  type        = map(string)
  default     = {}
}

variable "alarm_email" {
  description = "Email address that will be subscribed to the SNS topic and receive all security alerts. AWS sends a confirmation email that must be accepted before alerts are delivered."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alarm_email))
    error_message = "alarm_email must be a valid email address."
  }
}

variable "slack_webhook_url" {
  description = "Optional Slack Incoming Webhook URL. If set, the alerting Lambda also posts formatted alerts to Slack. Leave empty to disable Slack notifications. Treat as a secret - prefer passing via TF_VAR_slack_webhook_url rather than committing it."
  type        = string
  default     = ""
  sensitive   = true
}

# ---------------------------------------------------------------------------
# Retention / lifecycle tuning
# ---------------------------------------------------------------------------

variable "s3_log_expiration_days" {
  description = "Number of days after which CloudTrail log objects in S3 are permanently deleted by the lifecycle rule."
  type        = number
  default     = 365

  validation {
    condition     = var.s3_log_expiration_days >= 1
    error_message = "s3_log_expiration_days must be at least 1."
  }
}

variable "s3_noncurrent_version_expiration_days" {
  description = "Number of days after which non-current (overwritten/deleted) object versions are removed. Keeps versioning cost bounded."
  type        = number
  default     = 90
}

variable "s3_transition_to_ia_days" {
  description = "Number of days after which current log objects transition to the cheaper STANDARD_IA storage class. Must be less than s3_log_expiration_days."
  type        = number
  default     = 90
}

variable "cloudwatch_log_retention_days" {
  description = "Retention (in days) for the CloudTrail CloudWatch Logs log group. Must be a value accepted by CloudWatch Logs."
  type        = number
  default     = 90

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.cloudwatch_log_retention_days,
    )
    error_message = "cloudwatch_log_retention_days must be one of the values supported by CloudWatch Logs (e.g. 1, 7, 30, 90, 365, ...)."
  }
}

variable "lambda_log_retention_days" {
  description = "Retention (in days) for the alerting Lambda's own CloudWatch Logs log group."
  type        = number
  default     = 30
}

# ---------------------------------------------------------------------------
# Alarm behaviour
# ---------------------------------------------------------------------------

variable "alarm_period_seconds" {
  description = "Evaluation period (in seconds) for the metric alarms. CloudTrail-to-CloudWatch delivery is near-real-time but not instant, so a 5 minute window is a good default."
  type        = number
  default     = 300
}

variable "alarm_evaluation_periods" {
  description = "Number of periods over which data is compared to the threshold before the alarm fires."
  type        = number
  default     = 1
}

variable "lambda_runtime" {
  description = "Python runtime for the alerting Lambda function."
  type        = string
  default     = "python3.12"
}

variable "lambda_subscription_filter_pattern" {
  description = "CloudWatch Logs filter pattern selecting which CloudTrail events are forwarded to the alerting Lambda. The default targets the highest-severity events. Set to an empty string to forward ALL events (noisier and more costly)."
  type        = string
  default     = "{ ($.userIdentity.type = \"Root\") || ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") || ($.eventName = \"ConsoleLogin\") || ($.eventName = \"PutBucketPolicy\") || ($.eventName = \"PutBucketAcl\") || ($.eventName = \"PutBucketPublicAccessBlock\") || ($.eventName = \"DeletePublicAccessBlock\") || ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"CreateNetworkAclEntry\") || ($.eventName = \"AttachInternetGateway\") }"
}
