# cloudtrail.tf
# A multi-region CloudTrail that records management events across every region
# and global services (IAM, STS, CloudFront, etc.), validates log file integrity,
# and delivers events to BOTH:
#   1. the S3 bucket (durable, long-term audit store), and
#   2. a CloudWatch Logs log group (so metric filters/alarms and the alerting
#      Lambda can react in near real time).

# Destination log group for CloudTrail events in CloudWatch Logs.
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.trail_name}"
  retention_in_days = var.cloudwatch_log_retention_days
}

resource "aws_cloudtrail" "main" {
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.cloudtrail.id

  # Capture activity in all regions, including regions enabled in the future.
  is_multi_region_trail = true

  # Record events for global services (IAM, STS, CloudFront). Required to catch
  # things like root usage and IAM policy changes.
  include_global_service_events = true

  # Tamper-evidence: CloudTrail produces signed digest files so you can prove
  # logs were not modified or deleted after delivery.
  enable_log_file_validation = true

  # Make sure the trail is actually recording.
  enable_logging = true

  # Stream events to CloudWatch Logs for real-time detection. The ARN must end
  # with ":*" to target all log streams in the group.
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cloudwatch.arn

  # The bucket policy must be in place before CloudTrail validates write access,
  # otherwise trail creation fails with "insufficient permissions".
  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_iam_role_policy.cloudtrail_to_cloudwatch,
  ]
}
