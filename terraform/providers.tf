# providers.tf
# Configures the AWS provider. The region is variable-driven (defaults to
# us-east-1) and a common set of tags is applied to every taggable resource via
# `default_tags`, so we do not have to repeat tag blocks on each resource.

provider "aws" {
  region = var.aws_region

  # default_tags are merged onto every resource that supports tags. This keeps
  # tagging consistent (great for cost allocation and ownership) without
  # cluttering each resource definition.
  default_tags {
    tags = local.common_tags
  }
}

# Convenience data sources used to build ARNs and policies without hard-coding
# the account ID, region, or partition (works in aws, aws-us-gov, aws-cn).
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  # Tags applied to all resources. Callers can add/override via var.tags.
  common_tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Component   = "security-monitoring"
    },
    var.tags,
  )

  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition

  # Namespace for the custom CloudWatch metrics emitted by the metric filters.
  metric_namespace = "${var.project_name}/SecurityMetrics"

  # Deterministic resource names. Including the account ID keeps the (globally
  # unique) S3 bucket name collision-free without needing a random suffix.
  name_prefix          = "${var.project_name}-${var.environment}"
  bucket_name          = "${var.project_name}-cloudtrail-logs-${local.account_id}"
  trail_name           = "${var.project_name}-trail"
  lambda_function_name = "${var.project_name}-${var.environment}-security-alerting"

  # CloudTrail's ARN is built by hand so the S3 bucket policy can reference it
  # via an aws:SourceArn condition without creating a dependency cycle between
  # the bucket policy and the trail.
  trail_arn = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}
