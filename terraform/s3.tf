# s3.tf
# The destination S3 bucket that stores immutable CloudTrail log files, plus all
# of its security controls: versioning, server-side encryption, a full public
# access block, a lifecycle policy, and the bucket policy CloudTrail requires to
# deliver logs.

resource "aws_s3_bucket" "cloudtrail" {
  bucket = local.bucket_name

  # CloudTrail logs are an audit record; we never want to accidentally destroy
  # them. force_destroy stays false so `terraform destroy` fails loudly if the
  # bucket still holds objects (see docs/deployment.md for intentional cleanup).
  force_destroy = false
}

# Versioning protects against accidental or malicious overwrites/deletions of
# log files - important for an audit trail.
resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption at rest. SSE-S3 (AES256) is used by default so there is
# no KMS key policy to manage; switch to aws:kms + a CMK if your compliance
# regime requires customer-managed keys (see docs/detections.md).
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Block ALL forms of public access. A CloudTrail log bucket must never be
# public; this is defense-in-depth on top of the restrictive bucket policy.
resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle: transition older logs to cheaper storage, then expire them. Also
# clean up non-current versions and incomplete multipart uploads to control cost.
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  # Ensure versioning is configured before lifecycle rules that act on versions.
  depends_on = [aws_s3_bucket_versioning.cloudtrail]

  rule {
    id     = "cloudtrail-log-retention"
    status = "Enabled"

    # Applies to every object in the bucket.
    filter {}

    transition {
      days          = var.s3_transition_to_ia_days
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.s3_log_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.s3_noncurrent_version_expiration_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ---------------------------------------------------------------------------
# Bucket policy required by CloudTrail
# ---------------------------------------------------------------------------
# CloudTrail needs s3:GetBucketAcl on the bucket and s3:PutObject under the
# AWSLogs/<account-id>/ prefix. We additionally enforce:
#   * the bucket-owner-full-control canned ACL on writes, and
#   * an aws:SourceArn condition pinning access to THIS trail (prevents the
#     "confused deputy" problem), and
#   * TLS-only access (aws:SecureTransport).
data "aws_iam_policy_document" "cloudtrail_bucket" {
  # Allow CloudTrail to read the bucket ACL.
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # Allow CloudTrail to write log files for this account only.
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${local.account_id}/*"]

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

  # Defense-in-depth: deny any request that is not using TLS.
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.cloudtrail.arn,
      "${aws_s3_bucket.cloudtrail.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json

  # The public access block must exist first, otherwise applying a policy that
  # references service principals can race with the block settings.
  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]
}
