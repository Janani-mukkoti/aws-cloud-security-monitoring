"""Security alerting Lambda for the AWS Cloud Security Monitoring Lab.

This function is triggered by a **CloudWatch Logs subscription filter** attached
to the CloudTrail log group. CloudWatch Logs delivers matching log events to the
function as a gzip-compressed, base64-encoded JSON payload. The handler:

    1. decodes and decompresses the payload,
    2. parses each embedded CloudTrail event record,
    3. classifies it (severity + human-friendly title) using a small rules table,
    4. builds a concise, human-readable alert, and
    5. publishes that alert to an SNS topic and, optionally, to a Slack
       Incoming Webhook.

Design notes
------------
* Only the standard library plus ``boto3`` are used. ``boto3`` ships in the AWS
  Lambda Python runtime, so there are NO third-party dependencies to package.
* The function is defensive: a malformed record or a Slack failure is logged but
  never prevents the remaining alerts (or the SNS publish) from being delivered.

Environment variables
----------------------
SNS_TOPIC_ARN      (required) ARN of the SNS topic to publish alerts to.
SLACK_WEBHOOK_URL  (optional) Slack Incoming Webhook URL; Slack is skipped if unset.
PROJECT_NAME       (optional) Included in alert text for context.
ENVIRONMENT        (optional) Included in alert text for context.
"""

import base64
import gzip
import json
import logging
import os
import urllib.error
import urllib.request

import boto3

# ---------------------------------------------------------------------------
# Configuration & module-level clients
# ---------------------------------------------------------------------------
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

# Created at import time so it is reused across warm invocations.
_SNS = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
PROJECT_NAME = os.environ.get("PROJECT_NAME", "cloud-security-monitoring")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "")

# Maximum length allowed by SNS for the Subject field.
_MAX_SNS_SUBJECT = 100
# Network timeout (seconds) for the optional Slack webhook call.
_SLACK_TIMEOUT = 5

# Map of CloudTrail eventName -> (severity, human-friendly description). Used to
# enrich alerts. Anything not listed falls back to a generic "MEDIUM" entry.
_EVENT_RULES = {
    # Root usage / auth
    "ConsoleLogin": ("HIGH", "Console sign-in"),
    # IAM policy changes
    "PutUserPolicy": ("HIGH", "IAM inline user policy changed"),
    "PutRolePolicy": ("HIGH", "IAM inline role policy changed"),
    "PutGroupPolicy": ("HIGH", "IAM inline group policy changed"),
    "AttachUserPolicy": ("HIGH", "IAM policy attached to user"),
    "AttachRolePolicy": ("HIGH", "IAM policy attached to role"),
    "AttachGroupPolicy": ("HIGH", "IAM policy attached to group"),
    "DetachUserPolicy": ("HIGH", "IAM policy detached from user"),
    "DetachRolePolicy": ("HIGH", "IAM policy detached from role"),
    "CreatePolicy": ("MEDIUM", "IAM managed policy created"),
    "DeletePolicy": ("HIGH", "IAM managed policy deleted"),
    "CreatePolicyVersion": ("HIGH", "IAM policy version created"),
    # Security group changes
    "AuthorizeSecurityGroupIngress": ("HIGH", "Security group ingress added"),
    "AuthorizeSecurityGroupEgress": ("MEDIUM", "Security group egress added"),
    "RevokeSecurityGroupIngress": ("MEDIUM", "Security group ingress removed"),
    "CreateSecurityGroup": ("LOW", "Security group created"),
    "DeleteSecurityGroup": ("MEDIUM", "Security group deleted"),
    # Network ACL / gateway changes
    "CreateNetworkAclEntry": ("HIGH", "Network ACL entry created"),
    "DeleteNetworkAclEntry": ("HIGH", "Network ACL entry deleted"),
    "AttachInternetGateway": ("HIGH", "Internet gateway attached"),
    "CreateInternetGateway": ("MEDIUM", "Internet gateway created"),
    "DeleteInternetGateway": ("MEDIUM", "Internet gateway deleted"),
    # S3 exposure
    "PutBucketPolicy": ("HIGH", "S3 bucket policy changed"),
    "DeleteBucketPolicy": ("HIGH", "S3 bucket policy deleted"),
    "PutBucketAcl": ("HIGH", "S3 bucket ACL changed"),
    "PutBucketPublicAccessBlock": ("HIGH", "S3 public access block changed"),
    "DeletePublicAccessBlock": ("HIGH", "S3 public access block deleted"),
}


def _classify(record):
    """Return (severity, title) for a CloudTrail record.

    Root account usage and access-denied errors are escalated regardless of the
    specific event name because they are inherently noteworthy.
    """
    event_name = record.get("eventName", "UnknownEvent")
    user_type = (record.get("userIdentity") or {}).get("type", "")
    error_code = record.get("errorCode")

    if user_type == "Root":
        return "CRITICAL", "Root account activity"
    if error_code in ("AccessDenied", "UnauthorizedOperation") or (
        error_code and ("Unauthorized" in error_code or "AccessDenied" in error_code)
    ):
        return "HIGH", "Unauthorized / denied API call"

    severity, title = _EVENT_RULES.get(event_name, ("MEDIUM", event_name))
    return severity, title


def _summarize(record):
    """Extract the interesting fields from a raw CloudTrail event record."""
    identity = record.get("userIdentity") or {}
    severity, title = _classify(record)

    # Derive the most useful "who" string available.
    principal = (
        identity.get("arn")
        or identity.get("userName")
        or identity.get("principalId")
        or identity.get("type")
        or "unknown"
    )

    return {
        "severity": severity,
        "title": title,
        "event_name": record.get("eventName", "UnknownEvent"),
        "event_source": record.get("eventSource", "unknown"),
        "event_time": record.get("eventTime", "unknown"),
        "region": record.get("awsRegion", "unknown"),
        "source_ip": record.get("sourceIPAddress", "unknown"),
        "principal": principal,
        "account": record.get("recipientAccountId") or identity.get("accountId", "unknown"),
        "error_code": record.get("errorCode"),
        "error_message": record.get("errorMessage"),
    }


# Severities ordered so we can pick the most serious one for the subject line.
_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _format_alert(summaries):
    """Build the (subject, body) tuple for a batch of summarized records."""
    top = max(summaries, key=lambda s: _SEVERITY_ORDER.get(s["severity"], 0))

    context = PROJECT_NAME + (f"/{ENVIRONMENT}" if ENVIRONMENT else "")
    subject = f"[{top['severity']}] AWS security alert: {top['title']} ({context})"
    # SNS subjects must be ASCII and <= 100 characters.
    subject = subject.encode("ascii", "ignore").decode("ascii")[:_MAX_SNS_SUBJECT]

    lines = [
        f"{len(summaries)} security-relevant CloudTrail event(s) detected in {context}.",
        "",
    ]
    for i, s in enumerate(summaries, start=1):
        lines.append(f"#{i} [{s['severity']}] {s['title']}")
        lines.append(f"    Event       : {s['event_name']} ({s['event_source']})")
        lines.append(f"    Time        : {s['event_time']}")
        lines.append(f"    Region      : {s['region']}")
        lines.append(f"    Principal   : {s['principal']}")
        lines.append(f"    Account     : {s['account']}")
        lines.append(f"    Source IP   : {s['source_ip']}")
        if s["error_code"]:
            lines.append(f"    Error       : {s['error_code']} - {s.get('error_message') or ''}")
        lines.append("")

    lines.append("Investigate in the CloudTrail event history and CloudWatch Logs.")
    return subject, "\n".join(lines)


def _publish_sns(subject, message):
    """Publish the alert to SNS. Raises if SNS_TOPIC_ARN is not configured."""
    if not SNS_TOPIC_ARN:
        raise RuntimeError("SNS_TOPIC_ARN environment variable is not set")

    _SNS.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    LOGGER.info("Published alert to SNS topic %s", SNS_TOPIC_ARN)


def _post_slack(text):
    """Best-effort post to a Slack Incoming Webhook. Never raises."""
    if not SLACK_WEBHOOK_URL:
        return

    payload = json.dumps({"text": text}).encode("utf-8")
    request = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=_SLACK_TIMEOUT) as response:
            LOGGER.info("Posted alert to Slack (HTTP %s)", response.status)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        # Slack delivery is best-effort; log and continue so SNS still fires.
        LOGGER.warning("Failed to post to Slack: %s", exc)


def _decode_log_data(event):
    """Decode the gzip+base64 'awslogs.data' payload into a dict.

    Returns None if the event does not look like a CloudWatch Logs trigger.
    """
    awslogs = event.get("awslogs") if isinstance(event, dict) else None
    if not awslogs or "data" not in awslogs:
        return None

    compressed = base64.b64decode(awslogs["data"])
    decompressed = gzip.decompress(compressed)
    return json.loads(decompressed)


def lambda_handler(event, context):
    """Entry point invoked by AWS Lambda."""
    log_data = _decode_log_data(event)
    if log_data is None:
        LOGGER.warning("Event is not a CloudWatch Logs payload; nothing to do.")
        return {"status": "ignored", "reason": "no awslogs data"}

    # Control messages are sent by CloudWatch Logs to validate the subscription.
    if log_data.get("messageType") == "CONTROL_MESSAGE":
        LOGGER.info("Received CloudWatch Logs control message; acknowledging.")
        return {"status": "ok", "reason": "control message"}

    summaries = []
    for log_event in log_data.get("logEvents", []):
        raw = log_event.get("message", "")
        try:
            record = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            LOGGER.warning("Skipping non-JSON log event: %r", raw[:200])
            continue
        summaries.append(_summarize(record))

    if not summaries:
        LOGGER.info("No parseable CloudTrail records in payload.")
        return {"status": "ok", "alerts": 0}

    subject, body = _format_alert(summaries)

    # Publish to SNS first (the primary, reliable channel), then Slack.
    _publish_sns(subject, body)
    _post_slack(f"*{subject}*\n```{body}```")

    LOGGER.info("Processed %d record(s).", len(summaries))
    return {"status": "ok", "alerts": len(summaries)}
