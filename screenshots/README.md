# Screenshots

This folder is intentionally empty in the repo (see `.gitkeep`). After you deploy
the stack, capture the following screenshots and drop them here to make the
project portfolio-ready. Reference them from the top-level `README.md`.

Suggested captures:

1. **`cloudtrail-trail.png`** — CloudTrail console showing the multi-region trail
   with *Log file validation: Enabled* and both S3 + CloudWatch Logs destinations.
2. **`s3-bucket-settings.png`** — The log bucket showing *Bucket Versioning:
   Enabled*, default encryption, and *Block all public access: On*.
3. **`cloudwatch-alarms.png`** — The CloudWatch Alarms list showing all 7 alarms
   (with at least one in the `ALARM` state after a test event).
4. **`metric-filters.png`** — The CloudWatch Logs metric filters on the CloudTrail
   log group.
5. **`sns-subscription-confirmed.png`** — The SNS topic with a *Confirmed* email
   subscription.
6. **`email-alert.png`** — A received alert email (redact any account IDs / IPs).
7. **`lambda-logs.png`** — CloudWatch Logs for the alerting Lambda showing a
   processed event (`Processed N record(s).`).
8. **`slack-alert.png`** *(optional)* — A formatted alert posted to Slack.

Tip: redact account IDs, ARNs, email addresses, and source IPs before committing
screenshots to a public repository.
