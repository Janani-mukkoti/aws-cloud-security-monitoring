# Deployment guide

Step-by-step instructions to deploy, verify, and tear down the AWS Cloud
Security Monitoring Lab.

> This repository is **build-only**. Nothing here deploys automatically. You run
> Terraform yourself with your own AWS credentials.

## Prerequisites

* **Terraform** >= 1.5 — <https://developer.hashicorp.com/terraform/downloads>
* **AWS account** and credentials with permissions to create CloudTrail, S3,
  CloudWatch (Logs/Alarms), SNS, Lambda, and IAM resources.
* **AWS CLI** configured (`aws configure`) or environment variables set
  (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`).
* An **email address** to receive alerts.
* (Optional) A **Slack Incoming Webhook** URL if you want Slack notifications.

> **Note on existing trails:** An AWS account can have a limited number of
> trails per region. If you already have a multi-region trail you no longer
> need, remove it first, or deploy this into a sandbox account.

## 1. Configure variables

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars and set at least alarm_email
```

For the Slack webhook (a secret), prefer an environment variable over the file:

```bash
export TF_VAR_slack_webhook_url="https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

## 2. Initialize & review

```bash
terraform init
terraform fmt -recursive   # optional: format the code
terraform validate         # static validation
terraform plan             # review what will be created
```

## 3. Apply

```bash
terraform apply
```

Terraform prints useful outputs on completion, including the S3 bucket, log
group, SNS topic ARN, alarm names, and the Lambda function name.

## 4. Confirm the SNS email subscription (required)

After `apply`, AWS sends a **"Subscription Confirmation"** email to `alarm_email`.
**You must click the confirmation link** — until you do, no email alerts are
delivered. Check your spam folder if you do not see it.

## 5. Verify it works (safe test)

CloudTrail-to-CloudWatch delivery typically takes a few minutes. To generate a
benign event that several detections will catch, create and delete a throwaway
security group (replace the VPC ID):

```bash
# Triggers the SecurityGroupChanges detection
aws ec2 create-security-group --group-name sec-mon-test --description "test" --vpc-id vpc-xxxxxxxx
aws ec2 delete-security-group --group-name sec-mon-test
```

Or generate an `AccessDenied` by calling an API you are not permitted to use.
Within a few minutes you should see:

* the relevant **CloudWatch alarm** transition to `ALARM`, and
* an **email** (and Slack message, if configured) — both an alarm notification
  and a formatted message from the Lambda.

You can also inspect the Lambda logs:

```bash
aws logs tail "/aws/lambda/<alerting_lambda_name>" --follow
```

## 6. Teardown / cleanup

```bash
cd terraform
terraform destroy
```

The S3 bucket is created with `force_destroy = false` to protect the audit log,
so if it still contains objects `destroy` will fail on the bucket. That is
intentional. To intentionally remove it:

```bash
# WARNING: permanently deletes all stored CloudTrail logs
aws s3 rm "s3://<cloudtrail_s3_bucket>" --recursive
terraform destroy
```

(Alternatively, temporarily set `force_destroy = true` in `s3.tf`, re-apply,
then destroy.)

## Cost notes

Idle, this lab costs very little, but it is **not** guaranteed free:

* **CloudTrail** — the first copy of management events is free. This trail
  delivers to CloudWatch Logs, so you pay for Logs ingestion/storage.
* **S3** — pennies for log storage at low volume; the lifecycle rule transitions
  to STANDARD_IA and expires logs to keep this bounded.
* **CloudWatch Logs** — ingestion (~$0.50/GB) + storage. Retention defaults to 90
  days. CloudWatch **alarms** are ~$0.10/alarm/month (7 alarms here).
* **Lambda** — effectively free at this volume (well within the free tier).
* **SNS** — email notifications are free for typical volumes.

Estimate well under a few US dollars per month for a quiet account. Run
`terraform destroy` when you are done to avoid ongoing charges. Always confirm
current pricing for your region.
