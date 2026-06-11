# AWS Cloud Security Monitoring Lab

Automated, **infrastructure-as-code** cloud security monitoring for AWS. A
multi-region **CloudTrail** captures API activity across the account and streams
it to **CloudWatch Logs**, where seven CIS-aligned metric filters and alarms
detect suspicious activity (root usage, unauthorized calls, security-group /
network / IAM / S3 changes, and console logins without MFA). Alarms and a Python
**Lambda** that formats human-readable alerts both publish to an **SNS** topic
that notifies you by email (and optionally Slack). Everything is defined in
Terraform so you can stand it up — and tear it down — in minutes.

> **Build-only repo:** this project contains complete, production-quality code
> and docs. It does **not** deploy anything on its own; you apply it with your
> own AWS credentials. See [`docs/deployment.md`](docs/deployment.md).

## Architecture

```mermaid
flowchart LR
    API["AWS API activity<br/>all regions + global services"]

    subgraph aws["AWS account"]
        CT["CloudTrail<br/>multi-region + log-file validation"]
        S3[("S3 bucket<br/>versioned · encrypted<br/>private · lifecycle")]
        CWL["CloudWatch Logs<br/>log group"]
        MF["Metric filters<br/>7 detections"]
        AL["CloudWatch alarms"]
        LMB["Lambda<br/>parse + format alert"]
        SNS{{"SNS topic<br/>security-alerts"}}
    end

    EMAIL["Email inbox"]
    SLACK["Slack channel<br/>(optional)"]

    API --> CT
    CT -->|deliver logs| S3
    CT -->|stream events| CWL
    CWL --> MF --> AL -->|notify| SNS
    CWL -->|subscription filter| LMB -->|publish| SNS
    LMB -.optional.-> SLACK
    SNS -->|email subscription| EMAIL
```

The Mermaid source lives in [`diagrams/architecture.mmd`](diagrams/architecture.mmd).

## Skills / Tech

* **AWS CloudTrail** — multi-region trail with log-file validation
* **Amazon S3** — versioned, encrypted (SSE-S3), private, lifecycle-managed log bucket
* **Amazon CloudWatch Logs** — log group, metric filters, subscription filter
* **Amazon CloudWatch Alarms** — 7 CIS-aligned security detections
* **AWS Lambda (Python 3.12)** — event parsing & formatted alerting (stdlib + boto3)
* **Amazon SNS** — email fan-out (+ optional Slack webhook)
* **AWS IAM** — least-privilege roles & policies, confused-deputy guards
* **Terraform** (>= 1.5, AWS provider ~> 5.0) — modular IaC with `for_each`, `default_tags`, validations
* **Security engineering** — CIS AWS Foundations Benchmark detections, threat detection & alerting

## What gets created

| Area | Resources |
| --- | --- |
| Audit storage | S3 bucket (versioning, SSE-S3, public-access block, lifecycle, TLS-only + confused-deputy bucket policy) |
| Audit capture | Multi-region CloudTrail with log-file validation → S3 **and** CloudWatch Logs |
| Detection | 7 CloudWatch Logs metric filters + 7 alarms |
| Alerting | SNS topic + email subscription; Python Lambda (SNS + optional Slack) |
| Access | IAM roles for CloudTrail→CW Logs and the Lambda (least privilege) |

See [`docs/detections.md`](docs/detections.md) for what each alarm detects and why
it matters, and [`docs/architecture.md`](docs/architecture.md) for the design.

## Repository layout

```
.
├── terraform/                 # All infrastructure as code
│   ├── versions.tf            # Terraform & provider version pins
│   ├── providers.tf           # AWS provider, default_tags, shared locals
│   ├── variables.tf           # Inputs (only alarm_email is required)
│   ├── s3.tf                  # CloudTrail log bucket + security controls
│   ├── cloudtrail.tf          # Multi-region trail + CW Logs group
│   ├── cloudwatch_alarms.tf   # 7 detections via for_each (filters + alarms)
│   ├── sns.tf                 # SNS topic, email subscription, topic policy
│   ├── lambda.tf              # Lambda, log group, permission, subscription filter
│   ├── iam.tf                 # Least-privilege IAM roles & policies
│   ├── outputs.tf             # Useful outputs
│   └── terraform.tfvars.example
├── src/lambda/handler.py      # Alerting Lambda (stdlib + boto3)
├── docs/                      # architecture.md, deployment.md, detections.md
├── diagrams/architecture.mmd  # Mermaid source for the diagram above
└── screenshots/               # Add console screenshots after deploying
```

## Prerequisites

* Terraform >= 1.5 and an AWS account with credentials configured
  (`aws configure` or `AWS_*` environment variables)
* Permissions to create CloudTrail, S3, CloudWatch, SNS, Lambda, and IAM resources
* An email address for alerts (and optionally a Slack Incoming Webhook)

## Deploy / Run

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars      # set at least alarm_email
# optional secret: export TF_VAR_slack_webhook_url="https://hooks.slack.com/services/..."

terraform init
terraform validate
terraform plan
terraform apply
```

Then **confirm the SNS subscription email** AWS sends to your address — alerts
are not delivered until you do. Full walkthrough, including a safe end-to-end
test, is in [`docs/deployment.md`](docs/deployment.md).

## Teardown / Cleanup

```bash
cd terraform
terraform destroy
```

The log bucket uses `force_destroy = false` to protect the audit trail, so empty
it first if you truly want it gone:

```bash
aws s3 rm "s3://$(terraform output -raw cloudtrail_s3_bucket)" --recursive
terraform destroy
```

## Cost notes

Low-cost but **not** guaranteed free. Main line items: CloudWatch Logs ingestion
(~$0.50/GB), CloudWatch alarms (~$0.10/alarm/month × 7), small S3 storage, and
negligible Lambda/SNS usage. Expect well under a few USD/month for a quiet
account. Run `terraform destroy` when finished. Details in
[`docs/deployment.md`](docs/deployment.md#cost-notes).

## Security notes

* No secrets are committed. Copy `terraform.tfvars.example` → `terraform.tfvars`
  (git-ignored) and pass the Slack webhook via `TF_VAR_slack_webhook_url`.
* IAM follows least privilege; the S3 bucket is fully private with a TLS-only,
  confused-deputy-protected policy.
* KMS / SNS-SSE upgrade paths are documented in
  [`docs/detections.md`](docs/detections.md#hardening--production-enhancements).

## Resume bullet

> Implemented automated cloud security monitoring using AWS CloudTrail, CloudWatch, Lambda, and SNS to detect and alert on suspicious activities.

## License

[MIT](LICENSE) © 2026 Janani Mukkoti
