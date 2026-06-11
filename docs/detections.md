# Detections

This document explains every detection implemented by the stack: what it looks
for, the CloudWatch Logs metric-filter pattern used, and why it matters from a
security standpoint. The patterns are based on the
[CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
monitoring recommendations.

All detections work the same way:

1. CloudTrail streams management events into a CloudWatch Logs log group.
2. A **metric filter** matches relevant events and increments a custom metric in
   the `cloud-security-monitoring/SecurityMetrics` namespace.
3. A **CloudWatch alarm** fires when that metric is `>= 1` within the evaluation
   window (default 5 minutes) and publishes to the SNS topic.
4. Subscribers (email, and the formatting Lambda) receive the alert.

The detections are defined as a single map in
[`terraform/cloudwatch_alarms.tf`](../terraform/cloudwatch_alarms.tf), so adding
a new one is just another map entry.

---

## 1. Root account usage

**Metric:** `RootAccountUsage`

**Pattern:**
```
{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
```

**What it detects:** Any action performed using the AWS account **root user**
(excluding automated AWS service events).

**Why it matters:** The root user can do *anything* in the account, including
actions no IAM policy can restrict (closing the account, changing the support
plan, etc.). Best practice is to lock it away with a hardware MFA and never use
it for day-to-day work. Any root activity is therefore high-signal and should be
investigated immediately — it may indicate the root credentials have been
compromised.

## 2. Unauthorized API calls

**Metric:** `UnauthorizedAPICalls`

**Pattern:**
```
{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }
```

**What it detects:** API calls that were rejected with `UnauthorizedOperation`
or `AccessDenied`.

**Why it matters:** A burst of access-denied errors is a classic sign of
**reconnaissance** or **privilege-escalation attempts** — an attacker (or
leaked credential) probing what it is allowed to do. Occasional denials are
normal, so treat the *rate* and *source* as the signal.

## 3. Console sign-in without MFA

**Metric:** `ConsoleSignInWithoutMFA`

**Pattern:**
```
{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }
```

**What it detects:** A successful AWS Management Console login by an IAM user
that did **not** use multi-factor authentication.

**Why it matters:** MFA is one of the single most effective controls against
credential theft. A console login without it means a stolen password alone is
enough to gain access. The pattern is scoped to `IAMUser` to avoid false
positives from federated/SSO logins, which report MFA differently.

## 4. IAM policy changes

**Metric:** `IAMPolicyChanges`

**What it detects:** Creation, deletion, attachment, or detachment of IAM
policies (managed or inline) on users, roles, and groups.

**Why it matters:** Modifying IAM policies is the primary mechanism for
**privilege escalation** and **persistence**. An attacker who lands with limited
access will often try to attach `AdministratorAccess` or add an inline policy to
broaden their reach. Legitimate IAM changes should flow through code review /
IaC, so ad-hoc changes deserve scrutiny.

## 5. Security group changes

**Metric:** `SecurityGroupChanges`

**What it detects:** Creating/deleting security groups and authorizing/revoking
ingress or egress rules.

**Why it matters:** Security groups are stateful virtual firewalls. Opening
ingress (e.g. `0.0.0.0/0` on port 22/3389/3306) is a common way attackers expose
a host for remote access or open a path for data exfiltration. This alarm gives
early warning of network exposure changes.

## 6. Network ACL / gateway changes

**Metric:** `NetworkAclGatewayChanges`

**What it detects:** Changes to network ACLs (subnet-level firewall rules) and to
network gateways — Internet gateways and customer gateways.

**Why it matters:** NACLs and gateways control whether traffic can enter or leave
your VPC at all. Attaching an Internet gateway or loosening a NACL can make
previously private resources reachable from the internet, enabling lateral
movement or exfiltration.

## 7. S3 bucket policy / public-access changes

**Metric:** `S3PolicyChanges`

**What it detects:** Changes to S3 bucket policies, ACLs, and public-access-block
settings (both bucket-level and account-level).

**Why it matters:** Misconfigured S3 is one of the most common causes of public
data breaches. Disabling a public-access block or adding a permissive bucket
policy can expose sensitive data to the entire internet in a single API call.
This detection intentionally matches on `eventName` only (not `eventSource`) so
it catches both bucket-level (`s3.amazonaws.com`) and account-level
(`s3-control.amazonaws.com`) changes.

---

## Tuning & reducing noise

* **Evaluation window** — `alarm_period_seconds` (default 300) and
  `alarm_evaluation_periods` (default 1) control sensitivity. Increase the period
  to reduce noise, decrease it to react faster.
* **Lambda subscription filter** — `lambda_subscription_filter_pattern` selects
  which events reach the formatting Lambda. The default targets the
  highest-severity events; set it to `""` to forward everything (noisier).
* **Threshold** — all alarms fire at `>= 1` event. For high-volume accounts you
  may raise the threshold on the noisier detections (e.g. unauthorized calls).

## Hardening / production enhancements

These are intentionally left as documented enhancements so the lab stays easy to
stand up and tear down:

* **KMS encryption for S3 & CloudWatch Logs** — replace SSE-S3 (`AES256`) with a
  customer-managed KMS key. CloudTrail needs `kms:GenerateDataKey*` and the
  CloudWatch Logs service principal needs encrypt/decrypt permissions in the key
  policy.
* **SNS server-side encryption** — enable SSE on the SNS topic using a
  **customer-managed** KMS key whose policy grants `cloudwatch.amazonaws.com`
  `kms:GenerateDataKey*` and `kms:Decrypt`. The AWS-managed `alias/aws/sns` key
  cannot be used because its (non-editable) policy will silently block alarm
  delivery.
* **Organization trail** — for multi-account environments, convert the trail to
  an organization trail managed from the management account.
* **Additional detections** — CMK disable/scheduled-deletion, AWS Config changes,
  CloudTrail configuration changes, and disabling of GuardDuty are natural next
  additions to the `detections` map.
* **Anomaly detection** — pair the binary metric filters with CloudWatch anomaly
  detection or Amazon GuardDuty for behavioural alerting.
