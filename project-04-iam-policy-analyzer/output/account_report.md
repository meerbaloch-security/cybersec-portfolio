# IAM risk report

**9** principals or policies analysed: **5** critical, **6** high, **7** medium findings.

- Full administrators: **1** (alice-admin)
- Not admin, but can **escalate to admin**: **3** (ci-deployer, support-engineer, legacy-ops)

| Principal | Type | Worst | Findings | Policies |
|---|---|---|---|---|
| alice-admin | user | 🔴 critical | 1 | AdministratorAccess |
| ci-deployer | user | 🔴 critical | 2 | deploy-app (inline) |
| support-engineer | user | 🔴 critical | 1 | SupportTools (via group support) |
| legacy-ops | role | 🔴 critical | 9 | ops-everything-but-iam (inline) |
| data-analyst | user | 🟠 high | 2 | analytics (inline) |
| scoped-deployer | user | 🟡 medium | 1 | deploy-web (inline) |
| lambda-data-processor | role | 🟡 medium | 1 | LambdaDeploy |
| vendor-audit-role | role | 🟡 medium | 1 | ReadOnlyAccess |
| dev-intern | user | 🟢 none | 0 | read-reports (inline) |

## User: alice-admin

### 🔴 CRITICAL · IAM-001 · Full administrator access

Allows every action on every resource ("Action": "*" or equivalent NotAction).

**Permissions:** `*`  
**Fix:** Replace with least-privilege policies scoped to the services and resources actually used.


## User: ci-deployer

### 🔴 CRITICAL · PE-14 · Privilege escalation: Pass a role to a new EC2 instance

Can launch an instance with a privileged role and use that role's credentials from the instance.

**Permissions:** `iam:PassRole`, `ec2:RunInstances`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🟠 HIGH · IAM-005 · iam:PassRole on all roles

Can hand any role, including admin roles, to AWS services.

**Permissions:** `iam:PassRole`  
**Fix:** Scope Resource to the specific role ARNs and add an iam:PassedToService condition.


## User: support-engineer

### 🔴 CRITICAL · PE-01 · Privilege escalation: Create a new version of a managed policy

Can publish a new default version of a policy attached to itself containing "Action": "*".

**Permissions:** `iam:CreatePolicyVersion`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.


## Role: legacy-ops

### 🔴 CRITICAL · PE-17 · Privilege escalation: Replace the code of an existing Lambda function

Can change the code of a function that already runs with a privileged role.

**Permissions:** `lambda:UpdateFunctionCode`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🔴 CRITICAL · PE-21 · Privilege escalation: Run commands on EC2 instances through SSM

Can run commands on instances and use their instance-profile roles.

**Permissions:** `ssm:SendCommand`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🟠 HIGH · IAM-002 · Allow with NotAction

Grants everything except ['iam:*', 'organizations:*']; new AWS services are allowed automatically.

**Permissions:** `iam:*`, `organizations:*`  
**Fix:** Use an explicit Action list instead of NotAction with Allow.

### 🟠 HIGH · IAM-006 · Defense evasion (disables security logging or detection)

Allowed on all resources: cloudtrail:StopLogging, cloudtrail:DeleteTrail, cloudtrail:UpdateTrail, guardduty:DeleteDetector, guardduty:UpdateDetector, config:StopConfigurationRecorder, config:DeleteConfigurationRecorder, securityhub:DisableSecurityHub, logs:DeleteLogGroup

**Permissions:** `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail`, `guardduty:DeleteDetector`, `guardduty:UpdateDetector`, `config:StopConfigurationRecorder`, `config:DeleteConfigurationRecorder`, `securityhub:DisableSecurityHub`, `logs:DeleteLogGroup`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.

### 🟠 HIGH · IAM-006 · Secret and key access (data exfiltration risk)

Allowed on all resources: secretsmanager:GetSecretValue, kms:Decrypt, ssm:GetParameter, ssm:GetParameters, ssm:GetParametersByPath

**Permissions:** `secretsmanager:GetSecretValue`, `kms:Decrypt`, `ssm:GetParameter`, `ssm:GetParameters`, `ssm:GetParametersByPath`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.

### 🟠 HIGH · IAM-006 · Resource policy changes (can expose data publicly)

Allowed on all resources: s3:PutBucketPolicy, s3:PutBucketAcl, s3:DeleteBucketPolicy, s3:PutBucketPublicAccessBlock, kms:PutKeyPolicy, lambda:AddPermission, sns:SetTopicAttributes, sqs:SetQueueAttributes

**Permissions:** `s3:PutBucketPolicy`, `s3:PutBucketAcl`, `s3:DeleteBucketPolicy`, `s3:PutBucketPublicAccessBlock`, `kms:PutKeyPolicy`, `lambda:AddPermission`, `sns:SetTopicAttributes`, `sqs:SetQueueAttributes`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.

### 🟡 MEDIUM · IAM-006 · Broad data read access

Allowed on all resources: s3:GetObject, dynamodb:Scan, dynamodb:GetItem, rds:DownloadDBLogFilePortion

**Permissions:** `s3:GetObject`, `dynamodb:Scan`, `dynamodb:GetItem`, `rds:DownloadDBLogFilePortion`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.

### 🟡 MEDIUM · IAM-006 · Destructive actions

Allowed on all resources: s3:DeleteBucket, s3:DeleteObject, rds:DeleteDBInstance, ec2:TerminateInstances, dynamodb:DeleteTable, kms:ScheduleKeyDeletion

**Permissions:** `s3:DeleteBucket`, `s3:DeleteObject`, `rds:DeleteDBInstance`, `ec2:TerminateInstances`, `dynamodb:DeleteTable`, `kms:ScheduleKeyDeletion`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.

### 🟡 MEDIUM · IAM-006 · Network exposure

Allowed on all resources: ec2:AuthorizeSecurityGroupIngress, ec2:ModifyInstanceAttribute

**Permissions:** `ec2:AuthorizeSecurityGroupIngress`, `ec2:ModifyInstanceAttribute`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.


## User: data-analyst

### 🟠 HIGH · IAM-006 · Secret and key access (data exfiltration risk)

Allowed on all resources: secretsmanager:GetSecretValue

**Permissions:** `secretsmanager:GetSecretValue`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.

### 🟡 MEDIUM · IAM-006 · Broad data read access

Allowed on all resources: s3:GetObject

**Permissions:** `s3:GetObject`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.


## User: scoped-deployer

### 🟡 MEDIUM · PE-14 · Privilege escalation: Pass a role to a new EC2 instance

Can launch an instance with a privileged role and use that role's credentials from the instance. Permissions are scoped to specific resources, so confirm whether those resources are privileged.

**Permissions:** `iam:PassRole`, `ec2:RunInstances`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.


## Role: lambda-data-processor

### 🟡 MEDIUM · PE-17 · Privilege escalation: Replace the code of an existing Lambda function

Can change the code of a function that already runs with a privileged role. Permissions are scoped to specific resources, so confirm whether those resources are privileged.

**Permissions:** `lambda:UpdateFunctionCode`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.


## Role: vendor-audit-role

### 🟡 MEDIUM · IAM-008 · Role trusts an entire account

Any principal with sts:AssumeRole in arn:aws:iam::444455556666:root can assume this role.

**Permissions:** `sts:AssumeRole`  
**Fix:** Trust a specific role ARN, or add conditions (sts:ExternalId, aws:PrincipalArn).

> Note: could not read managed policy document(s): arn:aws:iam::aws:policy/ReadOnlyAccess
