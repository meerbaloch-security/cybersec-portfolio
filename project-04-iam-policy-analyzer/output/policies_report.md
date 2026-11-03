# IAM risk report

**3** principals or policies analysed: **12** critical, **4** high, **2** medium findings.

- Full administrators: **0** (none)
- Not admin, but can **escalate to admin**: **1** (overly_broad_admin_tools)

| Principal | Type | Worst | Findings | Policies |
|---|---|---|---|---|
| overly_broad_admin_tools | policy | 🔴 critical | 17 | overly_broad_admin_tools.json |
| public_bucket_policy | policy | 🔴 critical | 1 | public_bucket_policy.json |
| least_privilege_app | policy | 🟢 none | 0 | least_privilege_app.json |

## Policy: overly_broad_admin_tools

### 🔴 CRITICAL · IAM-003 · Service-wide wildcard: iam:*

Grants every iam action on all resources.

**Permissions:** `iam:*`  
**Fix:** List only the iam actions needed and scope Resource to specific ARNs.

### 🔴 CRITICAL · PE-01 · Privilege escalation: Create a new version of a managed policy

Can publish a new default version of a policy attached to itself containing "Action": "*".

**Permissions:** `iam:CreatePolicyVersion`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🔴 CRITICAL · PE-02 · Privilege escalation: Switch a policy's default version

Can roll a policy back to an older, more permissive version.

**Permissions:** `iam:SetDefaultPolicyVersion`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🔴 CRITICAL · PE-03 · Privilege escalation: Attach a managed policy to a user

Can attach AdministratorAccess to itself or another user.

**Permissions:** `iam:AttachUserPolicy`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🔴 CRITICAL · PE-04 · Privilege escalation: Attach a managed policy to a group

Can attach AdministratorAccess to a group it belongs to.

**Permissions:** `iam:AttachGroupPolicy`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🔴 CRITICAL · PE-06 · Privilege escalation: Write an inline policy on a user

Can add an inline admin policy to itself.

**Permissions:** `iam:PutUserPolicy`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🔴 CRITICAL · PE-07 · Privilege escalation: Write an inline policy on a group

Can add an inline admin policy to a group it belongs to.

**Permissions:** `iam:PutGroupPolicy`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🔴 CRITICAL · PE-09 · Privilege escalation: Add self to a privileged group

Can join an existing admin group.

**Permissions:** `iam:AddUserToGroup`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🔴 CRITICAL · PE-10 · Privilege escalation: Create access keys for other users

Can create keys for a more privileged user and act as them.

**Permissions:** `iam:CreateAccessKey`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🔴 CRITICAL · PE-11 · Privilege escalation: Set or reset another user's console password

Can give a privileged user a console password it knows.

**Permissions:** `iam:CreateLoginProfile`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🔴 CRITICAL · PE-12 · Privilege escalation: Reset another user's console password

Can change a privileged user's console password.

**Permissions:** `iam:UpdateLoginProfile`  
**Fix:** Remove these permissions, or scope them to non-privileged resources with a permissions boundary.

### 🟠 HIGH · IAM-003 · Service-wide wildcard: s3:*

Grants every s3 action on all resources.

**Permissions:** `s3:*`  
**Fix:** List only the s3 actions needed and scope Resource to specific ARNs.

### 🟠 HIGH · IAM-005 · iam:PassRole on all roles

Can hand any role, including admin roles, to AWS services.

**Permissions:** `iam:PassRole`  
**Fix:** Scope Resource to the specific role ARNs and add an iam:PassedToService condition.

### 🟠 HIGH · IAM-006 · Defense evasion (disables security logging or detection)

Allowed on all resources: cloudtrail:StopLogging

**Permissions:** `cloudtrail:StopLogging`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.

### 🟠 HIGH · IAM-006 · Resource policy changes (can expose data publicly)

Allowed on all resources: s3:PutBucketPolicy, s3:PutBucketAcl, s3:DeleteBucketPolicy, s3:PutBucketPublicAccessBlock

**Permissions:** `s3:PutBucketPolicy`, `s3:PutBucketAcl`, `s3:DeleteBucketPolicy`, `s3:PutBucketPublicAccessBlock`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.

### 🟡 MEDIUM · IAM-006 · Broad data read access

Allowed on all resources: s3:GetObject

**Permissions:** `s3:GetObject`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.

### 🟡 MEDIUM · IAM-006 · Destructive actions

Allowed on all resources: s3:DeleteBucket, s3:DeleteObject

**Permissions:** `s3:DeleteBucket`, `s3:DeleteObject`  
**Fix:** Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.


## Policy: public_bucket_policy

### 🔴 CRITICAL · IAM-004 · Resource policy allows anyone (Principal "*")

Any AWS account, or anonymous users for S3, can use this resource.

**Permissions:** `s3:GetObject`  
**Fix:** Restrict Principal to specific account or role ARNs, or add aws:SourceAccount / aws:PrincipalOrgID conditions.
