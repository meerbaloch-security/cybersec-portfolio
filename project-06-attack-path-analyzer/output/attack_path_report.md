# Attack path report: acme-retail-prod (111122223333)

**17 attack paths** reach **3 crown jewels** from 3 entry points. The shortest takes **2 steps**.

**3 fixes break at least 80% of paths; 5 break all of them.**

## Fix plan (highest impact first)

| # | Fix | Paths broken | Paths removed so far | Risk removed so far |
|---|---|---|---|---|
| 1 | Upgrade django to 3.2.14 and pillow to 10.0.1 on web-prod-1 (2 exploitable CVEs), or remove internet access to port 443 | 4 | 24% | 38% |
| 2 | Upgrade pillow to 10.0.1 on image-resizer, or remove internet access to port 443 | 2 | 35% | 61% |
| 3 | Close port 22 to the internet; use SSM Session Manager and key-only auth | 8 | 82% | 81% |
| 4 | Rotate and remove ci-bot's access key; use short-lived credentials (OIDC / IAM roles) | 2 | 94% | 93% |
| 5 | Add an sts:ExternalId condition to vendor-audit-role's trust policy and trust a specific role ARN | 1 | 100% | 100% |

## Attack paths

### #1 · risk 83 · Very likely · acme-customer-data

**Internet → web-prod-1 → web-app-role → acme-customer-data**

| Step | ATT&CK | Evidence |
|---|---|---|
| Exploit CVE-2023-4863 in pillow 8.0.0 | T1190 | Django storefront on port 443 open to the internet; CVE-2023-4863 in CISA KEV (exploited in the wild) |
| Use the attached role's credentials | T1552.005 | web-prod-1 runs as role web-app-role; credentials available from the instance metadata service (IMDSv1 also allows SSRF theft) |
| Read acme-customer-data | T1530 | web-app-role may call s3:GetObject on acme-customer-data |

### #2 · risk 83 · Very likely · acme-customer-data

**Internet → image-resizer → resizer-role → acme-customer-data**

| Step | ATT&CK | Evidence |
|---|---|---|
| Exploit CVE-2023-4863 in pillow 8.0.0 | T1190 | Lambda function URL on port 443 open to the internet; CVE-2023-4863 in CISA KEV (exploited in the wild) |
| Use the attached role's credentials | T1552.005 | image-resizer runs as role resizer-role; credentials available from the function environment |
| Read acme-customer-data | T1530 | resizer-role may call s3:GetObject on acme-customer-data |

### #3 · risk 58 · Very likely · acme-finance-reports

**Internet → image-resizer → resizer-role → acme-finance-reports**

| Step | ATT&CK | Evidence |
|---|---|---|
| Exploit CVE-2023-4863 in pillow 8.0.0 | T1190 | Lambda function URL on port 443 open to the internet; CVE-2023-4863 in CISA KEV (exploited in the wild) |
| Use the attached role's credentials | T1552.005 | image-resizer runs as role resizer-role; credentials available from the function environment |
| Read acme-finance-reports | T1530 | resizer-role may call s3:GetObject on acme-finance-reports |

### #4 · risk 58 · Likely · acme-customer-data

**Internet → web-prod-1 → web-app-role → deploy-role → Account administrator → acme-customer-data**

| Step | ATT&CK | Evidence |
|---|---|---|
| Exploit CVE-2023-4863 in pillow 8.0.0 | T1190 | Django storefront on port 443 open to the internet; CVE-2023-4863 in CISA KEV (exploited in the wild) |
| Use the attached role's credentials | T1552.005 | web-prod-1 runs as role web-app-role; credentials available from the instance metadata service (IMDSv1 also allows SSRF theft) |
| Assume role deploy-role | T1078.004 | web-app-role may call sts:AssumeRole on deploy-role, and deploy-role's trust policy allows it |
| Escalate: Launch an instance with an admin role | T1098 | deploy-role has iam:PassRole + ec2:RunInstances on all resources |
| Read acme-customer-data | T1530 | Administrators can access all data |

### #5 · risk 58 · Likely · prod-db-credentials

**Internet → web-prod-1 → web-app-role → deploy-role → Account administrator → prod-db-credentials**

| Step | ATT&CK | Evidence |
|---|---|---|
| Exploit CVE-2023-4863 in pillow 8.0.0 | T1190 | Django storefront on port 443 open to the internet; CVE-2023-4863 in CISA KEV (exploited in the wild) |
| Use the attached role's credentials | T1552.005 | web-prod-1 runs as role web-app-role; credentials available from the instance metadata service (IMDSv1 also allows SSRF theft) |
| Assume role deploy-role | T1078.004 | web-app-role may call sts:AssumeRole on deploy-role, and deploy-role's trust policy allows it |
| Escalate: Launch an instance with an admin role | T1098 | deploy-role has iam:PassRole + ec2:RunInstances on all resources |
| Read prod-db-credentials | T1530 | Administrators can access all data |

### #6 · risk 47 · Likely · acme-finance-reports

**Vendor account → vendor-audit-role → acme-finance-reports**

| Step | ATT&CK | Evidence |
|---|---|---|
| Assume role trusted by a third party | T1199 | Role vendor-audit-role trusts the whole account 444455556666 with no ExternalId condition; a compromise of that vendor (or a confused deputy) reaches this account |
| Read acme-finance-reports | T1530 | vendor-audit-role may call s3:GetObject on acme-finance-reports |

### #7 · risk 42 · Possible · acme-customer-data

**Leaked access key → ci-bot → image-resizer → resizer-role → acme-customer-data**

| Step | ATT&CK | Evidence |
|---|---|---|
| Use a leaked long-lived access key | T1078.004 | ci-bot has an access key 412 days old and no MFA |
| Replace the code of image-resizer | T1648 | ci-bot may call lambda:UpdateFunctionCode on image-resizer |
| Use the attached role's credentials | T1552.005 | image-resizer runs as role resizer-role; credentials available from the function environment |
| Read acme-customer-data | T1530 | resizer-role may call s3:GetObject on acme-customer-data |

### #8 · risk 41 · Likely · acme-finance-reports

**Internet → web-prod-1 → web-app-role → deploy-role → Account administrator → acme-finance-reports**

| Step | ATT&CK | Evidence |
|---|---|---|
| Exploit CVE-2023-4863 in pillow 8.0.0 | T1190 | Django storefront on port 443 open to the internet; CVE-2023-4863 in CISA KEV (exploited in the wild) |
| Use the attached role's credentials | T1552.005 | web-prod-1 runs as role web-app-role; credentials available from the instance metadata service (IMDSv1 also allows SSRF theft) |
| Assume role deploy-role | T1078.004 | web-app-role may call sts:AssumeRole on deploy-role, and deploy-role's trust policy allows it |
| Escalate: Launch an instance with an admin role | T1098 | deploy-role has iam:PassRole + ec2:RunInstances on all resources |
| Read acme-finance-reports | T1530 | Administrators can access all data |

### #9 · risk 29 · Possible · acme-finance-reports

**Leaked access key → ci-bot → image-resizer → resizer-role → acme-finance-reports**

| Step | ATT&CK | Evidence |
|---|---|---|
| Use a leaked long-lived access key | T1078.004 | ci-bot has an access key 412 days old and no MFA |
| Replace the code of image-resizer | T1648 | ci-bot may call lambda:UpdateFunctionCode on image-resizer |
| Use the attached role's credentials | T1552.005 | image-resizer runs as role resizer-role; credentials available from the function environment |
| Read acme-finance-reports | T1530 | resizer-role may call s3:GetObject on acme-finance-reports |

### #10 · risk 25 · Unlikely · acme-customer-data

**Internet → bastion-1 → bastion-role → web-prod-1 → web-app-role → acme-customer-data**

| Step | ATT&CK | Evidence |
|---|---|---|
| Brute-force SSH password | T1110 | Port 22 open to the internet with password login enabled |
| Use the attached role's credentials | T1552.005 | bastion-1 runs as role bastion-role; credentials available from the instance metadata service |
| Run commands on web-prod-1 via SSM | T1651 | bastion-role may call ssm:SendCommand on web-prod-1 |
| Use the attached role's credentials | T1552.005 | web-prod-1 runs as role web-app-role; credentials available from the instance metadata service (IMDSv1 also allows SSRF theft) |
| Read acme-customer-data | T1530 | web-app-role may call s3:GetObject on acme-customer-data |

### #11 · risk 25 · Unlikely · prod-db-credentials

**Internet → bastion-1 → bastion-role → internal-api → internal-api-role → prod-db-credentials**

| Step | ATT&CK | Evidence |
|---|---|---|
| Brute-force SSH password | T1110 | Port 22 open to the internet with password login enabled |
| Use the attached role's credentials | T1552.005 | bastion-1 runs as role bastion-role; credentials available from the instance metadata service |
| Run commands on internal-api via SSM | T1651 | bastion-role may call ssm:SendCommand on internal-api |
| Use the attached role's credentials | T1552.005 | internal-api runs as role internal-api-role; credentials available from the instance metadata service |
| Read prod-db-credentials | T1530 | internal-api-role may call secretsmanager:GetSecretValue on prod-db-credentials |

### #12 · risk 15 · Unlikely · acme-customer-data

**Internet → bastion-1 → bastion-role → batch-worker → batch-role → Account administrator → acme-customer-data**

| Step | ATT&CK | Evidence |
|---|---|---|
| Brute-force SSH password | T1110 | Port 22 open to the internet with password login enabled |
| Use the attached role's credentials | T1552.005 | bastion-1 runs as role bastion-role; credentials available from the instance metadata service |
| Run commands on batch-worker via SSM | T1651 | bastion-role may call ssm:SendCommand on batch-worker |
| Use the attached role's credentials | T1552.005 | batch-worker runs as role batch-role; credentials available from the instance metadata service |
| Escalate: Publish an admin version of its own policy | T1098 | batch-role has iam:CreatePolicyVersion on all resources |
| Read acme-customer-data | T1530 | Administrators can access all data |

### #13 · risk 15 · Unlikely · prod-db-credentials

**Internet → bastion-1 → bastion-role → batch-worker → batch-role → Account administrator → prod-db-credentials**

| Step | ATT&CK | Evidence |
|---|---|---|
| Brute-force SSH password | T1110 | Port 22 open to the internet with password login enabled |
| Use the attached role's credentials | T1552.005 | bastion-1 runs as role bastion-role; credentials available from the instance metadata service |
| Run commands on batch-worker via SSM | T1651 | bastion-role may call ssm:SendCommand on batch-worker |
| Use the attached role's credentials | T1552.005 | batch-worker runs as role batch-role; credentials available from the instance metadata service |
| Escalate: Publish an admin version of its own policy | T1098 | batch-role has iam:CreatePolicyVersion on all resources |
| Read prod-db-credentials | T1530 | Administrators can access all data |

### #14 · risk 15 · Unlikely · acme-customer-data

**Internet → bastion-1 → bastion-role → web-prod-1 → web-app-role → deploy-role → Account administrator → acme-customer-data**

| Step | ATT&CK | Evidence |
|---|---|---|
| Brute-force SSH password | T1110 | Port 22 open to the internet with password login enabled |
| Use the attached role's credentials | T1552.005 | bastion-1 runs as role bastion-role; credentials available from the instance metadata service |
| Run commands on web-prod-1 via SSM | T1651 | bastion-role may call ssm:SendCommand on web-prod-1 |
| Use the attached role's credentials | T1552.005 | web-prod-1 runs as role web-app-role; credentials available from the instance metadata service (IMDSv1 also allows SSRF theft) |
| Assume role deploy-role | T1078.004 | web-app-role may call sts:AssumeRole on deploy-role, and deploy-role's trust policy allows it |
| Escalate: Launch an instance with an admin role | T1098 | deploy-role has iam:PassRole + ec2:RunInstances on all resources |
| Read acme-customer-data | T1530 | Administrators can access all data |

### #15 · risk 15 · Unlikely · prod-db-credentials

**Internet → bastion-1 → bastion-role → web-prod-1 → web-app-role → deploy-role → Account administrator → prod-db-credentials**

| Step | ATT&CK | Evidence |
|---|---|---|
| Brute-force SSH password | T1110 | Port 22 open to the internet with password login enabled |
| Use the attached role's credentials | T1552.005 | bastion-1 runs as role bastion-role; credentials available from the instance metadata service |
| Run commands on web-prod-1 via SSM | T1651 | bastion-role may call ssm:SendCommand on web-prod-1 |
| Use the attached role's credentials | T1552.005 | web-prod-1 runs as role web-app-role; credentials available from the instance metadata service (IMDSv1 also allows SSRF theft) |
| Assume role deploy-role | T1078.004 | web-app-role may call sts:AssumeRole on deploy-role, and deploy-role's trust policy allows it |
| Escalate: Launch an instance with an admin role | T1098 | deploy-role has iam:PassRole + ec2:RunInstances on all resources |
| Read prod-db-credentials | T1530 | Administrators can access all data |

### #16 · risk 10 · Unlikely · acme-finance-reports

**Internet → bastion-1 → bastion-role → batch-worker → batch-role → Account administrator → acme-finance-reports**

| Step | ATT&CK | Evidence |
|---|---|---|
| Brute-force SSH password | T1110 | Port 22 open to the internet with password login enabled |
| Use the attached role's credentials | T1552.005 | bastion-1 runs as role bastion-role; credentials available from the instance metadata service |
| Run commands on batch-worker via SSM | T1651 | bastion-role may call ssm:SendCommand on batch-worker |
| Use the attached role's credentials | T1552.005 | batch-worker runs as role batch-role; credentials available from the instance metadata service |
| Escalate: Publish an admin version of its own policy | T1098 | batch-role has iam:CreatePolicyVersion on all resources |
| Read acme-finance-reports | T1530 | Administrators can access all data |

### #17 · risk 10 · Unlikely · acme-finance-reports

**Internet → bastion-1 → bastion-role → web-prod-1 → web-app-role → deploy-role → Account administrator → acme-finance-reports**

| Step | ATT&CK | Evidence |
|---|---|---|
| Brute-force SSH password | T1110 | Port 22 open to the internet with password login enabled |
| Use the attached role's credentials | T1552.005 | bastion-1 runs as role bastion-role; credentials available from the instance metadata service |
| Run commands on web-prod-1 via SSM | T1651 | bastion-role may call ssm:SendCommand on web-prod-1 |
| Use the attached role's credentials | T1552.005 | web-prod-1 runs as role web-app-role; credentials available from the instance metadata service (IMDSv1 also allows SSRF theft) |
| Assume role deploy-role | T1078.004 | web-app-role may call sts:AssumeRole on deploy-role, and deploy-role's trust policy allows it |
| Escalate: Launch an instance with an admin role | T1098 | deploy-role has iam:PassRole + ec2:RunInstances on all resources |
| Read acme-finance-reports | T1530 | Administrators can access all data |
