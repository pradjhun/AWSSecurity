# AWS Security Compliance Rules Reference

This document outlines the security compliance rules and standards that the AWS Security Dashboard tests against.

## AWS Config Rules

The dashboard monitors compliance through AWS Config rules, which evaluate AWS resources against configuration best practices.

### Identity and Access Management (IAM) Rules

#### IAM-1: Root User Access Key Check
- **Rule Name**: `root-user-access-key-check`
- **Description**: Checks if root user has active access keys
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 1.12
- **Risk Level**: Critical
- **Remediation**: Remove or deactivate root user access keys

#### IAM-2: MFA Enabled for Root User
- **Rule Name**: `root-user-mfa-enabled`
- **Description**: Checks if MFA is enabled for root user
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 1.13
- **Risk Level**: Critical
- **Remediation**: Enable MFA for root user account

#### IAM-3: IAM Users MFA Enabled
- **Rule Name**: `iam-user-mfa-enabled`
- **Description**: Checks if MFA is enabled for all IAM users
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 1.2
- **Risk Level**: High
- **Remediation**: Enable MFA for all IAM users with console access

#### IAM-4: IAM Password Policy
- **Rule Name**: `iam-password-policy`
- **Description**: Checks if password policy meets security requirements
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 1.5-1.11
- **Requirements**:
  - Minimum password length: 14 characters
  - Require uppercase letters
  - Require lowercase letters
  - Require numbers
  - Require symbols
  - Password expiration: 90 days maximum
- **Risk Level**: Medium
- **Remediation**: Configure compliant password policy

#### IAM-5: Access Key Rotation
- **Rule Name**: `access-keys-rotated`
- **Description**: Checks if access keys are rotated within 90 days
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 1.4
- **Risk Level**: Medium
- **Remediation**: Rotate access keys regularly

#### IAM-6: IAM Users No Inline Policies
- **Rule Name**: `iam-user-no-policies-check`
- **Description**: Checks if IAM users have no inline policies attached
- **Compliance Standard**: AWS Security Best Practices
- **Risk Level**: Medium
- **Remediation**: Use groups and managed policies instead

### Network Security Rules

#### EC2-1: Security Groups Restricted SSH
- **Rule Name**: `incoming-ssh-disabled`
- **Description**: Checks if security groups restrict SSH access (port 22) from 0.0.0.0/0
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 4.1
- **Risk Level**: High
- **Remediation**: Restrict SSH access to specific IP ranges

#### EC2-2: Security Groups Restricted RDP
- **Rule Name**: `restricted-rdp`
- **Description**: Checks if security groups restrict RDP access (port 3389) from 0.0.0.0/0
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 4.2
- **Risk Level**: High
- **Remediation**: Restrict RDP access to specific IP ranges

#### EC2-3: Default Security Group Closed
- **Rule Name**: `ec2-security-group-attached-to-eni`
- **Description**: Checks if default security groups restrict all traffic
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 4.3
- **Risk Level**: Medium
- **Remediation**: Remove all rules from default security groups

#### VPC-1: VPC Flow Logs Enabled
- **Rule Name**: `vpc-flow-logs-enabled`
- **Description**: Checks if VPC Flow Logs are enabled for VPCs
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 2.9
- **Risk Level**: Medium
- **Remediation**: Enable VPC Flow Logs for network monitoring

### Data Protection Rules

#### S3-1: Bucket Public Read Prohibited
- **Rule Name**: `s3-bucket-public-read-prohibited`
- **Description**: Checks if S3 buckets do not allow public read access
- **Compliance Standard**: AWS Foundational Security Standard
- **Risk Level**: Critical
- **Remediation**: Enable S3 Block Public Access settings

#### S3-2: Bucket Public Write Prohibited
- **Rule Name**: `s3-bucket-public-write-prohibited`
- **Description**: Checks if S3 buckets do not allow public write access
- **Compliance Standard**: AWS Foundational Security Standard
- **Risk Level**: Critical
- **Remediation**: Enable S3 Block Public Access settings

#### S3-3: Server Side Encryption Enabled
- **Rule Name**: `s3-bucket-server-side-encryption-enabled`
- **Description**: Checks if S3 buckets have server-side encryption enabled
- **Compliance Standard**: AWS Security Best Practices
- **Risk Level**: High
- **Remediation**: Enable default encryption for S3 buckets

#### S3-4: Bucket SSL Requests Only
- **Rule Name**: `s3-bucket-ssl-requests-only`
- **Description**: Checks if S3 buckets have policies requiring SSL requests
- **Compliance Standard**: AWS Security Best Practices
- **Risk Level**: Medium
- **Remediation**: Add bucket policy requiring SSL/TLS

#### RDS-1: Storage Encrypted
- **Rule Name**: `rds-storage-encrypted`
- **Description**: Checks if RDS instances have storage encryption enabled
- **Compliance Standard**: AWS Security Best Practices
- **Risk Level**: High
- **Remediation**: Enable encryption for RDS instances

#### RDS-2: Snapshot Encrypted
- **Rule Name**: `rds-snapshot-encrypted`
- **Description**: Checks if RDS snapshots are encrypted
- **Compliance Standard**: AWS Security Best Practices
- **Risk Level**: High
- **Remediation**: Enable encryption for RDS snapshots

### Logging and Monitoring Rules

#### CloudTrail-1: Enabled
- **Rule Name**: `cloudtrail-enabled`
- **Description**: Checks if CloudTrail is enabled in the account
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 2.1
- **Risk Level**: Critical
- **Remediation**: Enable CloudTrail logging

#### CloudTrail-2: Log File Validation
- **Rule Name**: `cloud-trail-log-file-validation-enabled`
- **Description**: Checks if CloudTrail log file validation is enabled
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 2.2
- **Risk Level**: Medium
- **Remediation**: Enable CloudTrail log file validation

#### CloudTrail-3: Encrypted
- **Rule Name**: `cloud-trail-encryption-enabled`
- **Description**: Checks if CloudTrail logs are encrypted at rest
- **Compliance Standard**: CIS AWS Foundations Benchmark v1.2.0 - 2.7
- **Risk Level**: Medium
- **Remediation**: Enable CloudTrail log encryption

#### CloudWatch-1: Log Group Retention
- **Rule Name**: `cw-loggroup-retention-period-check`
- **Description**: Checks if CloudWatch Log Groups have retention period set
- **Compliance Standard**: AWS Operational Best Practices
- **Risk Level**: Low
- **Remediation**: Set retention period for log groups

### Compute Security Rules

#### EC2-4: Instance Managed by SSM
- **Rule Name**: `ec2-instance-managed-by-systems-manager`
- **Description**: Checks if EC2 instances are managed by AWS Systems Manager
- **Compliance Standard**: AWS Operational Best Practices
- **Risk Level**: Medium
- **Remediation**: Install SSM agent and assign IAM role

#### EC2-5: No Public IP
- **Rule Name**: `ec2-instance-no-public-ip`
- **Description**: Checks if EC2 instances have public IP addresses
- **Compliance Standard**: AWS Security Best Practices
- **Risk Level**: Medium
- **Remediation**: Use private subnets for internal instances

#### Lambda-1: Function Public Access Prohibited
- **Rule Name**: `lambda-function-public-access-prohibited`
- **Description**: Checks if Lambda functions restrict public access
- **Compliance Standard**: AWS Security Best Practices
- **Risk Level**: High
- **Remediation**: Remove public access from Lambda functions

### Backup and Recovery Rules

#### Backup-1: Recovery Point Compliance
- **Rule Name**: `backup-recovery-point-minimum-frequency`
- **Description**: Checks if backup plans meet minimum frequency requirements
- **Compliance Standard**: AWS Operational Best Practices
- **Risk Level**: Medium
- **Remediation**: Configure appropriate backup frequency

#### EBS-1: Snapshot Public Restore Disabled
- **Rule Name**: `ebs-snapshot-public-restorable-check`
- **Description**: Checks if EBS snapshots are not publicly restorable
- **Compliance Standard**: AWS Security Best Practices
- **Risk Level**: High
- **Remediation**: Make EBS snapshots private

## Compliance Frameworks

### CIS AWS Foundations Benchmark
The Center for Internet Security (CIS) AWS Foundations Benchmark provides security configuration best practices for AWS.

**Key Areas:**
- Identity and Access Management
- Logging and Monitoring
- Storage
- Networking

### AWS Foundational Security Standard
AWS-developed security standard that defines fundamental security controls for AWS services.

**Coverage:**
- 40+ security controls
- Critical and high severity findings
- Automated remediation guidance

### PCI DSS (Payment Card Industry Data Security Standard)
For organizations handling credit card data.

**Key Requirements:**
- Network security
- Data encryption
- Access controls
- Regular monitoring

### SOC 2 Type II
Service Organization Control 2 framework for service providers.

**Trust Principles:**
- Security
- Availability
- Processing integrity
- Confidentiality
- Privacy

### HIPAA (Health Insurance Portability and Accountability Act)
For organizations handling protected health information.

**Security Rules:**
- Administrative safeguards
- Physical safeguards
- Technical safeguards

## Custom Security Rules

### Organization-Specific Rules
The dashboard can be extended to include custom rules specific to your organization:

#### Cost Optimization Rules
- **Rule**: `unused-security-groups`
- **Description**: Identifies security groups not attached to any resources
- **Risk Level**: Low
- **Impact**: Cost reduction

#### Operational Rules
- **Rule**: `resource-tagging-compliance`
- **Description**: Ensures all resources have required tags
- **Risk Level**: Low
- **Impact**: Operational efficiency

#### Advanced Security Rules
- **Rule**: `privileged-access-review`
- **Description**: Reviews accounts with administrative access
- **Risk Level**: High
- **Impact**: Privilege escalation prevention

## Compliance Scoring

### Score Calculation
The security score is calculated based on:
- **Critical violations**: -10 points each (max -50)
- **High violations**: -5 points each (max -30)
- **Medium violations**: -3 points each (max -15)
- **Low violations**: -1 point each (max -5)

### Score Categories
- **90-100**: Excellent security posture
- **80-89**: Good security posture
- **70-79**: Adequate security posture
- **60-69**: Poor security posture
- **Below 60**: Critical security issues

### Remediation Priority
1. **Critical**: Address immediately (0-24 hours)
2. **High**: Address within 1 week
3. **Medium**: Address within 1 month
4. **Low**: Address within next quarterly review

## Implementation Status

### Currently Monitored
✅ IAM user and role configuration
✅ Security group rules
✅ S3 bucket encryption and public access
✅ CloudTrail logging status
✅ GuardDuty threat detection
✅ Basic Config rule compliance

### Planned Enhancements
🔄 VPC Flow Logs analysis
🔄 RDS encryption compliance
🔄 Lambda function security
🔄 EBS encryption status
🔄 Advanced threat intelligence
🔄 Custom rule framework

### Integration Requirements
- AWS Config service must be enabled
- Appropriate IAM permissions for rule evaluation
- CloudTrail for audit logging
- GuardDuty for threat detection
- Regular rule updates for new AWS services

This compliance framework ensures comprehensive security monitoring aligned with industry standards and AWS best practices.