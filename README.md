# AWS Security Dashboard

A comprehensive security monitoring dashboard for AWS infrastructure that provides real-time insights into your AWS security posture across multiple domains.

## Features

### 🏠 Security Overview
- Overall security score calculation
- Critical alerts monitoring
- Recent security events from CloudTrail
- Security trends visualization
- Alert distribution by severity

### 👤 IAM Security Monitoring
- User and role inventory
- MFA compliance tracking
- Access key age monitoring
- User activity patterns
- Policy change tracking

### 🌐 Network Security Analysis
- Security group rule analysis
- VPC configuration monitoring
- Internet gateway tracking
- Open security group detection
- VPC flow logs analysis

### 🛡️ Data Protection
- S3 bucket encryption status
- Public bucket detection
- KMS key management
- Data access patterns
- Encryption compliance tracking

### 📋 Compliance Monitoring
- AWS Config rule compliance
- Compliance score by service
- Compliance trends over time
- Non-compliant resource tracking
- Regulatory standard adherence

### 🚨 Threat Detection
- GuardDuty findings analysis
- Security threat categorization
- Findings timeline tracking
- Threat severity analysis
- Active threat monitoring

## Prerequisites

### AWS Permissions Required

The dashboard requires read-only access to multiple AWS services. Create an IAM policy with the following minimum permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcs",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeRegions",
                "s3:ListAllMyBuckets",
                "s3:GetBucketEncryption",
                "s3:GetPublicAccessBlock",
                "kms:ListKeys",
                "cloudtrail:DescribeTrails",
                "cloudtrail:LookupEvents",
                "guardduty:ListDetectors",
                "guardduty:ListFindings",
                "guardduty:GetFindings",
                "config:DescribeConfigRules",
                "config:GetComplianceDetailsByConfigRule"
            ],
            "Resource": "*"
        }
    ]
}
```

### AWS Services Integration

The dashboard integrates with these AWS services:
- **IAM** - Identity and Access Management monitoring
- **EC2/VPC** - Network security analysis
- **S3** - Storage security and encryption
- **KMS** - Key management service
- **CloudTrail** - Activity logging and monitoring
- **GuardDuty** - Threat detection service
- **Config** - Compliance and configuration monitoring

## Setup Instructions

### 1. AWS Credentials Configuration

You can provide AWS credentials in two ways:

#### Option A: Environment Variables
Set these environment variables:
```bash
export AWS_ACCESS_KEY_ID=your_access_key_id
export AWS_SECRET_ACCESS_KEY=your_secret_access_key
```

#### Option B: Dashboard Interface
Enter credentials directly in the sidebar when running the dashboard.

### 2. Running the Dashboard

The dashboard is built with Streamlit and runs on port 5000:

```bash
streamlit run app.py --server.port 5000
```

### 3. Dashboard Configuration

Use the sidebar to:
- Configure AWS credentials and region
- Set auto-refresh intervals (30s, 1m, 5m, 10m)
- Enable/disable automatic data refresh

## Security Considerations

### Data Privacy
- All AWS API calls are read-only
- No data is stored permanently on the dashboard
- Credentials are handled securely in memory only
- All sensitive data fields are masked in displays

### Network Security
- Dashboard runs locally or in your secure environment
- Direct AWS API communication (no third-party services)
- Uses AWS SDK security best practices

### Permissions
- Follows principle of least privilege
- Only requests necessary read permissions
- No write or modify permissions required

## Dashboard Tabs Explained

### Overview Tab
Provides a high-level security posture summary with key metrics and trends.

### IAM Security Tab
Monitors user management, access patterns, and identity security controls.

### Network Security Tab
Analyzes network configurations, security groups, and traffic patterns.

### Data Protection Tab
Tracks encryption status, data access controls, and storage security.

### Compliance Tab
Shows compliance with AWS Config rules and security standards.

### Alerts & Threats Tab
Displays GuardDuty findings and active security threats.

## Troubleshooting

### Connection Issues
- Verify AWS credentials are correct
- Check IAM permissions match requirements
- Ensure selected region has required services enabled

### Missing Data
- Some services (GuardDuty, Config) must be enabled in your AWS account
- CloudTrail requires active trails for event data
- Regional services show data only for selected region

### Performance
- Large AWS accounts may experience slower load times
- Consider using more restrictive regions for faster queries
- Auto-refresh can be disabled for manual control

## Technical Architecture

### Components
- **app.py** - Main Streamlit application
- **aws_client.py** - AWS SDK wrapper and API client
- **security_monitors.py** - Security data collection and analysis
- **dashboard_components.py** - Visualization components using Plotly
- **utils.py** - Utility functions and data processing

### Data Flow
1. User provides AWS credentials via sidebar
2. AWS client establishes secure connections to services
3. Security monitors collect data from various AWS APIs
4. Dashboard components render visualizations
5. Data refreshes automatically based on configured intervals

## Support

For issues or questions:
1. Verify AWS permissions and service availability
2. Check AWS service status in your region
3. Review CloudTrail for API call errors
4. Ensure GuardDuty and Config are properly configured

## Security Monitoring Best Practices

### Regular Reviews
- Monitor security scores and trends weekly
- Review critical alerts immediately
- Audit IAM permissions monthly
- Track compliance score changes

### Alert Configuration
- Set up notifications for critical findings
- Monitor unusual access patterns
- Track policy changes in real-time
- Review public resource exposure regularly

### Continuous Improvement
- Use dashboard insights for security hardening
- Address non-compliant resources promptly
- Implement MFA for all users
- Regularly rotate access keys