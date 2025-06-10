# AWS Security Dashboard

A comprehensive, AI-powered security monitoring and vulnerability assessment platform for AWS infrastructure, built with Streamlit and enhanced with Trivy-inspired scanning capabilities.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [Security Scanning](#security-scanning)
- [AI-Powered Analysis](#ai-powered-analysis)
- [Export and Reporting](#export-and-reporting)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Overview

The AWS Security Dashboard provides enterprise-grade security monitoring for AWS environments with real-time vulnerability scanning, compliance assessment, and AI-powered recommendations. It combines comprehensive security checks with intelligent analysis to help organizations maintain robust cloud security postures.

### Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Streamlit     │    │   AWS Services  │    │  AI Analysis    │
│   Dashboard     │◄──►│   Integration   │◄──►│   (Bedrock)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Vulnerability  │    │   Multi-Region  │    │   Compliance    │
│   Scanner       │    │   Monitoring    │    │   Analysis      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Features

### Core Security Monitoring
- **Multi-region AWS infrastructure monitoring**
- **Real-time security alerts and notifications**
- **Comprehensive compliance assessment**
- **IAM security analysis and recommendations**
- **Network security evaluation**
- **Data protection and encryption monitoring**

### Advanced Vulnerability Scanning
- **Container image vulnerability detection (ECR)**
- **Infrastructure misconfiguration analysis**
- **Secret and credential exposure detection**
- **License compliance checking**
- **Software Bill of Materials (SBOM) generation**
- **CVE database integration with CVSS scoring**

### AI-Powered Intelligence
- **AWS Bedrock integration for intelligent analysis**
- **Contextual security recommendations**
- **Threat intelligence and exploit detection**
- **Automated compliance gap analysis**
- **Risk scoring and prioritization**

### Specialized Security Assessments
- **OWASP Top 10 for LLM Applications**
- **Enhanced security checks (Prowler-inspired)**
- **Database security assessments**
- **Kubernetes security evaluation (EKS)**
- **Serverless function security analysis**

### Reporting and Export
- **Executive security dashboards**
- **PDF compliance reports**
- **JSON/CSV data export**
- **Security Hub integration**
- **Real-time monitoring dashboards**

## Installation

### Prerequisites

- Python 3.11 or higher
- AWS CLI configured with appropriate permissions
- Access to AWS Bedrock (optional, for AI features)

### System Requirements

- **Memory**: Minimum 4GB RAM, recommended 8GB
- **Storage**: 2GB free space
- **Network**: Internet connectivity for AWS API calls

### Quick Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd aws-security-dashboard
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
streamlit run app.py --server.port 5000
```

### Docker Installation

```bash
# Build the container
docker build -t aws-security-dashboard .

# Run the container
docker run -p 5000:5000 -e AWS_ACCESS_KEY_ID=your_key -e AWS_SECRET_ACCESS_KEY=your_secret aws-security-dashboard
```

### Dependencies

The application requires the following Python packages:

```
streamlit>=1.28.0
boto3>=1.34.0
pandas>=2.0.0
plotly>=5.17.0
pyyaml>=6.0.0
requests>=2.31.0
anthropic>=0.7.0
reportlab>=4.0.0
streamlit-autorefresh>=0.0.1
trafilatura>=1.6.0
```

## Configuration

### AWS Credentials

The dashboard supports multiple authentication methods:

#### 1. Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

#### 2. AWS CLI Configuration
```bash
aws configure
```

#### 3. IAM Roles (for EC2 instances)
No additional configuration required when running on EC2 with appropriate IAM roles.

#### 4. Web Interface Configuration
Use the sidebar configuration panel to enter credentials directly in the application.

### Required AWS Permissions

The application requires the following AWS permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListPolicies",
                "iam:GetUser",
                "iam:GetRole",
                "iam:ListAttachedUserPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcs",
                "ec2:DescribeInternetGateways",
                "s3:ListAllMyBuckets",
                "s3:GetBucketEncryption",
                "s3:GetPublicAccessBlock",
                "s3:GetBucketVersioning",
                "kms:ListKeys",
                "kms:DescribeKey",
                "cloudtrail:DescribeTrails",
                "cloudtrail:LookupEvents",
                "guardduty:ListDetectors",
                "guardduty:ListFindings",
                "guardduty:GetFindings",
                "config:DescribeConfigRules",
                "config:GetComplianceDetailsByConfigRule",
                "ecr:DescribeRepositories",
                "ecr:DescribeImages",
                "lambda:ListFunctions",
                "lambda:GetPolicy",
                "rds:DescribeDBInstances",
                "rds:DescribeDBSnapshots",
                "rds:DescribeDBSnapshotAttributes",
                "eks:ListClusters",
                "eks:DescribeCluster",
                "ssm:DescribeParameters",
                "bedrock:InvokeModel"
            ],
            "Resource": "*"
        }
    ]
}
```

### Streamlit Configuration

Create `.streamlit/config.toml`:

```toml
[server]
headless = true
address = "0.0.0.0"
port = 5000

[theme]
primaryColor = "#FF6B6B"
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#F0F2F6"
textColor = "#262730"

[browser]
gatherUsageStats = false
```

## Usage Guide

### Dashboard Overview

The dashboard consists of 11 main tabs:

1. **Overview** - Security posture summary and key metrics
2. **IAM Security** - Identity and access management analysis
3. **Network Security** - Security groups and network configuration
4. **Data Protection** - Encryption and data security assessment
5. **Compliance** - Regulatory compliance monitoring
6. **Alerts & Threats** - Security alerts and threat detection
7. **Enhanced Checks** - Advanced security assessments
8. **Vulnerability Scanner** - Trivy-inspired comprehensive scanning
9. **AI Recommendations** - Intelligent security guidance
10. **OWASP LLM Top 10** - LLM application security assessment
11. **Export Reports** - Data export and reporting

### Getting Started

1. **Launch the application**
   ```bash
   streamlit run app.py --server.port 5000
   ```

2. **Configure AWS credentials** using the sidebar panel

3. **Select monitoring regions** for multi-region assessment

4. **Run initial security assessment** from the Overview tab

5. **Review findings** across different security domains

6. **Generate reports** and export data as needed

### Multi-Region Monitoring

The dashboard supports monitoring across multiple AWS regions:

1. Navigate to the sidebar configuration panel
2. Select "Configure Regions"
3. Choose the regions you want to monitor
4. The dashboard will aggregate findings across all selected regions

### Real-Time Monitoring

Enable continuous monitoring for real-time security updates:

1. Go to the "Vulnerability Scanner" tab
2. Click "Enable Continuous Monitoring"
3. Configure refresh intervals and alert thresholds
4. Monitor the real-time dashboard for active threats

## Security Scanning

### Vulnerability Scanner Features

The integrated vulnerability scanner provides comprehensive security assessment:

#### Container Security Scanning
- **ECR image vulnerability detection**
- **Package-level CVE analysis**
- **Multi-language dependency scanning** (Python, Node.js, Java, Go, Ruby, PHP)
- **Base image security assessment**
- **Container configuration analysis**

#### Infrastructure Misconfiguration Detection
- **S3 bucket security assessment**
  - Public access configuration
  - Encryption settings
  - Versioning status
- **Security group analysis**
  - Overly permissive rules
  - Port exposure assessment
  - Protocol security evaluation
- **IAM policy evaluation**
  - Privilege escalation risks
  - Overly broad permissions
  - Trust policy analysis
- **Lambda function security**
  - Environment variable encryption
  - Function policy assessment
  - Runtime security configuration

#### Secret Detection
- **AWS credential exposure**
- **API key detection**
- **Private key scanning**
- **JWT token identification**
- **Database connection string detection**

#### License Compliance
- **Open source license identification**
- **Commercial license usage detection**
- **GPL compliance assessment**
- **License risk evaluation**

### SBOM Generation

Generate Software Bill of Materials for compliance and inventory:

1. Navigate to "Vulnerability Scanner" tab
2. Enable "Generate SBOM" option
3. Run comprehensive scan
4. Download SBOM in CycloneDX format

### Scan Configuration

Configure scans based on your requirements:

```python
# Scan configuration example
scan_config = {
    "containers": True,
    "infrastructure": True,
    "secrets": True,
    "licenses": True,
    "kubernetes": True,
    "severity_threshold": "MEDIUM",
    "max_findings": 100,
    "timeout_minutes": 10
}
```

## AI-Powered Analysis

### AWS Bedrock Integration

The dashboard integrates with AWS Bedrock for intelligent security analysis:

#### Prerequisites
- AWS Bedrock access in your account
- Claude model availability in your region
- Appropriate IAM permissions for Bedrock

#### AI Features
- **Contextual security recommendations**
- **Risk assessment and prioritization**
- **Compliance gap analysis**
- **Threat intelligence correlation**
- **Executive summary generation**

#### Configuration
1. Ensure Bedrock access in your AWS account
2. Grant `bedrock:InvokeModel` permissions
3. The AI engine will automatically detect availability
4. Access AI features from the "AI Recommendations" tab

### Intelligent Compliance Analysis

The AI engine provides advanced compliance analysis:

- **Unknown issue identification**
- **Compliance gap remediation suggestions**
- **Framework-specific guidance** (SOC 2, ISO 27001, NIST)
- **Risk-based prioritization**

## Export and Reporting

### Report Types

#### 1. Executive Security Report (PDF)
- High-level security posture summary
- Key findings and recommendations
- Compliance status overview
- Risk assessment metrics

#### 2. Technical Security Report (JSON/CSV)
- Detailed vulnerability listings
- Complete scan results
- Infrastructure assessment data
- Raw security metrics

#### 3. Compliance Report
- Framework-specific compliance status
- Gap analysis and remediation guidance
- Audit trail documentation
- Regulatory requirement mapping

### Export Options

Access export functionality from the "Export Reports" tab:

```python
# Export options available
export_formats = [
    "PDF Compliance Report",
    "JSON Security Data",
    "CSV Findings Export",
    "Security Hub Format",
    "SBOM (CycloneDX)",
    "Executive Dashboard"
]
```

### Security Hub Integration

Export findings to AWS Security Hub:

1. Ensure Security Hub is enabled in your account
2. Configure appropriate IAM permissions
3. Use "Export to Security Hub" option
4. Findings will appear in Security Hub console

## API Reference

### Core Classes

#### SecurityMonitors
Main security monitoring class for AWS service integration.

```python
from security_monitors import SecurityMonitors

# Initialize
monitors = SecurityMonitors(aws_client)

# Get security overview
overview = monitors.get_security_overview()

# Get compliance data
compliance = monitors.get_compliance_data()
```

#### TrivyIntegratedScanner
Comprehensive vulnerability scanning engine.

```python
from trivy_integration import TrivyIntegratedScanner

# Initialize scanner
scanner = TrivyIntegratedScanner(aws_client)

# Run comprehensive scan
results = scanner.run_comprehensive_vulnerability_scan()

# Get security recommendations
recommendations = scanner.get_security_recommendations()
```

#### AIComplianceEngine
AI-powered security analysis and recommendations.

```python
from ai_compliance_engine import AIComplianceEngine

# Initialize AI engine
ai_engine = AIComplianceEngine(aws_client)

# Generate intelligent recommendations
recommendations = ai_engine.generate_intelligent_recommendations(
    overview_data, compliance_data
)
```

### Configuration Methods

```python
# Configure multi-region monitoring
aws_client.update_selected_regions(['us-east-1', 'us-west-2', 'eu-west-1'])

# Enable continuous monitoring
monitoring_config = scanner.enable_continuous_monitoring(interval_hours=24)

# Generate executive dashboard data
executive_data = scanner.generate_executive_dashboard_data()
```

## Troubleshooting

### Common Issues

#### 1. AWS Authentication Errors
**Problem**: "Unable to locate credentials"
**Solution**: 
- Verify AWS credentials configuration
- Check IAM permissions
- Ensure correct region selection

#### 2. Bedrock Access Denied
**Problem**: "Access denied to Bedrock service"
**Solution**:
- Verify Bedrock service availability in your region
- Check IAM permissions for `bedrock:InvokeModel`
- Ensure Claude model access

#### 3. Chart Rendering Errors
**Problem**: "Figure object error in charts"
**Solution**:
- Refresh the dashboard
- Check browser compatibility
- Clear browser cache

#### 4. Memory Issues
**Problem**: Application running slowly or crashing
**Solution**:
- Increase system memory allocation
- Reduce scan scope and findings limits
- Enable pagination for large datasets

### Performance Optimization

#### 1. Multi-Region Scanning
```python
# Optimize region selection
recommended_regions = ['us-east-1', 'us-west-2', 'eu-west-1']
```

#### 2. Scan Configuration
```python
# Optimize scan settings
optimized_config = {
    "max_findings": 50,
    "timeout_minutes": 5,
    "severity_threshold": "HIGH"
}
```

#### 3. Resource Management
- Use appropriate instance sizes for large environments
- Implement scan scheduling for off-peak hours
- Enable result caching for frequently accessed data

### Logging and Debugging

Enable detailed logging for troubleshooting:

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

### Support and Updates

#### Getting Help
1. Check the troubleshooting section
2. Review AWS service quotas and limits
3. Verify IAM permissions
4. Check application logs for detailed error messages

#### Version Updates
```bash
# Update dependencies
pip install -r requirements.txt --upgrade

# Check for application updates
git pull origin main
```

## Contributing

### Development Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd aws-security-dashboard
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install development dependencies**
```bash
pip install -r requirements-dev.txt
```

4. **Run tests**
```bash
pytest tests/
```

### Code Structure

```
aws-security-dashboard/
├── app.py                          # Main Streamlit application
├── aws_client.py                   # AWS service integration
├── security_monitors.py            # Core security monitoring
├── trivy_integration.py           # Vulnerability scanner
├── ai_compliance_engine.py        # AI-powered analysis
├── vulnerability_database.py      # CVE database management
├── real_time_security_monitor.py  # Real-time monitoring
├── dashboard_components.py        # UI components
├── enhanced_security_checks.py    # Advanced security checks
├── owasp_llm_security.py         # OWASP LLM assessment
├── export_manager.py             # Export functionality
├── utils.py                       # Utility functions
├── requirements.txt               # Python dependencies
├── .streamlit/                    # Streamlit configuration
│   └── config.toml
├── tests/                         # Test suite
└── docs/                          # Additional documentation
```

### Contributing Guidelines

1. **Follow PEP 8** style guidelines
2. **Add tests** for new functionality
3. **Update documentation** for new features
4. **Use type hints** for better code clarity
5. **Follow security best practices**

### Feature Requests

To request new features:
1. Check existing issues and feature requests
2. Create detailed feature description
3. Include use cases and requirements
4. Consider implementation complexity

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Security Notice

This application handles sensitive AWS security data. Always ensure:
- Secure credential management
- Encrypted data transmission
- Regular security updates
- Access control implementation
- Audit logging enablement

For security vulnerabilities, please report privately to the maintainers.

## Changelog

### Version 2.0.0
- Added Trivy-inspired vulnerability scanner
- Integrated AI-powered analysis with AWS Bedrock
- Enhanced multi-region monitoring
- Added OWASP LLM Top 10 assessment
- Improved real-time monitoring capabilities
- Added comprehensive export options

### Version 1.0.0
- Initial release with core security monitoring
- Basic compliance assessment
- IAM and network security analysis
- Export functionality