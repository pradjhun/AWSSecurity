# API Reference Guide

## Core Classes and Methods

### AWSClient
Main AWS service integration class for managing connections and API calls.

#### Initialization
```python
from aws_client import AWSClient

# Initialize with credentials
client = AWSClient(
    aws_access_key_id="your_key",
    aws_secret_access_key="your_secret", 
    region_name="us-east-1",
    selected_regions=["us-east-1", "us-west-2"]
)
```

#### Methods

##### Connection Management
```python
# Test AWS connection
success, message = client.test_connection()

# Get account ID
account_id = client.get_account_id()

# Update monitored regions
client.update_selected_regions(["us-east-1", "eu-west-1"])
```

##### IAM Operations
```python
# List IAM users
users = client.list_iam_users()

# List IAM roles
roles = client.list_iam_roles()

# Get user MFA devices
mfa_devices = client.get_user_mfa_devices("username")

# List access keys
access_keys = client.list_access_keys("username")
```

##### EC2 Operations
```python
# List security groups
security_groups = client.list_security_groups()

# List VPCs
vpcs = client.list_vpcs()

# List internet gateways
igws = client.list_internet_gateways()
```

##### S3 Operations
```python
# List S3 buckets
buckets = client.list_s3_buckets()

# Get bucket encryption
encryption = client.get_bucket_encryption("bucket-name")

# Get public access block
public_access = client.get_bucket_public_access_block("bucket-name")
```

### SecurityMonitors
Core security monitoring and assessment engine.

#### Initialization
```python
from security_monitors import SecurityMonitors

monitors = SecurityMonitors(aws_client)
```

#### Methods

##### Security Overview
```python
# Get comprehensive security overview
overview = monitors.get_security_overview()
# Returns: {
#     'total_users': int,
#     'mfa_enabled_users': int,
#     'security_groups': int,
#     'public_buckets': int,
#     'critical_alerts': int,
#     'security_score': float,
#     'total_regions': int
# }
```

##### Compliance Assessment
```python
# Get compliance data
compliance = monitors.get_compliance_data()
# Returns: {
#     'compliant_rules': int,
#     'non_compliant_rules': int,
#     'not_applicable_rules': int,
#     'compliance_percentage': float,
#     'rules': [...]
# }
```

##### Detailed Security Data
```python
# Get IAM security data
iam_data = monitors.get_iam_security_data()

# Get network security data
network_data = monitors.get_network_security_data()

# Get data protection information
data_protection = monitors.get_data_protection_data()

# Get alerts and threats
alerts = monitors.get_alerts_and_threats_data()
```

### TrivyIntegratedScanner
Comprehensive vulnerability scanning engine with Trivy-inspired capabilities.

#### Initialization
```python
from trivy_integration import TrivyIntegratedScanner

scanner = TrivyIntegratedScanner(aws_client)
```

#### Methods

##### Comprehensive Scanning
```python
# Run full vulnerability scan
results = scanner.run_comprehensive_vulnerability_scan()
# Returns: {
#     'timestamp': str,
#     'vulnerabilities': [...],
#     'misconfigurations': [...],
#     'secrets': [...],
#     'licenses': [...],
#     'scan_summary': {...},
#     'vulnerability_analysis': {...},
#     'security_alerts': [...]
# }
```

##### Container Scanning
```python
# Scan container images
vulnerabilities = scanner._scan_container_images()
```

##### Infrastructure Scanning
```python
# Scan infrastructure misconfigurations
misconfigurations = scanner._scan_infrastructure_misconfigurations()
```

##### Secret Detection
```python
# Scan for secrets
secrets = scanner._scan_for_secrets()
```

##### License Compliance
```python
# Scan license compliance
licenses = scanner._scan_license_compliance()
```

##### Reporting and Analysis
```python
# Get security recommendations
recommendations = scanner.get_security_recommendations()

# Export scan results
json_data = scanner.export_scan_results("json")
csv_data = scanner.export_scan_results("csv")

# Generate executive dashboard data
executive_data = scanner.generate_executive_dashboard_data()

# Get real-time monitoring data
monitoring_data = scanner.get_real_time_monitoring_data()

# Enable continuous monitoring
config = scanner.enable_continuous_monitoring(interval_hours=24)
```

### AIComplianceEngine
AI-powered security analysis using AWS Bedrock.

#### Initialization
```python
from ai_compliance_engine import AIComplianceEngine

ai_engine = AIComplianceEngine(aws_client)
```

#### Methods

##### AI Analysis
```python
# Test Bedrock connectivity
success, message = ai_engine.test_bedrock_connectivity()

# Generate intelligent recommendations
recommendations = ai_engine.generate_intelligent_recommendations(
    overview_data, 
    compliance_data, 
    enhanced_findings=None
)
# Returns: {
#     'generation_success': bool,
#     'recommendations': [...],
#     'ai_summary': {...}
# }
```

##### Contextual Remediation
```python
# Generate contextual remediation guidance
remediation = ai_engine.generate_contextual_remediation(finding_data)
```

### VulnerabilityDatabase
Comprehensive vulnerability database with CVE integration.

#### Initialization
```python
from vulnerability_database import VulnerabilityDatabase

vuln_db = VulnerabilityDatabase()
```

#### Methods

##### Vulnerability Lookup
```python
# Get vulnerability details
vuln_details = vuln_db.get_vulnerability_details("CVE-2024-1234")

# Get package vulnerabilities
package_vulns = vuln_db.get_package_vulnerabilities(
    "openssl", "1.1.1f", "debian"
)
```

##### Trending and Analysis
```python
# Get vulnerability trends
trends = vuln_db.get_vulnerability_trends(days=30)

# Generate vulnerability report
report = vuln_db.generate_vulnerability_report(scan_results)
```

### EnhancedSecurityChecks
Advanced security checks inspired by Prowler.

#### Initialization
```python
from enhanced_security_checks import EnhancedSecurityChecks

enhanced_checks = EnhancedSecurityChecks(aws_client)
```

#### Methods

##### Security Assessments
```python
# Run database security checks
db_findings = enhanced_checks.run_database_security_checks()

# Run container security checks
container_findings = enhanced_checks.run_container_security_checks()

# Run advanced IAM checks
iam_findings = enhanced_checks.run_advanced_iam_checks()

# Run network security deep dive
network_findings = enhanced_checks.run_network_security_deep_dive()

# Run all enhanced checks
all_findings = enhanced_checks.run_all_enhanced_checks()
```

### ExportManager
Comprehensive export and reporting functionality.

#### Initialization
```python
from export_manager import ExportManager

export_manager = ExportManager()
```

#### Methods

##### Data Export
```python
# Export findings to JSON
json_data = export_manager.export_findings_to_json(findings_data)

# Export compliance to CSV
csv_data = export_manager.export_compliance_to_csv(compliance_data)

# Export security overview to HTML
html_report = export_manager.export_security_overview_to_html(
    overview_data, compliance_data, recommendations
)
```

##### Specialized Exports
```python
# Export AWS Security Hub format
asff_data = export_manager.export_aws_security_hub_format(
    findings_data, account_id, region
)

# Generate PDF compliance report
pdf_data = export_manager.export_compliance_report_to_pdf(
    overview_data, compliance_data, recommendations, 
    enhanced_findings, ai_summary
)
```

### OWASPLLMSecurity
OWASP Top 10 for LLM Applications security assessment.

#### Initialization
```python
from owasp_llm_security import OWASPLLMSecurity

llm_security = OWASPLLMSecurity(ai_engine)
```

#### Methods

##### LLM Security Assessment
```python
# Assess LLM security posture
assessment = llm_security.assess_llm_security_posture(aws_data)

# Generate LLM security report
report = llm_security.generate_llm_security_report(assessment_results)

# Get AI guidance for vulnerabilities
guidance = llm_security.get_ai_llm_security_guidance(
    vulnerability_id, assessment_data, aws_context
)

# Create security checklist
checklist = llm_security.create_llm_security_checklist()
```

### DashboardComponents
UI visualization components using Plotly.

#### Initialization
```python
from dashboard_components import DashboardComponents

dashboard = DashboardComponents()
```

#### Methods

##### Chart Creation
```python
# Create security score chart
fig = dashboard.create_security_score_chart(trends_data)

# Create alert distribution chart
fig = dashboard.create_alert_distribution_chart(alert_data)

# Create user activity chart
fig = dashboard.create_user_activity_chart(activity_data)

# Create compliance status chart
fig = dashboard.create_compliance_status_chart(compliance_data)
```

##### Metric Components
```python
# Create metric card
dashboard.create_metric_card("Title", "Value", delta="+5", delta_color="normal")

# Create alert badge
dashboard.create_alert_badge("CRITICAL", 3)
```

## Data Structures

### Security Overview Response
```python
{
    'total_users': int,
    'mfa_enabled_users': int,
    'users_without_mfa': int,
    'security_groups': int,
    'public_buckets': int,
    'encrypted_buckets': int,
    'total_buckets': int,
    'critical_alerts': int,
    'security_score': float,
    'risk_level': str,
    'total_regions': int,
    'region_summary': {...}
}
```

### Vulnerability Finding
```python
{
    'id': 'CVE-2024-1234',
    'title': 'Buffer Overflow Vulnerability',
    'severity': 'CRITICAL',
    'package': 'openssl',
    'version': '1.1.1f',
    'fixed_version': '1.1.1k',
    'description': 'Detailed vulnerability description',
    'repository': 'my-app',
    'image_tag': 'latest',
    'type': 'OS Package',
    'scanner': 'trivy-integrated'
}
```

### Misconfiguration Finding
```python
{
    'id': 'AVD-AWS-0086',
    'title': 'S3 bucket should have public access blocked',
    'severity': 'HIGH',
    'resource': 'my-bucket',
    'resource_type': 'S3 Bucket',
    'description': 'S3 bucket allows public access',
    'remediation': 'Enable all public access block settings',
    'policy': 'AWS S3 Security',
    'scanner': 'trivy-integrated'
}
```

### Compliance Rule
```python
{
    'rule_name': 'cloudtrail-enabled',
    'description': 'Checks if CloudTrail is enabled',
    'compliance_status': 'COMPLIANT',
    'resource_type': 'CloudTrail',
    'severity': 'HIGH',
    'framework': 'CIS AWS Foundations',
    'remediation': 'Enable CloudTrail logging'
}
```

## Error Handling

### Common Exceptions
```python
# AWS credential errors
try:
    client = AWSClient()
except NoCredentialsError:
    print("AWS credentials not configured")

# Service unavailable errors
try:
    overview = monitors.get_security_overview()
except ClientError as e:
    print(f"AWS API error: {e}")

# AI service errors
try:
    recommendations = ai_engine.generate_intelligent_recommendations()
except Exception as e:
    print(f"AI analysis failed: {e}")
```

## Configuration Options

### AWS Client Configuration
```python
config = {
    'region_name': 'us-east-1',
    'selected_regions': ['us-east-1', 'us-west-2'],
    'max_retries': 3,
    'timeout': 60
}
```

### Scanner Configuration
```python
scan_config = {
    'severity_threshold': 'MEDIUM',
    'max_findings': 100,
    'scan_timeout_minutes': 10,
    'include_licenses': True,
    'include_secrets': True,
    'generate_sbom': False
}
```

### AI Configuration
```python
ai_config = {
    'model_id': 'anthropic.claude-v2',
    'max_tokens': 4000,
    'temperature': 0.1,
    'region': 'us-east-1'
}
```

## Best Practices

### Performance Optimization
```python
# Limit region scope
client.update_selected_regions(['us-east-1', 'us-west-2'])

# Use pagination for large datasets
findings = scanner.get_findings(max_results=50, page_token=None)

# Cache results when possible
cache_results = True
```

### Error Handling
```python
# Always handle AWS API errors
try:
    data = client.list_security_groups()
except ClientError as e:
    if e.response['Error']['Code'] == 'UnauthorizedOperation':
        print("Insufficient permissions")
    else:
        print(f"API error: {e}")
```

### Security Considerations
```python
# Use IAM roles when possible
# Encrypt sensitive data in transit and at rest
# Implement proper access controls
# Enable audit logging
# Regular credential rotation
```