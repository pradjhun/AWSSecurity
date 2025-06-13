"""
Enhanced security checks module inspired by Prowler's comprehensive coverage
"""
from datetime import datetime, timedelta
import json

class EnhancedSecurityChecks:
    """Advanced security checks for comprehensive AWS assessment"""
    
    def __init__(self, aws_client):
        self.aws_client = aws_client
    
    def run_database_security_checks(self):
        """Comprehensive database security assessment"""
        findings = []
        
        try:
            # RDS Security Checks
            rds_client = self.aws_client.get_client('rds')
            if rds_client:
                # Get RDS instances
                response = rds_client.describe_db_instances()
                instances = response.get('DBInstances', [])
                
                for instance in instances:
                    db_id = instance.get('DBInstanceIdentifier', 'Unknown')
                    
                    # Check encryption at rest
                    if not instance.get('StorageEncrypted', False):
                        findings.append({
                            'check_id': 'RDS.1',
                            'title': 'RDS instance should have encryption at rest enabled',
                            'resource': db_id,
                            'resource_type': 'RDS Instance',
                            'severity': 'HIGH',
                            'status': 'FAIL',
                            'description': f'RDS instance {db_id} does not have encryption at rest enabled',
                            'remediation': 'Enable encryption when creating a new instance or create encrypted snapshot and restore'
                        })
                    
                    # Check public accessibility
                    if instance.get('PubliclyAccessible', False):
                        findings.append({
                            'check_id': 'RDS.2',
                            'title': 'RDS instance should not be publicly accessible',
                            'resource': db_id,
                            'resource_type': 'RDS Instance',
                            'severity': 'CRITICAL',
                            'status': 'FAIL',
                            'description': f'RDS instance {db_id} is publicly accessible',
                            'remediation': 'Modify instance to disable public accessibility'
                        })
                    
                    # Check backup retention
                    backup_retention = instance.get('BackupRetentionPeriod', 0)
                    if backup_retention < 7:
                        findings.append({
                            'check_id': 'RDS.3',
                            'title': 'RDS instance should have adequate backup retention',
                            'resource': db_id,
                            'resource_type': 'RDS Instance',
                            'severity': 'MEDIUM',
                            'status': 'FAIL',
                            'description': f'RDS instance {db_id} has backup retention of {backup_retention} days (recommended: 7+ days)',
                            'remediation': 'Modify backup retention period to at least 7 days'
                        })
                
                # Check RDS snapshots
                snapshots_response = rds_client.describe_db_snapshots(SnapshotType='manual')
                snapshots = snapshots_response.get('DBSnapshots', [])
                
                for snapshot in snapshots:
                    snapshot_id = snapshot.get('DBSnapshotIdentifier', 'Unknown')
                    
                    # Check if snapshot is public
                    try:
                        attrs_response = rds_client.describe_db_snapshot_attributes(
                            DBSnapshotIdentifier=snapshot_id
                        )
                        attributes = attrs_response.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', [])
                        
                        for attr in attributes:
                            if attr.get('AttributeName') == 'restore' and 'all' in attr.get('AttributeValues', []):
                                findings.append({
                                    'check_id': 'RDS.4',
                                    'title': 'RDS snapshot should not be public',
                                    'resource': snapshot_id,
                                    'resource_type': 'RDS Snapshot',
                                    'severity': 'CRITICAL',
                                    'status': 'FAIL',
                                    'description': f'RDS snapshot {snapshot_id} is publicly accessible',
                                    'remediation': 'Remove public restore permissions from snapshot'
                                })
                    except Exception:
                        continue
                        
        except Exception as e:
            print(f"Error running RDS security checks: {str(e)}")
        
        return findings
    
    def run_container_security_checks(self):
        """Container and serverless security assessment"""
        findings = []
        
        try:
            # ECR Security Checks
            ecr_client = self.aws_client.get_client('ecr')
            if ecr_client:
                repositories = ecr_client.describe_repositories().get('repositories', [])
                
                for repo in repositories:
                    repo_name = repo.get('repositoryName', 'Unknown')
                    
                    # Check image scanning
                    scan_config = repo.get('imageScanningConfiguration', {})
                    if not scan_config.get('scanOnPush', False):
                        findings.append({
                            'check_id': 'ECR.1',
                            'title': 'ECR repository should have image scanning enabled',
                            'resource': repo_name,
                            'resource_type': 'ECR Repository',
                            'severity': 'MEDIUM',
                            'status': 'FAIL',
                            'description': f'ECR repository {repo_name} does not have scan on push enabled',
                            'remediation': 'Enable image scanning on push for the repository'
                        })
            
            # Lambda Security Checks
            lambda_client = self.aws_client.get_client('lambda')
            if lambda_client:
                functions_response = lambda_client.list_functions()
                functions = functions_response.get('Functions', [])
                
                for function in functions:
                    function_name = function.get('FunctionName', 'Unknown')
                    
                    # Check environment variable encryption
                    if 'Environment' in function:
                        kms_key = function['Environment'].get('KMSKeyArn')
                        if not kms_key:
                            findings.append({
                                'check_id': 'LAMBDA.1',
                                'title': 'Lambda function environment variables should be encrypted',
                                'resource': function_name,
                                'resource_type': 'Lambda Function',
                                'severity': 'MEDIUM',
                                'status': 'FAIL',
                                'description': f'Lambda function {function_name} environment variables are not encrypted with KMS',
                                'remediation': 'Configure KMS encryption for environment variables'
                            })
                    
                    # Check function policy for public access
                    try:
                        policy_response = lambda_client.get_policy(FunctionName=function_name)
                        policy = json.loads(policy_response.get('Policy', '{}'))
                        
                        for statement in policy.get('Statement', []):
                            principal = statement.get('Principal', {})
                            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                                findings.append({
                                    'check_id': 'LAMBDA.2',
                                    'title': 'Lambda function should not have public access',
                                    'resource': function_name,
                                    'resource_type': 'Lambda Function',
                                    'severity': 'HIGH',
                                    'status': 'FAIL',
                                    'description': f'Lambda function {function_name} allows public access',
                                    'remediation': 'Remove wildcard principals from function policy'
                                })
                    except Exception:
                        continue
                        
        except Exception as e:
            print(f"Error running container security checks: {str(e)}")
        
        return findings
    
    def run_advanced_iam_checks(self):
        """Advanced IAM security analysis"""
        findings = []
        
        try:
            iam_client = self.aws_client.get_client('iam')
            if not iam_client:
                return findings
            
            # Check for unused IAM users
            users = iam_client.list_users().get('Users', [])
            credential_report = self._get_credential_report()
            
            for user in users:
                username = user.get('UserName', 'Unknown')
                
                # Check for users without recent activity
                last_activity = self._get_user_last_activity(username, credential_report)
                if last_activity and (datetime.now() - last_activity).days > 90:
                    findings.append({
                        'check_id': 'IAM.1',
                        'title': 'IAM user should be active within 90 days',
                        'resource': username,
                        'resource_type': 'IAM User',
                        'severity': 'MEDIUM',
                        'status': 'FAIL',
                        'description': f'IAM user {username} has been inactive for more than 90 days',
                        'remediation': 'Remove unused IAM users or review their necessity'
                    })
                
                # Check for users with administrative privileges
                user_policies = iam_client.list_attached_user_policies(UserName=username).get('AttachedPolicies', [])
                for policy in user_policies:
                    if 'Administrator' in policy.get('PolicyName', '') or policy.get('PolicyArn', '').endswith('AdministratorAccess'):
                        findings.append({
                            'check_id': 'IAM.2',
                            'title': 'IAM user should not have administrative privileges',
                            'resource': username,
                            'resource_type': 'IAM User',
                            'severity': 'HIGH',
                            'status': 'FAIL',
                            'description': f'IAM user {username} has administrative privileges',
                            'remediation': 'Use roles instead of users for administrative access'
                        })
            
            # Check for roles with overly permissive trust policies
            roles = iam_client.list_roles().get('Roles', [])
            for role in roles:
                role_name = role.get('RoleName', 'Unknown')
                assume_role_policy = role.get('AssumeRolePolicyDocument', {})
                
                if isinstance(assume_role_policy, str):
                    try:
                        assume_role_policy = json.loads(assume_role_policy)
                    except:
                        continue
                
                for statement in assume_role_policy.get('Statement', []):
                    principal = statement.get('Principal', {})
                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                        findings.append({
                            'check_id': 'IAM.3',
                            'title': 'IAM role should not allow assumption by any principal',
                            'resource': role_name,
                            'resource_type': 'IAM Role',
                            'severity': 'HIGH',
                            'status': 'FAIL',
                            'description': f'IAM role {role_name} can be assumed by any AWS principal',
                            'remediation': 'Restrict role assumption to specific principals'
                        })
                        
        except Exception as e:
            print(f"Error running advanced IAM checks: {str(e)}")
        
        return findings
    
    def run_network_security_deep_dive(self):
        """Comprehensive network security assessment"""
        findings = []
        
        try:
            ec2_client = self.aws_client.get_client('ec2')
            if not ec2_client:
                return findings
            
            # Check VPC endpoints
            vpc_endpoints = ec2_client.describe_vpc_endpoints().get('VpcEndpoints', [])
            for endpoint in vpc_endpoints:
                endpoint_id = endpoint.get('VpcEndpointId', 'Unknown')
                
                # Check if VPC endpoint has policy restrictions
                policy_document = endpoint.get('PolicyDocument')
                if not policy_document or policy_document == '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}':
                    findings.append({
                        'check_id': 'VPC.1',
                        'title': 'VPC endpoint should have restrictive policy',
                        'resource': endpoint_id,
                        'resource_type': 'VPC Endpoint',
                        'severity': 'MEDIUM',
                        'status': 'FAIL',
                        'description': f'VPC endpoint {endpoint_id} allows unrestricted access',
                        'remediation': 'Apply restrictive resource policy to VPC endpoint'
                    })
            
            # Check Network ACLs
            nacls = ec2_client.describe_network_acls().get('NetworkAcls', [])
            for nacl in nacls:
                nacl_id = nacl.get('NetworkAclId', 'Unknown')
                
                # Check for overly permissive rules
                for entry in nacl.get('Entries', []):
                    cidr_block = entry.get('CidrBlock', '')
                    if cidr_block == '0.0.0.0/0' and entry.get('RuleAction') == 'allow':
                        port_range = entry.get('PortRange', {})
                        if not port_range or (port_range.get('From', 0) <= 22 <= port_range.get('To', 65535)):
                            findings.append({
                                'check_id': 'VPC.2',
                                'title': 'Network ACL should not allow unrestricted SSH access',
                                'resource': nacl_id,
                                'resource_type': 'Network ACL',
                                'severity': 'HIGH',
                                'status': 'FAIL',
                                'description': f'Network ACL {nacl_id} allows SSH access from anywhere',
                                'remediation': 'Restrict SSH access to specific IP ranges'
                            })
            
            # Check for unused security groups
            security_groups = ec2_client.describe_security_groups().get('SecurityGroups', [])
            instances = ec2_client.describe_instances()
            used_sg_ids = set()
            
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    for sg in instance.get('SecurityGroups', []):
                        used_sg_ids.add(sg.get('GroupId'))
            
            for sg in security_groups:
                sg_id = sg.get('GroupId', 'Unknown')
                if sg_id not in used_sg_ids and sg.get('GroupName') != 'default':
                    findings.append({
                        'check_id': 'EC2.1',
                        'title': 'Unused security groups should be removed',
                        'resource': sg_id,
                        'resource_type': 'Security Group',
                        'severity': 'LOW',
                        'status': 'FAIL',
                        'description': f'Security group {sg_id} is not attached to any resource',
                        'remediation': 'Remove unused security groups to reduce attack surface'
                    })
                    
        except Exception as e:
            print(f"Error running network security checks: {str(e)}")
        
        return findings
    
    def _get_credential_report(self):
        """Get IAM credential report"""
        try:
            iam_client = self.aws_client.get_client('iam')
            if iam_client:
                # Generate credential report first
                iam_client.generate_credential_report()
                # Get the report (may need retry logic in production)
                response = iam_client.get_credential_report()
                return response.get('Content', b'').decode('utf-8')
        except Exception:
            return None
    
    def _get_user_last_activity(self, username, credential_report):
        """Parse user last activity from credential report"""
        try:
            if not credential_report:
                return None
            
            lines = credential_report.split('\n')
            for line in lines[1:]:  # Skip header
                fields = line.split(',')
                if len(fields) > 4 and fields[0] == username:
                    # Parse last activity date
                    last_used = fields[4] if len(fields) > 4 else None
                    if last_used and last_used != 'N/A':
                        return datetime.strptime(last_used.split('T')[0], '%Y-%m-%d')
            return None
        except Exception:
            return None
    
    def run_all_enhanced_checks(self):
        """Run all enhanced security checks with error handling"""
        all_findings = []
        
        try:
            print("Running database security checks...")
            db_findings = self.run_database_security_checks()
            all_findings.extend(db_findings)
            
            print("Running container security checks...")
            container_findings = self.run_container_security_checks()
            all_findings.extend(container_findings)
            
            print("Running advanced IAM checks...")
            iam_findings = self.run_advanced_iam_checks()
            all_findings.extend(iam_findings)
            
            print("Running network security deep dive...")
            network_findings = self.run_network_security_deep_dive()
            all_findings.extend(network_findings)
            
        except Exception as e:
            print(f"Error in enhanced security checks: {str(e)}")
            return []
        
        return all_findings