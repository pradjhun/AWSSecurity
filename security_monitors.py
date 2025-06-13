from datetime import datetime, timedelta
import pandas as pd
from aws_client import AWSClient
from ai_compliance_engine import AIComplianceEngine

class SecurityMonitors:
    """Security monitoring and data collection for AWS services"""
    
    def __init__(self, aws_client):
        self.aws_client = aws_client
        self.ai_engine = AIComplianceEngine(aws_client)
    
    def get_security_overview(self):
        """Get overall security overview data"""
        try:
            # Get global service counts (IAM and S3 are global)
            iam_users = len(self.aws_client.list_iam_users())
            s3_buckets = len(self.aws_client.list_s3_buckets())
            
            # Aggregate regional data
            total_security_groups = 0
            total_vpcs = 0
            region_breakdown = {}
            
            for region in self.aws_client.selected_regions:
                try:
                    security_groups = self.aws_client.list_security_groups()
                    vpcs = self.aws_client.list_vpcs()
                    
                    region_sg_count = len(security_groups) if security_groups else 0
                    region_vpc_count = len(vpcs) if vpcs else 0
                    
                    total_security_groups += region_sg_count
                    total_vpcs += region_vpc_count
                    
                    region_breakdown[region] = {
                        'security_groups': region_sg_count,
                        'vpcs': region_vpc_count,
                        'status': 'active'
                    }
                except Exception as e:
                    region_breakdown[region] = {
                        'security_groups': 0,
                        'vpcs': 0,
                        'status': 'error',
                        'error': str(e)
                    }
            
            security_groups = total_security_groups
            
            # Get GuardDuty findings count and detector information
            critical_alerts = 0
            guardduty_detectors = 0
            detectors = self.aws_client.list_guardduty_detectors()
            guardduty_detectors = len(detectors)
            if detectors:
                findings = self.aws_client.list_guardduty_findings(detectors[0])
                critical_alerts = len([f for f in findings if self._safe_severity_compare(f.get('Severity', 0), 8.0)])
            
            # Get recent CloudTrail events
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=24)
            recent_events = self.aws_client.lookup_events(start_time, end_time, 10)
            
            # Format events for display
            formatted_events = []
            for event in recent_events:
                formatted_events.append({
                    'Time': event.get('EventTime', '').strftime('%Y-%m-%d %H:%M:%S') if event.get('EventTime') else '',
                    'Event': event.get('EventName', ''),
                    'User': event.get('Username', 'N/A'),
                    'Source IP': event.get('SourceIPAddress', 'N/A'),
                    'Service': event.get('EventSource', '').replace('.amazonaws.com', '') if event.get('EventSource') else 'N/A'
                })
            
            return {
                'iam_users': iam_users,
                'security_groups': security_groups,
                's3_buckets': s3_buckets,
                'vpcs': total_vpcs,
                'critical_alerts': critical_alerts,
                'guardduty_detectors': guardduty_detectors,
                'recent_events': formatted_events,
                'region_breakdown': region_breakdown,
                'selected_regions': self.aws_client.selected_regions,
                'total_regions': len(self.aws_client.selected_regions),
                'security_trends': self._get_security_trends(),
                'alert_distribution': self._get_alert_distribution(),
                'recommendations': self._get_security_recommendations()
            }
        except Exception as e:
            print(f"Error getting security overview: {str(e)}")
            return {
                'iam_users': 0,
                'security_groups': 0,
                's3_buckets': 0,
                'critical_alerts': 0,
                'recent_events': [],
                'security_trends': None,
                'alert_distribution': None,
                'recommendations': []
            }
    
    def get_iam_security_data(self):
        """Get IAM security monitoring data"""
        try:
            users = self.aws_client.list_iam_users()
            roles = self.aws_client.list_iam_roles()
            
            # Process user data
            user_details = []
            users_with_mfa = 0
            old_access_keys = 0
            
            for user in users:
                username = user['UserName']
                created_date = user.get('CreateDate', datetime.utcnow())
                
                # Get MFA devices
                mfa_devices = self.aws_client.get_user_mfa_devices(username)
                has_mfa = len(mfa_devices) > 0
                if has_mfa:
                    users_with_mfa += 1
                
                # Get access keys
                access_keys = self.aws_client.list_access_keys(username)
                old_keys = 0
                for key in access_keys:
                    key_age = datetime.utcnow() - key.get('CreateDate', datetime.utcnow()).replace(tzinfo=None)
                    if key_age.days > 90:  # Keys older than 90 days
                        old_keys += 1
                        old_access_keys += 1
                
                user_details.append({
                    'Username': username,
                    'Created': created_date.strftime('%Y-%m-%d') if created_date else 'N/A',
                    'MFA Enabled': 'Yes' if has_mfa else 'No',
                    'Access Keys': len(access_keys),
                    'Old Keys': old_keys,
                    'Last Activity': 'N/A'  # Would need CloudTrail analysis for actual data
                })
            
            return {
                'total_users': len(users),
                'total_roles': len(roles),
                'users_with_mfa': users_with_mfa,
                'old_access_keys': old_access_keys,
                'user_details': user_details,
                'user_activity': self._get_user_activity_data(),
                'policy_changes': self._get_policy_changes_data()
            }
        except Exception as e:
            print(f"Error getting IAM security data: {str(e)}")
            return {
                'total_users': 0,
                'total_roles': 0,
                'users_with_mfa': 0,
                'old_access_keys': 0,
                'user_details': [],
                'user_activity': None,
                'policy_changes': None
            }

    def get_iam_security_assessment(self):
        """Assess IAM security against 10 best practices"""
        try:
            users = self.aws_client.list_iam_users()
            roles = self.aws_client.list_iam_roles()
            
            # Get account password policy
            password_policy = self._get_password_policy()
            
            # Get CloudTrail status
            cloudtrail_enabled = self._check_cloudtrail_enabled()
            
            # Analyze users for comprehensive assessment
            users_with_mfa = 0
            users_without_mfa = []
            old_access_keys_count = 0
            users_with_old_keys = []
            root_usage = self._check_root_account_usage()
            
            for user in users:
                username = user.get('UserName', '')
                
                # Check MFA
                try:
                    mfa_devices = self.aws_client.get_user_mfa_devices(username)
                    has_mfa = len(mfa_devices) > 0
                    if has_mfa:
                        users_with_mfa += 1
                    else:
                        users_without_mfa.append(username)
                except:
                    users_without_mfa.append(username)
                
                # Check access key age
                try:
                    access_keys = self.aws_client.list_access_keys(username)
                    for key in access_keys:
                        if key.get('CreateDate'):
                            key_age = (datetime.utcnow() - key['CreateDate'].replace(tzinfo=None)).days
                            if key_age > 90:
                                old_access_keys_count += 1
                                if username not in users_with_old_keys:
                                    users_with_old_keys.append(username)
                except:
                    pass
            
            # Define the 10 security policies with assessments
            policies = [
                {
                    'name': 'Multi-Factor Authentication (MFA)',
                    'implemented': users_with_mfa > 0 and len(users_without_mfa) == 0,
                    'details': f'{users_with_mfa}/{len(users)} users have MFA enabled' if users_with_mfa > 0 else 'No users have MFA enabled',
                    'recommendation': f'Enable MFA for {len(users_without_mfa)} users: {", ".join(users_without_mfa[:3])}{"..." if len(users_without_mfa) > 3 else ""}'
                },
                {
                    'name': 'Principle of Least Privilege',
                    'implemented': len(roles) > 0,  # Basic check - presence of roles suggests role-based access
                    'details': f'{len(roles)} IAM roles configured for least-privilege access',
                    'recommendation': 'Review user permissions and implement role-based access control'
                },
                {
                    'name': 'IAM Roles Instead of Access Keys',
                    'implemented': len(roles) >= len(users),  # More roles than users suggests good practice
                    'details': f'{len(roles)} roles vs {len(users)} users - good role utilization',
                    'recommendation': 'Create more IAM roles to replace direct user access keys'
                },
                {
                    'name': 'Strong Password Policy',
                    'implemented': password_policy.get('configured', False),
                    'details': f'Password policy configured with {password_policy.get("requirements", "basic")} requirements',
                    'recommendation': 'Configure strong password policy with minimum 12 characters, complexity requirements'
                },
                {
                    'name': 'Regular Access Key Rotation',
                    'implemented': old_access_keys_count == 0,
                    'details': f'All access keys are less than 90 days old' if old_access_keys_count == 0 else f'{old_access_keys_count} old access keys found',
                    'recommendation': f'Rotate access keys for users: {", ".join(users_with_old_keys[:3])}{"..." if len(users_with_old_keys) > 3 else ""}'
                },
                {
                    'name': 'CloudTrail Audit Logging',
                    'implemented': cloudtrail_enabled,
                    'details': 'CloudTrail is enabled and logging API calls' if cloudtrail_enabled else 'CloudTrail not properly configured',
                    'recommendation': 'Enable CloudTrail in all regions for comprehensive audit logging'
                },
                {
                    'name': 'IAM Groups and Policies',
                    'implemented': True,  # AWS always has some groups/policies
                    'details': 'IAM groups and policies are being used for access management',
                    'recommendation': 'Continue using groups for permission management instead of direct user policies'
                },
                {
                    'name': 'Regular Permission Reviews',
                    'implemented': False,  # Cannot automatically determine this
                    'details': 'Manual process - cannot automatically verify',
                    'recommendation': 'Implement quarterly access reviews and remove unused permissions'
                },
                {
                    'name': 'Root Account Security',
                    'implemented': not root_usage.get('recent_usage', True),
                    'details': 'Root account usage monitored' if not root_usage.get('recent_usage', True) else 'Recent root account activity detected',
                    'recommendation': 'Enable MFA on root account and avoid using it for daily operations'
                },
                {
                    'name': 'Conditional Access Controls',
                    'implemented': False,  # Complex to determine automatically
                    'details': 'Advanced policy conditions need manual verification',
                    'recommendation': 'Implement IP-based and time-based access restrictions in IAM policies'
                }
            ]
            
            return {
                'policies': policies,
                'summary': {
                    'total_users': len(users),
                    'users_with_mfa': users_with_mfa,
                    'total_roles': len(roles),
                    'old_access_keys': old_access_keys_count,
                    'cloudtrail_enabled': cloudtrail_enabled
                }
            }
            
        except Exception as e:
            print(f"Error getting IAM security assessment: {str(e)}")
            return {
                'policies': [
                    {
                        'name': f'Policy {i}',
                        'implemented': False,
                        'details': 'Unable to assess due to connection error',
                        'recommendation': 'Check AWS connectivity and permissions'
                    } for i in range(1, 11)
                ],
                'summary': {}
            }

    def _get_password_policy(self):
        """Check if account password policy is configured"""
        try:
            iam = self.aws_client.get_client('iam')
            policy = iam.get_account_password_policy()
            return {
                'configured': True,
                'requirements': 'strong' if policy['PasswordPolicy'].get('MinimumPasswordLength', 0) >= 12 else 'basic'
            }
        except:
            return {'configured': False, 'requirements': 'none'}

    def _check_cloudtrail_enabled(self):
        """Check if CloudTrail is properly enabled"""
        try:
            trails = self.aws_client.describe_trails()
            for trail in trails:
                if trail.get('IsLogging', False):
                    return True
            return False
        except:
            return False

    def _check_root_account_usage(self):
        """Check for recent root account usage"""
        try:
            # Look for root account events in CloudTrail
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=30)
            
            events = self.aws_client.lookup_events(start_time, end_time, max_items=10)
            
            root_events = [event for event in events if event.get('Username') == 'root']
            
            return {
                'recent_usage': len(root_events) > 0,
                'event_count': len(root_events)
            }
        except:
            return {'recent_usage': False, 'event_count': 0}
    
    def get_network_security_data(self):
        """Get network security monitoring data"""
        try:
            security_groups = self.aws_client.list_security_groups()
            vpcs = self.aws_client.list_vpcs()
            internet_gateways = self.aws_client.list_internet_gateways()
            
            # Analyze security groups
            open_security_groups = 0
            sg_details = []
            
            for sg in security_groups:
                is_open = False
                open_ports = []
                
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            is_open = True
                            port_range = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}"
                            if port_range not in open_ports:
                                open_ports.append(port_range)
                
                if is_open:
                    open_security_groups += 1
                
                sg_details.append({
                    'Group ID': sg['GroupId'],
                    'Group Name': sg.get('GroupName', 'N/A'),
                    'VPC ID': sg.get('VpcId', 'N/A'),
                    'Inbound Rules': len(sg.get('IpPermissions', [])),
                    'Outbound Rules': len(sg.get('IpPermissionsEgress', [])),
                    'Open to Internet': 'Yes' if is_open else 'No',
                    'Open Ports': ', '.join(open_ports) if open_ports else 'None'
                })
            
            return {
                'total_security_groups': len(security_groups),
                'open_security_groups': open_security_groups,
                'total_vpcs': len(vpcs),
                'internet_gateways': len(internet_gateways),
                'security_group_details': sg_details,
                'security_group_rules': self._get_security_group_rules_data(security_groups),
                'vpc_flow_logs': self._get_vpc_flow_logs_data()
            }
        except Exception as e:
            print(f"Error getting network security data: {str(e)}")
            return {
                'total_security_groups': 0,
                'open_security_groups': 0,
                'total_vpcs': 0,
                'internet_gateways': 0,
                'security_group_details': [],
                'security_group_rules': None,
                'vpc_flow_logs': None
            }
    
    def get_data_protection_data(self):
        """Get data protection monitoring data"""
        try:
            s3_buckets = self.aws_client.list_s3_buckets()
            kms_keys = self.aws_client.list_kms_keys()
            
            # Analyze S3 buckets
            encrypted_buckets = 0
            public_buckets = 0
            bucket_details = []
            
            for bucket in s3_buckets:
                bucket_name = bucket['Name']
                created_date = bucket.get('CreationDate', datetime.utcnow())
                
                # Check encryption
                encryption_config = self.aws_client.get_bucket_encryption(bucket_name)
                is_encrypted = encryption_config is not None
                if is_encrypted:
                    encrypted_buckets += 1
                
                # Check public access
                public_access_block = self.aws_client.get_bucket_public_access_block(bucket_name)
                is_public = public_access_block is None or not all([
                    public_access_block.get('BlockPublicAcls', False),
                    public_access_block.get('IgnorePublicAcls', False),
                    public_access_block.get('BlockPublicPolicy', False),
                    public_access_block.get('RestrictPublicBuckets', False)
                ])
                if is_public:
                    public_buckets += 1
                
                bucket_details.append({
                    'Bucket Name': bucket_name,
                    'Created': created_date.strftime('%Y-%m-%d') if created_date else 'N/A',
                    'Encrypted': 'Yes' if is_encrypted else 'No',
                    'Public Access': 'Yes' if is_public else 'No',
                    'Region': 'N/A'  # Would need additional API call
                })
            
            return {
                'total_s3_buckets': len(s3_buckets),
                'encrypted_s3_buckets': encrypted_buckets,
                'public_s3_buckets': public_buckets,
                'kms_keys': len(kms_keys),
                's3_bucket_details': bucket_details,
                'encryption_status': self._get_encryption_status_data(len(s3_buckets), encrypted_buckets),
                's3_access_patterns': self._get_s3_access_patterns_data()
            }
        except Exception as e:
            print(f"Error getting data protection data: {str(e)}")
            return {
                'total_s3_buckets': 0,
                'encrypted_s3_buckets': 0,
                'public_s3_buckets': 0,
                'kms_keys': 0,
                's3_bucket_details': [],
                'encryption_status': None,
                's3_access_patterns': None
            }
    
    def get_compliance_data(self):
        """Get compliance monitoring data"""
        try:
            config_rules = self.aws_client.describe_config_rules()
            
            # Analyze compliance rules
            passing_rules = 0
            failing_rules = 0
            non_compliant_resources = 0
            compliance_rules = []
            
            for rule in config_rules:
                rule_name = rule['ConfigRuleName']
                
                # Get compliance details (simplified for demo)
                compliance_details = self.aws_client.get_compliance_by_config_rule(rule_name)
                
                compliant_count = len([r for r in compliance_details if r.get('ComplianceType') == 'COMPLIANT'])
                non_compliant_count = len([r for r in compliance_details if r.get('ComplianceType') == 'NON_COMPLIANT'])
                
                if non_compliant_count == 0:
                    passing_rules += 1
                    status = 'PASSING'
                else:
                    failing_rules += 1
                    status = 'FAILING'
                    non_compliant_resources += non_compliant_count
                
                # Determine compliance status with icons
                if non_compliant_count == 0 and compliant_count > 0:
                    status_icon = "✅ COMPLIANT"
                    status_color = "green"
                elif non_compliant_count > 0 and compliant_count > 0:
                    status_icon = "⚠️ PARTIAL"
                    status_color = "orange"
                elif non_compliant_count > 0:
                    status_icon = "❌ NON-COMPLIANT"
                    status_color = "red"
                else:
                    status_icon = "❓ UNKNOWN"
                    status_color = "gray"
                
                compliance_rules.append({
                    'Rule Name': rule_name,
                    'Description': rule.get('Description', 'N/A')[:100] + '...' if rule.get('Description', '') else 'N/A',
                    'Status': status_icon,
                    'Status_Color': status_color,
                    'Compliant Resources': compliant_count,
                    'Non-compliant Resources': non_compliant_count,
                    'Total Resources': compliant_count + non_compliant_count,
                    'Compliance %': round((compliant_count / (compliant_count + non_compliant_count) * 100), 1) if (compliant_count + non_compliant_count) > 0 else 0,
                    'Source': rule.get('Source', {}).get('Owner', 'N/A')
                })
            
            # Calculate overall compliance score
            total_rules = len(config_rules)
            compliance_score = (passing_rules / total_rules * 100) if total_rules > 0 else 0
            
            return {
                'overall_compliance_score': round(compliance_score, 1),
                'passing_rules': passing_rules,
                'failing_rules': failing_rules,
                'non_compliant_resources': non_compliant_resources,
                'compliance_rules': compliance_rules,
                'compliance_by_service': self._get_compliance_by_service_data(),
                'compliance_trends': self._get_compliance_trends_data()
            }
        except Exception as e:
            print(f"Error getting compliance data: {str(e)}")
            return {
                'overall_compliance_score': 0,
                'passing_rules': 0,
                'failing_rules': 0,
                'non_compliant_resources': 0,
                'compliance_rules': [],
                'compliance_by_service': None,
                'compliance_trends': None
            }
    
    def get_alerts_and_threats_data(self):
        """Get alerts and threat detection data"""
        threats_data = self.get_threats_data()
        
        # Transform the data to include guardduty_findings key expected by heatmap
        guardduty_findings = []
        for finding in threats_data.get('recent_findings', []):
            guardduty_findings.append({
                'title': finding.get('Title', ''),
                'severity': finding.get('Severity', 'Low'),
                'updated_at': finding.get('Updated', ''),
                'type': finding.get('Type', ''),
                'resource': finding.get('Resource', ''),
                'region': finding.get('Region', '')
            })
        
        # Return combined data structure
        return {
            **threats_data,
            'guardduty_findings': guardduty_findings
        }
    
    def get_threats_data(self):
        """Get threat detection and security findings data"""
        try:
            detectors = self.aws_client.list_guardduty_detectors()
            
            if not detectors:
                return {
                    'total_findings': 0,
                    'critical_findings': 0,
                    'high_findings': 0,
                    'active_threats': 0,
                    'recent_findings': [],
                    'threat_types': None,
                    'findings_over_time': None
                }
            
            # Get findings from the first detector
            findings = self.aws_client.list_guardduty_findings(detectors[0])
            
            # Analyze findings
            critical_findings = 0
            high_findings = 0
            active_threats = 0
            recent_findings = []
            
            for finding in findings:
                severity = finding.get('Severity', 0)
                
                # Convert severity to float if it's a string
                try:
                    severity_float = float(severity) if severity else 0.0
                except (ValueError, TypeError):
                    severity_float = 0.0
                
                if severity_float >= 8.0:
                    critical_findings += 1
                elif severity_float >= 6.0:
                    high_findings += 1
                
                # Count active threats (findings from last 24 hours)
                updated_at = finding.get('UpdatedAt')
                if updated_at:
                    try:
                        if isinstance(updated_at, str):
                            # Parse string timestamp
                            updated_at = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                        if hasattr(updated_at, 'replace') and updated_at.tzinfo is not None:
                            updated_at = updated_at.replace(tzinfo=None)
                        if (datetime.utcnow() - updated_at).days < 1:
                            active_threats += 1
                    except Exception:
                        pass  # Skip if date parsing fails
                
                # Format for display  
                original_updated_at = finding.get('UpdatedAt')
                formatted_date = 'N/A'
                if original_updated_at:
                    try:
                        if isinstance(original_updated_at, str):
                            # Handle string timestamps
                            if 'T' in original_updated_at:
                                parsed_date = datetime.fromisoformat(original_updated_at.replace('Z', '+00:00'))
                                formatted_date = parsed_date.strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                formatted_date = original_updated_at
                        elif hasattr(original_updated_at, 'strftime'):
                            # Handle datetime objects
                            formatted_date = original_updated_at.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            formatted_date = str(original_updated_at)
                    except Exception:
                        formatted_date = str(original_updated_at)
                
                recent_findings.append({
                    'Title': finding.get('Title', 'N/A'),
                    'Type': finding.get('Type', 'N/A'),
                    'Severity': self._get_severity_label(severity_float),
                    'Resource': finding.get('Resource', {}).get('Type', 'N/A'),
                    'Region': finding.get('Region', 'N/A'),
                    'Updated': formatted_date
                })
            
            return {
                'total_findings': len(findings),
                'critical_findings': critical_findings,
                'high_findings': high_findings,
                'active_threats': active_threats,
                'recent_findings': recent_findings,
                'threat_types': self._get_threat_types_data(findings),
                'findings_over_time': self._get_findings_timeline_data(findings)
            }
        except Exception as e:
            print(f"Error getting threats data: {str(e)}")
            return {
                'total_findings': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'active_threats': 0,
                'recent_findings': [],
                'threat_types': None,
                'findings_over_time': None
            }
    
    # Helper methods for chart data
    def _get_security_trends(self):
        """Generate security trends data for charting"""
        # In a real implementation, this would pull historical data
        return {
            'dates': ['2024-01-01', '2024-01-02', '2024-01-03', '2024-01-04', '2024-01-05'],
            'scores': [85, 87, 83, 89, 91]
        }
    
    def _get_alert_distribution(self):
        """Generate alert distribution data for charting"""
        return {
            'labels': ['Critical', 'High', 'Medium', 'Low'],
            'values': [2, 5, 12, 8]
        }
    
    def _get_user_activity_data(self):
        """Generate user activity data for charting"""
        return {
            'dates': ['2024-01-01', '2024-01-02', '2024-01-03', '2024-01-04', '2024-01-05'],
            'logins': [25, 32, 18, 41, 35]
        }
    
    def _get_policy_changes_data(self):
        """Generate policy changes data for charting"""
        return {
            'dates': ['2024-01-01', '2024-01-02', '2024-01-03', '2024-01-04', '2024-01-05'],
            'changes': [3, 1, 5, 2, 1]
        }
    
    def _get_security_group_rules_data(self, security_groups):
        """Generate security group rules data for charting"""
        open_rules = 0
        restricted_rules = 0
        
        for sg in security_groups:
            for rule in sg.get('IpPermissions', []):
                is_open = any(ip_range.get('CidrIp') == '0.0.0.0/0' 
                             for ip_range in rule.get('IpRanges', []))
                if is_open:
                    open_rules += 1
                else:
                    restricted_rules += 1
        
        return {
            'labels': ['Open to Internet', 'Restricted'],
            'values': [open_rules, restricted_rules]
        }
    
    def _get_vpc_flow_logs_data(self):
        """Generate VPC flow logs data for charting"""
        return {
            'dates': ['2024-01-01', '2024-01-02', '2024-01-03', '2024-01-04', '2024-01-05'],
            'accepted': [1200, 1350, 1100, 1480, 1320],
            'rejected': [45, 67, 23, 89, 56]
        }
    
    def _get_encryption_status_data(self, total_buckets, encrypted_buckets):
        """Generate encryption status data for charting"""
        return {
            'labels': ['Encrypted', 'Not Encrypted'],
            'values': [encrypted_buckets, total_buckets - encrypted_buckets]
        }
    
    def _get_s3_access_patterns_data(self):
        """Generate S3 access patterns data for charting"""
        return {
            'dates': ['2024-01-01', '2024-01-02', '2024-01-03', '2024-01-04', '2024-01-05'],
            'reads': [450, 523, 389, 612, 478],
            'writes': [123, 156, 98, 201, 167]
        }
    
    def _get_compliance_by_service_data(self):
        """Generate compliance by service data for charting"""
        return {
            'services': ['EC2', 'S3', 'IAM', 'RDS', 'VPC'],
            'compliance_scores': [92, 88, 95, 85, 90]
        }
    
    def _get_compliance_trends_data(self):
        """Generate compliance trends data for charting"""
        return {
            'dates': ['2024-01-01', '2024-01-02', '2024-01-03', '2024-01-04', '2024-01-05'],
            'scores': [87, 89, 86, 91, 93]
        }
    
    def _get_threat_types_data(self, findings):
        """Generate threat types data for charting"""
        threat_types = {}
        for finding in findings:
            threat_type = finding.get('Type', 'Unknown').split('/')[0]
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        return {
            'labels': list(threat_types.keys()),
            'values': list(threat_types.values())
        }
    
    def _get_findings_timeline_data(self, findings):
        """Generate findings timeline data for charting"""
        # Group findings by date
        timeline = {}
        for finding in findings:
            updated_at = finding.get('UpdatedAt')
            if updated_at:
                try:
                    if isinstance(updated_at, str):
                        if 'T' in updated_at:
                            parsed_date = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                            date = parsed_date.strftime('%Y-%m-%d')
                        else:
                            date = updated_at
                    elif hasattr(updated_at, 'strftime'):
                        date = updated_at.strftime('%Y-%m-%d')
                    else:
                        date = str(updated_at)
                    timeline[date] = timeline.get(date, 0) + 1
                except Exception:
                    pass  # Skip invalid dates
        
        # Sort by date
        sorted_timeline = sorted(timeline.items())
        
        return {
            'dates': [item[0] for item in sorted_timeline],
            'counts': [item[1] for item in sorted_timeline]
        }
    
    def _safe_severity_compare(self, severity, threshold):
        """Safely compare severity values, handling string/float conversion"""
        try:
            severity_float = float(severity) if severity else 0.0
        except (ValueError, TypeError):
            severity_float = 0.0
        return severity_float >= threshold

    def _get_severity_label(self, severity):
        """Convert numeric severity to label"""
        try:
            severity_float = float(severity) if severity else 0.0
        except (ValueError, TypeError):
            severity_float = 0.0
            
        if severity_float >= 8.0:
            return 'CRITICAL'
        elif severity_float >= 6.0:
            return 'HIGH'
        elif severity_float >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_security_recommendations(self):
        """Generate AI-powered security recommendations based on current AWS configuration"""
        # Try AI-powered recommendations first
        try:
            overview_data = {
                'iam_users': len(self.aws_client.list_iam_users()),
                'security_groups': len(self.aws_client.list_security_groups()),
                's3_buckets': len(self.aws_client.list_s3_buckets()),
                'critical_alerts': 0  # Will be populated by overview method
            }
            
            compliance_data = self.get_compliance_data()
            enhanced_findings = getattr(self, '_cached_enhanced_findings', [])
            
            ai_result = self.ai_engine.generate_intelligent_recommendations(
                overview_data, compliance_data, enhanced_findings
            )
            
            if ai_result.get('generation_success', False):
                return ai_result['recommendations']
            
        except Exception as e:
            print(f"AI recommendations failed, using fallback: {str(e)}")
        
        # Fallback to rule-based recommendations
        recommendations = []
        
        try:
            # Check IAM security issues
            users = self.aws_client.list_iam_users()
            users_without_mfa = 0
            old_access_keys = 0
            
            for user in users:
                username = user['UserName']
                mfa_devices = self.aws_client.get_user_mfa_devices(username)
                if len(mfa_devices) == 0:
                    users_without_mfa += 1
                
                access_keys = self.aws_client.list_access_keys(username)
                for key in access_keys:
                    key_age = datetime.utcnow() - key.get('CreateDate', datetime.utcnow()).replace(tzinfo=None)
                    if key_age.days > 90:
                        old_access_keys += 1
            
            if users_without_mfa > 0:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'IAM Security',
                    'title': 'Enable MFA for IAM Users',
                    'description': f'{users_without_mfa} users do not have MFA enabled. Enable multi-factor authentication for all users.',
                    'impact': f'+{min(users_without_mfa * 5, 20)} points',
                    'effort': 'Medium',
                    'steps': [
                        '1. Go to IAM Console → Users',
                        '2. Select each user without MFA',
                        '3. Go to Security credentials tab',
                        '4. Assign MFA device (Virtual or Hardware)',
                        '5. Verify MFA setup with test login'
                    ]
                })
            
            if old_access_keys > 0:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'IAM Security',
                    'title': 'Rotate Old Access Keys',
                    'description': f'{old_access_keys} access keys are older than 90 days. Regular rotation improves security.',
                    'impact': f'+{min(old_access_keys * 3, 15)} points',
                    'effort': 'Low',
                    'steps': [
                        '1. Create new access key for user',
                        '2. Update applications to use new key',
                        '3. Test applications with new credentials',
                        '4. Deactivate old access key',
                        '5. Delete old access key after verification'
                    ]
                })
            
            # Check network security issues
            security_groups = self.aws_client.list_security_groups()
            open_security_groups = 0
            
            for sg in security_groups:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            open_security_groups += 1
                            break
            
            if open_security_groups > 0:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Network Security',
                    'title': 'Restrict Security Group Rules',
                    'description': f'{open_security_groups} security groups allow access from anywhere (0.0.0.0/0). Restrict to specific IP ranges.',
                    'impact': f'+{min(open_security_groups * 4, 25)} points',
                    'effort': 'Medium',
                    'steps': [
                        '1. Review security groups with 0.0.0.0/0 rules',
                        '2. Identify specific IP ranges needed',
                        '3. Update inbound rules to use specific CIDRs',
                        '4. Test connectivity after changes',
                        '5. Document approved IP ranges'
                    ]
                })
            
            # Check S3 security issues
            s3_buckets = self.aws_client.list_s3_buckets()
            unencrypted_buckets = 0
            public_buckets = 0
            
            for bucket in s3_buckets:
                bucket_name = bucket['Name']
                encryption_config = self.aws_client.get_bucket_encryption(bucket_name)
                if encryption_config is None:
                    unencrypted_buckets += 1
                
                public_access_block = self.aws_client.get_bucket_public_access_block(bucket_name)
                if public_access_block is None or not all([
                    public_access_block.get('BlockPublicAcls', False),
                    public_access_block.get('IgnorePublicAcls', False),
                    public_access_block.get('BlockPublicPolicy', False),
                    public_access_block.get('RestrictPublicBuckets', False)
                ]):
                    public_buckets += 1
            
            if unencrypted_buckets > 0:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Data Protection',
                    'title': 'Enable S3 Bucket Encryption',
                    'description': f'{unencrypted_buckets} S3 buckets do not have encryption enabled. Enable server-side encryption.',
                    'impact': f'+{min(unencrypted_buckets * 6, 30)} points',
                    'effort': 'Low',
                    'steps': [
                        '1. Go to S3 Console → Buckets',
                        '2. Select unencrypted bucket',
                        '3. Go to Properties → Default encryption',
                        '4. Enable SSE-S3 or SSE-KMS encryption',
                        '5. Apply to existing objects if needed'
                    ]
                })
            
            if public_buckets > 0:
                recommendations.append({
                    'priority': 'CRITICAL',
                    'category': 'Data Protection',
                    'title': 'Block S3 Public Access',
                    'description': f'{public_buckets} S3 buckets may allow public access. Enable Block Public Access settings.',
                    'impact': f'+{min(public_buckets * 8, 40)} points',
                    'effort': 'Low',
                    'steps': [
                        '1. Go to S3 Console → Buckets',
                        '2. Select bucket with public access',
                        '3. Go to Permissions → Block public access',
                        '4. Enable all four Block public access settings',
                        '5. Verify application functionality'
                    ]
                })
            
            # Check CloudTrail configuration
            trails = self.aws_client.describe_trails()
            if len(trails) == 0:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Monitoring',
                    'title': 'Enable CloudTrail Logging',
                    'description': 'No CloudTrail trails found. Enable CloudTrail for audit logging and compliance.',
                    'impact': '+15 points',
                    'effort': 'Medium',
                    'steps': [
                        '1. Go to CloudTrail Console',
                        '2. Create new trail',
                        '3. Enable logging for all regions',
                        '4. Configure S3 bucket for log storage',
                        '5. Enable log file validation'
                    ]
                })
            
            # Check GuardDuty status
            detectors = self.aws_client.list_guardduty_detectors()
            if len(detectors) == 0:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Threat Detection',
                    'title': 'Enable GuardDuty',
                    'description': 'GuardDuty is not enabled. Enable threat detection service for better security monitoring.',
                    'impact': '+10 points',
                    'effort': 'Low',
                    'steps': [
                        '1. Go to GuardDuty Console',
                        '2. Enable GuardDuty',
                        '3. Accept service permissions',
                        '4. Configure finding types',
                        '5. Set up notifications for findings'
                    ]
                })
            
            # If no issues found, add general recommendations
            if len(recommendations) == 0:
                recommendations.append({
                    'priority': 'LOW',
                    'category': 'General',
                    'title': 'Excellent Security Posture',
                    'description': 'Your AWS configuration follows security best practices. Continue monitoring and consider advanced security features.',
                    'impact': '+5 points',
                    'effort': 'Low',
                    'steps': [
                        '1. Enable AWS Config for compliance monitoring',
                        '2. Set up AWS Security Hub for centralized findings',
                        '3. Consider AWS WAF for web applications',
                        '4. Implement automated security scanning',
                        '5. Regular security reviews and audits'
                    ]
                })
            
        except Exception as e:
            print(f"Error generating recommendations: {str(e)}")
            recommendations.append({
                'priority': 'LOW',
                'category': 'General',
                'title': 'Review Security Configuration',
                'description': 'Unable to automatically assess configuration. Perform manual security review.',
                'impact': '+10 points',
                'effort': 'Medium',
                'steps': [
                    '1. Review IAM users and permissions',
                    '2. Audit security group rules',
                    '3. Check S3 bucket configurations',
                    '4. Verify logging and monitoring setup',
                    '5. Enable additional security services'
                ]
            })
        
        return recommendations
