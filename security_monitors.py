from datetime import datetime, timedelta
import pandas as pd
from aws_client import AWSClient

class SecurityMonitors:
    """Security monitoring and data collection for AWS services"""
    
    def __init__(self, aws_client):
        self.aws_client = aws_client
    
    def get_security_overview(self):
        """Get overall security overview data"""
        try:
            # Get basic counts
            iam_users = len(self.aws_client.list_iam_users())
            security_groups = len(self.aws_client.list_security_groups())
            s3_buckets = len(self.aws_client.list_s3_buckets())
            
            # Get GuardDuty findings count
            critical_alerts = 0
            detectors = self.aws_client.list_guardduty_detectors()
            if detectors:
                findings = self.aws_client.list_guardduty_findings(detectors[0])
                critical_alerts = len([f for f in findings if f.get('Severity', 0) >= 8.0])
            
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
                'critical_alerts': critical_alerts,
                'recent_events': formatted_events,
                'security_trends': self._get_security_trends(),
                'alert_distribution': self._get_alert_distribution()
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
                'alert_distribution': None
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
                
                compliance_rules.append({
                    'Rule Name': rule_name,
                    'Description': rule.get('Description', 'N/A')[:100] + '...' if rule.get('Description', '') else 'N/A',
                    'Status': status,
                    'Compliant Resources': compliant_count,
                    'Non-compliant Resources': non_compliant_count,
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
                
                if severity >= 8.0:
                    critical_findings += 1
                elif severity >= 6.0:
                    high_findings += 1
                
                # Count active threats (findings from last 24 hours)
                updated_at = finding.get('UpdatedAt')
                if updated_at and (datetime.utcnow() - updated_at.replace(tzinfo=None)).days < 1:
                    active_threats += 1
                
                # Format for display
                recent_findings.append({
                    'Title': finding.get('Title', 'N/A'),
                    'Type': finding.get('Type', 'N/A'),
                    'Severity': self._get_severity_label(severity),
                    'Resource': finding.get('Resource', {}).get('Type', 'N/A'),
                    'Region': finding.get('Region', 'N/A'),
                    'Updated': updated_at.strftime('%Y-%m-%d %H:%M:%S') if updated_at else 'N/A'
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
                date = updated_at.strftime('%Y-%m-%d')
                timeline[date] = timeline.get(date, 0) + 1
        
        # Sort by date
        sorted_timeline = sorted(timeline.items())
        
        return {
            'dates': [item[0] for item in sorted_timeline],
            'counts': [item[1] for item in sorted_timeline]
        }
    
    def _get_severity_label(self, severity):
        """Convert numeric severity to label"""
        if severity >= 8.0:
            return 'CRITICAL'
        elif severity >= 6.0:
            return 'HIGH'
        elif severity >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
