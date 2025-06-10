import boto3
import streamlit as st
from botocore.exceptions import ClientError, NoCredentialsError
import os

class AWSClient:
    """AWS client wrapper for managing AWS service connections"""
    
    def __init__(self, aws_access_key_id=None, aws_secret_access_key=None, region_name='us-east-1', selected_regions=None):
        """Initialize AWS client with credentials and multi-region support"""
        self.aws_access_key_id = aws_access_key_id or os.getenv('AWS_ACCESS_KEY_ID')
        self.aws_secret_access_key = aws_secret_access_key or os.getenv('AWS_SECRET_ACCESS_KEY')
        self.region_name = region_name
        self.selected_regions = selected_regions or [region_name]
        
        # Initialize sessions for each region
        self.sessions = {}
        for region in self.selected_regions:
            self.sessions[region] = boto3.Session(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                region_name=region
            )
        
        # Initialize service clients by region
        self._clients = {}
    
    def get_client(self, service_name, region=None):
        """Get or create AWS service client for specific region"""
        region = region or self.region_name
        client_key = f"{service_name}_{region}"
        
        if client_key not in self._clients:
            try:
                if region in self.sessions:
                    self._clients[client_key] = self.sessions[region].client(service_name)
                else:
                    # Create session for new region if needed
                    self.sessions[region] = boto3.Session(
                        aws_access_key_id=self.aws_access_key_id,
                        aws_secret_access_key=self.aws_secret_access_key,
                        region_name=region
                    )
                    self._clients[client_key] = self.sessions[region].client(service_name)
            except Exception as e:
                print(f"Error creating {service_name} client for {region}: {str(e)}")
                return None
        return self._clients[client_key]
    
    def test_connection(self):
        """Test AWS connection by making a simple API call"""
        try:
            sts_client = self.get_client('sts')
            if sts_client:
                response = sts_client.get_caller_identity()
                return True
            return False
        except (ClientError, NoCredentialsError) as e:
            st.error(f"AWS connection test failed: {str(e)}")
            return False
        except Exception as e:
            st.error(f"Unexpected error during connection test: {str(e)}")
            return False
    
    def get_account_id(self):
        """Get AWS account ID"""
        try:
            sts_client = self.get_client('sts')
            if sts_client:
                response = sts_client.get_caller_identity()
                return response.get('Account')
            return None
        except Exception as e:
            st.error(f"Error getting account ID: {str(e)}")
            return None
    
    def get_regions(self):
        """Get list of available AWS regions"""
        try:
            ec2_client = self.get_client('ec2')
            if ec2_client:
                response = ec2_client.describe_regions()
                return [region['RegionName'] for region in response['Regions']]
            return []
        except Exception as e:
            print(f"Error getting regions: {str(e)}")
            return ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'eu-central-1']
    
    def update_selected_regions(self, new_regions):
        """Update the list of selected regions for monitoring"""
        self.selected_regions = new_regions
        # Initialize sessions for new regions
        for region in new_regions:
            if region not in self.sessions:
                self.sessions[region] = boto3.Session(
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                    region_name=region
                )
    
    def get_multi_region_data(self, service_method, service_name='ec2', **kwargs):
        """Execute a service method across all selected regions"""
        results = {}
        for region in self.selected_regions:
            try:
                client = self.get_client(service_name, region)
                if client and hasattr(client, service_method):
                    method = getattr(client, service_method)
                    results[region] = method(**kwargs)
                else:
                    results[region] = {'error': f'{service_method} not available'}
            except Exception as e:
                results[region] = {'error': str(e)}
        return results
    
    # IAM methods
    def list_iam_users(self):
        """List IAM users"""
        try:
            iam_client = self.get_client('iam')
            if iam_client:
                paginator = iam_client.get_paginator('list_users')
                users = []
                for page in paginator.paginate():
                    users.extend(page['Users'])
                return users
            return []
        except Exception as e:
            st.error(f"Error listing IAM users: {str(e)}")
            return []
    
    def list_iam_roles(self):
        """List IAM roles"""
        try:
            iam_client = self.get_client('iam')
            if iam_client:
                paginator = iam_client.get_paginator('list_roles')
                roles = []
                for page in paginator.paginate():
                    roles.extend(page['Roles'])
                return roles
            return []
        except Exception as e:
            st.error(f"Error listing IAM roles: {str(e)}")
            return []
    
    def get_user_mfa_devices(self, username):
        """Get MFA devices for a user"""
        try:
            iam_client = self.get_client('iam')
            if iam_client:
                response = iam_client.list_mfa_devices(UserName=username)
                return response['MFADevices']
            return []
        except Exception as e:
            return []
    
    def list_access_keys(self, username):
        """List access keys for a user"""
        try:
            iam_client = self.get_client('iam')
            if iam_client:
                response = iam_client.list_access_keys(UserName=username)
                return response['AccessKeyMetadata']
            return []
        except Exception as e:
            return []
    
    # EC2/VPC methods
    def list_security_groups(self):
        """List security groups"""
        try:
            ec2_client = self.get_client('ec2')
            if ec2_client:
                response = ec2_client.describe_security_groups()
                return response['SecurityGroups']
            return []
        except Exception as e:
            st.error(f"Error listing security groups: {str(e)}")
            return []
    
    def list_vpcs(self):
        """List VPCs"""
        try:
            ec2_client = self.get_client('ec2')
            if ec2_client:
                response = ec2_client.describe_vpcs()
                return response['Vpcs']
            return []
        except Exception as e:
            st.error(f"Error listing VPCs: {str(e)}")
            return []
    
    def list_internet_gateways(self):
        """List internet gateways"""
        try:
            ec2_client = self.get_client('ec2')
            if ec2_client:
                response = ec2_client.describe_internet_gateways()
                return response['InternetGateways']
            return []
        except Exception as e:
            st.error(f"Error listing internet gateways: {str(e)}")
            return []
    
    # S3 methods
    def list_s3_buckets(self):
        """List S3 buckets"""
        try:
            s3_client = self.get_client('s3')
            if s3_client:
                response = s3_client.list_buckets()
                return response['Buckets']
            return []
        except Exception as e:
            st.error(f"Error listing S3 buckets: {str(e)}")
            return []
    
    def get_bucket_encryption(self, bucket_name):
        """Get bucket encryption configuration"""
        try:
            s3_client = self.get_client('s3')
            if s3_client:
                response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                return response['ServerSideEncryptionConfiguration']
            return None
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return None
            return None
        except Exception as e:
            return None
    
    def get_bucket_public_access_block(self, bucket_name):
        """Get bucket public access block configuration"""
        try:
            s3_client = self.get_client('s3')
            if s3_client:
                response = s3_client.get_public_access_block(Bucket=bucket_name)
                return response['PublicAccessBlockConfiguration']
            return None
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                return None
            return None
        except Exception as e:
            return None
    
    # KMS methods
    def list_kms_keys(self):
        """List KMS keys"""
        try:
            kms_client = self.get_client('kms')
            if kms_client:
                paginator = kms_client.get_paginator('list_keys')
                keys = []
                for page in paginator.paginate():
                    keys.extend(page['Keys'])
                return keys
            return []
        except Exception as e:
            st.error(f"Error listing KMS keys: {str(e)}")
            return []
    
    # CloudTrail methods
    def describe_trails(self):
        """Describe CloudTrail trails"""
        try:
            cloudtrail_client = self.get_client('cloudtrail')
            if cloudtrail_client:
                response = cloudtrail_client.describe_trails()
                return response['trailList']
            return []
        except Exception as e:
            st.error(f"Error describing CloudTrail trails: {str(e)}")
            return []
    
    def lookup_events(self, start_time, end_time, max_items=50):
        """Lookup CloudTrail events"""
        try:
            cloudtrail_client = self.get_client('cloudtrail')
            if cloudtrail_client:
                response = cloudtrail_client.lookup_events(
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=max_items
                )
                return response['Events']
            return []
        except Exception as e:
            st.error(f"Error looking up CloudTrail events: {str(e)}")
            return []
    
    # GuardDuty methods
    def list_guardduty_detectors(self):
        """List GuardDuty detectors"""
        try:
            guardduty_client = self.get_client('guardduty')
            if guardduty_client:
                response = guardduty_client.list_detectors()
                return response['DetectorIds']
            return []
        except Exception as e:
            st.error(f"Error listing GuardDuty detectors: {str(e)}")
            return []
    
    def list_guardduty_findings(self, detector_id, max_items=50):
        """List GuardDuty findings"""
        try:
            guardduty_client = self.get_client('guardduty')
            if guardduty_client:
                response = guardduty_client.list_findings(
                    DetectorId=detector_id,
                    MaxResults=max_items
                )
                finding_ids = response['FindingIds']
                
                if finding_ids:
                    findings_response = guardduty_client.get_findings(
                        DetectorId=detector_id,
                        FindingIds=finding_ids
                    )
                    return findings_response['Findings']
                return []
            return []
        except Exception as e:
            st.error(f"Error listing GuardDuty findings: {str(e)}")
            return []
    
    # Config methods
    def describe_config_rules(self):
        """Describe Config rules"""
        try:
            config_client = self.get_client('config')
            if config_client:
                response = config_client.describe_config_rules()
                return response['ConfigRules']
            return []
        except Exception as e:
            st.error(f"Error describing Config rules: {str(e)}")
            return []
    
    def get_compliance_by_config_rule(self, rule_name):
        """Get compliance details for a Config rule"""
        try:
            config_client = self.get_client('config')
            if config_client:
                response = config_client.get_compliance_details_by_config_rule(
                    ConfigRuleName=rule_name
                )
                return response['EvaluationResults']
            return []
        except Exception as e:
            return []
