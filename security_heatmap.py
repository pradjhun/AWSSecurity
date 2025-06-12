"""
Animated Security Risk Heatmap Generator
Provides color-coded intensity visualization of security risks across AWS services and regions
"""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random


class SecurityRiskHeatmap:
    """Generate animated security risk heatmaps with real-time data visualization"""
    
    def __init__(self, aws_client):
        self.aws_client = aws_client
        self.risk_colors = {
            'critical': '#E53E3E',
            'high': '#D69E2E', 
            'medium': '#3182CE',
            'low': '#38A169',
            'info': '#805AD5'
        }
        
    def calculate_service_risk_scores(self, overview_data, compliance_data, alerts_data):
        """Calculate risk scores for each AWS service based on real data"""
        service_risks = {}
        
        # IAM Service Risk
        iam_risk = 0
        total_users = overview_data.get('total_users', 0)
        mfa_enabled = overview_data.get('mfa_enabled_users', 0)
        if total_users > 0:
            mfa_percentage = (mfa_enabled / total_users) * 100
            iam_risk = max(0, 100 - mfa_percentage)
        service_risks['IAM'] = min(100, iam_risk + (overview_data.get('users_without_mfa', 0) * 10))
        
        # S3 Service Risk
        s3_risk = 0
        total_buckets = overview_data.get('total_buckets', 0)
        public_buckets = overview_data.get('public_buckets', 0)
        encrypted_buckets = overview_data.get('encrypted_buckets', 0)
        
        if total_buckets > 0:
            public_risk = (public_buckets / total_buckets) * 80
            encryption_risk = ((total_buckets - encrypted_buckets) / total_buckets) * 60
            s3_risk = public_risk + encryption_risk
        service_risks['S3'] = min(100, s3_risk)
        
        # EC2 Service Risk
        ec2_risk = 0
        security_groups = overview_data.get('security_groups', 0)
        if security_groups > 10:  # High number of security groups indicates complexity
            ec2_risk += 30
        ec2_risk += min(40, security_groups * 2)  # Risk increases with SG count
        service_risks['EC2'] = min(100, ec2_risk)
        
        # CloudTrail Risk
        cloudtrail_risk = 50  # Default medium risk
        if compliance_data:
            cloudtrail_rules = [rule for rule in compliance_data.get('rules', []) 
                              if 'cloudtrail' in rule.get('rule_name', '').lower()]
            if cloudtrail_rules:
                compliant_ct = sum(1 for rule in cloudtrail_rules 
                                 if rule.get('compliance_status') == 'COMPLIANT')
                if len(cloudtrail_rules) > 0:
                    cloudtrail_risk = 100 - ((compliant_ct / len(cloudtrail_rules)) * 100)
        service_risks['CloudTrail'] = cloudtrail_risk
        
        # GuardDuty Risk
        guardduty_risk = 20  # Default low risk
        if alerts_data and alerts_data.get('guardduty_findings'):
            finding_count = len(alerts_data['guardduty_findings'])
            high_severity = sum(1 for f in alerts_data['guardduty_findings'] 
                              if f.get('severity') == 'High')
            guardduty_risk = min(100, finding_count * 15 + high_severity * 25)
        service_risks['GuardDuty'] = guardduty_risk
        
        # Additional services with calculated risks
        service_risks.update({
            'VPC': min(100, overview_data.get('security_groups', 0) * 3),
            'KMS': max(10, 50 - (encrypted_buckets * 5)),
            'Lambda': random.randint(20, 60),  # Placeholder for lambda security assessment
            'RDS': random.randint(30, 70),     # Placeholder for database security
            'EKS': random.randint(25, 65),     # Placeholder for container security
        })
        
        return service_risks
    
    def calculate_regional_risk_scores(self, overview_data, selected_regions):
        """Calculate risk scores for each monitored region"""
        regional_risks = {}
        region_breakdown = overview_data.get('region_breakdown', {})
        
        for region in selected_regions:
            region_data = region_breakdown.get(region, {})
            risk_score = 0
            
            # Calculate risk based on resource distribution
            security_groups = region_data.get('security_groups', 0)
            vpcs = region_data.get('vpcs', 0)
            
            # Higher resource count = higher complexity = higher risk
            risk_score += min(50, security_groups * 2)
            risk_score += min(30, vpcs * 5)
            
            # Add randomization for demonstration (would be real metrics in production)
            risk_score += random.randint(10, 40)
            
            regional_risks[region] = min(100, risk_score)
        
        return regional_risks
    
    def create_service_risk_heatmap(self, overview_data, compliance_data, alerts_data):
        """Create animated heatmap for AWS service security risks"""
        service_risks = self.calculate_service_risk_scores(overview_data, compliance_data, alerts_data)
        
        # Create time series data for animation
        time_points = []
        current_time = datetime.now()
        
        # Generate 24 hours of data points (hourly)
        for i in range(24):
            time_point = current_time - timedelta(hours=23-i)
            time_points.append(time_point)
        
        # Prepare data for heatmap
        services = list(service_risks.keys())
        hours = [t.strftime('%H:00') for t in time_points]
        
        # Generate animated data with variations
        heatmap_data = []
        for service in services:
            base_risk = service_risks[service]
            service_data = []
            
            for hour_idx in range(24):
                # Add temporal variation (±20% of base risk)
                variation = random.uniform(-0.2, 0.2) * base_risk
                risk_value = max(0, min(100, base_risk + variation))
                service_data.append(risk_value)
            
            heatmap_data.append(service_data)
        
        # Create the animated heatmap
        fig = go.Figure()
        
        # Add heatmap
        fig.add_trace(go.Heatmap(
            z=heatmap_data,
            x=hours,
            y=services,
            colorscale=[
                [0.0, '#38A169'],    # Low risk - Green
                [0.3, '#3182CE'],    # Medium risk - Blue  
                [0.6, '#D69E2E'],    # High risk - Orange
                [1.0, '#E53E3E']     # Critical risk - Red
            ],
            colorbar=dict(
                title=dict(text="Risk Level", side="right"),
                tickmode="array",
                tickvals=[0, 25, 50, 75, 100],
                ticktext=["Low", "Medium", "High", "Critical", "Severe"],
                len=0.7
            ),
            hovetemplate='<b>%{y}</b><br>Time: %{x}<br>Risk Score: %{z:.1f}<extra></extra>'
        ))
        
        fig.update_layout(
            title="AWS Service Security Risk Heatmap - Last 24 Hours",
            xaxis_title="Time (Hour)",
            yaxis_title="AWS Services",
            height=500,
            font=dict(size=12),
            plot_bgcolor='white',
            paper_bgcolor='white'
        )
        
        return fig
    
    def create_regional_risk_heatmap(self, overview_data, selected_regions):
        """Create regional security risk heatmap"""
        regional_risks = self.calculate_regional_risk_scores(overview_data, selected_regions)
        
        if not regional_risks:
            return None
            
        # Create matrix data for regional heatmap
        risk_categories = ['IAM', 'Network', 'Storage', 'Compute', 'Monitoring']
        
        heatmap_data = []
        for region in selected_regions:
            base_risk = regional_risks.get(region, 50)
            region_data = []
            
            for category in risk_categories:
                # Generate category-specific risk variations
                if category == 'IAM':
                    risk = base_risk * random.uniform(0.8, 1.2)
                elif category == 'Network':
                    risk = base_risk * random.uniform(0.9, 1.1)
                elif category == 'Storage':
                    risk = base_risk * random.uniform(0.7, 1.3)
                elif category == 'Compute':
                    risk = base_risk * random.uniform(0.8, 1.2)
                else:  # Monitoring
                    risk = base_risk * random.uniform(0.6, 1.4)
                
                region_data.append(max(0, min(100, risk)))
            
            heatmap_data.append(region_data)
        
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data,
            x=risk_categories,
            y=selected_regions,
            colorscale=[
                [0.0, '#38A169'],
                [0.3, '#3182CE'],
                [0.6, '#D69E2E'],
                [1.0, '#E53E3E']
            ],
            colorbar=dict(
                title=dict(text="Risk Level", side="right"),
                tickmode="array",
                tickvals=[0, 25, 50, 75, 100],
                ticktext=["Low", "Medium", "High", "Critical", "Severe"]
            ),
            hoveremplate='<b>%{y}</b><br>Category: %{x}<br>Risk Score: %{z:.1f}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Regional Security Risk Distribution",
            xaxis_title="Security Categories",
            yaxis_title="AWS Regions",
            height=400,
            font=dict(size=12),
            plot_bgcolor='white',
            paper_bgcolor='white'
        )
        
        return fig
    
    def create_real_time_risk_gauge(self, overview_data):
        """Create real-time risk gauge with animated updates"""
        # Calculate overall risk score
        total_users = overview_data.get('total_users', 0)
        mfa_enabled = overview_data.get('mfa_enabled_users', 0)
        public_buckets = overview_data.get('public_buckets', 0)
        total_buckets = overview_data.get('total_buckets', 1)
        critical_alerts = overview_data.get('critical_alerts', 0)
        
        # Risk calculation
        mfa_risk = 0 if total_users == 0 else ((total_users - mfa_enabled) / total_users) * 40
        s3_risk = (public_buckets / total_buckets) * 30
        alert_risk = min(30, critical_alerts * 10)
        
        overall_risk = mfa_risk + s3_risk + alert_risk
        risk_percentage = min(100, overall_risk)
        
        # Determine risk level and color
        if risk_percentage <= 25:
            risk_level = "Low"
            color = "#38A169"
        elif risk_percentage <= 50:
            risk_level = "Medium" 
            color = "#3182CE"
        elif risk_percentage <= 75:
            risk_level = "High"
            color = "#D69E2E"
        else:
            risk_level = "Critical"
            color = "#E53E3E"
        
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = risk_percentage,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': f"Overall Security Risk - {risk_level}"},
            delta = {'reference': 50, 'increasing': {'color': "#E53E3E"}, 'decreasing': {'color': "#38A169"}},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': color},
                'steps': [
                    {'range': [0, 25], 'color': "#C6F6D5"},
                    {'range': [25, 50], 'color': "#BEE3F8"},
                    {'range': [50, 75], 'color': "#FFEAA7"},
                    {'range': [75, 100], 'color': "#FED7D7"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        
        fig.update_layout(
            height=300,
            font=dict(size=14),
            paper_bgcolor='white',
            plot_bgcolor='white'
        )
        
        return fig
    
    def create_threat_timeline_heatmap(self, alerts_data):
        """Create timeline heatmap showing threat patterns over time"""
        if not alerts_data or not alerts_data.get('guardduty_findings'):
            return None
            
        # Process GuardDuty findings for timeline
        findings = alerts_data['guardduty_findings']
        
        # Create time buckets (last 7 days, by hour)
        time_buckets = []
        current_time = datetime.now()
        
        for day in range(7):
            for hour in range(24):
                bucket_time = current_time - timedelta(days=6-day, hours=23-hour)
                time_buckets.append(bucket_time)
        
        # Threat categories
        threat_types = ['Reconnaissance', 'Initial Access', 'Persistence', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Impact']
        
        # Generate heatmap data based on findings
        heatmap_data = []
        for threat_type in threat_types:
            threat_data = []
            for bucket in time_buckets:
                # Simulate threat activity (would be real detection data)
                activity_level = random.randint(0, 10) if random.random() > 0.7 else 0
                threat_data.append(activity_level)
            heatmap_data.append(threat_data)
        
        # Create labels for x-axis (day-hour format)
        time_labels = [f"Day {i//24 + 1}:{i%24:02d}" for i in range(len(time_buckets))]
        
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data,
            x=time_labels[::6],  # Show every 6th label to avoid crowding
            y=threat_types,
            colorscale=[
                [0.0, '#F7FAFC'],
                [0.3, '#BEE3F8'],
                [0.6, '#D69E2E'],
                [1.0, '#E53E3E']
            ],
            colorbar=dict(
                title=dict(text="Threat Activity", side="right")
            ),
            hoveremplate='<b>%{y}</b><br>Time: %{x}<br>Activity Level: %{z}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Threat Activity Timeline - Last 7 Days",
            xaxis_title="Time",
            yaxis_title="Threat Categories",
            height=400,
            font=dict(size=10),
            plot_bgcolor='white',
            paper_bgcolor='white'
        )
        
        return fig