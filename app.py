import streamlit as st
import boto3
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from streamlit_autorefresh import st_autorefresh
import os

from aws_client import AWSClient
from security_monitors import SecurityMonitors
from dashboard_components import DashboardComponents
from utils import format_timestamp, calculate_security_score, get_severity_color

# Page configuration
st.set_page_config(
    page_title="AWS Security Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'aws_client' not in st.session_state:
    st.session_state.aws_client = None
if 'connected' not in st.session_state:
    st.session_state.connected = False

def main():
    st.title("🔒 AWS Security Dashboard")
    st.markdown("Comprehensive security monitoring for your AWS infrastructure")
    
    # Sidebar for AWS configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Auto-refresh settings
        refresh_interval = st.selectbox(
            "Auto-refresh interval",
            [30, 60, 300, 600],
            index=1,
            format_func=lambda x: f"{x} seconds"
        )
        
        auto_refresh = st.checkbox("Enable auto-refresh", value=True)
        
        if auto_refresh:
            st_autorefresh(interval=refresh_interval * 1000, key="dashboard_refresh")
        
        st.divider()
        
        # AWS Credentials
        st.subheader("AWS Credentials")
        
        # Get credentials from environment or user input
        aws_access_key = st.text_input(
            "Access Key ID",
            value=os.getenv("AWS_ACCESS_KEY_ID", ""),
            type="password"
        )
        aws_secret_key = st.text_input(
            "Secret Access Key",
            value=os.getenv("AWS_SECRET_ACCESS_KEY", ""),
            type="password"
        )
        aws_region = st.selectbox(
            "AWS Region",
            ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"],
            index=0
        )
        
        # Connect to AWS
        if st.button("Connect to AWS", type="primary"):
            if aws_access_key and aws_secret_key:
                try:
                    st.session_state.aws_client = AWSClient(
                        aws_access_key_id=aws_access_key,
                        aws_secret_access_key=aws_secret_key,
                        region_name=aws_region
                    )
                    
                    if st.session_state.aws_client.test_connection():
                        st.session_state.connected = True
                        st.success("Successfully connected to AWS!")
                        st.rerun()
                    else:
                        st.error("Failed to connect to AWS. Please check your credentials.")
                        st.session_state.connected = False
                except Exception as e:
                    st.error(f"Error connecting to AWS: {str(e)}")
                    st.session_state.connected = False
            else:
                st.error("Please provide both Access Key ID and Secret Access Key")
        
        # Connection status
        if st.session_state.connected:
            st.success("✅ Connected to AWS")
            if st.button("Disconnect"):
                st.session_state.aws_client = None
                st.session_state.connected = False
                st.rerun()
        else:
            st.warning("❌ Not connected to AWS")
    
    # Main dashboard content
    if not st.session_state.connected or not st.session_state.aws_client:
        st.warning("Please configure and connect to AWS using the sidebar to view the security dashboard.")
        
        # Show sample dashboard structure
        st.subheader("Dashboard Preview")
        st.info("This dashboard will display the following security monitoring sections once connected:")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Overall Security Score", "N/A", "N/A")
        with col2:
            st.metric("Critical Alerts", "N/A", "N/A")
        with col3:
            st.metric("IAM Users", "N/A", "N/A")
        with col4:
            st.metric("Security Groups", "N/A", "N/A")
        
        return
    
    # Initialize security monitors and dashboard components
    security_monitors = SecurityMonitors(st.session_state.aws_client)
    dashboard_components = DashboardComponents()
    
    # Main dashboard tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🏠 Overview",
        "👤 IAM Security",
        "🌐 Network Security",
        "🛡️ Data Protection",
        "📋 Compliance",
        "🚨 Alerts & Threats"
    ])
    
    with tab1:
        show_overview_tab(security_monitors, dashboard_components)
    
    with tab2:
        show_iam_security_tab(security_monitors, dashboard_components)
    
    with tab3:
        show_network_security_tab(security_monitors, dashboard_components)
    
    with tab4:
        show_data_protection_tab(security_monitors, dashboard_components)
    
    with tab5:
        show_compliance_tab(security_monitors, dashboard_components)
    
    with tab6:
        show_alerts_threats_tab(security_monitors, dashboard_components)

def show_overview_tab(security_monitors, dashboard_components):
    st.header("Security Overview")
    
    try:
        # Get overview data
        overview_data = security_monitors.get_security_overview()
        
        # Security score and key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            security_score = calculate_security_score(overview_data)
            st.metric(
                "Overall Security Score",
                f"{security_score}/100",
                delta=f"{security_score - 85}" if security_score != 85 else None
            )
        
        with col2:
            critical_alerts = overview_data.get('critical_alerts', 0)
            st.metric(
                "Critical Alerts",
                critical_alerts,
                delta=f"+{critical_alerts}" if critical_alerts > 0 else None
            )
        
        with col3:
            iam_users = overview_data.get('iam_users', 0)
            st.metric("IAM Users", iam_users)
        
        with col4:
            security_groups = overview_data.get('security_groups', 0)
            st.metric("Security Groups", security_groups)
        
        # Charts row
        col1, col2 = st.columns(2)
        
        with col1:
            # Security score trends
            if overview_data.get('security_trends'):
                dashboard_components.create_security_score_chart(overview_data['security_trends'])
            else:
                st.info("Security trends data not available")
        
        with col2:
            # Alert distribution
            if overview_data.get('alert_distribution'):
                dashboard_components.create_alert_distribution_chart(overview_data['alert_distribution'])
            else:
                st.info("Alert distribution data not available")
        
        # Recent security events
        st.subheader("Recent Security Events")
        recent_events = overview_data.get('recent_events', [])
        
        if recent_events:
            df_events = pd.DataFrame(recent_events)
            st.dataframe(df_events, use_container_width=True)
        else:
            st.info("No recent security events found")
        
        # Security recommendations
        st.subheader("🎯 Security Recommendations")
        st.markdown("Implement these recommendations to improve your security score:")
        
        recommendations = overview_data.get('recommendations', [])
        
        if recommendations:
            # Sort recommendations by priority
            priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            sorted_recommendations = sorted(recommendations, key=lambda x: priority_order.get(x['priority'], 4))
            
            for i, rec in enumerate(sorted_recommendations):
                # Create expandable recommendation card
                priority_color = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠', 
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(rec['priority'], '⚪')
                
                with st.expander(f"{priority_color} {rec['title']} - {rec['impact']} ({rec['effort']} effort)", expanded=(i < 2)):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.markdown(f"**Category:** {rec['category']}")
                        st.markdown(f"**Description:** {rec['description']}")
                        
                        st.markdown("**Implementation Steps:**")
                        for step in rec['steps']:
                            st.markdown(f"- {step}")
                    
                    with col2:
                        st.markdown(f"**Priority:** {rec['priority']}")
                        st.markdown(f"**Security Impact:** {rec['impact']}")
                        st.markdown(f"**Implementation Effort:** {rec['effort']}")
                        
                        # Add completion checkbox (for UI purposes)
                        st.checkbox(f"Mark as completed", key=f"rec_{i}")
        else:
            st.info("Unable to generate specific recommendations. Please ensure AWS services are properly configured.")
            
    except Exception as e:
        st.error(f"Error loading overview data: {str(e)}")

def show_iam_security_tab(security_monitors, dashboard_components):
    st.header("IAM Security Monitoring")
    
    try:
        iam_data = security_monitors.get_iam_security_data()
        
        # IAM metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Users", iam_data.get('total_users', 0))
        
        with col2:
            users_with_mfa = iam_data.get('users_with_mfa', 0)
            total_users = iam_data.get('total_users', 1)
            mfa_percentage = (users_with_mfa / total_users) * 100 if total_users > 0 else 0
            st.metric("MFA Enabled", f"{mfa_percentage:.1f}%")
        
        with col3:
            st.metric("Total Roles", iam_data.get('total_roles', 0))
        
        with col4:
            old_access_keys = iam_data.get('old_access_keys', 0)
            st.metric("Old Access Keys", old_access_keys, delta=f"+{old_access_keys}" if old_access_keys > 0 else None)
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            if iam_data.get('user_activity'):
                dashboard_components.create_user_activity_chart(iam_data['user_activity'])
            else:
                st.info("User activity data not available")
        
        with col2:
            if iam_data.get('policy_changes'):
                dashboard_components.create_policy_changes_chart(iam_data['policy_changes'])
            else:
                st.info("Policy changes data not available")
        
        # User details table
        st.subheader("IAM User Details")
        if iam_data.get('user_details'):
            df_users = pd.DataFrame(iam_data['user_details'])
            st.dataframe(df_users, use_container_width=True)
        else:
            st.info("No IAM user data available")
            
    except Exception as e:
        st.error(f"Error loading IAM security data: {str(e)}")

def show_network_security_tab(security_monitors, dashboard_components):
    st.header("Network Security Monitoring")
    
    try:
        network_data = security_monitors.get_network_security_data()
        
        # Network metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Security Groups", network_data.get('total_security_groups', 0))
        
        with col2:
            open_security_groups = network_data.get('open_security_groups', 0)
            st.metric("Open Security Groups", open_security_groups, 
                     delta=f"+{open_security_groups}" if open_security_groups > 0 else None)
        
        with col3:
            st.metric("VPCs", network_data.get('total_vpcs', 0))
        
        with col4:
            st.metric("Internet Gateways", network_data.get('internet_gateways', 0))
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            if network_data.get('security_group_rules'):
                dashboard_components.create_security_group_chart(network_data['security_group_rules'])
            else:
                st.info("Security group rules data not available")
        
        with col2:
            if network_data.get('vpc_flow_logs'):
                dashboard_components.create_vpc_flow_chart(network_data['vpc_flow_logs'])
            else:
                st.info("VPC flow logs data not available")
        
        # Security groups table
        st.subheader("Security Group Analysis")
        if network_data.get('security_group_details'):
            df_sg = pd.DataFrame(network_data['security_group_details'])
            st.dataframe(df_sg, use_container_width=True)
        else:
            st.info("No security group data available")
            
    except Exception as e:
        st.error(f"Error loading network security data: {str(e)}")

def show_data_protection_tab(security_monitors, dashboard_components):
    st.header("Data Protection Monitoring")
    
    try:
        data_protection = security_monitors.get_data_protection_data()
        
        # Data protection metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("S3 Buckets", data_protection.get('total_s3_buckets', 0))
        
        with col2:
            encrypted_buckets = data_protection.get('encrypted_s3_buckets', 0)
            total_buckets = data_protection.get('total_s3_buckets', 1)
            encryption_percentage = (encrypted_buckets / total_buckets) * 100 if total_buckets > 0 else 0
            st.metric("Encrypted Buckets", f"{encryption_percentage:.1f}%")
        
        with col3:
            public_buckets = data_protection.get('public_s3_buckets', 0)
            st.metric("Public Buckets", public_buckets, 
                     delta=f"+{public_buckets}" if public_buckets > 0 else None)
        
        with col4:
            st.metric("KMS Keys", data_protection.get('kms_keys', 0))
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            if data_protection.get('encryption_status'):
                dashboard_components.create_encryption_status_chart(data_protection['encryption_status'])
            else:
                st.info("Encryption status data not available")
        
        with col2:
            if data_protection.get('s3_access_patterns'):
                dashboard_components.create_s3_access_chart(data_protection['s3_access_patterns'])
            else:
                st.info("S3 access patterns data not available")
        
        # S3 bucket details
        st.subheader("S3 Bucket Security Analysis")
        if data_protection.get('s3_bucket_details'):
            df_s3 = pd.DataFrame(data_protection['s3_bucket_details'])
            st.dataframe(df_s3, use_container_width=True)
        else:
            st.info("No S3 bucket data available")
            
    except Exception as e:
        st.error(f"Error loading data protection data: {str(e)}")

def show_compliance_tab(security_monitors, dashboard_components):
    st.header("Compliance Monitoring")
    
    try:
        compliance_data = security_monitors.get_compliance_data()
        
        # Compliance metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            compliance_score = compliance_data.get('overall_compliance_score', 0)
            st.metric("Compliance Score", f"{compliance_score}%")
        
        with col2:
            passing_rules = compliance_data.get('passing_rules', 0)
            st.metric("Passing Rules", passing_rules)
        
        with col3:
            failing_rules = compliance_data.get('failing_rules', 0)
            st.metric("Failing Rules", failing_rules, 
                     delta=f"+{failing_rules}" if failing_rules > 0 else None)
        
        with col4:
            non_compliant_resources = compliance_data.get('non_compliant_resources', 0)
            st.metric("Non-compliant Resources", non_compliant_resources)
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            if compliance_data.get('compliance_by_service'):
                dashboard_components.create_compliance_by_service_chart(compliance_data['compliance_by_service'])
            else:
                st.info("Compliance by service data not available")
        
        with col2:
            if compliance_data.get('compliance_trends'):
                dashboard_components.create_compliance_trends_chart(compliance_data['compliance_trends'])
            else:
                st.info("Compliance trends data not available")
        
        # Compliance rules table
        st.subheader("Compliance Rules Status")
        if compliance_data.get('compliance_rules'):
            df_compliance = pd.DataFrame(compliance_data['compliance_rules'])
            st.dataframe(df_compliance, use_container_width=True)
        else:
            st.info("No compliance rules data available")
            
    except Exception as e:
        st.error(f"Error loading compliance data: {str(e)}")

def show_alerts_threats_tab(security_monitors, dashboard_components):
    st.header("Alerts & Threat Detection")
    
    try:
        threats_data = security_monitors.get_threats_data()
        
        # Threat metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_findings = threats_data.get('total_findings', 0)
            st.metric("Total Findings", total_findings)
        
        with col2:
            critical_findings = threats_data.get('critical_findings', 0)
            st.metric("Critical Findings", critical_findings, 
                     delta=f"+{critical_findings}" if critical_findings > 0 else None)
        
        with col3:
            high_findings = threats_data.get('high_findings', 0)
            st.metric("High Severity", high_findings)
        
        with col4:
            active_threats = threats_data.get('active_threats', 0)
            st.metric("Active Threats", active_threats, 
                     delta=f"+{active_threats}" if active_threats > 0 else None)
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            if threats_data.get('threat_types'):
                dashboard_components.create_threat_types_chart(threats_data['threat_types'])
            else:
                st.info("Threat types data not available")
        
        with col2:
            if threats_data.get('findings_over_time'):
                dashboard_components.create_findings_timeline_chart(threats_data['findings_over_time'])
            else:
                st.info("Findings timeline data not available")
        
        # Recent threats table
        st.subheader("Recent Security Findings")
        if threats_data.get('recent_findings'):
            df_threats = pd.DataFrame(threats_data['recent_findings'])
            
            # Color code by severity
            def highlight_severity(row):
                if row['Severity'] == 'CRITICAL':
                    return ['background-color: #ffebee'] * len(row)
                elif row['Severity'] == 'HIGH':
                    return ['background-color: #fff3e0'] * len(row)
                else:
                    return [''] * len(row)
            
            styled_df = df_threats.style.apply(highlight_severity, axis=1)
            st.dataframe(styled_df, use_container_width=True)
        else:
            st.info("No recent security findings available")
            
    except Exception as e:
        st.error(f"Error loading threats data: {str(e)}")

if __name__ == "__main__":
    main()
