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
from enhanced_security_checks import EnhancedSecurityChecks
from export_manager import ExportManager

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
        # Multi-region selection
        st.subheader("🌍 Region Selection")
        
        available_regions = [
            "us-east-1", "us-west-1", "us-west-2", 
            "eu-west-1", "eu-central-1", "eu-west-2", "eu-west-3",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", 
            "ap-northeast-2", "ap-south-1", "ca-central-1",
            "sa-east-1", "af-south-1", "me-south-1"
        ]
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            selected_regions = st.multiselect(
                "Select Regions to Monitor",
                options=available_regions,
                default=["us-east-1"],
                help="Monitor security across multiple AWS regions"
            )
        
        with col2:
            primary_region = st.selectbox(
                "Primary Region",
                options=selected_regions if selected_regions else ["us-east-1"],
                index=0,
                help="Primary region for global services"
            )
        
        if not selected_regions:
            st.warning("Select at least one region to monitor.")
            st.stop()
        
        # Connect to AWS
        if st.button("Connect to AWS", type="primary"):
            if aws_access_key and aws_secret_key:
                try:
                    st.session_state.aws_client = AWSClient(
                        aws_access_key_id=aws_access_key,
                        aws_secret_access_key=aws_secret_key,
                        region_name=primary_region,
                        selected_regions=selected_regions
                    )
                    st.session_state.selected_regions = selected_regions
                    st.session_state.primary_region = primary_region
                    
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
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9 = st.tabs([
        "🏠 Overview",
        "👤 IAM Security", 
        "🌐 Network Security",
        "🛡️ Data Protection",
        "📋 Compliance",
        "🚨 Alerts & Threats",
        "🔍 Enhanced Checks",
        "🤖 AI Recommendations",
        "📤 Export Reports"
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
    
    with tab7:
        show_enhanced_checks_tab(security_monitors, dashboard_components)
    
    with tab8:
        show_ai_recommendations_tab(security_monitors, dashboard_components)
    
    with tab9:
        show_export_reports_tab(security_monitors, dashboard_components)

def show_overview_tab(security_monitors, dashboard_components):
    st.header("Security Overview")
    
    try:
        # Get overview data
        overview_data = security_monitors.get_security_overview()
        
        # Multi-region overview
        if overview_data.get('total_regions', 1) > 1:
            st.subheader("🌍 Multi-Region Overview")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Regions", overview_data.get('total_regions', 1))
            with col2:
                active_regions = len([r for r in overview_data.get('region_breakdown', {}).values() if r.get('status') == 'active'])
                st.metric("Active Regions", active_regions)
            with col3:
                selected_regions = overview_data.get('selected_regions', [])
                st.metric("Monitored Regions", len(selected_regions))
            
            # Region breakdown table
            region_breakdown = overview_data.get('region_breakdown', {})
            if region_breakdown:
                st.write("**Region Resource Distribution:**")
                
                region_data = []
                for region, data in region_breakdown.items():
                    region_data.append({
                        'Region': region,
                        'Security Groups': data.get('security_groups', 0),
                        'VPCs': data.get('vpcs', 0),
                        'Status': '✅ Active' if data.get('status') == 'active' else '❌ Error'
                    })
                
                if region_data:
                    df = pd.DataFrame(region_data)
                    st.dataframe(df, use_container_width=True)
            
            st.divider()
        
        # Security score and key metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
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
        
        with col5:
            s3_buckets = overview_data.get('s3_buckets', 0)
            st.metric("S3 Buckets", s3_buckets)
        
        # Charts row
        col1, col2 = st.columns(2)
        
        with col1:
            # Security score trends
            if overview_data.get('security_trends'):
                dashboard_components.create_security_score_chart(overview_data['security_trends'])
            else:
                st.info("Security trends data not available")
        
        with col2:
            # Alert distribution or region distribution
            if overview_data.get('total_regions', 1) > 1 and overview_data.get('region_breakdown'):
                dashboard_components.create_region_distribution_chart(overview_data['region_breakdown'])
            elif overview_data.get('alert_distribution'):
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
        
        # One-click compliance report
        st.subheader("📄 Quick Actions")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🚀 Generate Compliance Report (PDF)", type="primary", key="quick_pdf_report"):
                try:
                    with st.spinner("Generating comprehensive compliance report..."):
                        export_manager = ExportManager()
                        compliance_data = security_monitors.get_compliance_data()
                        enhanced_findings = getattr(st.session_state, 'enhanced_findings', [])
                        
                        pdf_data = export_manager.export_compliance_report_to_pdf(
                            overview_data,
                            compliance_data,
                            overview_data.get('recommendations', []),
                            enhanced_findings
                        )
                        
                        filename = export_manager.get_pdf_filename()
                        
                        st.download_button(
                            label="📥 Download Compliance Report",
                            data=pdf_data,
                            file_name=filename,
                            mime="application/pdf",
                            key="download_compliance_pdf"
                        )
                        st.success("Compliance report generated successfully!")
                except Exception as e:
                    st.error(f"Error generating PDF report: {str(e)}")
        
        with col2:
            if st.button("📊 Export All Data (JSON)", key="quick_json_export"):
                try:
                    export_manager = ExportManager()
                    all_data = {
                        'overview': overview_data,
                        'compliance': security_monitors.get_compliance_data(),
                        'enhanced_findings': getattr(st.session_state, 'enhanced_findings', [])
                    }
                    json_data = export_manager.export_findings_to_json(all_data)
                    filename = export_manager.get_export_filename('json', 'complete_assessment')
                    
                    st.download_button(
                        label="📥 Download JSON Export",
                        data=json_data,
                        file_name=filename,
                        mime="application/json",
                        key="download_json_all"
                    )
                except Exception as e:
                    st.error(f"Error exporting data: {str(e)}")
        
        with col3:
            if st.button("🔍 Run Enhanced Checks", key="quick_enhanced_checks"):
                st.info("Redirecting to Enhanced Checks tab...")
                st.session_state.run_enhanced_checks = True

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
        overview_data = security_monitors.get_security_overview()
        
        # Initialize compliance analyzer and interactive popup
        from compliance_analyzer import ComplianceAnalyzer
        from interactive_compliance_popup import InteractiveCompliancePopup
        compliance_analyzer = ComplianceAnalyzer(security_monitors.ai_engine)
        popup_system = InteractiveCompliancePopup(security_monitors.ai_engine)
        
        # Analyze unknown compliance issues
        unknown_analysis = compliance_analyzer.analyze_unknown_compliance_issues(compliance_data, overview_data)
        
        # Show AI-powered message box for unknown compliance issues
        if unknown_analysis['total_unknown'] > 0 or unknown_analysis['total_unclear'] > 0:
            st.warning(f"🔍 Found {unknown_analysis['total_unknown']} unknown and {unknown_analysis['total_unclear']} unclear compliance issues")
            
            with st.spinner("Analyzing compliance issues and generating solutions..."):
                solutions = compliance_analyzer.generate_compliance_solutions(
                    unknown_analysis['unknown_issues'],
                    unknown_analysis['unclear_issues'], 
                    overview_data
                )
                
                if solutions:
                    compliance_analyzer.display_compliance_message_box(solutions)
        
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
        col1, col2, col3 = st.columns(3)
        
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
        
        with col3:
            if compliance_data.get('compliance_rules'):
                dashboard_components.create_compliance_status_chart(compliance_data['compliance_rules'])
            else:
                st.info("Compliance status distribution not available")
        
        # Compliance rules table with visual indicators
        st.subheader("Compliance Rules Status")
        if compliance_data.get('compliance_rules'):
            df_compliance = pd.DataFrame(compliance_data['compliance_rules'])
            
            # Create a styled dataframe display
            def highlight_compliance_status(row):
                """Apply styling based on compliance status"""
                color = row['Status_Color'] if 'Status_Color' in row else 'black'
                color_map = {
                    'green': 'background-color: #d4edda; color: #155724',
                    'orange': 'background-color: #fff3cd; color: #856404', 
                    'red': 'background-color: #f8d7da; color: #721c24',
                    'gray': 'background-color: #f8f9fa; color: #6c757d'
                }
                style = color_map.get(color, '')
                return [''] * len(row) if not style else [style if col == 'Status' else '' for col in row.index]
            
            # Display compliance summary cards
            col1, col2, col3, col4 = st.columns(4)
            
            compliant_rules = len([r for r in compliance_data['compliance_rules'] if 'COMPLIANT' in r['Status'] and 'NON-COMPLIANT' not in r['Status']])
            partial_rules = len([r for r in compliance_data['compliance_rules'] if 'PARTIAL' in r['Status']])
            non_compliant_rules = len([r for r in compliance_data['compliance_rules'] if 'NON-COMPLIANT' in r['Status']])
            unknown_rules = len([r for r in compliance_data['compliance_rules'] if 'UNKNOWN' in r['Status']])
            
            with col1:
                st.metric("✅ Compliant", compliant_rules)
            with col2:
                st.metric("⚠️ Partial", partial_rules)
            with col3:
                st.metric("❌ Non-Compliant", non_compliant_rules)
            with col4:
                st.metric("❓ Unknown", unknown_rules)
            
            # Filter and display options
            status_filter = st.selectbox(
                "Filter by compliance status:",
                ["All", "✅ Compliant", "⚠️ Partial", "❌ Non-Compliant", "❓ Unknown"],
                key="compliance_filter"
            )
            
            # Apply filter
            if status_filter != "All":
                filter_key = status_filter.split(" ", 1)[1] if " " in status_filter else status_filter
                df_filtered = df_compliance[df_compliance['Status'].str.contains(filter_key, na=False)]
            else:
                df_filtered = df_compliance
            
            # Remove internal status color column for display
            display_columns = [col for col in df_filtered.columns if col != 'Status_Color']
            df_display = df_filtered[display_columns]
            
            # Add bulk guidance button
            popup_system.create_bulk_guidance_popup(compliance_data['compliance_rules'], overview_data)
            
            # Display the filtered dataframe
            if len(df_display) > 0:
                st.dataframe(df_display, use_container_width=True)
                
                # Show detailed view for selected rules
                if len(df_display) <= 10:  # Only show details for smaller datasets
                    st.subheader("Rule Details")
                    # Convert to list for iteration
                    rules_list = df_display.to_dict('records')
                    for rule in rules_list:
                        with st.expander(f"{rule['Status']} {rule['Rule Name']}", expanded=False):
                            col1, col2, col3 = st.columns([2, 1, 1])
                            
                            with col1:
                                st.markdown(f"**Description:** {rule['Description']}")
                                st.markdown(f"**Source:** {rule['Source']}")
                            
                            with col2:
                                st.markdown(f"**Compliance Rate:** {rule['Compliance %']}%")
                                st.markdown(f"**Total Resources:** {rule['Total Resources']}")
                                st.markdown(f"**Compliant:** {rule['Compliant Resources']}")
                                st.markdown(f"**Non-compliant:** {rule['Non-compliant Resources']}")
                            
                            with col3:
                                # Interactive AI guidance popup for each rule
                                popup_system.create_compliance_popup(
                                    rule.get('Rule Name', f'Rule_{rule.get("Rule Name", "Unknown")}'),
                                    rule,
                                    overview_data
                                )
            else:
                st.info(f"No rules found for status: {status_filter}")
        else:
            st.info("No compliance rules data available")
        
        # Compliance standards reference
        st.subheader("📋 Compliance Standards Reference")
        st.markdown("The dashboard evaluates your AWS configuration against these compliance frameworks:")
        
        # Create tabs for different compliance standards
        framework_tab1, framework_tab2, framework_tab3, framework_tab4 = st.tabs([
            "CIS Benchmark", "AWS Foundational", "Industry Standards", "Custom Rules"
        ])
        
        with framework_tab1:
            st.markdown("### CIS AWS Foundations Benchmark v1.2.0")
            st.markdown("**Identity and Access Management:**")
            st.markdown("- 1.2: MFA enabled for all IAM users with console password")
            st.markdown("- 1.4: Access keys rotated within 90 days")
            st.markdown("- 1.12: Root user has no access keys")
            st.markdown("- 1.13: MFA enabled for root user")
            
            st.markdown("**Logging and Monitoring:**")
            st.markdown("- 2.1: CloudTrail enabled in all regions")
            st.markdown("- 2.2: CloudTrail log file validation enabled")
            st.markdown("- 2.7: CloudTrail logs encrypted at rest")
            st.markdown("- 2.9: VPC Flow Logs enabled")
            
            st.markdown("**Networking:**")
            st.markdown("- 4.1: No security groups allow ingress from 0.0.0.0/0 to port 22")
            st.markdown("- 4.2: No security groups allow ingress from 0.0.0.0/0 to port 3389")
            st.markdown("- 4.3: Default security group restricts all traffic")
        
        with framework_tab2:
            st.markdown("### AWS Foundational Security Standard")
            st.markdown("**Data Protection:**")
            st.markdown("- S3.1: S3 buckets prohibit public read access")
            st.markdown("- S3.2: S3 buckets prohibit public write access")
            st.markdown("- S3.3: S3 buckets have server-side encryption enabled")
            st.markdown("- RDS.3: RDS instances have encryption at rest enabled")
            
            st.markdown("**Network Security:**")
            st.markdown("- EC2.2: VPC default security group restricts all traffic")
            st.markdown("- EC2.13: Security groups do not allow unrestricted inbound traffic")
            st.markdown("- EC2.14: Security groups do not allow unrestricted outbound traffic")
            
            st.markdown("**Compute Security:**")
            st.markdown("- EC2.8: EC2 instances use IMDSv2")
            st.markdown("- Lambda.1: Lambda functions prohibit public access")
        
        with framework_tab3:
            st.markdown("### Industry Compliance Standards")
            
            st.markdown("**PCI DSS Requirements:**")
            st.markdown("- Requirement 1: Install and maintain firewall configuration")
            st.markdown("- Requirement 2: Do not use vendor-supplied defaults")
            st.markdown("- Requirement 3: Protect stored cardholder data")
            st.markdown("- Requirement 4: Encrypt transmission of cardholder data")
            
            st.markdown("**HIPAA Security Rules:**")
            st.markdown("- Administrative Safeguards: Access management procedures")
            st.markdown("- Physical Safeguards: Facility access controls")
            st.markdown("- Technical Safeguards: Access control and audit controls")
            
            st.markdown("**SOC 2 Trust Principles:**")
            st.markdown("- Security: Protection against unauthorized access")
            st.markdown("- Availability: System operation and usability")
            st.markdown("- Confidentiality: Information designated as confidential")
        
        with framework_tab4:
            st.markdown("### Custom Organizational Rules")
            st.markdown("**Cost Optimization:**")
            st.markdown("- Unused security groups identification")
            st.markdown("- Orphaned resources detection")
            st.markdown("- Resource right-sizing recommendations")
            
            st.markdown("**Operational Excellence:**")
            st.markdown("- Resource tagging compliance")
            st.markdown("- Backup policy adherence")
            st.markdown("- Change management controls")
            
            st.markdown("**Advanced Security:**")
            st.markdown("- Privileged access reviews")
            st.markdown("- Certificate expiration monitoring")
            st.markdown("- Vulnerability assessment compliance")
        
        # Scoring methodology
        st.subheader("🎯 Compliance Scoring Methodology")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Violation Impact:**")
            st.markdown("- Critical: -10 points (max -50)")
            st.markdown("- High: -5 points (max -30)")
            st.markdown("- Medium: -3 points (max -15)")
            st.markdown("- Low: -1 point (max -5)")
        
        with col2:
            st.markdown("**Score Categories:**")
            st.markdown("- 90-100: Excellent security posture")
            st.markdown("- 80-89: Good security posture")
            st.markdown("- 70-79: Adequate security posture")
            st.markdown("- 60-69: Poor security posture")
            st.markdown("- Below 60: Critical security issues")
            
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

def show_enhanced_checks_tab(security_monitors, dashboard_components):
    st.header("🔍 Enhanced Security Checks")
    st.markdown("Comprehensive security assessments based on industry best practices")
    
    try:
        # Initialize enhanced security checks
        enhanced_checks = EnhancedSecurityChecks(st.session_state.aws_client)
        
        # Check selection
        st.subheader("Available Security Assessments")
        
        col1, col2 = st.columns(2)
        
        with col1:
            run_database_checks = st.checkbox("Database Security Assessment", value=True)
            run_container_checks = st.checkbox("Container & Serverless Security", value=True)
        
        with col2:
            run_advanced_iam = st.checkbox("Advanced IAM Analysis", value=True)
            run_network_deep_dive = st.checkbox("Network Security Deep Dive", value=True)
        
        if st.button("Run Enhanced Security Checks", type="primary"):
            with st.spinner("Running comprehensive security assessments..."):
                all_findings = []
                
                if run_database_checks:
                    st.info("Running database security checks...")
                    db_findings = enhanced_checks.run_database_security_checks()
                    all_findings.extend(db_findings)
                
                if run_container_checks:
                    st.info("Running container and serverless security checks...")
                    container_findings = enhanced_checks.run_container_security_checks()
                    all_findings.extend(container_findings)
                
                if run_advanced_iam:
                    st.info("Running advanced IAM analysis...")
                    iam_findings = enhanced_checks.run_advanced_iam_checks()
                    all_findings.extend(iam_findings)
                
                if run_network_deep_dive:
                    st.info("Running network security deep dive...")
                    network_findings = enhanced_checks.run_network_security_deep_dive()
                    all_findings.extend(network_findings)
                
                # Store findings in session state for export
                st.session_state.enhanced_findings = all_findings
                
                # Analyze findings for unknown or unclear issues
                from compliance_analyzer import ComplianceAnalyzer
                compliance_analyzer = ComplianceAnalyzer(security_monitors.ai_engine)
                
                unknown_enhanced_issues = []
                unclear_enhanced_issues = []
                
                for finding in all_findings:
                    severity = finding.get('severity', '').upper()
                    status = finding.get('status', '').upper()
                    
                    # Identify unknown or unclear findings
                    if 'UNKNOWN' in status or severity == 'UNKNOWN' or not finding.get('description'):
                        unknown_enhanced_issues.append({
                            'rule_name': finding.get('title', 'Unknown Check'),
                            'status': status,
                            'resource_type': finding.get('resource_type', 'Unknown'),
                            'description': finding.get('description', 'No description available'),
                            'check_id': finding.get('check_id', 'Unknown'),
                            'severity': severity
                        })
                    elif 'PARTIAL' in status or severity == 'INFO' or 'INSUFFICIENT' in status:
                        unclear_enhanced_issues.append({
                            'rule_name': finding.get('title', 'Unknown Check'),
                            'status': status,
                            'resource_type': finding.get('resource_type', 'Unknown'),
                            'description': finding.get('description', 'No description available'),
                            'check_id': finding.get('check_id', 'Unknown'),
                            'severity': severity
                        })
                
                # Show AI-powered message box for unknown enhanced findings
                if unknown_enhanced_issues or unclear_enhanced_issues:
                    st.warning(f"Found {len(unknown_enhanced_issues)} unknown and {len(unclear_enhanced_issues)} unclear security findings requiring analysis")
                    
                    # Generate solutions for enhanced findings
                    overview_data = security_monitors.get_security_overview()
                    with st.spinner("Generating AI-powered solutions for unclear findings..."):
                        enhanced_solutions = compliance_analyzer.generate_compliance_solutions(
                            unknown_enhanced_issues,
                            unclear_enhanced_issues,
                            overview_data
                        )
                        
                        if enhanced_solutions:
                            st.subheader("AI-Powered Enhanced Security Analysis")
                            compliance_analyzer.display_compliance_message_box(enhanced_solutions)
                
                # Display results
                st.subheader("Security Assessment Results")
                
                if all_findings:
                    # Summary metrics
                    col1, col2, col3, col4 = st.columns(4)
                    
                    critical_count = len([f for f in all_findings if f.get('severity') == 'CRITICAL'])
                    high_count = len([f for f in all_findings if f.get('severity') == 'HIGH'])
                    medium_count = len([f for f in all_findings if f.get('severity') == 'MEDIUM'])
                    low_count = len([f for f in all_findings if f.get('severity') == 'LOW'])
                    
                    with col1:
                        st.metric("Critical Issues", critical_count)
                    with col2:
                        st.metric("High Severity", high_count)
                    with col3:
                        st.metric("Medium Severity", medium_count)
                    with col4:
                        st.metric("Low Severity", low_count)
                    
                    # Severity filter
                    severity_filter = st.selectbox(
                        "Filter by severity:",
                        ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
                    )
                    
                    # Filter findings
                    filtered_findings = all_findings
                    if severity_filter != "All":
                        filtered_findings = [f for f in all_findings if f.get('severity') == severity_filter]
                    
                    # Display findings
                    for finding in filtered_findings:
                        severity_color = {
                            'CRITICAL': '🔴',
                            'HIGH': '🟠',
                            'MEDIUM': '🟡',
                            'LOW': '🟢'
                        }.get(finding.get('severity', 'LOW'), '⚪')
                        
                        with st.expander(f"{severity_color} {finding.get('title', 'Security Finding')}", expanded=False):
                            col1, col2 = st.columns([2, 1])
                            
                            with col1:
                                st.markdown(f"**Check ID:** {finding.get('check_id', 'N/A')}")
                                st.markdown(f"**Description:** {finding.get('description', 'N/A')}")
                                st.markdown(f"**Remediation:** {finding.get('remediation', 'N/A')}")
                            
                            with col2:
                                st.markdown(f"**Severity:** {finding.get('severity', 'N/A')}")
                                st.markdown(f"**Resource:** {finding.get('resource', 'N/A')}")
                                st.markdown(f"**Resource Type:** {finding.get('resource_type', 'N/A')}")
                                st.markdown(f"**Status:** {finding.get('status', 'N/A')}")
                else:
                    st.success("No security issues found in the selected assessments!")
                
                # PDF Export option after running checks
                if all_findings:
                    st.subheader("📄 Export Enhanced Findings")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button("Generate PDF Report with Findings", type="primary", key="enhanced_pdf_export"):
                            try:
                                with st.spinner("Generating PDF report with enhanced findings..."):
                                    export_manager = ExportManager()
                                    overview_data = security_monitors.get_security_overview()
                                    compliance_data = security_monitors.get_compliance_data()
                                    
                                    pdf_data = export_manager.export_compliance_report_to_pdf(
                                        overview_data,
                                        compliance_data,
                                        overview_data.get('recommendations', []),
                                        all_findings
                                    )
                                    
                                    filename = export_manager.get_pdf_filename("enhanced_security_assessment")
                                    
                                    st.download_button(
                                        label="Download Enhanced Security Report",
                                        data=pdf_data,
                                        file_name=filename,
                                        mime="application/pdf",
                                        key="download_enhanced_pdf"
                                    )
                                    st.success("Enhanced security report generated successfully!")
                            except Exception as e:
                                st.error(f"Error generating enhanced PDF report: {str(e)}")
                    
                    with col2:
                        # JSON export for enhanced findings
                        if st.button("Export Findings as JSON", key="enhanced_json_export"):
                            export_manager = ExportManager()
                            json_data = export_manager.export_findings_to_json(all_findings)
                            filename = export_manager.get_export_filename('json', 'enhanced_findings')
                            
                            st.download_button(
                                label="Download JSON Findings",
                                data=json_data,
                                file_name=filename,
                                mime="application/json",
                                key="download_enhanced_json"
                            )
                    
    except Exception as e:
        st.error(f"Error running enhanced security checks: {str(e)}")

def show_ai_recommendations_tab(security_monitors, dashboard_components):
    st.header("🤖 AI-Powered Security Recommendations")
    
    # Test Bedrock connectivity first
    if hasattr(security_monitors, 'ai_engine'):
        connectivity_test = security_monitors.ai_engine.test_bedrock_connectivity()
        
        if connectivity_test[0]:
            st.success("✅ AWS Bedrock AI engine is connected and ready")
        else:
            st.error(f"❌ Bedrock connectivity issue: {connectivity_test[1]}")
            st.info("💡 Ensure your AWS credentials have access to Bedrock service and the Claude model is available in your region")
            st.info("📍 Note: Bedrock may not be available in all regions. Try us-east-1 or us-west-2.")
    else:
        st.error("❌ AI engine not initialized")
    
    # Add refresh button
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🔄 Generate Fresh AI Recommendations", type="primary"):
            st.rerun()
    
    try:
        # Get comprehensive data for AI analysis
        overview_data = security_monitors.get_security_overview()
        compliance_data = security_monitors.get_compliance_data()
        
        # Try to get enhanced findings if available
        enhanced_findings = []
        try:
            from enhanced_security_checks import EnhancedSecurityChecks
            enhanced_checks = EnhancedSecurityChecks(security_monitors.aws_client)
            enhanced_findings = enhanced_checks.run_all_enhanced_checks()
        except Exception as e:
            st.info(f"Enhanced findings not available: {str(e)}")
        
        # Generate AI recommendations
        with st.spinner("🧠 AI is analyzing your AWS security configuration..."):
            try:
                ai_result = security_monitors.ai_engine.generate_intelligent_recommendations(
                    overview_data, compliance_data, enhanced_findings
                )
                st.info(f"AI analysis completed. Success: {ai_result.get('generation_success', False)}")
            except Exception as ai_error:
                st.error(f"AI recommendation generation failed: {str(ai_error)}")
                ai_result = {'generation_success': False, 'recommendations': [], 'ai_summary': {}}
        
        if ai_result.get('generation_success', False):
            st.success("✨ AI analysis completed successfully!")
            
            # Display AI summary
            ai_summary = ai_result.get('ai_summary', {})
            if ai_summary:
                st.subheader("📊 Executive Summary")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.info(f"**Analysis Time:** {ai_summary.get('analysis_timestamp', 'Unknown')[:19]}")
                with col2:
                    st.info(f"**Source:** AWS Bedrock AI")
                with col3:
                    st.info(f"**Recommendations:** {len(ai_result.get('recommendations', []))}")
                
                if ai_summary.get('executive_summary'):
                    st.markdown(f"**Executive Summary:** {ai_summary['executive_summary']}")
                
                if ai_summary.get('risk_assessment'):
                    st.markdown(f"**Risk Assessment:** {ai_summary['risk_assessment']}")
                
                if ai_summary.get('compliance_gaps'):
                    st.markdown(f"**Key Compliance Gaps:** {ai_summary['compliance_gaps']}")
            
            # Display recommendations
            recommendations = ai_result.get('recommendations', [])
            if recommendations:
                st.subheader("🎯 Prioritized Security Recommendations")
                
                # Filter controls
                col1, col2, col3 = st.columns(3)
                with col1:
                    priority_filter = st.selectbox(
                        "Filter by Priority:",
                        ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
                    )
                with col2:
                    category_filter = st.selectbox(
                        "Filter by Category:",
                        ["All"] + list(set([r.get('category', 'Unknown') for r in recommendations]))
                    )
                with col3:
                    effort_filter = st.selectbox(
                        "Filter by Effort:",
                        ["All", "Low", "Medium", "High"]
                    )
                
                # Apply filters
                filtered_recommendations = recommendations
                if priority_filter != "All":
                    filtered_recommendations = [r for r in filtered_recommendations if r.get('priority') == priority_filter]
                if category_filter != "All":
                    filtered_recommendations = [r for r in filtered_recommendations if r.get('category') == category_filter]
                if effort_filter != "All":
                    filtered_recommendations = [r for r in filtered_recommendations if r.get('effort') == effort_filter]
                
                # Display filtered recommendations
                for i, rec in enumerate(filtered_recommendations, 1):
                    priority = rec.get('priority', 'MEDIUM')
                    
                    # Priority color coding
                    if priority == 'CRITICAL':
                        priority_color = "🔴"
                        container_type = "error"
                    elif priority == 'HIGH':
                        priority_color = "🟠"
                        container_type = "warning"
                    elif priority == 'MEDIUM':
                        priority_color = "🟡"
                        container_type = "info"
                    else:
                        priority_color = "🟢"
                        container_type = "success"
                    
                    with st.container():
                        st.markdown(f"### {priority_color} {rec.get('title', 'Security Recommendation')}")
                        
                        # Recommendation details in columns
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Priority", priority)
                        with col2:
                            st.metric("Impact", rec.get('impact', 'Unknown'))
                        with col3:
                            st.metric("Effort", rec.get('effort', 'Unknown'))
                        with col4:
                            st.metric("Timeline", rec.get('implementation_timeline', 'Unknown'))
                        
                        # Description and AI insight
                        st.markdown(f"**Description:** {rec.get('description', 'No description available')}")
                        
                        if rec.get('ai_insight'):
                            st.markdown(f"**🧠 AI Insight:** {rec['ai_insight']}")
                        
                        # Business impact
                        if rec.get('business_impact'):
                            st.markdown(f"**💼 Business Impact:** {rec['business_impact']}")
                        
                        # Implementation steps
                        if rec.get('steps'):
                            with st.expander("📋 Implementation Steps"):
                                for step_idx, step in enumerate(rec['steps'], 1):
                                    st.markdown(f"{step_idx}. {step}")
                        
                        # Additional details in expander
                        with st.expander("📖 Additional Details"):
                            if rec.get('compliance_frameworks'):
                                st.markdown(f"**Compliance Frameworks:** {', '.join(rec['compliance_frameworks'])}")
                            
                            if rec.get('risk_mitigation'):
                                st.markdown(f"**Risk Mitigation:** {rec['risk_mitigation']}")
                            
                            st.markdown(f"**Category:** {rec.get('category', 'Unknown')}")
                            st.markdown(f"**AI Generated:** {'Yes' if rec.get('ai_generated', False) else 'No'}")
                        
                        st.divider()
                
                if not filtered_recommendations:
                    st.info("No recommendations match the selected filters.")
            
            else:
                st.warning("No recommendations generated by AI analysis.")
        
        else:
            st.error("❌ AI recommendation generation failed. Using fallback recommendations.")
            
            # Show fallback recommendations
            fallback_recommendations = ai_result.get('recommendations', [])
            if fallback_recommendations:
                st.subheader("📋 Standard Security Recommendations")
                for rec in fallback_recommendations:
                    with st.expander(f"⚠️ {rec.get('title', 'Security Recommendation')}"):
                        st.markdown(f"**Priority:** {rec.get('priority', 'Unknown')}")
                        st.markdown(f"**Description:** {rec.get('description', 'No description available')}")
                        st.markdown(f"**Category:** {rec.get('category', 'Unknown')}")
    
    except Exception as e:
        st.error(f"❌ Error generating AI recommendations: {str(e)}")
        st.info("💡 Please ensure AWS Bedrock is accessible in your region and try again.")

def show_export_reports_tab(security_monitors, dashboard_components):
    st.header("📤 Export Security Reports")
    st.markdown("Export comprehensive security assessments in multiple formats")
    
    try:
        export_manager = ExportManager()
        
        # Get current data
        overview_data = security_monitors.get_security_overview()
        compliance_data = security_monitors.get_compliance_data()
        
        st.subheader("Available Export Formats")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📊 Standard Reports")
            
            # JSON Export
            if st.button("Export Overview as JSON", key="json_export"):
                json_data = export_manager.export_findings_to_json(overview_data)
                filename = export_manager.get_export_filename('json', 'security_overview')
                
                st.download_button(
                    label="Download JSON Report",
                    data=json_data,
                    file_name=filename,
                    mime="application/json"
                )
            
            # CSV Export
            if st.button("Export Compliance as CSV", key="csv_export"):
                if compliance_data.get('compliance_rules'):
                    csv_data = export_manager.export_compliance_to_csv(compliance_data['compliance_rules'])
                    filename = export_manager.get_export_filename('csv', 'compliance_rules')
                    
                    st.download_button(
                        label="Download CSV Report",
                        data=csv_data,
                        file_name=filename,
                        mime="text/csv"
                    )
                else:
                    st.warning("No compliance data available for export")
        
        with col2:
            st.markdown("### 📋 Comprehensive Reports")
            
            # PDF Compliance Report
            if st.button("📄 Generate Compliance Report (PDF)", type="primary", key="pdf_compliance_export"):
                try:
                    with st.spinner("Generating comprehensive PDF compliance report..."):
                        enhanced_findings = getattr(st.session_state, 'enhanced_findings', [])
                        
                        pdf_data = export_manager.export_compliance_report_to_pdf(
                            overview_data,
                            compliance_data,
                            overview_data.get('recommendations', []),
                            enhanced_findings
                        )
                        
                        filename = export_manager.get_pdf_filename()
                        
                        st.download_button(
                            label="📥 Download PDF Compliance Report",
                            data=pdf_data,
                            file_name=filename,
                            mime="application/pdf",
                            key="download_pdf_compliance"
                        )
                        st.success("PDF compliance report generated successfully!")
                except Exception as e:
                    st.error(f"Error generating PDF report: {str(e)}")
            
            # HTML Export
            if st.button("Generate Executive Report (HTML)", key="html_export"):
                recommendations = overview_data.get('recommendations', [])
                html_data = export_manager.export_security_overview_to_html(
                    overview_data, 
                    compliance_data.get('compliance_rules'),
                    recommendations
                )
                filename = export_manager.get_export_filename('html', 'executive_report')
                
                st.download_button(
                    label="Download Executive Report",
                    data=html_data,
                    file_name=filename,
                    mime="text/html"
                )
            
            # Security Hub Format
            if st.button("Export for AWS Security Hub", key="asff_export"):
                # Get enhanced findings if available
                enhanced_findings = getattr(st.session_state, 'enhanced_findings', [])
                if enhanced_findings:
                    account_id = st.session_state.aws_client.get_account_id() or "123456789012"
                    region = st.session_state.aws_client.region_name
                    
                    asff_data = export_manager.export_aws_security_hub_format(
                        enhanced_findings, account_id, region
                    )
                    filename = export_manager.get_export_filename('asff', 'security_hub_findings')
                    
                    st.download_button(
                        label="Download ASFF Format",
                        data=asff_data,
                        file_name=filename,
                        mime="application/json"
                    )
                else:
                    st.warning("No enhanced findings available. Run Enhanced Checks first.")
        
        # Export Statistics
        st.subheader("📈 Export Statistics")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Compliance Rules", len(compliance_data.get('compliance_rules', [])))
        with col2:
            enhanced_findings_count = len(getattr(st.session_state, 'enhanced_findings', []))
            st.metric("Enhanced Findings", enhanced_findings_count)
        with col3:
            recommendations_count = len(overview_data.get('recommendations', []))
            st.metric("Security Recommendations", recommendations_count)
            
    except Exception as e:
        st.error(f"Error in export functionality: {str(e)}")

if __name__ == "__main__":
    main()
