import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd

class DashboardComponents:
    """Dashboard visualization components using Plotly"""
    
    def __init__(self):
        self.color_palette = {
            'primary': '#1f77b4',
            'secondary': '#ff7f0e',
            'success': '#2ca02c',
            'danger': '#d62728',
            'warning': '#ff7f0e',
            'info': '#17a2b8'
        }
    
    def create_security_score_chart(self, trends_data):
        """Create security score trends chart"""
        try:
            if not trends_data or 'dates' not in trends_data or 'scores' not in trends_data:
                st.info("No security trends data available")
                return
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=trends_data['dates'],
                y=trends_data['scores'],
                mode='lines+markers',
                name='Security Score',
                line=dict(color=self.color_palette['primary'], width=3),
                marker=dict(size=8)
            ))
            
            fig.update_layout(
                title="Security Score Trends",
                xaxis_title="Date",
                yaxis_title="Security Score",
                yaxis=dict(range=[0, 100]),
                height=400,
                showlegend=False
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating security score chart: {str(e)}")
    
    def create_alert_distribution_chart(self, alert_data):
        """Create alert distribution pie chart"""
        try:
            if not alert_data or 'labels' not in alert_data or 'values' not in alert_data:
                return None
            
            colors = ['#d62728', '#ff7f0e', '#ffbb78', '#2ca02c']
            
            fig = go.Figure(data=[go.Pie(
                labels=alert_data['labels'],
                values=alert_data['values'],
                hole=0.4,
                marker_colors=colors
            )])
            
            fig.update_layout(
                title="Alert Distribution by Severity",
                height=400,
                showlegend=True
            )
            
            return fig
            
        except Exception as e:
            st.error(f"Error creating alert distribution chart: {str(e)}")
            return None
    
    def create_user_activity_chart(self, activity_data):
        """Create user activity chart"""
        try:
            if not activity_data or 'dates' not in activity_data:
                return None
            
            # Handle different data structures
            y_values = activity_data.get('logins') or activity_data.get('values') or []
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=activity_data['dates'],
                y=y_values,
                mode='lines+markers',
                name='Activity',
                line=dict(color=self.color_palette['primary'])
            ))
            
            fig.update_layout(
                title="Activity Trends",
                xaxis_title="Date",
                yaxis_title="Count",
                height=400,
                showlegend=False
            )
            
            return fig
            
        except Exception as e:
            st.error(f"Error creating user activity chart: {str(e)}")
            return None
    
    def create_policy_changes_chart(self, policy_data):
        """Create policy changes chart"""
        try:
            if not policy_data or 'dates' not in policy_data or 'changes' not in policy_data:
                st.info("No policy changes data available")
                return
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=policy_data['dates'],
                y=policy_data['changes'],
                mode='lines+markers',
                name='Policy Changes',
                line=dict(color=self.color_palette['warning'], width=2),
                marker=dict(size=6)
            ))
            
            fig.update_layout(
                title="IAM Policy Changes Over Time",
                xaxis_title="Date",
                yaxis_title="Number of Changes",
                height=400,
                showlegend=False
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating policy changes chart: {str(e)}")
    
    def create_security_group_chart(self, sg_data):
        """Create security group rules chart"""
        try:
            if not sg_data or 'labels' not in sg_data or 'values' not in sg_data:
                st.info("No security group rules data available")
                return
            
            colors = [self.color_palette['danger'], self.color_palette['success']]
            
            fig = go.Figure(data=[go.Pie(
                labels=sg_data['labels'],
                values=sg_data['values'],
                marker_colors=colors,
                hole=0.3
            )])
            
            fig.update_layout(
                title="Security Group Rules Distribution",
                height=400,
                showlegend=True
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating security group chart: {str(e)}")
    
    def create_vpc_flow_chart(self, flow_data):
        """Create VPC flow logs chart"""
        try:
            if not flow_data or 'dates' not in flow_data:
                st.info("No VPC flow logs data available")
                return
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=flow_data['dates'],
                y=flow_data.get('accepted', []),
                mode='lines+markers',
                name='Accepted',
                line=dict(color=self.color_palette['success']),
                fill='tonexty'
            ))
            
            fig.add_trace(go.Scatter(
                x=flow_data['dates'],
                y=flow_data.get('rejected', []),
                mode='lines+markers',
                name='Rejected',
                line=dict(color=self.color_palette['danger'])
            ))
            
            fig.update_layout(
                title="VPC Flow Logs - Traffic Analysis",
                xaxis_title="Date",
                yaxis_title="Number of Connections",
                height=400,
                showlegend=True
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating VPC flow chart: {str(e)}")
    
    def create_encryption_status_chart(self, encryption_data):
        """Create encryption status chart"""
        try:
            if not encryption_data or 'labels' not in encryption_data or 'values' not in encryption_data:
                st.info("No encryption status data available")
                return
            
            colors = [self.color_palette['success'], self.color_palette['danger']]
            
            fig = go.Figure(data=[go.Pie(
                labels=encryption_data['labels'],
                values=encryption_data['values'],
                marker_colors=colors,
                hole=0.4
            )])
            
            fig.update_layout(
                title="S3 Bucket Encryption Status",
                height=400,
                showlegend=True
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating encryption status chart: {str(e)}")
    
    def create_s3_access_chart(self, access_data):
        """Create S3 access patterns chart"""
        try:
            if not access_data or 'dates' not in access_data:
                st.info("No S3 access patterns data available")
                return
            
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                x=access_data['dates'],
                y=access_data.get('reads', []),
                name='Reads',
                marker_color=self.color_palette['primary']
            ))
            
            fig.add_trace(go.Bar(
                x=access_data['dates'],
                y=access_data.get('writes', []),
                name='Writes',
                marker_color=self.color_palette['secondary']
            ))
            
            fig.update_layout(
                title="S3 Access Patterns",
                xaxis_title="Date",
                yaxis_title="Number of Operations",
                height=400,
                barmode='group',
                showlegend=True
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating S3 access chart: {str(e)}")
    
    def create_compliance_by_service_chart(self, compliance_data):
        """Create compliance by service chart"""
        try:
            if not compliance_data or 'services' not in compliance_data or 'compliance_scores' not in compliance_data:
                st.info("No compliance by service data available")
                return
            
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                x=compliance_data['services'],
                y=compliance_data['compliance_scores'],
                marker_color=self.color_palette['primary'],
                text=compliance_data['compliance_scores'],
                textposition='auto'
            ))
            
            fig.update_layout(
                title="Compliance Score by AWS Service",
                xaxis_title="AWS Service",
                yaxis_title="Compliance Score (%)",
                yaxis=dict(range=[0, 100]),
                height=400,
                showlegend=False
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating compliance by service chart: {str(e)}")
    
    def create_compliance_trends_chart(self, trends_data):
        """Create compliance trends chart"""
        try:
            if not trends_data or 'dates' not in trends_data or 'scores' not in trends_data:
                st.info("No compliance trends data available")
                return
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=trends_data['dates'],
                y=trends_data['scores'],
                mode='lines+markers',
                name='Compliance Score',
                line=dict(color=self.color_palette['success'], width=3),
                marker=dict(size=8),
                fill='tozeroy',
                fillcolor='rgba(44, 160, 44, 0.1)'
            ))
            
            fig.update_layout(
                title="Compliance Score Trends",
                xaxis_title="Date",
                yaxis_title="Compliance Score (%)",
                yaxis=dict(range=[0, 100]),
                height=400,
                showlegend=False
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating compliance trends chart: {str(e)}")
    
    def create_compliance_status_chart(self, compliance_rules_data):
        """Create compliance status distribution chart"""
        try:
            if not compliance_rules_data:
                st.info("No compliance rules data available")
                return
            
            # Count status types
            status_counts = {
                'Compliant': 0,
                'Partial': 0,
                'Non-Compliant': 0,
                'Unknown': 0
            }
            
            for rule in compliance_rules_data:
                status = rule.get('Status', '')
                if 'COMPLIANT' in status and 'NON-COMPLIANT' not in status:
                    status_counts['Compliant'] += 1
                elif 'PARTIAL' in status:
                    status_counts['Partial'] += 1
                elif 'NON-COMPLIANT' in status:
                    status_counts['Non-Compliant'] += 1
                else:
                    status_counts['Unknown'] += 1
            
            # Create donut chart
            labels = list(status_counts.keys())
            values = list(status_counts.values())
            colors = ['#28a745', '#ffc107', '#dc3545', '#6c757d']  # Green, Yellow, Red, Gray
            
            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                hole=0.4,
                marker_colors=colors,
                textinfo='label+percent',
                textposition='outside'
            )])
            
            fig.update_layout(
                title="Compliance Rules Status Distribution",
                height=400,
                showlegend=True,
                annotations=[dict(text='Compliance<br>Status', x=0.5, y=0.5, font_size=14, showarrow=False)]
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating compliance status chart: {str(e)}")
    
    def create_threat_types_chart(self, threat_data):
        """Create threat types chart"""
        try:
            if not threat_data or 'labels' not in threat_data or 'values' not in threat_data:
                st.info("No threat types data available")
                return
            
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                x=threat_data['values'],
                y=threat_data['labels'],
                orientation='h',
                marker_color=self.color_palette['danger'],
                text=threat_data['values'],
                textposition='auto'
            ))
            
            fig.update_layout(
                title="Security Threats by Type",
                xaxis_title="Number of Findings",
                yaxis_title="Threat Type",
                height=400,
                showlegend=False
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating threat types chart: {str(e)}")
    
    def create_findings_timeline_chart(self, timeline_data):
        """Create findings timeline chart"""
        try:
            if not timeline_data or 'dates' not in timeline_data or 'counts' not in timeline_data:
                st.info("No findings timeline data available")
                return
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=timeline_data['dates'],
                y=timeline_data['counts'],
                mode='lines+markers',
                name='Security Findings',
                line=dict(color=self.color_palette['danger'], width=2),
                marker=dict(size=6),
                fill='tozeroy',
                fillcolor='rgba(214, 39, 40, 0.1)'
            ))
            
            fig.update_layout(
                title="Security Findings Over Time",
                xaxis_title="Date",
                yaxis_title="Number of Findings",
                height=400,
                showlegend=False
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error creating findings timeline chart: {str(e)}")
    
    def create_metric_card(self, title, value, delta=None, delta_color="normal"):
        """Create a metric card component"""
        try:
            # Handle delta_color parameter properly
            metric_kwargs = {
                "label": title,
                "value": value
            }
            
            if delta is not None:
                metric_kwargs["delta"] = delta
                
            if delta_color in ["normal", "inverse", "off"]:
                metric_kwargs["delta_color"] = delta_color
            
            st.metric(**metric_kwargs)
        except Exception as e:
            st.error(f"Error creating metric card: {str(e)}")
    
    def create_alert_badge(self, severity, count):
        """Create an alert badge with severity color"""
        try:
            color = self._get_severity_color(severity)
            
            st.markdown(
                f"""
                <div style="
                    background-color: {color};
                    color: white;
                    padding: 5px 10px;
                    border-radius: 15px;
                    display: inline-block;
                    margin: 2px;
                    font-size: 12px;
                    font-weight: bold;
                ">
                    {severity}: {count}
                </div>
                """,
                unsafe_allow_html=True
            )
        except Exception as e:
            st.error(f"Error creating alert badge: {str(e)}")
    
    def create_region_distribution_chart(self, region_data):
        """Create multi-region resource distribution chart"""
        if not region_data:
            return None
            
        try:
            regions = []
            security_groups = []
            vpcs = []
            
            for region, data in region_data.items():
                if data.get('status') == 'active':
                    regions.append(region)
                    security_groups.append(data.get('security_groups', 0))
                    vpcs.append(data.get('vpcs', 0))
            
            if not regions:
                st.info("No active regions to display")
                return None
            
            fig = go.Figure()
            
            # Add security groups bars
            fig.add_trace(go.Bar(
                name='Security Groups',
                x=regions,
                y=security_groups,
                marker_color='#1f77b4'
            ))
            
            # Add VPCs bars  
            fig.add_trace(go.Bar(
                name='VPCs',
                x=regions,
                y=vpcs,
                marker_color='#ff7f0e'
            ))
            
            fig.update_layout(
                title='Resource Distribution Across Regions',
                xaxis_title='AWS Regions',
                yaxis_title='Resource Count',
                barmode='group',
                height=400,
                showlegend=True,
                font=dict(size=12)
            )
            
            st.plotly_chart(fig, use_container_width=True)
            return fig
            
        except Exception as e:
            st.error(f"Error creating region distribution chart: {str(e)}")
            return None
    
    def _get_severity_color(self, severity):
        """Get color for severity level"""
        severity_colors = {
            'CRITICAL': '#d62728',
            'HIGH': '#ff7f0e',
            'MEDIUM': '#ffbb78',
            'LOW': '#2ca02c'
        }
        return severity_colors.get(severity.upper(), '#17a2b8')
