"""
Export functionality for AWS Security Dashboard
Supports multiple output formats: JSON, CSV, HTML reports
"""
import json
import csv
import io
from datetime import datetime
import pandas as pd

class ExportManager:
    """Handles export functionality for security assessment data"""
    
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def export_findings_to_json(self, findings_data, include_metadata=True):
        """Export security findings to JSON format"""
        try:
            export_data = {
                "export_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "export_format": "JSON",
                    "dashboard_version": "1.0.0",
                    "total_findings": len(findings_data) if isinstance(findings_data, list) else 0
                } if include_metadata else {},
                "findings": findings_data
            }
            
            return json.dumps(export_data, indent=2, default=str)
            
        except Exception as e:
            return json.dumps({"error": f"Export failed: {str(e)}"}, indent=2)
    
    def export_compliance_to_csv(self, compliance_data):
        """Export compliance rules to CSV format"""
        try:
            output = io.StringIO()
            
            if not compliance_data or not isinstance(compliance_data, list):
                return "No compliance data available for export"
            
            # Define CSV headers
            headers = [
                'Rule Name', 'Status', 'Description', 'Compliant Resources', 
                'Non-compliant Resources', 'Total Resources', 'Compliance %', 
                'Source', 'Export Date'
            ]
            
            writer = csv.writer(output)
            writer.writerow(headers)
            
            for rule in compliance_data:
                row = [
                    rule.get('Rule Name', ''),
                    rule.get('Status', '').replace('✅ ', '').replace('❌ ', '').replace('⚠️ ', '').replace('❓ ', ''),
                    rule.get('Description', ''),
                    rule.get('Compliant Resources', 0),
                    rule.get('Non-compliant Resources', 0),
                    rule.get('Total Resources', 0),
                    rule.get('Compliance %', 0),
                    rule.get('Source', ''),
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ]
                writer.writerow(row)
            
            return output.getvalue()
            
        except Exception as e:
            return f"CSV export failed: {str(e)}"
    
    def export_security_overview_to_html(self, overview_data, compliance_data=None, recommendations=None):
        """Export comprehensive security overview to HTML report"""
        try:
            html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-radius: 5px; min-width: 150px; }}
        .critical {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
        .high {{ background: #fff3cd; border-left: 4px solid #ffc107; }}
        .medium {{ background: #d1ecf1; border-left: 4px solid #17a2b8; }}
        .low {{ background: #d4edda; border-left: 4px solid #28a745; }}
        .compliant {{ color: #28a745; }}
        .non-compliant {{ color: #dc3545; }}
        .partial {{ color: #ffc107; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .footer {{ text-align: center; margin-top: 40px; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 AWS Security Assessment Report</h1>
        <p>Generated on: {timestamp}</p>
        <p>Account Overview and Security Posture Analysis</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="metric">
            <h3>Security Score</h3>
            <p style="font-size: 24px; margin: 0;">{security_score}/100</p>
        </div>
        <div class="metric">
            <h3>Critical Alerts</h3>
            <p style="font-size: 24px; margin: 0; color: #dc3545;">{critical_alerts}</p>
        </div>
        <div class="metric">
            <h3>IAM Users</h3>
            <p style="font-size: 24px; margin: 0;">{iam_users}</p>
        </div>
        <div class="metric">
            <h3>Security Groups</h3>
            <p style="font-size: 24px; margin: 0;">{security_groups}</p>
        </div>
    </div>

    {compliance_section}

    {recommendations_section}

    <div class="section">
        <h2>Recent Security Events</h2>
        {events_table}
    </div>

    <div class="footer">
        <p>This report was generated by AWS Security Dashboard</p>
        <p>Report ID: {report_id}</p>
    </div>
</body>
</html>
            """
            
            # Calculate security score
            security_score = self._calculate_display_score(overview_data)
            
            # Generate compliance section
            compliance_section = self._generate_compliance_html_section(compliance_data)
            
            # Generate recommendations section
            recommendations_section = self._generate_recommendations_html_section(recommendations)
            
            # Generate events table
            events_table = self._generate_events_html_table(overview_data.get('recent_events', []))
            
            # Format the HTML
            formatted_html = html_template.format(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                security_score=security_score,
                critical_alerts=overview_data.get('critical_alerts', 0),
                iam_users=overview_data.get('iam_users', 0),
                security_groups=overview_data.get('security_groups', 0),
                compliance_section=compliance_section,
                recommendations_section=recommendations_section,
                events_table=events_table,
                report_id=f"AWS_SEC_RPT_{self.timestamp}"
            )
            
            return formatted_html
            
        except Exception as e:
            return f"<html><body><h1>HTML Export Error</h1><p>{str(e)}</p></body></html>"
    
    def _calculate_display_score(self, overview_data):
        """Calculate security score for display"""
        try:
            score = 100
            critical_alerts = overview_data.get('critical_alerts', 0)
            score -= min(critical_alerts * 10, 50)
            return max(score, 0)
        except:
            return 85
    
    def _generate_compliance_html_section(self, compliance_data):
        """Generate HTML section for compliance data"""
        if not compliance_data:
            return '<div class="section"><h2>Compliance Status</h2><p>No compliance data available</p></div>'
        
        try:
            compliant = len([r for r in compliance_data if 'COMPLIANT' in r.get('Status', '') and 'NON-COMPLIANT' not in r.get('Status', '')])
            partial = len([r for r in compliance_data if 'PARTIAL' in r.get('Status', '')])
            non_compliant = len([r for r in compliance_data if 'NON-COMPLIANT' in r.get('Status', '')])
            
            table_rows = ""
            for rule in compliance_data[:10]:  # Limit to first 10 for readability
                status_class = "compliant" if "COMPLIANT" in rule.get('Status', '') and "NON-COMPLIANT" not in rule.get('Status', '') else \
                              "partial" if "PARTIAL" in rule.get('Status', '') else \
                              "non-compliant"
                
                table_rows += f"""
                <tr>
                    <td>{rule.get('Rule Name', 'N/A')}</td>
                    <td class="{status_class}">{rule.get('Status', 'N/A').replace('✅ ', '').replace('❌ ', '').replace('⚠️ ', '').replace('❓ ', '')}</td>
                    <td>{rule.get('Compliance %', 0)}%</td>
                    <td>{rule.get('Compliant Resources', 0)}</td>
                    <td>{rule.get('Non-compliant Resources', 0)}</td>
                </tr>
                """
            
            return f"""
            <div class="section">
                <h2>Compliance Status</h2>
                <div class="metric">
                    <h3>Compliant Rules</h3>
                    <p style="font-size: 20px; margin: 0; color: #28a745;">{compliant}</p>
                </div>
                <div class="metric">
                    <h3>Partial Compliance</h3>
                    <p style="font-size: 20px; margin: 0; color: #ffc107;">{partial}</p>
                </div>
                <div class="metric">
                    <h3>Non-Compliant</h3>
                    <p style="font-size: 20px; margin: 0; color: #dc3545;">{non_compliant}</p>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Status</th>
                            <th>Compliance %</th>
                            <th>Compliant Resources</th>
                            <th>Non-compliant Resources</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows}
                    </tbody>
                </table>
            </div>
            """
        except Exception as e:
            return f'<div class="section"><h2>Compliance Status</h2><p>Error generating compliance section: {str(e)}</p></div>'
    
    def _generate_recommendations_html_section(self, recommendations):
        """Generate HTML section for security recommendations"""
        if not recommendations:
            return '<div class="section"><h2>Security Recommendations</h2><p>No recommendations available</p></div>'
        
        try:
            recommendations_html = ""
            for rec in recommendations[:5]:  # Limit to top 5 recommendations
                priority_class = rec.get('priority', 'LOW').lower()
                
                steps_html = ""
                for step in rec.get('steps', []):
                    steps_html += f"<li>{step}</li>"
                
                recommendations_html += f"""
                <div class="section {priority_class}">
                    <h3>{rec.get('title', 'N/A')} - {rec.get('impact', 'Unknown impact')}</h3>
                    <p><strong>Priority:</strong> {rec.get('priority', 'N/A')}</p>
                    <p><strong>Category:</strong> {rec.get('category', 'N/A')}</p>
                    <p><strong>Description:</strong> {rec.get('description', 'N/A')}</p>
                    <p><strong>Implementation Steps:</strong></p>
                    <ol>{steps_html}</ol>
                </div>
                """
            
            return f"""
            <div class="section">
                <h2>Security Recommendations</h2>
                {recommendations_html}
            </div>
            """
        except Exception as e:
            return f'<div class="section"><h2>Security Recommendations</h2><p>Error generating recommendations: {str(e)}</p></div>'
    
    def _generate_events_html_table(self, events):
        """Generate HTML table for recent security events"""
        if not events:
            return "<p>No recent security events found</p>"
        
        try:
            table_rows = ""
            for event in events[:10]:  # Limit to 10 most recent
                table_rows += f"""
                <tr>
                    <td>{event.get('Time', 'N/A')}</td>
                    <td>{event.get('Event', 'N/A')}</td>
                    <td>{event.get('User', 'N/A')}</td>
                    <td>{event.get('Source IP', 'N/A')}</td>
                    <td>{event.get('Service', 'N/A')}</td>
                </tr>
                """
            
            return f"""
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Event</th>
                        <th>User</th>
                        <th>Source IP</th>
                        <th>Service</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
            """
        except Exception as e:
            return f"<p>Error generating events table: {str(e)}</p>"
    
    def export_aws_security_hub_format(self, findings_data, account_id, region):
        """Export findings in AWS Security Hub ASFF format"""
        try:
            asff_findings = []
            
            for finding in findings_data:
                asff_finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"aws-security-dashboard/{finding.get('check_id', 'unknown')}/{account_id}",
                    "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
                    "GeneratorId": "aws-security-dashboard",
                    "AwsAccountId": account_id,
                    "Types": ["Effects/Data Exposure/AWS"],
                    "FirstObservedAt": datetime.now().isoformat() + "Z",
                    "LastObservedAt": datetime.now().isoformat() + "Z",
                    "CreatedAt": datetime.now().isoformat() + "Z",
                    "UpdatedAt": datetime.now().isoformat() + "Z",
                    "Severity": {
                        "Label": finding.get('severity', 'MEDIUM').upper()
                    },
                    "Title": finding.get('title', 'Security Finding'),
                    "Description": finding.get('description', 'No description available'),
                    "Resources": [{
                        "Type": finding.get('resource_type', 'Other'),
                        "Id": finding.get('resource', 'unknown'),
                        "Region": region
                    }],
                    "Compliance": {
                        "Status": "FAILED" if finding.get('status') == 'FAIL' else "PASSED"
                    },
                    "Remediation": {
                        "Recommendation": {
                            "Text": finding.get('remediation', 'No remediation guidance available')
                        }
                    }
                }
                asff_findings.append(asff_finding)
            
            return json.dumps({"Findings": asff_findings}, indent=2, default=str)
            
        except Exception as e:
            return json.dumps({"error": f"ASFF export failed: {str(e)}"}, indent=2)
    
    def get_export_filename(self, export_type, prefix="aws_security"):
        """Generate standardized export filenames"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extensions = {
            'json': 'json',
            'csv': 'csv', 
            'html': 'html',
            'asff': 'json'
        }
        ext = extensions.get(export_type.lower(), 'txt')
        return f"{prefix}_{export_type.lower()}_{timestamp}.{ext}"