"""
PDF Compliance Report Generator for AWS Security Dashboard
"""
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white, red, green, orange, gray
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from datetime import datetime
import io
import base64

class PDFComplianceReportGenerator:
    """Generate comprehensive PDF compliance reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
    
    def setup_custom_styles(self):
        """Setup custom paragraph styles for the report"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=HexColor('#2c3e50')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubTitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=20,
            textColor=HexColor('#34495e')
        ))
        
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=15,
            alignment=TA_JUSTIFY,
            leftIndent=20,
            rightIndent=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='RecommendationText',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            leftIndent=15
        ))
    
    def generate_compliance_report(self, overview_data, compliance_data, recommendations, enhanced_findings=None):
        """Generate comprehensive PDF compliance report"""
        
        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Build story elements
        story = []
        
        # Cover page
        story.extend(self._create_cover_page(overview_data))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(overview_data, compliance_data))
        story.append(PageBreak())
        
        # Security metrics overview
        story.extend(self._create_security_metrics(overview_data))
        story.append(Spacer(1, 20))
        
        # Compliance status section
        story.extend(self._create_compliance_section(compliance_data))
        story.append(PageBreak())
        
        # Security recommendations
        story.extend(self._create_recommendations_section(recommendations))
        story.append(PageBreak())
        
        # Enhanced findings section
        if enhanced_findings:
            story.extend(self._create_enhanced_findings_section(enhanced_findings))
            story.append(PageBreak())
        
        # Compliance frameworks reference
        story.extend(self._create_frameworks_reference())
        story.append(PageBreak())
        
        # Appendix
        story.extend(self._create_appendix(overview_data))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def _create_cover_page(self, overview_data):
        """Create report cover page"""
        elements = []
        
        # Title
        title = Paragraph("AWS Security Compliance Report", self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 50))
        
        # Subtitle
        subtitle = Paragraph("Comprehensive Security Assessment and Compliance Analysis", self.styles['SubTitle'])
        elements.append(subtitle)
        elements.append(Spacer(1, 100))
        
        # Report metadata table
        report_date = datetime.now().strftime("%B %d, %Y at %I:%M %p")
        security_score = self._calculate_security_score(overview_data)
        
        metadata = [
            ['Report Generated:', report_date],
            ['Assessment Date:', datetime.now().strftime("%Y-%m-%d")],
            ['Security Score:', f"{security_score}/100"],
            ['Critical Alerts:', str(overview_data.get('critical_alerts', 0))],
            ['Report Type:', 'Compliance Assessment'],
            ['Report Version:', '1.0']
        ]
        
        metadata_table = Table(metadata, colWidths=[2*inch, 3*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(metadata_table)
        elements.append(Spacer(1, 100))
        
        # Disclaimer
        disclaimer = Paragraph(
            "<b>Confidential Report</b><br/>"
            "This report contains sensitive security information and should be handled according to your organization's data classification policies.",
            self.styles['Normal']
        )
        elements.append(disclaimer)
        
        return elements
    
    def _create_executive_summary(self, overview_data, compliance_data):
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['Heading1']))
        elements.append(Spacer(1, 20))
        
        # Calculate key metrics
        security_score = self._calculate_security_score(overview_data)
        compliance_score = compliance_data.get('overall_compliance_score', 0)
        critical_alerts = overview_data.get('critical_alerts', 0)
        
        # Risk assessment
        risk_level = self._determine_risk_level(security_score, critical_alerts)
        
        summary_text = f"""
        This comprehensive security assessment evaluates your AWS infrastructure against industry-standard 
        compliance frameworks and security best practices. The assessment was conducted on {datetime.now().strftime("%B %d, %Y")} 
        and covers critical areas including Identity and Access Management (IAM), network security, 
        data protection, and regulatory compliance.
        
        <b>Key Findings:</b>
        • Overall Security Score: {security_score}/100
        • Compliance Score: {compliance_score}%
        • Critical Security Alerts: {critical_alerts}
        • Risk Level: {risk_level}
        
        <b>Assessment Scope:</b>
        • IAM Users and Roles: {overview_data.get('iam_users', 0)} users analyzed
        • Security Groups: {overview_data.get('security_groups', 0)} groups reviewed
        • S3 Buckets: {overview_data.get('s3_buckets', 0)} buckets assessed
        • Compliance Rules: {len(compliance_data.get('compliance_rules', []))} rules evaluated
        
        This report provides actionable recommendations to enhance your security posture and achieve 
        compliance with regulatory requirements.
        """
        
        summary_para = Paragraph(summary_text, self.styles['ExecutiveSummary'])
        elements.append(summary_para)
        
        return elements
    
    def _create_security_metrics(self, overview_data):
        """Create security metrics visualization section"""
        elements = []
        
        elements.append(Paragraph("Security Metrics Overview", self.styles['Heading1']))
        elements.append(Spacer(1, 20))
        
        # Security metrics table
        security_score = self._calculate_security_score(overview_data)
        metrics_data = [
            ['Metric', 'Value', 'Status'],
            ['Overall Security Score', f"{security_score}/100", self._get_score_status(security_score)],
            ['Critical Alerts', str(overview_data.get('critical_alerts', 0)), 'Needs Attention' if overview_data.get('critical_alerts', 0) > 0 else 'Good'],
            ['IAM Users', str(overview_data.get('iam_users', 0)), 'Monitored'],
            ['Security Groups', str(overview_data.get('security_groups', 0)), 'Reviewed'],
            ['S3 Buckets', str(overview_data.get('s3_buckets', 0)), 'Assessed']
        ]
        
        metrics_table = Table(metrics_data, colWidths=[2.5*inch, 1.5*inch, 2*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
        ]))
        
        elements.append(metrics_table)
        
        return elements
    
    def _create_compliance_section(self, compliance_data):
        """Create compliance status section"""
        elements = []
        
        elements.append(Paragraph("Compliance Status Analysis", self.styles['Heading1']))
        elements.append(Spacer(1, 20))
        
        # Compliance summary
        compliance_rules = compliance_data.get('compliance_rules', [])
        if compliance_rules:
            compliant = len([r for r in compliance_rules if 'COMPLIANT' in r.get('Status', '') and 'NON-COMPLIANT' not in r.get('Status', '')])
            partial = len([r for r in compliance_rules if 'PARTIAL' in r.get('Status', '')])
            non_compliant = len([r for r in compliance_rules if 'NON-COMPLIANT' in r.get('Status', '')])
            
            summary_data = [
                ['Compliance Category', 'Count', 'Percentage'],
                ['Fully Compliant', str(compliant), f"{round((compliant/len(compliance_rules)*100), 1)}%"],
                ['Partially Compliant', str(partial), f"{round((partial/len(compliance_rules)*100), 1)}%"],
                ['Non-Compliant', str(non_compliant), f"{round((non_compliant/len(compliance_rules)*100), 1)}%"],
                ['Total Rules Evaluated', str(len(compliance_rules)), '100%']
            ]
            
            summary_table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
            ]))
            
            elements.append(summary_table)
            elements.append(Spacer(1, 30))
            
            # Top compliance issues
            elements.append(Paragraph("Critical Compliance Issues", self.styles['SubTitle']))
            
            non_compliant_rules = [r for r in compliance_rules if 'NON-COMPLIANT' in r.get('Status', '')][:5]
            
            if non_compliant_rules:
                issues_data = [['Rule Name', 'Non-Compliant Resources', 'Compliance %']]
                
                for rule in non_compliant_rules:
                    issues_data.append([
                        rule.get('Rule Name', 'N/A')[:40] + '...' if len(rule.get('Rule Name', '')) > 40 else rule.get('Rule Name', 'N/A'),
                        str(rule.get('Non-compliant Resources', 0)),
                        f"{rule.get('Compliance %', 0)}%"
                    ])
                
                issues_table = Table(issues_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
                issues_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e74c3c')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, black),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('BACKGROUND', (0, 1), (-1, -1), HexColor('#fadbd8')),
                ]))
                
                elements.append(issues_table)
            else:
                elements.append(Paragraph("No critical compliance issues identified.", self.styles['Normal']))
        
        return elements
    
    def _create_recommendations_section(self, recommendations):
        """Create security recommendations section"""
        elements = []
        
        elements.append(Paragraph("Security Recommendations", self.styles['Heading1']))
        elements.append(Spacer(1, 20))
        
        if not recommendations:
            elements.append(Paragraph("No specific recommendations available at this time.", self.styles['Normal']))
            return elements
        
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_recommendations = sorted(recommendations, key=lambda x: priority_order.get(x.get('priority', 'LOW'), 4))
        
        for i, rec in enumerate(sorted_recommendations[:10]):  # Limit to top 10
            # Recommendation header
            priority_symbol = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(rec.get('priority', 'LOW'), '⚪')
            
            header_text = f"<b>{i+1}. {rec.get('title', 'Recommendation')} - {rec.get('impact', 'Unknown impact')}</b>"
            elements.append(Paragraph(header_text, self.styles['SubTitle']))
            
            # Recommendation details
            details = f"""
            <b>Priority:</b> {rec.get('priority', 'N/A')}<br/>
            <b>Category:</b> {rec.get('category', 'N/A')}<br/>
            <b>Implementation Effort:</b> {rec.get('effort', 'N/A')}<br/>
            <b>Description:</b> {rec.get('description', 'N/A')}
            """
            elements.append(Paragraph(details, self.styles['RecommendationText']))
            
            # Implementation steps
            if rec.get('steps'):
                elements.append(Paragraph("<b>Implementation Steps:</b>", self.styles['RecommendationText']))
                for step in rec.get('steps', []):
                    elements.append(Paragraph(f"• {step}", self.styles['RecommendationText']))
            
            elements.append(Spacer(1, 15))
        
        return elements
    
    def _create_enhanced_findings_section(self, enhanced_findings):
        """Create enhanced security findings section"""
        elements = []
        
        elements.append(Paragraph("Enhanced Security Findings", self.styles['Heading1']))
        elements.append(Spacer(1, 20))
        
        if not enhanced_findings:
            elements.append(Paragraph("No enhanced security findings available.", self.styles['Normal']))
            return elements
        
        # Findings summary
        critical_count = len([f for f in enhanced_findings if f.get('severity') == 'CRITICAL'])
        high_count = len([f for f in enhanced_findings if f.get('severity') == 'HIGH'])
        medium_count = len([f for f in enhanced_findings if f.get('severity') == 'MEDIUM'])
        low_count = len([f for f in enhanced_findings if f.get('severity') == 'LOW'])
        
        findings_summary = [
            ['Severity Level', 'Count', 'Action Required'],
            ['Critical', str(critical_count), 'Immediate (0-24 hours)'],
            ['High', str(high_count), 'Within 1 week'],
            ['Medium', str(medium_count), 'Within 1 month'],
            ['Low', str(low_count), 'Next quarterly review']
        ]
        
        findings_table = Table(findings_summary, colWidths=[2*inch, 1*inch, 2.5*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#8e44ad')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f4ecf7')),
        ]))
        
        elements.append(findings_table)
        elements.append(Spacer(1, 30))
        
        # Critical and high findings details
        critical_high_findings = [f for f in enhanced_findings if f.get('severity') in ['CRITICAL', 'HIGH']][:10]
        
        if critical_high_findings:
            elements.append(Paragraph("Critical and High Severity Findings", self.styles['SubTitle']))
            
            for finding in critical_high_findings:
                finding_text = f"""
                <b>{finding.get('title', 'Security Finding')}</b> ({finding.get('severity', 'Unknown')})<br/>
                <b>Check ID:</b> {finding.get('check_id', 'N/A')}<br/>
                <b>Resource:</b> {finding.get('resource', 'N/A')}<br/>
                <b>Description:</b> {finding.get('description', 'N/A')}<br/>
                <b>Remediation:</b> {finding.get('remediation', 'N/A')}
                """
                elements.append(Paragraph(finding_text, self.styles['RecommendationText']))
                elements.append(Spacer(1, 10))
        
        return elements
    
    def _create_frameworks_reference(self):
        """Create compliance frameworks reference section"""
        elements = []
        
        elements.append(Paragraph("Compliance Frameworks Reference", self.styles['Heading1']))
        elements.append(Spacer(1, 20))
        
        frameworks_text = """
        This assessment evaluates your AWS infrastructure against the following industry-standard 
        compliance frameworks and security benchmarks:
        
        <b>CIS AWS Foundations Benchmark v1.2.0</b>
        • Identity and Access Management controls
        • Logging and monitoring requirements
        • Network security configurations
        • Storage security best practices
        
        <b>AWS Foundational Security Standard</b>
        • AWS-native security controls
        • Service-specific security configurations
        • Cross-service security dependencies
        
        <b>Industry Compliance Standards</b>
        • PCI DSS for payment card data protection
        • HIPAA for healthcare data security
        • SOC 2 for service organization controls
        • GDPR for data privacy requirements
        
        Each framework provides specific controls and requirements that help organizations
        maintain security and compliance in cloud environments.
        """
        
        elements.append(Paragraph(frameworks_text, self.styles['Normal']))
        
        return elements
    
    def _create_appendix(self, overview_data):
        """Create report appendix"""
        elements = []
        
        elements.append(Paragraph("Appendix", self.styles['Heading1']))
        elements.append(Spacer(1, 20))
        
        # Methodology
        elements.append(Paragraph("Assessment Methodology", self.styles['SubTitle']))
        methodology_text = """
        This security assessment was conducted using automated tools and best practice guidelines.
        The assessment methodology includes:
        
        • Automated security configuration scanning
        • Compliance rule evaluation against industry standards
        • Risk-based prioritization of findings
        • Integration with AWS native security services
        • Comprehensive reporting and remediation guidance
        """
        elements.append(Paragraph(methodology_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Contact information
        elements.append(Paragraph("Support and Contact Information", self.styles['SubTitle']))
        contact_text = """
        For questions regarding this security assessment or to discuss remediation strategies,
        please contact your security team or AWS solutions architect.
        
        Report generated by: AWS Security Dashboard
        Report version: 1.0
        """
        elements.append(Paragraph(contact_text, self.styles['Normal']))
        
        return elements
    
    def _calculate_security_score(self, overview_data):
        """Calculate security score for display"""
        try:
            score = 100
            critical_alerts = overview_data.get('critical_alerts', 0)
            score -= min(critical_alerts * 10, 50)
            return max(score, 0)
        except:
            return 85
    
    def _determine_risk_level(self, security_score, critical_alerts):
        """Determine overall risk level"""
        if critical_alerts > 5 or security_score < 60:
            return "High Risk"
        elif critical_alerts > 2 or security_score < 80:
            return "Medium Risk"
        else:
            return "Low Risk"
    
    def _get_score_status(self, score):
        """Get status description for security score"""
        if score >= 90:
            return "Excellent"
        elif score >= 80:
            return "Good"
        elif score >= 70:
            return "Fair"
        else:
            return "Needs Improvement"
    
    def generate_filename(self, prefix="aws_compliance_report"):
        """Generate standardized PDF filename"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{prefix}_{timestamp}.pdf"