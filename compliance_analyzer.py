"""
AI-Powered Compliance Analyzer for Unknown Issues
Identifies and provides solutions for compliance gaps using LLM analysis
"""
import json
import streamlit as st
from datetime import datetime
from typing import Dict, List, Any

class ComplianceAnalyzer:
    """AI-powered compliance analyzer for identifying and resolving unknown compliance issues"""
    
    def __init__(self, ai_engine):
        self.ai_engine = ai_engine
        
    def analyze_unknown_compliance_issues(self, compliance_data, overview_data):
        """Analyze compliance data to identify unknown or unclear compliance issues"""
        
        # Extract unknown/unclear compliance rules
        unknown_issues = []
        unclear_issues = []
        
        compliance_rules = compliance_data.get('compliance_rules', [])
        
        for rule in compliance_rules:
            status = rule.get('Status', '').upper()
            rule_name = rule.get('Rule Name', 'Unknown Rule')
            
            # Identify unknown compliance issues
            if 'UNKNOWN' in status or 'NOT_APPLICABLE' in status or status == '':
                unknown_issues.append({
                    'rule_name': rule_name,
                    'status': status,
                    'resource_type': rule.get('Resource Type', 'Unknown'),
                    'description': rule.get('Description', 'No description available'),
                    'compliance_type': rule.get('Compliance Type', 'General')
                })
            
            # Identify unclear or partially compliant issues
            elif 'PARTIAL' in status or 'INSUFFICIENT_DATA' in status:
                unclear_issues.append({
                    'rule_name': rule_name,
                    'status': status,
                    'resource_type': rule.get('Resource Type', 'Unknown'),
                    'description': rule.get('Description', 'No description available'),
                    'compliance_type': rule.get('Compliance Type', 'General'),
                    'compliant_resources': rule.get('Compliant Resources', 0),
                    'non_compliant_resources': rule.get('Non-compliant Resources', 0)
                })
        
        return {
            'unknown_issues': unknown_issues,
            'unclear_issues': unclear_issues,
            'total_unknown': len(unknown_issues),
            'total_unclear': len(unclear_issues)
        }
    
    def generate_compliance_solutions(self, unknown_issues, unclear_issues, overview_data):
        """Generate AI-powered solutions for unknown and unclear compliance issues"""
        
        if not self.ai_engine or not self.ai_engine.bedrock_client:
            return self._generate_fallback_solutions(unknown_issues, unclear_issues)
        
        try:
            # Prepare context for AI analysis
            context = {
                'unknown_issues_count': len(unknown_issues),
                'unclear_issues_count': len(unclear_issues),
                'infrastructure_summary': {
                    'iam_users': overview_data.get('iam_users', 0),
                    'security_groups': overview_data.get('security_groups', 0),
                    's3_buckets': overview_data.get('s3_buckets', 0),
                    'regions': overview_data.get('total_regions', 1)
                },
                'sample_unknown_issues': unknown_issues[:3],  # Sample for analysis
                'sample_unclear_issues': unclear_issues[:3]
            }
            
            # Generate AI-powered solutions
            ai_response = self._invoke_compliance_ai_analysis(context)
            
            if ai_response:
                return ai_response
            else:
                return self._generate_fallback_solutions(unknown_issues, unclear_issues)
                
        except Exception as e:
            st.error(f"Error generating AI compliance solutions: {str(e)}")
            return self._generate_fallback_solutions(unknown_issues, unclear_issues)
    
    def _invoke_compliance_ai_analysis(self, context):
        """Invoke AI analysis for compliance solutions"""
        
        prompt = f"""
Analyze AWS compliance issues and provide specific solutions.

COMPLIANCE ANALYSIS CONTEXT:
- Unknown compliance issues: {context['unknown_issues_count']}
- Unclear compliance issues: {context['unclear_issues_count']}
- Infrastructure: {context['infrastructure_summary']['iam_users']} IAM users, {context['infrastructure_summary']['security_groups']} security groups, {context['infrastructure_summary']['s3_buckets']} S3 buckets
- Monitored regions: {context['infrastructure_summary']['regions']}

SAMPLE UNKNOWN ISSUES:
{json.dumps(context['sample_unknown_issues'], indent=2) if context['sample_unknown_issues'] else 'None'}

SAMPLE UNCLEAR ISSUES:
{json.dumps(context['sample_unclear_issues'], indent=2) if context['sample_unclear_issues'] else 'None'}

Provide solutions in JSON format:
{{
  "unknown_solutions": [
    {{
      "issue_type": "Unknown compliance rule",
      "root_cause": "Specific reason why compliance status is unknown",
      "immediate_actions": ["Action 1", "Action 2"],
      "investigation_steps": ["Step 1", "Step 2"],
      "resolution_timeline": "Time estimate",
      "aws_services_involved": ["Service1", "Service2"],
      "documentation_links": ["Link1", "Link2"]
    }}
  ],
  "unclear_solutions": [
    {{
      "issue_type": "Partial compliance",
      "root_cause": "Why compliance is partial or unclear",
      "immediate_actions": ["Action 1", "Action 2"],
      "remediation_steps": ["Step 1", "Step 2"],
      "monitoring_setup": "How to monitor compliance",
      "resolution_timeline": "Time estimate"
    }}
  ],
  "general_recommendations": [
    "Recommendation 1",
    "Recommendation 2"
  ],
  "prevention_strategies": [
    "Strategy 1",
    "Strategy 2"
  ]
}}
"""
        
        try:
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 3000,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3
            }
            
            response = self.ai_engine.bedrock_client.invoke_model(
                modelId=self.ai_engine.model_id,
                body=json.dumps(request_body)
            )
            
            response_body = json.loads(response['body'].read())
            ai_response = response_body['content'][0]['text']
            
            # Parse JSON response
            start_idx = ai_response.find('{')
            end_idx = ai_response.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = ai_response[start_idx:end_idx]
                parsed_response = json.loads(json_str)
                
                # Add metadata
                parsed_response['ai_generated'] = True
                parsed_response['analysis_timestamp'] = datetime.now().isoformat()
                parsed_response['analysis_source'] = 'AWS Bedrock AI Analysis'
                
                return parsed_response
            
        except Exception as e:
            print(f"Error in compliance AI analysis: {str(e)}")
            return None
    
    def _generate_fallback_solutions(self, unknown_issues, unclear_issues):
        """Generate fallback solutions when AI is not available"""
        
        return {
            'unknown_solutions': [
                {
                    'issue_type': 'Unknown Compliance Status',
                    'root_cause': 'Insufficient data or configuration issues preventing compliance assessment',
                    'immediate_actions': [
                        'Review AWS Config service configuration',
                        'Verify required permissions for compliance checks',
                        'Check if AWS Config rules are properly deployed'
                    ],
                    'investigation_steps': [
                        'Enable AWS Config in all regions',
                        'Deploy standard compliance rule sets',
                        'Review CloudTrail logging configuration',
                        'Verify IAM permissions for compliance services'
                    ],
                    'resolution_timeline': '1-2 weeks',
                    'aws_services_involved': ['AWS Config', 'CloudTrail', 'IAM'],
                    'documentation_links': [
                        'https://docs.aws.amazon.com/config/',
                        'https://docs.aws.amazon.com/securityhub/'
                    ]
                }
            ],
            'unclear_solutions': [
                {
                    'issue_type': 'Partial Compliance',
                    'root_cause': 'Some resources comply while others do not, indicating inconsistent configuration',
                    'immediate_actions': [
                        'Identify non-compliant resources',
                        'Review resource configuration differences',
                        'Implement consistent security policies'
                    ],
                    'remediation_steps': [
                        'Use AWS Systems Manager for configuration management',
                        'Implement Infrastructure as Code (IaC)',
                        'Set up automated compliance remediation',
                        'Regular compliance monitoring and reporting'
                    ],
                    'monitoring_setup': 'Configure CloudWatch alarms for compliance status changes',
                    'resolution_timeline': '2-4 weeks'
                }
            ],
            'general_recommendations': [
                'Enable AWS Security Hub for centralized compliance monitoring',
                'Implement AWS Well-Architected Framework principles',
                'Use AWS Control Tower for multi-account governance',
                'Regular security and compliance assessments'
            ],
            'prevention_strategies': [
                'Implement preventive controls using AWS Config rules',
                'Use AWS Organizations for policy-based management',
                'Automate compliance checking in CI/CD pipelines',
                'Regular training on AWS security best practices'
            ],
            'ai_generated': False,
            'analysis_timestamp': datetime.now().isoformat(),
            'analysis_source': 'Standard Best Practices'
        }
    
    def display_compliance_message_box(self, solutions):
        """Display an interactive message box with compliance solutions"""
        
        if not solutions:
            return
            
        # Main message box
        st.info("🔍 **Compliance Analysis Complete** - Unknown and unclear compliance issues identified")
        
        # Create expandable sections for different types of solutions
        unknown_solutions = solutions.get('unknown_solutions', [])
        unclear_solutions = solutions.get('unclear_solutions', [])
        
        if unknown_solutions:
            with st.expander("❓ Unknown Compliance Issues - Click to see solutions", expanded=True):
                for i, solution in enumerate(unknown_solutions, 1):
                    st.subheader(f"Issue {i}: {solution.get('issue_type', 'Unknown Issue')}")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write("**Root Cause:**")
                        st.write(solution.get('root_cause', 'Not specified'))
                        
                        st.write("**Immediate Actions:**")
                        for action in solution.get('immediate_actions', []):
                            st.write(f"• {action}")
                    
                    with col2:
                        st.write("**Investigation Steps:**")
                        for step in solution.get('investigation_steps', []):
                            st.write(f"• {step}")
                        
                        if solution.get('resolution_timeline'):
                            st.write(f"**Timeline:** {solution['resolution_timeline']}")
                    
                    if solution.get('aws_services_involved'):
                        st.write("**AWS Services Involved:**")
                        st.write(", ".join(solution['aws_services_involved']))
                    
                    st.divider()
        
        if unclear_solutions:
            with st.expander("⚠️ Unclear/Partial Compliance Issues - Click to see solutions", expanded=True):
                for i, solution in enumerate(unclear_solutions, 1):
                    st.subheader(f"Issue {i}: {solution.get('issue_type', 'Unclear Issue')}")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write("**Root Cause:**")
                        st.write(solution.get('root_cause', 'Not specified'))
                        
                        st.write("**Immediate Actions:**")
                        for action in solution.get('immediate_actions', []):
                            st.write(f"• {action}")
                    
                    with col2:
                        st.write("**Remediation Steps:**")
                        for step in solution.get('remediation_steps', []):
                            st.write(f"• {step}")
                        
                        if solution.get('monitoring_setup'):
                            st.write(f"**Monitoring:** {solution['monitoring_setup']}")
                    
                    st.divider()
        
        # General recommendations
        if solutions.get('general_recommendations'):
            with st.expander("💡 General Recommendations"):
                for rec in solutions['general_recommendations']:
                    st.write(f"• {rec}")
        
        # Prevention strategies
        if solutions.get('prevention_strategies'):
            with st.expander("🛡️ Prevention Strategies"):
                for strategy in solutions['prevention_strategies']:
                    st.write(f"• {strategy}")
        
        # Analysis metadata
        if solutions.get('ai_generated'):
            st.caption(f"✨ AI-powered analysis completed at {solutions.get('analysis_timestamp', 'Unknown time')}")
        else:
            st.caption(f"📋 Standard analysis completed at {solutions.get('analysis_timestamp', 'Unknown time')}")