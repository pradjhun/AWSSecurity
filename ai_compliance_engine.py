"""
AI-Powered Compliance Recommendation Engine using AWS Bedrock
"""
import json
import boto3
import streamlit as st
from datetime import datetime
from typing import Dict, List, Any

class AIComplianceEngine:
    """AI-powered compliance and security recommendation engine using AWS Bedrock"""
    
    def __init__(self, aws_client):
        self.aws_client = aws_client
        self.bedrock_client = None
        self.model_id = "anthropic.claude-3-haiku-20240307-v1:0"  # Fast, cost-effective model
        self.initialize_bedrock()
    
    def initialize_bedrock(self):
        """Initialize AWS Bedrock client"""
        try:
            # Try to initialize bedrock-runtime client directly
            self.bedrock_client = boto3.client(
                'bedrock-runtime',
                aws_access_key_id=self.aws_client.aws_access_key_id,
                aws_secret_access_key=self.aws_client.aws_secret_access_key,
                region_name=self.aws_client.region_name
            )
        except Exception as e:
            print(f"Error initializing Bedrock: {str(e)}")
            self.bedrock_client = None
    
    def generate_intelligent_recommendations(self, overview_data, compliance_data, enhanced_findings=None):
        """Generate AI-powered security and compliance recommendations"""
        if not self.bedrock_client:
            return self._fallback_recommendations()
        
        try:
            # Prepare context data for AI analysis
            context = self._prepare_analysis_context(overview_data, compliance_data, enhanced_findings)
            
            # Generate recommendations using Bedrock
            recommendations = self._invoke_ai_analysis(context)
            
            return recommendations
            
        except Exception as e:
            print(f"Error generating AI recommendations: {str(e)}")
            return self._fallback_recommendations()
    
    def _prepare_analysis_context(self, overview_data, compliance_data, enhanced_findings):
        """Prepare structured context for AI analysis"""
        
        # Security metrics summary
        security_score = self._calculate_security_score(overview_data)
        critical_alerts = overview_data.get('critical_alerts', 0)
        
        # Compliance status summary
        compliance_rules = compliance_data.get('compliance_rules', [])
        compliant_count = len([r for r in compliance_rules if 'COMPLIANT' in r.get('Status', '') and 'NON-COMPLIANT' not in r.get('Status', '')])
        non_compliant_count = len([r for r in compliance_rules if 'NON-COMPLIANT' in r.get('Status', '')])
        
        # Enhanced findings summary
        findings_summary = {}
        if enhanced_findings:
            findings_summary = {
                'critical': len([f for f in enhanced_findings if f.get('severity') == 'CRITICAL']),
                'high': len([f for f in enhanced_findings if f.get('severity') == 'HIGH']),
                'medium': len([f for f in enhanced_findings if f.get('severity') == 'MEDIUM']),
                'low': len([f for f in enhanced_findings if f.get('severity') == 'LOW'])
            }
        
        # Infrastructure summary
        infrastructure = {
            'iam_users': overview_data.get('iam_users', 0),
            'security_groups': overview_data.get('security_groups', 0),
            's3_buckets': overview_data.get('s3_buckets', 0)
        }
        
        context = {
            'security_metrics': {
                'overall_score': security_score,
                'critical_alerts': critical_alerts,
                'risk_level': self._determine_risk_level(security_score, critical_alerts)
            },
            'compliance_status': {
                'total_rules': len(compliance_rules),
                'compliant_rules': compliant_count,
                'non_compliant_rules': non_compliant_count,
                'compliance_percentage': round((compliant_count / len(compliance_rules) * 100), 1) if compliance_rules else 0
            },
            'infrastructure_summary': infrastructure,
            'enhanced_findings': findings_summary,
            'top_non_compliant_rules': [
                {
                    'name': rule.get('Rule Name', 'Unknown'),
                    'non_compliant_resources': rule.get('Non-compliant Resources', 0),
                    'compliance_percentage': rule.get('Compliance %', 0)
                }
                for rule in sorted(
                    [r for r in compliance_rules if 'NON-COMPLIANT' in r.get('Status', '')],
                    key=lambda x: x.get('Non-compliant Resources', 0),
                    reverse=True
                )[:5]
            ]
        }
        
        return context
    
    def _invoke_ai_analysis(self, context):
        """Invoke Bedrock AI model for intelligent analysis"""
        
        prompt = self._build_analysis_prompt(context)
        
        try:
            # Prepare request body for Claude
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4000,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.3,
                "system": "You are an expert AWS security and compliance consultant with deep knowledge of cloud security best practices, compliance frameworks, and risk assessment."
            }
            
            # Invoke Bedrock model
            if self.bedrock_client:
                response = self.bedrock_client.invoke_model(
                    modelId=self.model_id,
                    body=json.dumps(request_body)
                )
            else:
                raise Exception("Bedrock client not initialized")
            
            # Parse response
            response_body = json.loads(response['body'].read())
            ai_response = response_body['content'][0]['text']
            
            # Parse structured recommendations from AI response
            return self._parse_ai_recommendations(ai_response)
            
        except Exception as e:
            print(f"Error invoking Bedrock model: {str(e)}")
            return self._fallback_recommendations()
    
    def _build_analysis_prompt(self, context):
        """Build comprehensive analysis prompt for AI model"""
        
        prompt = f"""
As an AWS security and compliance expert, analyze the following security assessment data and provide intelligent, actionable recommendations.

CURRENT SECURITY STATUS:
- Overall Security Score: {context['security_metrics']['overall_score']}/100
- Critical Security Alerts: {context['security_metrics']['critical_alerts']}
- Risk Level: {context['security_metrics']['risk_level']}

COMPLIANCE STATUS:
- Total Compliance Rules Evaluated: {context['compliance_status']['total_rules']}
- Compliant Rules: {context['compliance_status']['compliant_rules']}
- Non-Compliant Rules: {context['compliance_status']['non_compliant_rules']}
- Overall Compliance: {context['compliance_status']['compliance_percentage']}%

INFRASTRUCTURE OVERVIEW:
- IAM Users: {context['infrastructure_summary']['iam_users']}
- Security Groups: {context['infrastructure_summary']['security_groups']}
- S3 Buckets: {context['infrastructure_summary']['s3_buckets']}

ENHANCED FINDINGS SUMMARY:
{json.dumps(context['enhanced_findings'], indent=2) if context['enhanced_findings'] else 'No enhanced findings available'}

TOP NON-COMPLIANT RULES:
{json.dumps(context['top_non_compliant_rules'], indent=2) if context['top_non_compliant_rules'] else 'No significant compliance issues'}

Based on this comprehensive security assessment, provide exactly 8 intelligent, prioritized recommendations in the following JSON format:

{{
  "recommendations": [
    {{
      "priority": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "Category Name",
      "title": "Recommendation Title",
      "description": "Detailed description of the security issue and why it matters",
      "impact": "Security impact and risk reduction (e.g., '+15 points')",
      "effort": "Implementation complexity (Low|Medium|High)",
      "ai_insight": "AI-generated insight about this specific recommendation for this environment",
      "implementation_timeline": "Recommended timeline (e.g., 'Immediate', 'Within 1 week')",
      "business_impact": "How this affects business operations and compliance",
      "steps": [
        "Step 1: Specific action",
        "Step 2: Next action",
        "Step 3: Verification step"
      ],
      "compliance_frameworks": ["Framework names this addresses"],
      "risk_mitigation": "Specific risks this recommendation mitigates"
    }}
  ],
  "executive_summary": "2-3 sentence executive summary of the overall security posture and key priorities",
  "risk_assessment": "Overall risk assessment with specific focus areas",
  "compliance_gaps": "Key compliance gaps that need immediate attention"
}}

Focus on:
1. Contextual recommendations based on the specific security profile
2. Prioritization based on actual risk exposure
3. Practical implementation guidance
4. Business impact consideration
5. Compliance framework alignment
6. Cost-benefit analysis where relevant

Ensure recommendations are specific to this environment's configuration and risk profile, not generic advice.
"""
        
        return prompt
    
    def _parse_ai_recommendations(self, ai_response):
        """Parse structured recommendations from AI response"""
        try:
            # Extract JSON from AI response
            start_idx = ai_response.find('{')
            end_idx = ai_response.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = ai_response[start_idx:end_idx]
                parsed_response = json.loads(json_str)
                
                # Validate and structure the response
                recommendations = parsed_response.get('recommendations', [])
                
                # Add metadata to each recommendation
                for rec in recommendations:
                    rec['ai_generated'] = True
                    rec['generated_at'] = datetime.now().isoformat()
                    rec['source'] = 'AWS Bedrock AI Analysis'
                
                # Add AI summary data
                ai_summary = {
                    'executive_summary': parsed_response.get('executive_summary', ''),
                    'risk_assessment': parsed_response.get('risk_assessment', ''),
                    'compliance_gaps': parsed_response.get('compliance_gaps', ''),
                    'analysis_timestamp': datetime.now().isoformat()
                }
                
                return {
                    'recommendations': recommendations,
                    'ai_summary': ai_summary,
                    'generation_success': True
                }
            else:
                return self._fallback_recommendations()
                
        except json.JSONDecodeError as e:
            print(f"Error parsing AI response JSON: {str(e)}")
            return self._fallback_recommendations()
        except Exception as e:
            print(f"Error processing AI recommendations: {str(e)}")
            return self._fallback_recommendations()
    
    def generate_contextual_remediation(self, finding_data):
        """Generate AI-powered contextual remediation guidance for specific findings"""
        if not self.bedrock_client:
            return self._generate_basic_remediation(finding_data)
        
        try:
            prompt = f"""
As an AWS security expert, provide detailed remediation guidance for this specific security finding:

FINDING DETAILS:
- Title: {finding_data.get('title', 'Unknown')}
- Severity: {finding_data.get('severity', 'Unknown')}
- Resource: {finding_data.get('resource', 'Unknown')}
- Resource Type: {finding_data.get('resource_type', 'Unknown')}
- Description: {finding_data.get('description', 'No description')}
- Check ID: {finding_data.get('check_id', 'Unknown')}

Provide remediation guidance in JSON format:
{{
  "immediate_actions": ["Action 1", "Action 2"],
  "detailed_steps": [
    {{
      "step": 1,
      "action": "Specific action description",
      "command": "AWS CLI command if applicable",
      "verification": "How to verify completion"
    }}
  ],
  "preventive_measures": ["Prevention step 1", "Prevention step 2"],
  "monitoring_setup": "How to monitor for this issue in the future",
  "estimated_time": "Time estimate for remediation",
  "business_impact": "Impact of leaving this unresolved",
  "automation_options": "Available automation for this remediation"
}}
"""
            
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2
            }
            
            response = self.bedrock_client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(request_body)
            )
            
            response_body = json.loads(response['body'].read())
            ai_response = response_body['content'][0]['text']
            
            # Parse JSON response
            start_idx = ai_response.find('{')
            end_idx = ai_response.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = ai_response[start_idx:end_idx]
                return json.loads(json_str)
            
        except Exception as e:
            print(f"Error generating AI remediation: {str(e)}")
        
        return self._generate_basic_remediation(finding_data)
    
    def _generate_basic_remediation(self, finding_data):
        """Generate basic remediation guidance when AI is not available"""
        return {
            "immediate_actions": ["Review security configuration", "Assess risk level"],
            "detailed_steps": [
                {
                    "step": 1,
                    "action": "Identify affected resources",
                    "command": "Review AWS console for resource details",
                    "verification": "Confirm resource identification"
                }
            ],
            "preventive_measures": ["Implement monitoring", "Regular security reviews"],
            "monitoring_setup": "Set up CloudWatch alarms for similar issues",
            "estimated_time": "1-2 hours",
            "business_impact": "Potential security vulnerability",
            "automation_options": "Consider AWS Config rules for automation"
        }
    
    def _calculate_security_score(self, overview_data):
        """Calculate security score"""
        try:
            score = 100
            critical_alerts = overview_data.get('critical_alerts', 0)
            score -= min(critical_alerts * 10, 50)
            return max(score, 0)
        except:
            return 85
    
    def _determine_risk_level(self, security_score, critical_alerts):
        """Determine risk level"""
        if critical_alerts > 5 or security_score < 60:
            return "High Risk"
        elif critical_alerts > 2 or security_score < 80:
            return "Medium Risk"
        else:
            return "Low Risk"
    
    def _fallback_recommendations(self):
        """Provide fallback recommendations when AI is not available"""
        return {
            'recommendations': [
                {
                    'priority': 'HIGH',
                    'category': 'IAM Security',
                    'title': 'Enable MFA for All Users',
                    'description': 'Multi-factor authentication significantly reduces the risk of unauthorized access.',
                    'impact': '+15 points',
                    'effort': 'Medium',
                    'ai_insight': 'Standard security best practice recommendation (AI analysis not available)',
                    'implementation_timeline': 'Within 1 week',
                    'business_impact': 'Reduces risk of account compromise',
                    'steps': [
                        'Audit users without MFA',
                        'Enable MFA for each user',
                        'Verify MFA setup'
                    ],
                    'compliance_frameworks': ['CIS AWS Foundations'],
                    'risk_mitigation': 'Prevents unauthorized access',
                    'ai_generated': False,
                    'source': 'Standard Best Practices'
                }
            ],
            'ai_summary': {
                'executive_summary': 'AI analysis not available. Using standard best practice recommendations.',
                'risk_assessment': 'Manual assessment required',
                'compliance_gaps': 'Comprehensive analysis requires AI capabilities',
                'analysis_timestamp': datetime.now().isoformat()
            },
            'generation_success': False
        }
    
    def test_bedrock_connectivity(self):
        """Test Bedrock service connectivity and model availability"""
        try:
            if not self.bedrock_client:
                return False, "Bedrock client not initialized"
            
            # Test with a simple prompt
            test_prompt = "Respond with 'OK' if you can process this request."
            
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 10,
                "messages": [{"role": "user", "content": test_prompt}],
                "temperature": 0.1
            }
            
            response = self.bedrock_client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(request_body)
            )
            
            response_body = json.loads(response['body'].read())
            return True, "Bedrock connectivity successful"
            
        except Exception as e:
            return False, f"Bedrock connectivity failed: {str(e)}"