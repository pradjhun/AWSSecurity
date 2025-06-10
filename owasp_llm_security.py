"""
OWASP Top 10 for LLM Applications Security Assessment
Provides comprehensive security analysis for Large Language Model applications
"""
import streamlit as st
from datetime import datetime
from typing import Dict, List, Any
import json

class OWASPLLMSecurity:
    """OWASP Top 10 for LLM Applications security assessment and guidance"""
    
    def __init__(self, ai_engine=None):
        self.ai_engine = ai_engine
        self.owasp_llm_top_10 = self._get_owasp_llm_top_10()
    
    def _get_owasp_llm_top_10(self):
        """Define OWASP Top 10 for LLM Applications"""
        return {
            "LLM01": {
                "name": "Prompt Injection",
                "description": "Manipulating LLM through crafted inputs, causing unintended actions",
                "severity": "CRITICAL",
                "category": "Input Validation",
                "impact": "Data exfiltration, unauthorized actions, model manipulation",
                "examples": [
                    "Direct prompt injection through user inputs",
                    "Indirect injection via external content",
                    "System prompt overrides"
                ],
                "mitigations": [
                    "Input validation and sanitization",
                    "Privilege separation",
                    "Human oversight for sensitive operations"
                ]
            },
            "LLM02": {
                "name": "Insecure Output Handling",
                "description": "Insufficient validation of LLM outputs before downstream processing",
                "severity": "HIGH",
                "category": "Output Validation",
                "impact": "XSS, CSRF, SSRF, privilege escalation",
                "examples": [
                    "Unvalidated LLM outputs in web applications",
                    "Code execution from LLM-generated scripts",
                    "Database queries from LLM outputs"
                ],
                "mitigations": [
                    "Output encoding and validation",
                    "Content Security Policy (CSP)",
                    "Sandboxed execution environments"
                ]
            },
            "LLM03": {
                "name": "Training Data Poisoning",
                "description": "Manipulating training data to introduce vulnerabilities or biases",
                "severity": "HIGH",
                "category": "Data Integrity",
                "impact": "Model bias, backdoors, performance degradation",
                "examples": [
                    "Malicious data in training sets",
                    "Adversarial examples in fine-tuning",
                    "Biased or harmful content injection"
                ],
                "mitigations": [
                    "Data provenance tracking",
                    "Training data validation",
                    "Anomaly detection in datasets"
                ]
            },
            "LLM04": {
                "name": "Model Denial of Service",
                "description": "Causing resource exhaustion through expensive model operations",
                "severity": "MEDIUM",
                "category": "Availability",
                "impact": "Service disruption, increased costs, resource exhaustion",
                "examples": [
                    "Resource-intensive prompts",
                    "Recursive or infinite loops",
                    "Large input processing"
                ],
                "mitigations": [
                    "Rate limiting and throttling",
                    "Input length restrictions",
                    "Resource monitoring and alerting"
                ]
            },
            "LLM05": {
                "name": "Supply Chain Vulnerabilities",
                "description": "Vulnerabilities in third-party datasets, models, or plugins",
                "severity": "MEDIUM",
                "category": "Supply Chain",
                "impact": "Compromised model integrity, data breaches",
                "examples": [
                    "Compromised pre-trained models",
                    "Malicious plugins or extensions",
                    "Untrusted data sources"
                ],
                "mitigations": [
                    "Model and plugin validation",
                    "Dependency scanning",
                    "Trusted supplier verification"
                ]
            },
            "LLM06": {
                "name": "Sensitive Information Disclosure",
                "description": "LLM inadvertently revealing confidential information",
                "severity": "HIGH",
                "category": "Information Disclosure",
                "impact": "Privacy violations, data breaches, compliance issues",
                "examples": [
                    "Training data memorization",
                    "Prompt leakage",
                    "Sensitive data in outputs"
                ],
                "mitigations": [
                    "Data sanitization and filtering",
                    "Differential privacy techniques",
                    "Output monitoring and filtering"
                ]
            },
            "LLM07": {
                "name": "Insecure Plugin Design",
                "description": "LLM plugins lacking proper access controls",
                "severity": "HIGH",
                "category": "Access Control",
                "impact": "Unauthorized access, data breaches, system compromise",
                "examples": [
                    "Excessive plugin permissions",
                    "Unvalidated plugin inputs",
                    "Inadequate authentication"
                ],
                "mitigations": [
                    "Principle of least privilege",
                    "Plugin sandboxing",
                    "Strict input validation"
                ]
            },
            "LLM08": {
                "name": "Excessive Agency",
                "description": "LLM systems granted too much autonomy or functionality",
                "severity": "MEDIUM",
                "category": "Access Control",
                "impact": "Unintended actions, system damage, data modification",
                "examples": [
                    "Autonomous system modifications",
                    "Unrestricted API access",
                    "High-privilege operations"
                ],
                "mitigations": [
                    "Function-level access controls",
                    "Human-in-the-loop validation",
                    "Activity logging and monitoring"
                ]
            },
            "LLM09": {
                "name": "Overreliance",
                "description": "Excessive dependence on LLM without proper oversight",
                "severity": "MEDIUM",
                "category": "Human Oversight",
                "impact": "Misinformation spread, poor decisions, reduced accountability",
                "examples": [
                    "Automated decision-making",
                    "Unverified information propagation",
                    "Lack of human review"
                ],
                "mitigations": [
                    "Human oversight requirements",
                    "Confidence scoring",
                    "Decision audit trails"
                ]
            },
            "LLM10": {
                "name": "Model Theft",
                "description": "Unauthorized access to proprietary LLM models",
                "severity": "MEDIUM",
                "category": "Intellectual Property",
                "impact": "IP theft, competitive disadvantage, financial loss",
                "examples": [
                    "Model extraction attacks",
                    "API abuse for replication",
                    "Unauthorized model access"
                ],
                "mitigations": [
                    "API rate limiting",
                    "Model access controls",
                    "Usage monitoring and analytics"
                ]
            }
        }
    
    def assess_llm_security_posture(self, aws_data=None):
        """Assess current LLM security posture based on AWS infrastructure"""
        assessment_results = {}
        
        for vuln_id, vuln_data in self.owasp_llm_top_10.items():
            # Simulate assessment based on AWS configuration
            assessment_results[vuln_id] = self._assess_vulnerability(vuln_id, vuln_data, aws_data)
        
        return assessment_results
    
    def _assess_vulnerability(self, vuln_id, vuln_data, aws_data):
        """Assess individual OWASP LLM vulnerability"""
        
        # Simulate assessment logic based on AWS services
        risk_level = "MEDIUM"  # Default
        compliance_status = "PARTIAL"
        findings = []
        recommendations = []
        
        if vuln_id == "LLM01":  # Prompt Injection
            if aws_data and aws_data.get('iam_users', 0) > 10:
                risk_level = "HIGH"
                findings.append("Multiple IAM users with potential LLM access")
            recommendations.extend([
                "Implement input validation for LLM prompts",
                "Use AWS WAF for web application protection",
                "Configure CloudWatch monitoring for unusual patterns"
            ])
        
        elif vuln_id == "LLM02":  # Insecure Output Handling
            if aws_data and aws_data.get('s3_buckets', 0) > 5:
                findings.append("Multiple S3 buckets may store LLM outputs")
            recommendations.extend([
                "Enable S3 bucket encryption",
                "Configure output validation pipelines",
                "Use AWS Lambda for output sanitization"
            ])
        
        elif vuln_id == "LLM04":  # Model Denial of Service
            if aws_data and aws_data.get('security_groups', 0) > 20:
                risk_level = "HIGH"
                findings.append("Complex network configuration may enable DoS")
            recommendations.extend([
                "Configure API Gateway throttling",
                "Set up CloudWatch alarms for resource usage",
                "Implement AWS Shield for DDoS protection"
            ])
        
        elif vuln_id == "LLM06":  # Sensitive Information Disclosure
            if aws_data and aws_data.get('critical_alerts', 0) > 0:
                risk_level = "HIGH"
                findings.append("Critical security alerts indicate potential data exposure risks")
            recommendations.extend([
                "Enable AWS GuardDuty for anomaly detection",
                "Configure data loss prevention (DLP)",
                "Implement AWS Macie for sensitive data discovery"
            ])
        
        # Add more assessment logic for other vulnerabilities
        else:
            findings.append(f"Standard assessment for {vuln_data['name']}")
            recommendations.extend(vuln_data['mitigations'][:2])
        
        return {
            'risk_level': risk_level,
            'compliance_status': compliance_status,
            'findings': findings,
            'recommendations': recommendations,
            'severity': vuln_data['severity'],
            'category': vuln_data['category'],
            'assessed_at': datetime.now().isoformat()
        }
    
    def generate_llm_security_report(self, assessment_results):
        """Generate comprehensive LLM security report"""
        
        total_vulnerabilities = len(assessment_results)
        high_risk = len([v for v in assessment_results.values() if v['risk_level'] == 'HIGH'])
        medium_risk = len([v for v in assessment_results.values() if v['risk_level'] == 'MEDIUM'])
        low_risk = len([v for v in assessment_results.values() if v['risk_level'] == 'LOW'])
        
        # Calculate overall security score
        risk_weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        total_risk_score = sum(risk_weights.get(v['risk_level'], 1) for v in assessment_results.values())
        max_possible_score = total_vulnerabilities * 3
        security_score = max(0, 100 - int((total_risk_score / max_possible_score) * 100))
        
        return {
            'overall_score': security_score,
            'total_vulnerabilities': total_vulnerabilities,
            'risk_distribution': {
                'high': high_risk,
                'medium': medium_risk,
                'low': low_risk
            },
            'priority_vulnerabilities': [
                vuln_id for vuln_id, data in assessment_results.items()
                if data['risk_level'] == 'HIGH'
            ],
            'generated_at': datetime.now().isoformat()
        }
    
    def get_ai_llm_security_guidance(self, vulnerability_id, assessment_data, aws_context=None):
        """Generate AI-powered guidance for specific LLM vulnerabilities"""
        
        if not self.ai_engine or not self.ai_engine.bedrock_client:
            return self._get_fallback_llm_guidance(vulnerability_id, assessment_data)
        
        try:
            vuln_info = self.owasp_llm_top_10.get(vulnerability_id, {})
            
            prompt = f"""
Provide security guidance for OWASP LLM vulnerability: {vuln_info.get('name', 'Unknown')}

VULNERABILITY DETAILS:
- ID: {vulnerability_id}
- Name: {vuln_info.get('name', 'Unknown')}
- Description: {vuln_info.get('description', 'No description')}
- Severity: {vuln_info.get('severity', 'Unknown')}
- Category: {vuln_info.get('category', 'Unknown')}

CURRENT ASSESSMENT:
- Risk Level: {assessment_data.get('risk_level', 'Unknown')}
- Findings: {assessment_data.get('findings', [])}
- Compliance Status: {assessment_data.get('compliance_status', 'Unknown')}

AWS CONTEXT:
{json.dumps(aws_context, indent=2) if aws_context else 'No AWS context available'}

Provide guidance in JSON format:
{{
  "threat_analysis": "Detailed threat analysis for this LLM vulnerability",
  "aws_specific_risks": ["Risk 1", "Risk 2"],
  "implementation_guide": [
    {{
      "step": 1,
      "action": "Specific action to take",
      "aws_service": "Relevant AWS service",
      "configuration": "Configuration details",
      "validation": "How to verify implementation"
    }}
  ],
  "monitoring_strategy": {{
    "cloudwatch_metrics": ["Metric 1", "Metric 2"],
    "alerting_rules": ["Alert condition 1", "Alert condition 2"],
    "logging_requirements": ["Log type 1", "Log type 2"]
  }},
  "compliance_mapping": {{
    "frameworks": ["Framework 1", "Framework 2"],
    "controls": ["Control 1", "Control 2"]
  }},
  "testing_approach": [
    "Testing method 1",
    "Testing method 2"
  ],
  "incident_response": "Incident response considerations for this vulnerability"
}}
"""
            
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
                # Clean up JSON
                import re
                json_str = re.sub(r',\s*}', '}', json_str)
                json_str = re.sub(r',\s*]', ']', json_str)
                
                parsed_guidance = json.loads(json_str)
                parsed_guidance['ai_generated'] = True
                parsed_guidance['generated_at'] = datetime.now().isoformat()
                
                return parsed_guidance
            
        except Exception as e:
            print(f"Error generating AI LLM guidance: {str(e)}")
            return self._get_fallback_llm_guidance(vulnerability_id, assessment_data)
        
        return self._get_fallback_llm_guidance(vulnerability_id, assessment_data)
    
    def _get_fallback_llm_guidance(self, vulnerability_id, assessment_data):
        """Fallback guidance when AI is not available"""
        
        vuln_info = self.owasp_llm_top_10.get(vulnerability_id, {})
        
        return {
            'threat_analysis': f"Standard threat analysis for {vuln_info.get('name', 'Unknown vulnerability')}",
            'aws_specific_risks': [
                "Potential security misconfigurations",
                "Inadequate access controls",
                "Insufficient monitoring"
            ],
            'implementation_guide': [
                {
                    'step': 1,
                    'action': 'Review current security configuration',
                    'aws_service': 'AWS Config',
                    'configuration': 'Enable security compliance rules',
                    'validation': 'Check compliance dashboard'
                },
                {
                    'step': 2,
                    'action': 'Implement monitoring',
                    'aws_service': 'CloudWatch',
                    'configuration': 'Set up relevant metrics and alarms',
                    'validation': 'Test alarm notifications'
                }
            ],
            'monitoring_strategy': {
                'cloudwatch_metrics': ['API call rates', 'Error rates', 'Response times'],
                'alerting_rules': ['Unusual activity patterns', 'Failed authentication attempts'],
                'logging_requirements': ['Access logs', 'Application logs', 'Security events']
            },
            'compliance_mapping': {
                'frameworks': ['SOC 2', 'ISO 27001'],
                'controls': ['Access Control', 'Monitoring', 'Incident Response']
            },
            'testing_approach': [
                'Security testing of LLM interfaces',
                'Penetration testing for injection attacks',
                'Regular security assessments'
            ],
            'incident_response': 'Establish procedures for LLM-related security incidents',
            'ai_generated': False,
            'generated_at': datetime.now().isoformat()
        }
    
    def create_llm_security_checklist(self):
        """Create actionable security checklist for LLM applications"""
        
        checklist = {
            'input_validation': [
                "Implement prompt injection detection",
                "Validate all user inputs",
                "Sanitize external content sources",
                "Use allowlists for acceptable inputs"
            ],
            'output_handling': [
                "Validate LLM outputs before processing",
                "Implement output encoding",
                "Use content security policies",
                "Monitor for sensitive data in outputs"
            ],
            'access_control': [
                "Implement least privilege access",
                "Use multi-factor authentication",
                "Regular access reviews",
                "Plugin permission management"
            ],
            'monitoring': [
                "Log all LLM interactions",
                "Monitor for unusual patterns",
                "Set up anomaly detection",
                "Regular security assessments"
            ],
            'data_protection': [
                "Encrypt data in transit and at rest",
                "Implement data loss prevention",
                "Regular data inventory",
                "Privacy impact assessments"
            ]
        }
        
        return checklist