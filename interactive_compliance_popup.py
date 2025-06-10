"""
Interactive Compliance Guidance Popup with AI-Driven Recommendations
Provides contextual, real-time compliance guidance through interactive popups
"""
import json
import streamlit as st
from datetime import datetime
from typing import Dict, List, Any

class InteractiveCompliancePopup:
    """Interactive popup system for AI-driven compliance guidance"""
    
    def __init__(self, ai_engine):
        self.ai_engine = ai_engine
    
    def create_compliance_popup(self, rule_name, rule_data, context_data=None):
        """Create an interactive popup for a specific compliance rule"""
        
        # Initialize session state for popup control
        popup_key = f"popup_{rule_name.replace(' ', '_').lower()}"
        
        if popup_key not in st.session_state:
            st.session_state[popup_key] = False
        
        # Create button to trigger popup
        if st.button(f"🔍 Get AI Guidance", key=f"btn_{popup_key}", help="Get AI-powered guidance for this compliance issue"):
            st.session_state[popup_key] = True
        
        # Display popup modal
        if st.session_state[popup_key]:
            self._display_popup_modal(rule_name, rule_data, context_data, popup_key)
    
    def _display_popup_modal(self, rule_name, rule_data, context_data, popup_key):
        """Display the interactive popup modal with AI guidance"""
        
        # Create modal-like container
        with st.container():
            st.markdown("""
            <style>
            .popup-container {
                border: 2px solid #1f77b4;
                border-radius: 10px;
                padding: 20px;
                background-color: #f8f9fa;
                margin: 10px 0;
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            }
            .popup-header {
                background-color: #1f77b4;
                color: white;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 15px;
            }
            .guidance-section {
                background-color: white;
                padding: 15px;
                border-radius: 5px;
                margin: 10px 0;
                border-left: 4px solid #17a2b8;
            }
            .action-item {
                background-color: #e8f4f8;
                padding: 10px;
                border-radius: 5px;
                margin: 5px 0;
                border-left: 3px solid #28a745;
            }
            </style>
            """, unsafe_allow_html=True)
            
            # Popup header with close button
            col1, col2 = st.columns([4, 1])
            with col1:
                st.markdown(f"""
                <div class="popup-header">
                    <h3>🤖 AI Compliance Guidance: {rule_name}</h3>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                if st.button("✖", key=f"close_{popup_key}", help="Close popup"):
                    st.session_state[popup_key] = False
                    st.rerun()
            
            # Generate AI guidance
            with st.spinner("Generating personalized compliance guidance..."):
                guidance = self._generate_ai_guidance(rule_name, rule_data, context_data)
            
            if guidance:
                self._render_guidance_content(guidance)
            
            # Interactive elements
            self._render_interactive_elements(rule_name, rule_data, popup_key)
    
    def _generate_ai_guidance(self, rule_name, rule_data, context_data):
        """Generate AI-powered guidance for the specific compliance rule"""
        
        if not self.ai_engine or not self.ai_engine.bedrock_client:
            return self._generate_fallback_guidance(rule_name, rule_data)
        
        try:
            # Prepare context for AI analysis
            prompt = self._build_guidance_prompt(rule_name, rule_data, context_data)
            
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2500,
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
                # Clean up common JSON issues
                import re
                json_str = re.sub(r',\s*}', '}', json_str)
                json_str = re.sub(r',\s*]', ']', json_str)
                
                parsed_guidance = json.loads(json_str)
                parsed_guidance['ai_generated'] = True
                parsed_guidance['generated_at'] = datetime.now().isoformat()
                
                return parsed_guidance
            
        except Exception as e:
            st.error(f"Error generating AI guidance: {str(e)}")
            return self._generate_fallback_guidance(rule_name, rule_data)
        
        return self._generate_fallback_guidance(rule_name, rule_data)
    
    def _build_guidance_prompt(self, rule_name, rule_data, context_data):
        """Build AI prompt for compliance guidance"""
        
        prompt = f"""
Provide interactive compliance guidance for this AWS security rule:

RULE DETAILS:
- Name: {rule_name}
- Status: {rule_data.get('Status', 'Unknown')}
- Resource Type: {rule_data.get('Resource Type', 'Unknown')}
- Compliant Resources: {rule_data.get('Compliant Resources', 0)}
- Non-compliant Resources: {rule_data.get('Non-compliant Resources', 0)}
- Description: {rule_data.get('Description', 'No description available')}

INFRASTRUCTURE CONTEXT:
{json.dumps(context_data, indent=2) if context_data else 'No additional context'}

Provide guidance in JSON format:
{{
  "summary": "Brief explanation of the compliance issue and its importance",
  "risk_assessment": {{
    "risk_level": "HIGH|MEDIUM|LOW",
    "business_impact": "Description of potential business impact",
    "security_implications": "Security risks if not addressed"
  }},
  "step_by_step_guide": [
    {{
      "step": 1,
      "title": "Step title",
      "description": "Detailed description",
      "aws_console_path": "Path in AWS console",
      "cli_command": "AWS CLI command if applicable",
      "estimated_time": "Time estimate"
    }}
  ],
  "quick_fixes": [
    {{
      "action": "Quick action description",
      "method": "Console|CLI|CloudFormation",
      "complexity": "Easy|Medium|Advanced",
      "impact": "Expected outcome"
    }}
  ],
  "prevention_measures": [
    "Prevention measure 1",
    "Prevention measure 2"
  ],
  "monitoring_setup": {{
    "cloudwatch_alarms": "Recommended CloudWatch alarms",
    "config_rules": "Additional Config rules to deploy",
    "automation": "Automation recommendations"
  }},
  "related_rules": [
    "Rule 1",
    "Rule 2"
  ],
  "resources": [
    {{
      "title": "Resource title",
      "url": "Documentation URL",
      "type": "Documentation|Tutorial|Best Practice"
    }}
  ]
}}
"""
        return prompt
    
    def _generate_fallback_guidance(self, rule_name, rule_data):
        """Generate fallback guidance when AI is not available"""
        
        status = rule_data.get('Status', '').upper()
        non_compliant = rule_data.get('Non-compliant Resources', 0)
        
        risk_level = "HIGH" if non_compliant > 10 else "MEDIUM" if non_compliant > 0 else "LOW"
        
        return {
            'summary': f'Compliance guidance for {rule_name}. Current status: {status}',
            'risk_assessment': {
                'risk_level': risk_level,
                'business_impact': 'Non-compliance may affect security posture and regulatory requirements',
                'security_implications': 'Potential security vulnerabilities or policy violations'
            },
            'step_by_step_guide': [
                {
                    'step': 1,
                    'title': 'Review Current Configuration',
                    'description': 'Examine the current resource configuration in AWS Console',
                    'aws_console_path': 'AWS Config > Rules > Select specific rule',
                    'cli_command': 'aws configservice describe-compliance-by-config-rule',
                    'estimated_time': '15 minutes'
                },
                {
                    'step': 2,
                    'title': 'Identify Non-compliant Resources',
                    'description': 'List and analyze resources that are not meeting compliance requirements',
                    'aws_console_path': 'AWS Config > Compliance > Non-compliant resources',
                    'cli_command': 'aws configservice get-compliance-details-by-config-rule',
                    'estimated_time': '20 minutes'
                },
                {
                    'step': 3,
                    'title': 'Apply Remediation',
                    'description': 'Implement necessary changes to bring resources into compliance',
                    'aws_console_path': 'Service-specific console',
                    'cli_command': 'Service-specific CLI commands',
                    'estimated_time': '30-60 minutes'
                }
            ],
            'quick_fixes': [
                {
                    'action': 'Enable automatic remediation if available',
                    'method': 'Console',
                    'complexity': 'Easy',
                    'impact': 'Automated compliance enforcement'
                },
                {
                    'action': 'Review and update resource policies',
                    'method': 'Console',
                    'complexity': 'Medium',
                    'impact': 'Improved security configuration'
                }
            ],
            'prevention_measures': [
                'Implement Infrastructure as Code (IaC) with compliance templates',
                'Set up continuous compliance monitoring',
                'Regular security and compliance training',
                'Use AWS Service Catalog for pre-approved configurations'
            ],
            'monitoring_setup': {
                'cloudwatch_alarms': 'Set up alarms for compliance status changes',
                'config_rules': 'Deploy additional preventive Config rules',
                'automation': 'Use AWS Systems Manager for automated remediation'
            },
            'related_rules': [
                'Related security configuration rules',
                'Complementary compliance checks'
            ],
            'resources': [
                {
                    'title': 'AWS Config Best Practices',
                    'url': 'https://docs.aws.amazon.com/config/latest/developerguide/best-practices.html',
                    'type': 'Best Practice'
                },
                {
                    'title': 'AWS Security Best Practices',
                    'url': 'https://aws.amazon.com/architecture/security-identity-compliance/',
                    'type': 'Documentation'
                }
            ],
            'ai_generated': False,
            'generated_at': datetime.now().isoformat()
        }
    
    def _render_guidance_content(self, guidance):
        """Render the guidance content in the popup"""
        
        # Summary section
        st.markdown(f"""
        <div class="guidance-section">
            <h4>📋 Summary</h4>
            <p>{guidance.get('summary', 'No summary available')}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Risk assessment
        risk_data = guidance.get('risk_assessment', {})
        if risk_data:
            risk_level = risk_data.get('risk_level', 'UNKNOWN')
            risk_color = {'HIGH': '#dc3545', 'MEDIUM': '#ffc107', 'LOW': '#28a745'}.get(risk_level, '#6c757d')
            
            st.markdown(f"""
            <div class="guidance-section">
                <h4>⚠️ Risk Assessment</h4>
                <p><strong>Risk Level:</strong> <span style="color: {risk_color}; font-weight: bold;">{risk_level}</span></p>
                <p><strong>Business Impact:</strong> {risk_data.get('business_impact', 'Not specified')}</p>
                <p><strong>Security Implications:</strong> {risk_data.get('security_implications', 'Not specified')}</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Step-by-step guide
        steps = guidance.get('step_by_step_guide', [])
        if steps:
            st.markdown('<div class="guidance-section"><h4>📝 Step-by-Step Guide</h4></div>', unsafe_allow_html=True)
            
            for step in steps:
                with st.expander(f"Step {step.get('step', 'N/A')}: {step.get('title', 'Unknown Step')}", expanded=False):
                    st.write(f"**Description:** {step.get('description', 'No description')}")
                    st.write(f"**AWS Console Path:** {step.get('aws_console_path', 'Not specified')}")
                    if step.get('cli_command'):
                        st.code(step['cli_command'], language='bash')
                    st.write(f"**Estimated Time:** {step.get('estimated_time', 'Not specified')}")
        
        # Quick fixes
        quick_fixes = guidance.get('quick_fixes', [])
        if quick_fixes:
            st.markdown('<div class="guidance-section"><h4>⚡ Quick Fixes</h4></div>', unsafe_allow_html=True)
            
            for fix in quick_fixes:
                st.markdown(f"""
                <div class="action-item">
                    <strong>{fix.get('action', 'Unknown action')}</strong><br>
                    Method: {fix.get('method', 'Not specified')} | 
                    Complexity: {fix.get('complexity', 'Unknown')} | 
                    Impact: {fix.get('impact', 'Not specified')}
                </div>
                """, unsafe_allow_html=True)
    
    def _render_interactive_elements(self, rule_name, rule_data, popup_key):
        """Render interactive elements in the popup"""
        
        st.divider()
        
        # Interactive buttons
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("📊 View Details", key=f"details_{popup_key}"):
                self._show_detailed_analysis(rule_name, rule_data)
        
        with col2:
            if st.button("🔧 Auto-Fix", key=f"autofix_{popup_key}"):
                self._show_auto_fix_options(rule_name, rule_data)
        
        with col3:
            if st.button("📚 Learn More", key=f"learn_{popup_key}"):
                self._show_learning_resources(rule_name, rule_data)
        
        with col4:
            if st.button("✅ Mark Resolved", key=f"resolve_{popup_key}"):
                self._mark_as_resolved(rule_name, popup_key)
    
    def _show_detailed_analysis(self, rule_name, rule_data):
        """Show detailed analysis of the compliance rule"""
        st.subheader("Detailed Analysis")
        
        # Create detailed breakdown
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Compliance Status Breakdown:**")
            compliant = rule_data.get('Compliant Resources', 0)
            non_compliant = rule_data.get('Non-compliant Resources', 0)
            total = compliant + non_compliant
            
            if total > 0:
                compliance_rate = (compliant / total) * 100
                st.progress(compliance_rate / 100)
                st.write(f"Compliance Rate: {compliance_rate:.1f}%")
            
            st.write(f"✅ Compliant: {compliant}")
            st.write(f"❌ Non-compliant: {non_compliant}")
        
        with col2:
            st.write("**Rule Information:**")
            st.write(f"**Type:** {rule_data.get('Resource Type', 'Unknown')}")
            st.write(f"**Status:** {rule_data.get('Status', 'Unknown')}")
            st.write(f"**Framework:** {rule_data.get('Compliance Type', 'General')}")
    
    def _show_auto_fix_options(self, rule_name, rule_data):
        """Show auto-fix options for the compliance rule"""
        st.subheader("Auto-Fix Options")
        
        st.info("🤖 AI-suggested automatic remediation options")
        
        # Simulated auto-fix options
        auto_fix_options = [
            "Enable automatic remediation through AWS Config",
            "Deploy CloudFormation template for compliance",
            "Configure Systems Manager automation",
            "Set up preventive controls"
        ]
        
        for option in auto_fix_options:
            if st.button(option, key=f"autofix_option_{option.replace(' ', '_')}"):
                st.success(f"Initiated: {option}")
                st.info("This would trigger the actual remediation process in a real implementation")
    
    def _show_learning_resources(self, rule_name, rule_data):
        """Show learning resources related to the compliance rule"""
        st.subheader("Learning Resources")
        
        # Curated learning resources
        resources = [
            {
                "title": "AWS Config Best Practices",
                "url": "https://docs.aws.amazon.com/config/latest/developerguide/best-practices.html",
                "type": "Documentation"
            },
            {
                "title": "AWS Security Hub Compliance Standards",
                "url": "https://docs.aws.amazon.com/securityhub/latest/userguide/standards.html",
                "type": "Guide"
            },
            {
                "title": "AWS Well-Architected Security Pillar",
                "url": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
                "type": "Best Practice"
            }
        ]
        
        for resource in resources:
            st.markdown(f"📖 **{resource['title']}** ({resource['type']})")
            st.markdown(f"[Open Resource]({resource['url']})")
            st.divider()
    
    def _mark_as_resolved(self, rule_name, popup_key):
        """Mark the compliance issue as resolved"""
        st.success(f"✅ Marked '{rule_name}' as resolved")
        st.info("This would update the compliance status in a real implementation")
        
        # Close popup after marking as resolved
        st.session_state[popup_key] = False
        
        # Add to session state for tracking
        if 'resolved_compliance_issues' not in st.session_state:
            st.session_state.resolved_compliance_issues = []
        
        st.session_state.resolved_compliance_issues.append({
            'rule_name': rule_name,
            'resolved_at': datetime.now().isoformat(),
            'method': 'manual_review'
        })
        
        st.rerun()
    
    def create_bulk_guidance_popup(self, compliance_rules, context_data=None):
        """Create a bulk guidance popup for multiple compliance issues"""
        
        if st.button("🎯 Get Bulk AI Guidance", help="Get AI guidance for all compliance issues"):
            
            with st.container():
                st.markdown("""
                <div style="border: 2px solid #28a745; border-radius: 10px; padding: 20px; background-color: #f8f9fa;">
                    <h3>🤖 Bulk Compliance Guidance</h3>
                </div>
                """, unsafe_allow_html=True)
                
                # Analyze all rules
                non_compliant_rules = [rule for rule in compliance_rules if 'NON-COMPLIANT' in rule.get('Status', '')]
                unknown_rules = [rule for rule in compliance_rules if 'UNKNOWN' in rule.get('Status', '') or rule.get('Status', '') == '']
                
                if non_compliant_rules or unknown_rules:
                    with st.spinner("Generating comprehensive guidance for all compliance issues..."):
                        bulk_guidance = self._generate_bulk_ai_guidance(non_compliant_rules, unknown_rules, context_data)
                    
                    if bulk_guidance:
                        self._render_bulk_guidance(bulk_guidance)
                else:
                    st.success("🎉 All compliance rules are in good standing!")
    
    def _generate_bulk_ai_guidance(self, non_compliant_rules, unknown_rules, context_data):
        """Generate bulk AI guidance for multiple compliance issues"""
        
        # Simplified bulk guidance for demo
        return {
            'priority_matrix': [
                {'rule': rule.get('Rule Name', 'Unknown'), 'priority': 'HIGH', 'impact': 'Security Risk'}
                for rule in non_compliant_rules[:3]
            ],
            'recommended_sequence': [
                f"1. Address {rule.get('Rule Name', 'Unknown')}"
                for rule in non_compliant_rules[:5]
            ],
            'estimated_timeline': '2-4 weeks for complete remediation',
            'resource_requirements': 'Security team, 20-40 hours',
            'cost_estimate': 'Low to Medium based on automation level'
        }
    
    def _render_bulk_guidance(self, guidance):
        """Render bulk guidance content"""
        
        st.subheader("🎯 Priority Matrix")
        priority_data = guidance.get('priority_matrix', [])
        if priority_data:
            for item in priority_data:
                st.write(f"**{item.get('rule', 'Unknown')}** - Priority: {item.get('priority', 'Unknown')} - Impact: {item.get('impact', 'Unknown')}")
        
        st.subheader("📋 Recommended Sequence")
        sequence = guidance.get('recommended_sequence', [])
        for step in sequence:
            st.write(f"• {step}")
        
        st.subheader("📊 Overall Estimates")
        st.write(f"**Timeline:** {guidance.get('estimated_timeline', 'Unknown')}")
        st.write(f"**Resources:** {guidance.get('resource_requirements', 'Unknown')}")
        st.write(f"**Cost:** {guidance.get('cost_estimate', 'Unknown')}")