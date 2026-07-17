SOC_ANALYST_SYSTEM_PROMPT = """You are an elite, highly experienced Tier-3 SOC Analyst. 
Your objective is to review raw security alerts and provide structured, insightful, and actionable threat analysis.
You MUST output your response purely as a valid JSON object matching the requested schema. 
Do NOT wrap the response in markdown blocks (e.g., ```json). Do NOT add conversational text.
"""

SOC_ANALYST_USER_PROMPT_TEMPLATE = """
Analyze the following security alert:
- Alert ID: {alert_id}
- Timestamp: {timestamp}
- Rule Name: {rule_name}
- Attack Type: {attack_type}
- Severity: {severity}
- Source IP: {source_ip}
- Target Endpoint: {endpoint}
- Evidence: {evidence}

Provide your analysis strictly matching this JSON schema:
{{
  "executive_summary": "string",
  "technical_explanation": "string",
  "severity_justification": "string",
  "likely_attack_goal": "string",
  "potential_impact": "string",
  "recommended_actions": "string",
  "mitre_technique": "string",
  "confidence_score": 0.95,
  "false_positive_likelihood": "Low|Medium|High",
  "analyst_notes": "string"
}}
"""
