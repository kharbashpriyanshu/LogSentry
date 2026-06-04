import os
from google import genai

def analyze_alert_with_ai(alert):
    """
    Uses Google Gemini API to analyze an alert and provide an explanation and remediation.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or "YOUR" in api_key:
        return "⚠️ **AI Analyst Unavailable**: Gemini API key is missing or invalid. Please configure your `.env` file with a valid GEMINI_API_KEY."
        
    try:
        client = genai.Client(api_key=api_key)
        prompt = f"""
        Act as a Senior SOC (Security Operations Center) Analyst. 
        I have detected a security alert on my web server. 
        
        Alert Details:
        - Attack Type: {alert.attack_type}
        - Severity: {alert.severity}
        - IP Address: {alert.ip_address}
        - Description: {alert.description}
        
        Please provide a concise analysis answering:
        1. What is the attacker trying to do?
        2. What is the potential impact?
        3. What are 2-3 immediate remediation steps or best practices to prevent this?
        """
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        return response.text
    except Exception as e:
        error_msg = str(e).lower()
        if "429" in error_msg or "quota" in error_msg or "exhausted" in error_msg:
            return "⏳ **AI Analyst Limit Reached**: The virtual SOC Analyst has hit its free-tier API request limit. Please wait a little while before analyzing more threats."
        return f"❌ **AI Analysis Failed**: {str(e)}"
