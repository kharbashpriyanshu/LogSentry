import os
import requests

def check_abuseipdb(ip_address):
    """
    Checks an IP address against the AbuseIPDB API.
    Returns a tuple: (confidence_score, report_summary)
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    
    if not api_key or api_key == "YOUR_API_KEY_HERE":
        # Mock data for demonstration purposes if no key is provided
        if ip_address.startswith("192.") or ip_address.startswith("10.") or ip_address.startswith("172."):
            return (0, "Private/Local IP - Not Checked")
        return (85, "Mocked Report: Known malicious actor (No API Key)")

    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']
            score = data.get('abuseConfidenceScore', 0)
            usage = data.get('usageType', 'Unknown')
            return (score, f"Usage: {usage}")
        elif response.status_code == 401:
            return (None, "API Error: Unauthorized (Invalid Key)")
        elif response.status_code == 429:
            return (None, "API Error: Rate Limit Exceeded")
        else:
            return (None, f"API Error: {response.status_code}")
    except Exception as e:
        return (None, "Connection Error")
