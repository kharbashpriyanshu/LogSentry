import re

# Threat Signatures
SQLI_REGEX = re.compile(r'(?i)(UNION.*?SELECT|OR.*?=.*?|DROP\s+TABLE|--$|WAITFOR\s+DELAY)')
XSS_REGEX = re.compile(r'(?i)(<script>|javascript:|onerror=|onload=)')
TRAVERSAL_REGEX = re.compile(r'(?i)(\.\./|\.\.\\|/etc/passwd|/windows/system32)')

def analyze_log_entry(entry):
    """
    Analyzes a single LogEntry for malicious payloads.
    Returns a dictionary with alert details if malicious, else None.
    """
    alerts = []
    
    # Check Endpoint for known attack signatures
    if SQLI_REGEX.search(entry.endpoint):
        alerts.append({"attack_type": "SQL Injection", "severity": "Critical", "description": f"SQLi payload detected in endpoint: {entry.endpoint}"})
    if XSS_REGEX.search(entry.endpoint):
        alerts.append({"attack_type": "Cross-Site Scripting (XSS)", "severity": "High", "description": f"XSS payload detected in endpoint: {entry.endpoint}"})
    if TRAVERSAL_REGEX.search(entry.endpoint):
        alerts.append({"attack_type": "Path Traversal", "severity": "High", "description": f"Path traversal attempt in endpoint: {entry.endpoint}"})
    
    if alerts:
        # Return the highest severity alert (for now, just the first one matched)
        return alerts[0]
    return None

def detect_brute_force(db, LogEntry, Alert):
    """
    Runs an aggregation to detect brute force attacks.
    Criteria: >10 failed logins (401/403) from same IP.
    """
    from sqlalchemy import func
    
    failed_attempts = db.session.query(
        LogEntry.ip_address, func.count(LogEntry.id).label('count')
    ).filter(LogEntry.status_code.in_([401, 403]))\
     .group_by(LogEntry.ip_address)\
     .having(func.count(LogEntry.id) > 10).all()
     
    new_alerts = []
    for ip, count in failed_attempts:
        # Check if we already alerted for this IP recently to avoid duplicates
        existing = db.session.query(Alert).filter_by(ip_address=ip, attack_type="Brute Force").first()
        if not existing:
            alert = Alert(
                ip_address=ip,
                attack_type="Brute Force",
                severity="High",
                description=f"Detected {count} failed access attempts (401/403) from this IP."
            )
            db.session.add(alert)
            new_alerts.append(alert)
            
    if new_alerts:
        db.session.commit()
    return new_alerts
