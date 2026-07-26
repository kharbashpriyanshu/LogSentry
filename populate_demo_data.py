"""
LogSentry v1.0.0 — Demo Data Population Script
================================================
Submits synthetic log files to the local backend to populate the database
with representative security telemetry for portfolio demonstrations.

All data is synthetic. No credentials, PII, or production IPs are used.
All IPs are RFC 1918 private ranges or documentation ranges.

Usage:
    python populate_demo_data.py [--api-url http://127.0.0.1:8002]

The backend must be running at the specified API URL before executing.
"""

import argparse
import sys
import time
import os

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' not installed. Run: pip install requests")
    sys.exit(1)


def submit_log(api_url: str, filepath: str, parser_name: str) -> bool:
    """Submit a log file to the detection endpoint. Returns True on success."""
    if not os.path.exists(filepath):
        print(f"  [SKIP] File not found: {filepath}")
        return False
    
    print(f"  [SUBMIT] {os.path.basename(filepath)} -> parser={parser_name} ...", end="", flush=True)
    try:
        with open(filepath, "rb") as f:
            response = requests.post(
                f"{api_url}/detection/analyze-file",
                data={"parser_name": parser_name},
                files={"file": f},
                timeout=30,
            )
        if response.status_code == 200:
            summary = response.json().get("summary", {})
            n_alerts = response.json().get("alerts", [])
            alert_count = len(n_alerts) if isinstance(n_alerts, list) else summary.get("alerts_created", "?")
            print(f" [OK] {alert_count} alerts created")
            return True
        else:
            print(f" [FAIL] HTTP {response.status_code}: {response.text[:120]}")
            return False
    except requests.ConnectionError:
        print(f" [FAIL] Connection refused -- is the backend running at {api_url}?")
        return False
    except Exception as e:
        print(f" [FAIL] Error: {e}")
        return False


def check_backend(api_url: str) -> bool:
    """Verify the backend is reachable before sending data."""
    try:
        r = requests.get(f"{api_url}/health", timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"  [HEALTH] Backend: {data.get('status', 'ok')} | "
                  f"version={data.get('version', '?')} | "
                  f"parsers={data.get('parsers_available', '?')} | "
                  f"rules={data.get('detection_rules_available', '?')}")
            return True
    except requests.ConnectionError:
        pass
    print(f"  [ERROR] Cannot reach backend at {api_url}")
    return False


def main():
    parser = argparse.ArgumentParser(description="LogSentry demo data population tool")
    parser.add_argument(
        "--api-url",
        default="http://127.0.0.1:8002/api/v1",
        help="Backend API URL (default: http://127.0.0.1:8002/api/v1)"
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=1.0,
        help="Seconds to wait between submissions (default: 1.0)"
    )
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("=" * 60)
    print("  LogSentry v1.0.0 — Demo Data Population")
    print("=" * 60)
    print(f"\n  Target API: {args.api_url}")
    print()

    # Step 1: Verify backend is available
    print("[STEP 1] Checking backend health...")
    if not check_backend(args.api_url):
        print("\n  Start the backend first:")
        print("    uvicorn app.main:app --host 127.0.0.1 --port 8002 --reload")
        sys.exit(1)
    print()

    # Step 2: Define log files to submit
    log_files = [
        # Comprehensive demo: benign + all major attack types
        {
            "path": os.path.join(base_dir, "sample_data", "demo_comprehensive.log"),
            "parser": "apache",
            "description": "Comprehensive demo (benign + SQLi + XSS + PathTraversal + CmdInjection + DirEnum + BruteForce)",
        },
        # Apache benign baseline
        {
            "path": os.path.join(base_dir, "sample_data", "apache.log"),
            "parser": "apache",
            "description": "Apache benign baseline traffic",
        },
        # Additional attack samples (original file)
        {
            "path": os.path.join(base_dir, "sample_data", "attack_samples.log"),
            "parser": "apache",
            "description": "Targeted attack samples (multiple IPs, multiple attack types)",
        },
        # Malicious log (original)
        {
            "path": os.path.join(base_dir, "sample_malicious.log"),
            "parser": "apache",
            "description": "Malicious log file (brute force + injection)",
        },
    ]

    # Step 3: Submit all files
    print("[STEP 2] Submitting log files...")
    success_count = 0
    for entry in log_files:
        print(f"\n  -> {entry['description']}")
        ok = submit_log(args.api_url, entry["path"], entry["parser"])
        if ok:
            success_count += 1
        time.sleep(args.wait)

    # Step 4: Summary
    print()
    print("=" * 60)
    print(f"  COMPLETE: {success_count}/{len(log_files)} files processed")
    print()
    print("  Verify results:")
    print(f"    curl {args.api_url}/dashboard/summary")
    print(f"    curl {args.api_url}/alerts")
    print()
    print("  Open the SOC Dashboard:")
    print("    http://localhost:5173/dashboard")
    print("=" * 60)


if __name__ == "__main__":
    main()
