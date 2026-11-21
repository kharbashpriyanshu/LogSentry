#!/usr/bin/env python3
"""
LogSentry Enterprise Universal Log Shipper Agent
=================================================
A lightweight, zero-dependency forwarder agent for production servers.
Tails local log files in real-time and streams parsed events to LogSentry SIEM.

Supported Environments:
  - Linux: Ubuntu, Debian, RHEL, CentOS, Alpine, Arch, Amazon Linux
  - Windows: Windows Server 2016/2019/2022/2025, Windows 10/11
  - Containers: Docker, Kubernetes Pods, Nomad, Bare-metal

Usage:
  python logsentry_shipper.py --file /var/log/nginx/access.log --parser nginx --server http://siem:8000
  python logsentry_shipper.py --file /var/log/auth.log --parser linux_auth --server http://siem:8000
  python logsentry_shipper.py --file "C:\\inetpub\\logs\\LogFiles\\*.log" --parser iis --server http://siem:8000
"""

import argparse
import glob
import json
import os
import platform
import socket
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime

HOSTNAME = platform.node() or socket.gethostname() or "unknown-host"


class LogShipper:
    def __init__(
        self,
        file_patterns: list[str],
        parser_name: str,
        server_url: str,
        api_key: str | None = None,
        tenant_id: str = "default",
        batch_size: int = 50,
        flush_interval_seconds: float = 2.0,
    ):
        self.file_patterns = file_patterns
        self.parser_name = parser_name
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.file_positions: dict[str, int] = {}
        self.queue: list[dict] = []
        self.last_flush = time.time()
        self.is_running = True

    def find_matching_files(self) -> list[str]:
        files = []
        for pat in self.file_patterns:
            files.extend(glob.glob(pat))
        return sorted(set(files))

    def tail_files(self):
        for filepath in self.find_matching_files():
            if not os.path.isfile(filepath):
                continue

            # If opening file for first time, seek to end so we don't re-ingest past history
            if filepath not in self.file_positions:
                try:
                    size = os.path.getsize(filepath)
                    self.file_positions[filepath] = size
                    print(
                        f"[*] Tailing new log file: {filepath} (initial offset: {size} bytes)"
                    )
                except Exception as e:
                    print(f"[-] Could not open {filepath}: {e}")
                    continue

            try:
                curr_size = os.path.getsize(filepath)
                # Check for log rotation (file truncated or smaller than last seen position)
                if curr_size < self.file_positions[filepath]:
                    print(
                        f"[*] Detected log rotation on {filepath}. Resetting offset to 0."
                    )
                    self.file_positions[filepath] = 0

                if curr_size > self.file_positions[filepath]:
                    with open(filepath, encoding="utf-8", errors="ignore") as f:
                        f.seek(self.file_positions[filepath])
                        lines = f.readlines()
                        self.file_positions[filepath] = f.tell()

                        for line in lines:
                            line_clean = line.strip()
                            if line_clean:
                                self.enqueue_line(line_clean, filepath)
            except Exception as e:
                print(f"[-] Error reading {filepath}: {e}")

    def enqueue_line(self, line: str, source_path: str):
        now_iso = datetime.now(UTC).isoformat()
        event = {
            "parser_name": self.parser_name,
            "raw_log": line,
            "hostname": HOSTNAME,
            "tenant_id": self.tenant_id,
            "timestamp": now_iso,
        }
        self.queue.append(event)
        if len(self.queue) >= self.batch_size:
            self.flush()

    def flush(self):
        if not self.queue:
            return

        batch = list(self.queue)
        self.queue.clear()
        self.last_flush = time.time()

        url = f"{self.server_url}/api/v1/detection/analyze"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        for event in batch:
            payload = json.dumps({"event": event}).encode("utf-8")
            req = urllib.request.Request(  # noqa: S310
                url, data=payload, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:  # noqa: S310
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        alerts = data.get("alerts", [])
                        if alerts:
                            print(
                                f"\033[91m[ALERT TRIGGERED]\033[0m {len(alerts)} alerts generated on {HOSTNAME}: {[a.get('title') for a in alerts]}"
                            )
            except urllib.error.HTTPError as e:
                print(
                    f"[-] HTTP Error {e.code}: {e.read().decode('utf-8', errors='ignore')[:120]}"
                )
            except Exception as e:
                print(f"[-] Connection error forwarding to {url}: {e}")

    def run(self):
        print("=" * 68)
        print("      LOGSENTRY SIEM — UNIVERSAL ENTERPRISE LOG SHIPPER         ")
        print("=" * 68)
        print(f" Host:        {HOSTNAME}")
        print(f" Target SIEM: {self.server_url}")
        print(f" Parser:      {self.parser_name}")
        print(f" Watching:    {self.file_patterns}")
        print("=" * 68 + "\n")
        print("[+] Shipper active. Forwarding telemetry in real-time...\n")

        try:
            while self.is_running:
                self.tail_files()
                if time.time() - self.last_flush >= self.flush_interval:
                    self.flush()
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[*] Shipper shutting down gracefully.")
            self.flush()


def main():
    parser = argparse.ArgumentParser(
        description="LogSentry Enterprise Universal Log Shipper"
    )
    parser.add_argument(
        "--file",
        nargs="+",
        required=True,
        help="Log file path(s) or glob patterns to tail (e.g. /var/log/nginx/*.log)",
    )
    parser.add_argument(
        "--parser",
        required=True,
        choices=["apache", "nginx", "linux_auth", "windows_event", "cloudtrail"],
        help="Log parser to apply for telemetry normalization",
    )
    parser.add_argument(
        "--server",
        default="http://localhost:8000",
        help="LogSentry server base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Optional tenant API key for authentication",
    )
    parser.add_argument(
        "--tenant-id",
        default="default",
        help="Tenant workspace ID (default: default)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Maximum events per flush (default: 50)",
    )

    args = parser.parse_args()

    shipper = LogShipper(
        file_patterns=args.file,
        parser_name=args.parser,
        server_url=args.server,
        api_key=args.api_key,
        tenant_id=args.tenant_id,
        batch_size=args.batch_size,
    )
    shipper.run()


if __name__ == "__main__":
    main()
