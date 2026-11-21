#!/usr/bin/env python3
"""LogSentry Enterprise Universal Log Shipper Agent.

=================================================
A lightweight, zero-dependency forwarder agent for production servers.
Tails local log files in real-time and streams parsed events to LogSentry SIEM.

Upgraded with:
  1. Persistent on-disk file checkpoints (.logsentry_shipper_checkpoint.json)
  2. Batch delivery via POST /api/v1/detection/batch
  3. Local disk spool with exponential backoff retry on network failure
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
CHECKPOINT_FILE = ".logsentry_shipper_checkpoint.json"
SPOOL_FILE = ".logsentry_shipper_spool.jsonl"


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
        checkpoint_path: str = CHECKPOINT_FILE,
        spool_path: str = SPOOL_FILE,
    ):
        self.file_patterns = file_patterns
        self.parser_name = parser_name
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.checkpoint_path = checkpoint_path
        self.spool_path = spool_path
        self.file_positions: dict[str, int] = self._load_checkpoint()
        self.queue: list[dict] = []
        self.last_flush = time.time()
        self.is_running = True
        self.backoff_delay = 1.0

    def _load_checkpoint(self) -> dict[str, int]:
        """Loads persistent file offsets from disk."""
        if os.path.exists(self.checkpoint_path):
            try:
                with open(self.checkpoint_path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_checkpoint(self):
        """Saves current file offsets to disk atomically."""
        try:
            tmp_path = f"{self.checkpoint_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self.file_positions, f)
            os.replace(tmp_path, self.checkpoint_path)
        except Exception as e:
            print(f"[-] Warning: Failed to save checkpoint: {e}")

    def find_matching_files(self) -> list[str]:
        files = []
        for pat in self.file_patterns:
            files.extend(glob.glob(pat))
        return sorted(set(files))

    def tail_files(self):
        for filepath in self.find_matching_files():
            if not os.path.isfile(filepath):
                continue

            # If opening file for first time, check saved checkpoint or seek to end
            if filepath not in self.file_positions:
                try:
                    size = os.path.getsize(filepath)
                    self.file_positions[filepath] = size
                    self._save_checkpoint()
                    print(
                        f"[*] Tailing new log file: {filepath} (initial offset: {size} bytes)"
                    )
                except Exception as e:
                    print(f"[-] Could not open {filepath}: {e}")
                    continue

            try:
                curr_size = os.path.getsize(filepath)
                last_pos = self.file_positions[filepath]

                # Handle log rotation (file was truncated or replaced)
                if curr_size < last_pos:
                    print(f"[!] Log rotation detected on {filepath}. Resetting offset.")
                    last_pos = 0

                if curr_size > last_pos:
                    with open(filepath, encoding="utf-8", errors="replace") as f:
                        f.seek(last_pos)
                        new_lines = f.readlines()
                        self.file_positions[filepath] = f.tell()
                        self._save_checkpoint()

                    for line in new_lines:
                        line = line.strip()
                        if line:
                            self.queue.append(
                                {
                                    "raw_log": line,
                                    "source": f"{HOSTNAME}:{os.path.basename(filepath)}",
                                    "source_type": self.parser_name,
                                    "source_ip": "127.0.0.1",
                                    "timestamp": datetime.now(UTC).isoformat(),
                                    "tenant_id": self.tenant_id,
                                }
                            )

                            if len(self.queue) >= self.batch_size:
                                self.flush()
            except Exception as e:
                print(f"[-] Error reading {filepath}: {e}")

    def flush(self):
        if not self.queue:
            return

        batch = self.queue[: self.batch_size]
        self.queue = self.queue[self.batch_size :]
        self.last_flush = time.time()

        batch_url = f"{self.server_url}/api/v1/detection/batch"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = json.dumps(
            {
                "events": batch,
                "tenant_id": self.tenant_id,
                "agent_id": f"shipper-{HOSTNAME}",
            }
        ).encode("utf-8")

        req = urllib.request.Request(  # noqa: S310
            batch_url, data=payload, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:  # noqa: S310
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    ack_count = len(data.get("ack_ids", []))
                    alerts_count = data.get("alerts_generated", 0)
                    campaigns = data.get("correlated_campaigns", [])
                    print(
                        f"[+] Transmitted batch of {ack_count} events to SIEM. "
                        f"Generated: {alerts_count} alerts."
                    )
                    if campaigns:
                        for c in campaigns:
                            print(
                                f"\033[91m[CAMPAIGN DETECTED]\033[0m {c.get('title')}: {c.get('summary')}"
                            )
                    # Reset backoff on success
                    self.backoff_delay = 1.0
                    # After successful batch, attempt to drain any backlogged spool
                    self.drain_spool()
        except Exception as e:
            print(
                f"[-] Network failure to {batch_url}: {e}. Spooling {len(batch)} events to disk."
            )
            self._spool_events(batch)
            time.sleep(self.backoff_delay)
            self.backoff_delay = min(30.0, self.backoff_delay * 2.0)

    def _spool_events(self, events: list[dict]):
        """Persists unsent events to disk spool."""
        try:
            with open(self.spool_path, "a", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev) + "\n")
        except Exception as e:
            print(f"[-] Critical: Failed to write to disk spool: {e}")

    def drain_spool(self):
        """Reads persistent disk spool, replays queued events to SIEM, and truncates acknowledged items."""
        if not os.path.exists(self.spool_path) or os.path.getsize(self.spool_path) == 0:
            return

        try:
            with open(self.spool_path, encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            if not lines:
                return

            spooled_events = []
            for line in lines:
                try:
                    spooled_events.append(json.loads(line))
                except Exception:
                    pass

            if not spooled_events:
                open(self.spool_path, "w", encoding="utf-8").close()
                return

            print(
                f"[*] Replaying {len(spooled_events)} backlogged events from disk spool..."
            )
            batch = spooled_events[: self.batch_size]

            batch_url = f"{self.server_url}/api/v1/detection/batch"
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            payload = json.dumps(
                {
                    "events": batch,
                    "tenant_id": self.tenant_id,
                    "agent_id": f"shipper-{HOSTNAME}",
                }
            ).encode("utf-8")

            req = urllib.request.Request(  # noqa: S310
                batch_url, data=payload, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=8.0) as resp:  # noqa: S310
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    acked = len(data.get("ack_ids", []))
                    # Remove successfully sent events from spool
                    remaining = lines[len(batch) :]
                    with open(self.spool_path, "w", encoding="utf-8") as f:
                        for rem in remaining:
                            f.write(rem + "\n")
                    print(
                        f"[+] Successfully drained {len(batch)} spooled events ({acked} acknowledged, remaining: {len(remaining)})."
                    )
        except Exception as e:
            print(f"[-] Could not drain spool: {e}")

    def run(self):
        print("=" * 68)
        print("      LOGSENTRY SIEM — UNIVERSAL ENTERPRISE LOG SHIPPER         ")
        print("=" * 68)
        print(f" Host:        {HOSTNAME}")
        print(f" Target SIEM: {self.server_url}")
        print(f" Parser:      {self.parser_name}")
        print(f" Watching:    {self.file_patterns}")
        print(f" Checkpoint:  {self.checkpoint_path}")
        print(f" Disk Spool:  {self.spool_path}")
        print("=" * 68 + "\n")
        print("[+] Shipper active. Forwarding telemetry in real-time...\n")

        # Initial check to drain any existing backlog from previous runs
        self.drain_spool()

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
    parser.add_argument("--parser", default="nginx", help="Parser engine name")
    parser.add_argument(
        "--server",
        default="http://127.0.0.1:8000",
        help="Target LogSentry API endpoint",
    )
    parser.add_argument("--api-key", default=None, help="Agent ingestion API key")
    parser.add_argument(
        "--tenant-id", default="default", help="Enterprise workspace tenant identifier"
    )
    parser.add_argument(
        "--batch-size", type=int, default=50, help="Batch transmit size"
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
