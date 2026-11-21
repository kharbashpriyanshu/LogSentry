import json
import os
import time
import urllib.parse
from collections import defaultdict

from app.detection.engine import DetectionEngine
from app.parsers.factory import ParserFactory
from benchmark_dataset_generator import create_labeled_dataset


def benchmark_realworld_production_dataset(
    file_path: str = "sample_data/elastic_apache_10k.log",
):
    print("=" * 70)
    print("BENCHMARK 1: High-Volume Production Dataset (Elastic 10k Apache Logs)")
    print("=" * 70)

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return {}

    with open(file_path, encoding="utf-8", errors="ignore") as f:
        raw_lines = [l.strip() for l in f if l.strip()]

    total_lines = len(raw_lines)
    print(f"Total Log Records to Process: {total_lines:,}")

    parser = ParserFactory.get_parser("apache")
    engine = DetectionEngine()

    # Step 1: Parsing Benchmark
    t0 = time.perf_counter()
    parsed_events = []
    parse_failures = 0
    for line in raw_lines:
        ev = parser.parse_line(line)
        if ev:
            parsed_events.append(ev)
        else:
            parse_failures += 1
    t_parse = time.perf_counter() - t0

    parse_eps = total_lines / t_parse if t_parse > 0 else 0
    avg_parse_latency_us = (t_parse / total_lines) * 1_000_000

    print("\n[1] Parsing Performance:")
    print(f"    - Parse Time:               {t_parse:.4f} s")
    print(f"    - Parse Throughput:         {parse_eps:,.1f} events/sec")
    print(f"    - Avg Parse Latency:        {avg_parse_latency_us:.2f} µs/event")
    print(
        f"    - Successfully Parsed:      {len(parsed_events):,}/{total_lines:,} ({(len(parsed_events)/total_lines)*100:.2f}%)"
    )
    print(f"    - Parse Failures:           {parse_failures:,}")

    # Step 2: Detection Engine Benchmark
    t0 = time.perf_counter()
    alerts_triggered = []
    for ev in parsed_events:
        alerts = engine.process_event(ev)
        if alerts:
            alerts_triggered.extend(alerts)
    t_detect = time.perf_counter() - t0

    detect_eps = len(parsed_events) / t_detect if t_detect > 0 else 0
    avg_detect_latency_us = (t_detect / len(parsed_events)) * 1_000_000

    print("\n[2] Threat Detection Engine Performance:")
    print(f"    - Detection Engine Time:    {t_detect:.4f} s")
    print(f"    - Detection Throughput:     {detect_eps:,.1f} events/sec")
    print(f"    - Avg Detection Latency:    {avg_detect_latency_us:.2f} µs/event")
    print(f"    - Security Alerts Flagged:  {len(alerts_triggered):,}")

    # Total Pipeline Speed
    t_total = t_parse + t_detect
    total_eps = total_lines / t_total if t_total > 0 else 0
    avg_total_latency_us = (t_total / total_lines) * 1_000_000

    print("\n[3] Combined Ingestion + Detection Pipeline:")
    print(f"    - Total Time Elapsed:       {t_total:.4f} s")
    print(f"    - Overall Throughput:       {total_eps:,.1f} events/sec")
    print(
        f"    - End-to-End Latency:       {avg_total_latency_us:.2f} µs/event ({avg_total_latency_us/1000:.4f} ms)"
    )

    return {
        "dataset": "Elastic 10k Production Apache Logs",
        "total_lines": total_lines,
        "parsed_events": len(parsed_events),
        "total_time_seconds": t_total,
        "throughput_eps": total_eps,
        "avg_latency_microseconds": avg_total_latency_us,
        "alerts_flagged": len(alerts_triggered),
    }


def benchmark_labeled_accuracy_dataset():
    print("\n" + "=" * 70)
    print("BENCHMARK 2: Labeled Ground-Truth Evaluation (Accuracy & Confusion Matrix)")
    print("=" * 70)

    labeled_file = "sample_data/labeled_benchmark.json"
    if not os.path.exists(labeled_file):
        create_labeled_dataset(labeled_file)

    with open(labeled_file, encoding="utf-8") as f:
        data = json.load(f)

    total_events = len(data)
    print(f"Total Labeled Events: {total_events}")

    benign_count = sum(1 for d in data if d["label"] == "BENIGN")
    attack_count = sum(1 for d in data if d["label"] == "ATTACK")
    print(f"    - Benign Events: {benign_count}")
    print(f"    - Attack Events: {attack_count}")

    parser = ParserFactory.get_parser("apache")
    engine = DetectionEngine()

    tp = 0  # Real attack correctly detected
    fp = 0  # Benign incorrectly flagged as attack
    tn = 0  # Benign correctly passed
    fn = 0  # Real attack missed

    category_stats = defaultdict(lambda: {"total": 0, "detected": 0, "missed": 0})

    t0 = time.perf_counter()
    for item in data:
        raw = item["raw"]
        expected_label = item["label"]
        category = item["category"]

        category_stats[category]["total"] += 1

        ev = parser.parse_line(raw)
        if not ev:
            print(f"Parser error on: {raw}")
            continue

        # Real-world endpoints may be URL encoded; decode for payload matching
        if ev.endpoint:
            ev.endpoint = urllib.parse.unquote_plus(ev.endpoint)

        alerts = engine.process_event(ev)
        has_alert = len(alerts) > 0

        if expected_label == "ATTACK":
            if has_alert:
                tp += 1
                category_stats[category]["detected"] += 1
            else:
                fn += 1
                category_stats[category]["missed"] += 1
        else:  # BENIGN
            if has_alert:
                fp += 1
                category_stats[category]["missed"] += 1  # false positive
            else:
                tn += 1
                category_stats[category]["detected"] += 1  # correctly clean

    t_eval = time.perf_counter() - t0

    # Metrics calculation
    accuracy = (tp + tn) / total_events if total_events > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = (
        2 * (precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0
    )
    throughput = total_events / t_eval if t_eval > 0 else 0
    avg_latency_us = (t_eval / total_events) * 1_000_000

    print("\n[1] Performance & Timing:")
    print(f"    - Total Evaluation Time:    {t_eval:.4f} s")
    print(f"    - Evaluation Throughput:    {throughput:,.1f} events/sec")
    print(
        f"    - Avg Latency per Event:    {avg_latency_us:.2f} µs ({avg_latency_us/1000:.4f} ms)"
    )

    print("\n[2] Confusion Matrix:")
    print("    ┌─────────────────────────┬─────────────────────────┐")
    print(f"    │  True Positives (TP): {tp:3d}│ False Positives (FP): {fp:3d}│")
    print("    ├─────────────────────────┼─────────────────────────┤")
    print(f"    │ False Negatives (FN): {fn:3d}│  True Negatives (TN): {tn:3d}│")
    print("    └─────────────────────────┴─────────────────────────┘")

    print("\n[3] Core Accuracy Metrics:")
    print(f"    - Accuracy:                 {accuracy * 100:.2f}%")
    print(f"    - Precision:                {precision * 100:.2f}%")
    print(f"    - Recall (Detection Rate):  {recall * 100:.2f}%")
    print(f"    - F1-Score:                 {f1 * 100:.2f}%")

    print("\n[4] Attack Class Breakdown:")
    print(f"    {'Category':<20} {'Total':<8} {'Detected':<10} {'Detection Rate'}")
    print(f"    {'-'*20} {'-'*8} {'-'*10} {'-'*14}")
    for cat, stats in category_stats.items():
        rate = (stats["detected"] / stats["total"]) * 100 if stats["total"] > 0 else 0
        status_label = "Clean (TN)" if cat == "BENIGN" else f"{rate:.1f}%"
        print(
            f"    {cat:<20} {stats['total']:<8} {stats['detected']:<10} {status_label}"
        )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "throughput_eps": throughput,
        "avg_latency_us": avg_latency_us,
        "total_time_seconds": t_eval,
    }


if __name__ == "__main__":
    benchmark_realworld_production_dataset()
    benchmark_labeled_accuracy_dataset()
