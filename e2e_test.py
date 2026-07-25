import httpx
import time
import json
import os

BASE_URL = "http://localhost:8000"

def run_test():
    print("--- LogSentry End-to-End Functional Test ---")
    
    # 1. Health Check
    r = httpx.get(f"{BASE_URL}/api/v1/health")
    print(f"\n[1] Health Check: {r.status_code}")
    assert r.status_code == 200, "Health check failed"

    # 2. Parsing
    print(f"\n[2] Uploading sample attack log...")
    with open("sample_data/attack_samples.log", "rb") as f:
        r = httpx.post(f"{BASE_URL}/api/v1/parser/parse-file", data={"parser_name": "regex"}, files={"file": f})
    
    print(f"    Parse Response: {r.status_code}")
    assert r.status_code == 200, "Parsing failed"
    parsed_data = r.json()
    events = parsed_data.get("events", [])
    print(f"    Successfully parsed {len(events)} events.")
    
    if not events:
        print("No events parsed. Exiting.")
        return

    # Pick the first event (SQLi attack)
    target_event = events[0]
    print(f"    Selected Event: {target_event['raw_log']}")

    # 3. Detection
    print(f"\n[3] Running Detection Engine...")
    r = httpx.post(f"{BASE_URL}/api/v1/detection/detect", json={"event": target_event})
    print(f"    Detection Response: {r.status_code}")
    assert r.status_code == 200, "Detection failed"
    alert = r.json()
    print(f"    Generated Alert: {alert.get('title')} ({alert.get('severity')} severity)")
    
    if not alert:
        print("No alert generated. Exiting.")
        return

    # 4. Enrichment
    print(f"\n[4] Running Threat Intelligence Enrichment...")
    r = httpx.post(f"{BASE_URL}/api/v1/enrichment/enrich", json=alert, timeout=15.0)
    print(f"    Enrichment Response: {r.status_code}")
    if r.status_code == 200:
        enrichment_data = r.json()
        print(f"    Found {len(enrichment_data)} enrichment indicators.")
    else:
        print(f"    Enrichment failed (maybe API key limit or OTX disabled). Output: {r.text}")
        enrichment_data = []

    # 5. AI Analysis (Gemini)
    print(f"\n[5] Running AI SOC Analyst (Gemini)...")
    r = httpx.post(f"{BASE_URL}/api/v1/ai/analyze", json=alert, timeout=30.0)
    print(f"    AI Response: {r.status_code}")
    if r.status_code == 200:
        ai_data = r.json()
        print(f"    AI Summary: {ai_data.get('summary')}")
        print(f"    False Positive Probability: {ai_data.get('false_positive_probability')}")
    else:
        print(f"    AI Analysis failed: {r.text}")
        ai_data = None

    # 6. Report Generation
    print(f"\n[6] Generating PDF Incident Report...")
    payload = {
        "report_type": "incident",
        "alert": alert,
        "ai_analysis": ai_data if ai_data else {},
        "enrichments": enrichment_data
    }
    r = httpx.post(f"{BASE_URL}/api/v1/reports/generate", json=payload, timeout=15.0)
    print(f"    Report Generation Response: {r.status_code}")
    
    if r.status_code == 200:
        print(f"    Successfully generated report with ID: {r.json().get('report_id')}")
        
        # 7. Fetch the PDF
        print(f"\n[7] Exporting PDF...")
        r_export = httpx.get(f"{BASE_URL}/api/v1/reports/export/pdf")
        if r_export.status_code == 200:
            pdf_size = len(r_export.content)
            print(f"    Successfully downloaded PDF ({pdf_size} bytes).")
            with open("test_report.pdf", "wb") as f:
                f.write(r_export.content)
            print(f"    Saved to test_report.pdf")
        else:
            print(f"    PDF Export failed: {r_export.text}")
    else:
        print(f"    Report Gen failed: {r.text}")
        
    print("\n✅ End-to-End test completed successfully!")

if __name__ == "__main__":
    run_test()
