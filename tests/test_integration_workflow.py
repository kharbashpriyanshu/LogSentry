import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_full_incident_lifecycle(db_session):
    # 1. Post a malicious log
    log_content = b'127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /?id=1&q=information_schema HTTP/1.0" 200 2326 "-" "-"\n'
    response = client.post(
        "/api/v1/detection/analyze-file",
        data={"parser_name": "apache"},
        files={"file": ("test.log", log_content, "text/plain")}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["alerts"]) > 0
    alert_id = data["alerts"][0]["alert_id"]
    
    # 2. Assign Analyst & Set Investigating
    response = client.patch(f"/api/v1/alerts/{alert_id}", json={
        "assignee": "analyst_bob",
        "status": "INVESTIGATING"
    })
    assert response.status_code == 200
    alert = response.json()
    assert alert["assignee"] == "analyst_bob"
    assert alert["status"] == "INVESTIGATING"
    
    # 3. Escalate Alert to Incident
    response = client.post("/api/v1/incidents", json={
        "title": "SQL Injection Attack",
        "severity": "critical",
        "alert_ids": [alert_id]
    })
    assert response.status_code == 201
    incident = response.json()
    incident_id = incident["id"]
    assert len(incident["alert_ids"]) == 1
    assert incident["alert_ids"][0] == alert_id
    
    # 4. Update Incident
    response = client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "investigating",
        "assignee": "analyst_bob"
    })
    assert response.status_code == 200
    incident = response.json()
    assert incident["status"] == "investigating"
    assert incident["assignee"] == "analyst_bob"
    
    # 5. Resolve Incident
    response = client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "resolved"
    })
    assert response.status_code == 200
    incident = response.json()
    assert incident["status"] == "resolved"
    
    # 6. Retrieve Timeline
    response = client.get(f"/api/v1/incidents/{incident_id}/timeline")
    assert response.status_code == 200
    timeline = response.json()
    
    # Assert timeline has events
    assert len(timeline) >= 4 # created, status_changed, assigned, escalated
    actions = [event["action"] for event in timeline]
    assert "created" in actions
    assert "status_changed" in actions
    assert "assigned" in actions
