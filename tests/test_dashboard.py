import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_dashboard_summary(db_session):
    response = client.get("/api/v1/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_alerts" in data
    assert "events_processed" in data

def test_dashboard_severity_distribution(db_session):
    response = client.get("/api/v1/dashboard/severity-distribution")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_dashboard_alert_trend(db_session):
    response = client.get("/api/v1/dashboard/alert-trend")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_dashboard_top_sources(db_session):
    response = client.get("/api/v1/dashboard/top-sources")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_websocket_connection():
    with client.websocket_connect("/api/v1/dashboard/ws/events") as websocket:
        # We can't easily trigger an event in the same test cleanly without an async task,
        # but we can verify the connection succeeds and stays open.
        pass
