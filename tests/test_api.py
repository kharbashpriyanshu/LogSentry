import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "parsers_available" in data
    
    # Check headers (Middleware)
    assert "x-correlation-id" in response.headers
    assert "x-process-time" in response.headers

def test_parse_line_success():
    payload = {
        "parser_name": "apache",
        "log_line": '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 2326 "-" "-"'
    }
    response = client.post("/api/v1/parser/parse-line", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["event"]["source_ip"] == "127.0.0.1"

def test_parse_line_invalid_parser():
    payload = {
        "parser_name": "unknown",
        "log_line": "garbage"
    }
    response = client.post("/api/v1/parser/parse-line", json=payload)
    assert response.status_code == 400
    assert response.json()["error"] == "Unsupported Parser"

def test_parse_line_validation_error():
    payload = {
        "parser_name": "apache"
        # missing log_line
    }
    response = client.post("/api/v1/parser/parse-line", json=payload)
    assert response.status_code == 422
    assert response.json()["error"] == "Validation Error"

def test_parse_file_success(tmp_path):
    log_content = b'127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 2326 "-" "-"\n'
    file_path = tmp_path / "test.log"
    file_path.write_bytes(log_content)
    
    with open(file_path, "rb") as f:
        response = client.post(
            "/api/v1/parser/parse-file",
            data={"parser_name": "apache"},
            files={"file": ("test.log", f, "text/plain")}
        )
        
    assert response.status_code == 200
    data = response.json()
    assert data["total_lines_processed"] == 1
    assert data["successful_parses"] == 1
    assert len(data["events"]) == 1

def test_detection_analyze():
    # Construct a raw event dictionary bypassing the parser
    event_payload = {
        "timestamp": "2024-01-01T12:00:00Z",
        "source_ip": "1.1.1.1",
        "method": "GET",
        "endpoint": "/?id=1 UNION SELECT",
        "protocol": "HTTP/1.1",
        "status_code": 200,
        "raw_log": "test",
        "parser_name": "test"
    }
    response = client.post("/api/v1/detection/analyze", json={"event": event_payload})
    assert response.status_code == 200
    data = response.json()
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["rule_name"] == "sqli"

def test_alerts_example():
    response = client.get("/api/v1/alerts/example")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["attack_type"] == "SQL Injection"
