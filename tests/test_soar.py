from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity
from app.services.soar_service import SOARService


def test_soar_quarantine_and_release():
    ip = "198.51.100.44"
    record = SOARService.quarantine_ip(
        ip=ip,
        reason="Automated Brute Force Containment",
        duration_seconds=3600,
        severity="HIGH",
        analyst="TEST_RUNNER",
    )
    assert record["ip"] == ip
    assert SOARService.is_ip_quarantined(ip) is True

    # List quarantines
    active = SOARService.get_active_quarantines()
    assert any(h["ip"] == ip for h in active)

    # Release
    released = SOARService.release_ip(ip, analyst="admin", reason="Test completed")
    assert released is True
    assert SOARService.is_ip_quarantined(ip) is False


def test_soar_auto_containment_critical():
    alert = DetectionAlert(
        rule_name="cmd_injection",
        rule_version="1.0.0",
        severity=Severity.CRITICAL,
        confidence=0.95,
        risk_score=95.0,
        title="OS Command Injection",
        description="Critical shell injection",
        source_ip="203.0.113.77",
        endpoint="/ping?ip=127.0.0.1;cat /etc/passwd",
        attack_type="Command Injection",
        mitre_technique="T1059",
        mitre_tactic="Execution",
        recommendation="Isolate IP",
        evidence={},
        raw_log_reference="dummy",
    )
    res = SOARService.evaluate_auto_containment(alert)
    assert res is not None
    assert res["ip"] == "203.0.113.77"
    assert SOARService.is_ip_quarantined("203.0.113.77") is True

    # Cleanup
    SOARService.release_ip("203.0.113.77")
