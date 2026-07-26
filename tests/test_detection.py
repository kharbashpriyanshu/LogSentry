import pytest
from datetime import datetime, timezone, timedelta
from app.schemas.log_event import LogEvent
from app.detection.registry import RuleRegistry
from app.detection.engine import DetectionEngine
from app.detection.rules.brute_force import BruteForceRule

def create_event(endpoint="/", status_code=200, source_ip="192.168.1.1", method="GET", ts=None):
    return LogEvent(
        timestamp=ts or datetime.now(timezone.utc),
        source_ip=source_ip,
        method=method,
        endpoint=endpoint,
        status_code=status_code,
        raw_log="dummy raw log",
        parser_name="dummy_parser"
    )

def test_sqli_rule():
    rule = RuleRegistry.get_rule("sqli")
    assert rule.match(create_event(endpoint="/?id=1' OR 1=1--"))
    assert rule.match(create_event(endpoint="/login?user=admin' UNION SELECT"))
    assert not rule.match(create_event(endpoint="/index.html"))

def test_xss_rule():
    rule = RuleRegistry.get_rule("xss")
    assert rule.match(create_event(endpoint="/?search=<script>alert(1)</script>"))
    assert not rule.match(create_event(endpoint="/search?q=hello"))

def test_path_traversal_rule():
    rule = RuleRegistry.get_rule("path_traversal")
    assert rule.match(create_event(endpoint="/download?file=../../../etc/passwd"))
    assert not rule.match(create_event(endpoint="/download?file=image.png"))

def test_cmd_injection_rule():
    rule = RuleRegistry.get_rule("cmd_injection")
    assert rule.match(create_event(endpoint="/ping?ip=127.0.0.1;cat /etc/passwd"))
    assert not rule.match(create_event(endpoint="/ping?ip=127.0.0.1"))

def test_dir_enum_rule():
    rule = RuleRegistry.get_rule("dir_enum")
    rule.threshold = 3
    rule.window_seconds = 60
    rule._state.clear()
    
    ip = "192.168.1.50"
    # Event 1: Single administrative request should NOT trigger alert
    assert not rule.match(create_event(endpoint="/admin/settings", source_ip=ip))
    # Event 2: Second unique path should NOT trigger alert
    assert not rule.match(create_event(endpoint="/.git/config", source_ip=ip))
    # Event 3: Third unique path triggers alert
    assert rule.match(create_event(endpoint="/backup", source_ip=ip))
    
    # Generate alert and verify evidence
    alert = rule.generate_alert(create_event(endpoint="/backup", source_ip=ip))
    assert alert.attack_type == "Directory Enumeration"
    assert alert.evidence["unique_paths_probed"] == 3
    assert "/admin/settings" in alert.evidence["sample_paths"]
    assert "/.git/config" in alert.evidence["sample_paths"]
    assert "/backup" in alert.evidence["sample_paths"]
    assert not rule.match(create_event(endpoint="/public/style.css", source_ip=ip))

def test_dir_enum_normal_traffic():
    rule = RuleRegistry.get_rule("dir_enum")
    rule.threshold = 3
    rule.window_seconds = 60
    rule._state.clear()

    ip = "10.0.0.5"
    normal_endpoints = [
        "/",
        "/index.html",
        "/robots.txt",
        "/favicon.ico",
        "/css/app.css",
        "/js/app.js",
        "/images/logo.png",
        "/about",
        "/contact"
    ]
    for ep in normal_endpoints:
        assert not rule.match(create_event(endpoint=ep, source_ip=ip))

def test_dir_enum_robots_txt_handling():
    rule = RuleRegistry.get_rule("dir_enum")
    rule.threshold = 3
    rule.window_seconds = 60
    rule._state.clear()

    ip = "10.10.10.10"
    # robots.txt alone MUST NOT produce Directory Enumeration
    for _ in range(5):
        assert not rule.match(create_event(endpoint="/robots.txt", source_ip=ip))

    # However, in a reconnaissance sequence, it contributes to overall detection
    rule._state.clear()
    assert not rule.match(create_event(endpoint="/robots.txt", source_ip=ip))
    assert not rule.match(create_event(endpoint="/admin", source_ip=ip))
    assert rule.match(create_event(endpoint="/backup", source_ip=ip))
    alert = rule.generate_alert(create_event(endpoint="/backup", source_ip=ip))
    assert "/robots.txt" in alert.evidence["sample_paths"]

def test_dir_enum_false_positive_protection():
    rule = RuleRegistry.get_rule("dir_enum")
    rule.threshold = 3
    rule.window_seconds = 60
    rule._state.clear()

    # Single /admin request from IP 1
    assert not rule.match(create_event(endpoint="/admin", source_ip="1.1.1.1"))
    # Single /robots.txt request from IP 2
    assert not rule.match(create_event(endpoint="/robots.txt", source_ip="2.2.2.2"))
    # Single 404 request from IP 3
    assert not rule.match(create_event(endpoint="/nonexistent", status_code=404, source_ip="3.3.3.3"))

def test_dir_enum_mixed_traffic():
    dir_rule = RuleRegistry.get_rule("dir_enum")
    xss_rule = RuleRegistry.get_rule("xss")
    sqli_rule = RuleRegistry.get_rule("sqli")
    dir_rule._state.clear()

    ip = "172.16.0.50"
    xss_event = create_event(endpoint="/search?q=<script>alert(1)</script>", source_ip=ip)
    sqli_event = create_event(endpoint="/products?id=1' UNION SELECT", source_ip=ip)

    # Specific attack rules fire
    assert xss_rule.match(xss_event)
    assert sqli_rule.match(sqli_event)
    # Ordinary endpoint base paths should not count towards dir_enum
    assert not dir_rule.match(xss_event)
    assert not dir_rule.match(sqli_event)

def test_brute_force_rule():
    rule = RuleRegistry.get_rule("brute_force")
    rule.threshold = 3
    rule.window_seconds = 60
    rule._state.clear() # Reset state for test isolation
    
    ip = "10.0.0.99"
    # Event 1
    assert not rule.match(create_event(endpoint="/login", status_code=401, source_ip=ip))
    # Event 2
    assert not rule.match(create_event(endpoint="/login", status_code=401, source_ip=ip))
    # Event 3 (threshold reached)
    assert rule.match(create_event(endpoint="/login", status_code=401, source_ip=ip))
    
    # Event 4 (state should be reset, so false)
    assert not rule.match(create_event(endpoint="/login", status_code=401, source_ip=ip))

def test_brute_force_cleanup():
    rule = BruteForceRule()
    rule.threshold = 3
    rule.window_seconds = 60
    
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(seconds=120)
    
    # Inject a stale IP directly into state
    rule._state["stale_ip"] = [old_time]
    
    # Simulate a new event that triggers cleanup because _cleanup_counter > 1000
    rule._cleanup_counter = 1001
    rule.match(create_event(endpoint="/login", status_code=401, source_ip="active_ip", ts=now))
    
    # Stale IP should be removed entirely
    assert "stale_ip" not in rule._state
    assert rule._cleanup_counter == 0

def test_detection_engine():
    engine = DetectionEngine()
    event_sqli = create_event(endpoint="/?q=1 OR 1=1")
    event_clean = create_event(endpoint="/")
    
    alerts = engine.process_events([event_sqli, event_clean])
    assert len(alerts) == 1
    assert alerts[0].rule_name == "sqli"

def test_malformed_event_handling():
    engine = DetectionEngine()
    event = create_event(endpoint=None)
    alerts = engine.process_event(event)
    assert len(alerts) == 0

def test_rule_registry_invalid():
    with pytest.raises(ValueError):
        RuleRegistry.get_rule("non_existent_rule")
