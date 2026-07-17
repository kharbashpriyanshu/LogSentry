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
    assert rule.match(create_event(endpoint="/admin/settings"))
    assert rule.match(create_event(endpoint="/.git/config"))
    assert not rule.match(create_event(endpoint="/public/style.css"))

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
