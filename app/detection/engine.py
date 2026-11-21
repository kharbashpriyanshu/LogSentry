import logging

# Import rules to trigger registration
import app.detection.rules  # noqa: F401
from app.config.settings import settings
from app.detection.base import RegexDetectionRule
from app.detection.registry import RuleRegistry
from app.detection.yaml_rule import YamlDetectionRule, YamlRuleLoader
from app.schemas.detection_alert import DetectionAlert
from app.schemas.log_event import LogEvent

logger = logging.getLogger(__name__)

# Trigger characters for fast-path regex bypass
_TRIGGER_CHARS = set("'\"<>;|%\\=`()$")


class DetectionEngine:
    """Core engine that processes LogEvents against registered rules with fast pre-filtering."""

    def __init__(self, load_yaml_rules: bool = True):
        # Load rules configured as enabled in settings
        enabled_rule_names = settings.DETECTION_ENABLED_RULES
        self.rules = RuleRegistry.get_rules_by_names(enabled_rule_names)

        # Load dynamic YAML / Sigma rules from rules/ directory
        if load_yaml_rules:
            try:
                yaml_rules = YamlRuleLoader.load_directory("rules")
                for yr in yaml_rules:
                    if yr not in self.rules:
                        self.rules.append(yr)
            except Exception as e:
                logger.error(f"Failed to auto-load YAML rules: {e}")

        self.regex_rules = [
            r
            for r in self.rules
            if isinstance(r, (RegexDetectionRule, YamlDetectionRule))
        ]
        self.behavioral_rules = [
            r
            for r in self.rules
            if not isinstance(r, (RegexDetectionRule, YamlDetectionRule))
        ]
        logger.info(
            f"DetectionEngine initialized with {len(self.rules)} rules "
            f"({len(self.regex_rules)} regex/sigma, {len(self.behavioral_rules)} behavioral)."
        )

    def process_event(self, event: LogEvent) -> list[DetectionAlert]:
        """Process a single LogEvent through all enabled rules with fast pre-filtering."""
        alerts = []
        endpoint = event.endpoint or ""

        # Field-aware pre-filtering across endpoint, raw_log, and command_line
        searchable_context = f"{endpoint} {event.raw_log or ''} {getattr(event, 'command_line', '') or ''}"
        has_triggers = (
            any(c in _TRIGGER_CHARS for c in searchable_context)
            or ".." in searchable_context
            or any(
                kw in searchable_context.upper()
                for kw in (
                    "UNION",
                    "SELECT",
                    "DROP",
                    "SCRIPT",
                    "EXEC",
                    "POWERSHELL",
                    "JNDI",
                    "CAT",
                    "PASSWD",
                )
            )
        )

        # 1. Evaluate regex & Sigma rules
        for rule in self.regex_rules:
            try:
                # Fast pre-filtering: skip heavy native regex rules only if no trigger characters anywhere in event context
                if isinstance(rule, RegexDetectionRule) and not has_triggers:
                    continue
                if rule.match(event):
                    alert = rule.generate_alert(event)
                    alerts.append(alert)
                    logger.warning(
                        f"Detection Engine Alert triggered: {alert.rule_name} - {alert.title}"
                    )
            except Exception as e:
                # Isolate rule failures to prevent engine crash
                logger.error(
                    f"Rule '{rule.rule_name}' failed during processing: {e}",
                    exc_info=True,
                )

        # 2. Evaluate behavioral / stateful rules (dir_enum, brute_force)
        for rule in self.behavioral_rules:
            try:
                # Fast path: brute force only needs evaluation on failed authentication codes
                if rule.rule_name == "brute_force" and event.status_code not in (
                    401,
                    403,
                ):
                    continue
                if rule.match(event):
                    alert = rule.generate_alert(event)
                    alerts.append(alert)
                    logger.warning(
                        f"Detection Engine Alert triggered: {alert.rule_name} - {alert.title}"
                    )
            except Exception as e:
                logger.error(
                    f"Rule '{rule.rule_name}' failed during processing: {e}",
                    exc_info=True,
                )

        return alerts

    def process_events(self, events: list[LogEvent]) -> list[DetectionAlert]:
        """Process a batch of LogEvents."""
        alerts = []
        for event in events:
            alerts.extend(self.process_event(event))
        return alerts
