import logging
import os
import re
from typing import Any

import yaml

from app.config.settings import settings
from app.detection.base import BaseRule
from app.detection.registry import RuleRegistry
from app.schemas.detection_alert import DetectionAlert
from app.schemas.log_event import LogEvent
from app.schemas.severity import Severity

logger = logging.getLogger(__name__)


class YamlDetectionRule(BaseRule):
    """
    Dynamic detection rule defined via industry-standard YAML / Sigma syntax.
    Enables SOC teams to author and update rules on the fly without changing Python code.
    """

    def __init__(self, data: dict[str, Any], file_path: str | None = None):
        self._raw_data = data
        self._file_path = file_path

        self._title = data.get("title", "Untitled Sigma Rule")
        self._name = (
            data.get("name") or data.get("id") or self._title.lower().replace(" ", "_")
        )
        self._version = str(data.get("version", "1.0.0"))
        self._description = data.get(
            "description", "Dynamic YAML / Sigma Detection Rule"
        )

        # Map severity
        sev_str = str(data.get("severity") or data.get("level", "medium")).upper()
        if sev_str == "CRITICAL":
            self._severity = Severity.CRITICAL
        elif sev_str == "HIGH":
            self._severity = Severity.HIGH
        elif sev_str == "LOW":
            self._severity = Severity.LOW
        else:
            self._severity = Severity.MEDIUM

        self._attack_type = data.get("attack_type", data.get("category", "Web Attack"))
        self._mitre_technique = data.get("mitre_technique", "T1190")
        self._mitre_tactic = data.get("mitre_tactic", "Initial Access")
        self._recommendation = data.get(
            "recommendation", "Review request logs and block offending source IP."
        )
        self._risk_score = float(data.get("risk_score", 70.0))

        # Parse detection logic
        self._detection = data.get("detection", {})
        self._compiled_regexes: dict[str, re.Pattern] = {}
        self._init_detection()

    def _init_detection(self):
        selection = self._detection.get("selection", {})
        for field, condition in selection.items():
            if "|" in field:
                attr, modifier = field.split("|", 1)
                if modifier in ("re", "regex"):
                    try:
                        self._compiled_regexes[field] = re.compile(
                            str(condition), re.IGNORECASE
                        )
                    except Exception as e:
                        logger.error(f"Failed to compile regex for field {field}: {e}")

    @property
    def rule_name(self) -> str:
        return self._name

    @property
    def rule_version(self) -> str:
        return self._version

    @property
    def description(self) -> str:
        return self._description

    @property
    def severity(self) -> Severity:
        return self._severity

    @property
    def attack_type(self) -> str:
        return self._attack_type

    @property
    def mitre_technique(self) -> str:
        return self._mitre_technique

    @property
    def mitre_tactic(self) -> str:
        return self._mitre_tactic

    @property
    def recommendation(self) -> str:
        return self._recommendation

    @property
    def risk_score(self) -> float:
        return self._risk_score

    @property
    def title(self) -> str:
        return self._title

    def match(self, event: LogEvent) -> bool:
        selection = self._detection.get("selection", {})
        if not selection:
            return False

        for field, criteria in selection.items():
            if "|" in field:
                attr_name, modifier = field.split("|", 1)
            else:
                attr_name, modifier = field, "exact"

            event_val = getattr(event, attr_name, None)
            if event_val is None:
                return False

            if modifier == "contains":
                val_str = str(event_val).lower()
                if isinstance(criteria, list):
                    if not any(str(c).lower() in val_str for c in criteria):
                        return False
                else:
                    if str(criteria).lower() not in val_str:
                        return False

            elif modifier in ("re", "regex"):
                pattern = self._compiled_regexes.get(field)
                if not pattern or not pattern.search(str(event_val)):
                    return False

            elif modifier == "exact":
                if isinstance(criteria, list):
                    if event_val not in criteria:
                        return False
                else:
                    if event_val != criteria:
                        return False

            elif modifier == "startswith":
                val_str = str(event_val).lower()
                if isinstance(criteria, list):
                    if not any(val_str.startswith(str(c).lower()) for c in criteria):
                        return False
                else:
                    if not val_str.startswith(str(criteria).lower()):
                        return False

        return True

    def generate_alert(self, event: LogEvent) -> DetectionAlert:
        return DetectionAlert(
            rule_name=self.rule_name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=settings.DETECTION_DEFAULT_CONFIDENCE,
            risk_score=self.risk_score,
            title=self.title,
            description=f"Sigma detection [{self.title}] triggered by {event.source_ip} targeting {event.endpoint}",
            source_ip=event.source_ip,
            endpoint=event.endpoint,
            attack_type=self.attack_type,
            mitre_technique=self.mitre_technique,
            mitre_tactic=self.mitre_tactic,
            recommendation=self.recommendation,
            evidence={
                "endpoint": event.endpoint,
                "method": event.method,
                "status_code": event.status_code,
                "user_agent": event.user_agent,
                "rule_format": "sigma/yaml",
            },
            raw_log_reference=event.raw_log,
        )


class YamlRuleLoader:
    """Discovers, parses, and registers dynamic YAML/Sigma rules."""

    @staticmethod
    def load_from_file(file_path: str) -> YamlDetectionRule | None:
        try:
            with open(file_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return None
            rule = YamlDetectionRule(data, file_path=file_path)
            RuleRegistry.register_rule_instance(rule)
            return rule
        except Exception as e:
            logger.error(f"Error loading rule from {file_path}: {e}")
            return None

    @staticmethod
    def load_directory(directory: str = "rules") -> list[YamlDetectionRule]:
        loaded_rules = []
        if not os.path.exists(directory):
            return loaded_rules

        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".yml") or file.endswith(".yaml"):
                    full_path = os.path.join(root, file)
                    rule = YamlRuleLoader.load_from_file(full_path)
                    if rule:
                        loaded_rules.append(rule)

        logger.info(
            f"Loaded {len(loaded_rules)} dynamic YAML/Sigma rules from '{directory}'."
        )
        return loaded_rules
