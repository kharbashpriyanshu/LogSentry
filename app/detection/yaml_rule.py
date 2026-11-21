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

SIGMA_FIELD_ALIASES: dict[str, str] = {
    "cs-method": "method",
    "method": "method",
    "cs-uri-stem": "endpoint",
    "c-uri": "endpoint",
    "url": "endpoint",
    "endpoint": "endpoint",
    "c-ip": "source_ip",
    "sourceip": "source_ip",
    "source_ip": "source_ip",
    "src_ip": "source_ip",
    "sc-status": "status_code",
    "status": "status_code",
    "status_code": "status_code",
    "commandline": "command_line",
    "command_line": "command_line",
    "image": "process_name",
    "processname": "process_name",
    "process_name": "process_name",
    "user": "user",
    "targetusername": "user",
    "eventid": "event_id",
    "event_id": "event_id",
    "hostname": "hostname",
    "raw_log": "raw_log",
}


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

        # Map Sigma / YAML severity levels
        sev_str = str(data.get("severity") or data.get("level", "medium")).upper()
        if sev_str == "CRITICAL":
            self._severity = Severity.CRITICAL
        elif sev_str == "HIGH":
            self._severity = Severity.HIGH
        elif sev_str == "LOW":
            self._severity = Severity.LOW
        else:
            self._severity = Severity.MEDIUM

        # Parse tags for MITRE tactics and techniques
        self._mitre_technique = data.get("mitre_technique", "T1190")
        self._mitre_tactic = data.get("mitre_tactic", "Initial Access")
        tags = data.get("tags", [])
        if isinstance(tags, list):
            for tag in tags:
                tag_lower = str(tag).lower()
                if tag_lower.startswith("attack.t") and len(tag_lower) > 7:
                    self._mitre_technique = tag_lower.replace("attack.", "").upper()
                elif tag_lower.startswith("attack."):
                    self._mitre_tactic = (
                        tag_lower.replace("attack.", "").replace("_", " ").title()
                    )

        self._attack_type = data.get(
            "attack_type",
            (
                data.get("logsource", {}).get("category", "Web Attack")
                if isinstance(data.get("logsource"), dict)
                else "Web Attack"
            ),
        )
        self._recommendation = data.get(
            "recommendation", "Review request logs and block offending source IP."
        )
        self._risk_score = float(data.get("risk_score", 70.0))

        # Parse detection logic
        self._detection = data.get("detection", {})
        self._compiled_regexes: dict[str, re.Pattern] = {}
        self._init_detection()

    def _init_detection(self):
        for block_name in ("selection", "filter"):
            block = self._detection.get(block_name, {})
            if not isinstance(block, dict):
                continue
            for field, condition in block.items():
                if "|" in field:
                    _, modifier = field.split("|", 1)
                    if modifier in ("re", "regex"):
                        try:
                            self._compiled_regexes[f"{block_name}:{field}"] = (
                                re.compile(str(condition), re.IGNORECASE)
                            )
                        except Exception as e:
                            logger.error(f"Failed to compile regex for {field}: {e}")

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

    def _evaluate_criteria_block(
        self, block: dict[str, Any], block_name: str, event: LogEvent
    ) -> bool:
        """Evaluate a dictionary of field criteria against a LogEvent."""
        for field, criteria in block.items():
            if "|" in field:
                raw_attr, modifier = field.split("|", 1)
            else:
                raw_attr, modifier = field, "exact"

            attr_name = SIGMA_FIELD_ALIASES.get(raw_attr.lower(), raw_attr)
            event_val = getattr(event, attr_name, None)

            # If field is None on event, check raw_log as fallback if searching text
            if event_val is None:
                if modifier in ("contains", "startswith", "endswith", "re", "regex"):
                    event_val = event.raw_log
                else:
                    return False

            val_str = str(event_val).lower()

            if modifier == "contains":
                if isinstance(criteria, list):
                    if not any(str(c).lower() in val_str for c in criteria):
                        return False
                else:
                    if str(criteria).lower() not in val_str:
                        return False

            elif modifier in ("re", "regex"):
                pattern = self._compiled_regexes.get(f"{block_name}:{field}")
                if not pattern or not pattern.search(str(event_val)):
                    return False

            elif modifier == "exact":
                if isinstance(criteria, list):
                    if str(event_val) not in [str(c) for c in criteria]:
                        return False
                else:
                    if str(event_val) != str(criteria):
                        return False

            elif modifier == "startswith":
                if isinstance(criteria, list):
                    if not any(val_str.startswith(str(c).lower()) for c in criteria):
                        return False
                else:
                    if not val_str.startswith(str(criteria).lower()):
                        return False

            elif modifier == "endswith":
                if isinstance(criteria, list):
                    if not any(val_str.endswith(str(c).lower()) for c in criteria):
                        return False
                else:
                    if not val_str.endswith(str(criteria).lower()):
                        return False

        return True

    def match(self, event: LogEvent) -> bool:
        selection = self._detection.get("selection", {})
        if not selection or not isinstance(selection, dict):
            return False

        # Evaluate selection
        selection_match = self._evaluate_criteria_block(selection, "selection", event)
        if not selection_match:
            return False

        # Evaluate filter (if defined)
        filter_block = self._detection.get("filter", {})
        if filter_block and isinstance(filter_block, dict):
            filter_match = self._evaluate_criteria_block(filter_block, "filter", event)
            condition = str(
                self._detection.get("condition", "selection and not filter")
            ).lower()
            if "not filter" in condition and filter_match:
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
            tenant_id=event.tenant_id or "default",
            evidence={
                "endpoint": event.endpoint,
                "method": event.method,
                "status_code": event.status_code,
                "user": event.user,
                "command_line": event.command_line,
                "rule_file": self._file_path,
            },
            raw_log_reference=event.raw_log,
        )


class YamlRuleLoader:
    """Discovers, parses, and loads Sigma & YAML detection rules."""

    @classmethod
    def load_from_dict(
        cls, data: dict[str, Any], file_path: str | None = None
    ) -> YamlDetectionRule:
        rule = YamlDetectionRule(data, file_path=file_path)
        RuleRegistry.register_rule_instance(rule)
        return rule

    @classmethod
    def load_file(cls, file_path: str) -> YamlDetectionRule | None:
        try:
            with open(file_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return None
            return cls.load_from_dict(data, file_path=file_path)
        except Exception as e:
            logger.error(f"Failed to load YAML rule from {file_path}: {e}")
            return None

    @classmethod
    def load_directory(cls, dir_path: str) -> list[YamlDetectionRule]:
        rules = []
        if not os.path.exists(dir_path):
            return rules

        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    full_path = os.path.join(root, file)
                    rule = cls.load_file(full_path)
                    if rule:
                        rules.append(rule)
        logger.info(
            f"Loaded {len(rules)} YAML / Sigma detection rules from '{dir_path}'."
        )
        return rules
