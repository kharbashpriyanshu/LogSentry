from app.detection.base import RegexDetectionRule
from app.schemas.severity import Severity
import re

CMD_INJECTION_PATTERN = re.compile(r'(?i)(;|&&|\|\||\||\$\(\s*.*?\)|\`.*?\`|wget|curl|nc\s)')

class CommandInjectionRule(RegexDetectionRule):
    @property
    def rule_name(self) -> str: return "cmd_injection"
    @property
    def rule_version(self) -> str: return "1.1.0"
    @property
    def description(self) -> str: return "Detects OS Command Injection attempts."
    @property
    def severity(self) -> Severity: return Severity.CRITICAL
    @property
    def pattern(self) -> re.Pattern: return CMD_INJECTION_PATTERN
    @property
    def attack_type(self) -> str: return "Command Injection"
    @property
    def mitre_technique(self) -> str: return "T1059"
    @property
    def mitre_tactic(self) -> str: return "Execution"
    @property
    def recommendation(self) -> str: return "Avoid calling OS commands directly. If necessary, use safe APIs and strictly validate arguments."
    @property
    def risk_score(self) -> float: return 95.0
    @property
    def title(self) -> str: return "OS Command Injection Attempt"
