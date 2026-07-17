from app.detection.base import RegexDetectionRule
from app.schemas.severity import Severity
import re

SQLI_PATTERN = re.compile(r'(?i)(UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|SLEEP\(|information_schema)')

class SQLInjectionRule(RegexDetectionRule):
    @property
    def rule_name(self) -> str: return "sqli"
    @property
    def rule_version(self) -> str: return "1.1.0"
    @property
    def description(self) -> str: return "Detects basic SQL Injection attempts in URL parameters."
    @property
    def severity(self) -> Severity: return Severity.HIGH
    @property
    def pattern(self) -> re.Pattern: return SQLI_PATTERN
    @property
    def attack_type(self) -> str: return "SQL Injection"
    @property
    def mitre_technique(self) -> str: return "T1190"
    @property
    def mitre_tactic(self) -> str: return "Initial Access"
    @property
    def recommendation(self) -> str: return "Sanitize database inputs and use parameterized queries."
    @property
    def risk_score(self) -> float: return 85.0
    @property
    def title(self) -> str: return "SQL Injection Attempt Detected"
