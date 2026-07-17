from app.detection.base import RegexDetectionRule
from app.schemas.severity import Severity
import re

XSS_PATTERN = re.compile(r'(?i)(<script>|javascript:|onerror=|alert\(|document\.cookie)')

class XSSRule(RegexDetectionRule):
    @property
    def rule_name(self) -> str: return "xss"
    @property
    def rule_version(self) -> str: return "1.1.0"
    @property
    def description(self) -> str: return "Detects Cross-Site Scripting (XSS) payloads."
    @property
    def severity(self) -> Severity: return Severity.MEDIUM
    @property
    def pattern(self) -> re.Pattern: return XSS_PATTERN
    @property
    def attack_type(self) -> str: return "XSS"
    @property
    def mitre_technique(self) -> str: return "T1190"
    @property
    def mitre_tactic(self) -> str: return "Initial Access"
    @property
    def recommendation(self) -> str: return "Encode user input on output and implement strict Content Security Policy (CSP)."
    @property
    def risk_score(self) -> float: return 60.0
    @property
    def title(self) -> str: return "Cross-Site Scripting (XSS) Detected"
