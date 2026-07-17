from app.detection.base import RegexDetectionRule
from app.schemas.severity import Severity
import re

PATH_TRAVERSAL_PATTERN = re.compile(r'(?i)(\.\./|\.\.\\|%2e%2e|/etc/passwd|c:\\windows\\)')

class PathTraversalRule(RegexDetectionRule):
    @property
    def rule_name(self) -> str: return "path_traversal"
    @property
    def rule_version(self) -> str: return "1.1.0"
    @property
    def description(self) -> str: return "Detects Path/Directory Traversal attempts."
    @property
    def severity(self) -> Severity: return Severity.HIGH
    @property
    def pattern(self) -> re.Pattern: return PATH_TRAVERSAL_PATTERN
    @property
    def attack_type(self) -> str: return "Path Traversal"
    @property
    def mitre_technique(self) -> str: return "T1190"
    @property
    def mitre_tactic(self) -> str: return "Initial Access"
    @property
    def recommendation(self) -> str: return "Normalize file paths before accessing system files. Prevent accessing paths outside the web root."
    @property
    def risk_score(self) -> float: return 75.0
    @property
    def title(self) -> str: return "Path Traversal Attempt"
