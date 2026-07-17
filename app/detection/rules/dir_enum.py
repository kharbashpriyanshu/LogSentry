from app.detection.base import RegexDetectionRule
from app.schemas.severity import Severity
import re

DIR_ENUM_PATTERN = re.compile(r'(?i)(/admin|/login|/\.git|/backup|/config|/phpmyadmin)')

class DirectoryEnumerationRule(RegexDetectionRule):
    @property
    def rule_name(self) -> str: return "dir_enum"
    @property
    def rule_version(self) -> str: return "1.1.0"
    @property
    def description(self) -> str: return "Detects directory enumeration or sensitive file access."
    @property
    def severity(self) -> Severity: return Severity.LOW
    @property
    def pattern(self) -> re.Pattern: return DIR_ENUM_PATTERN
    @property
    def attack_type(self) -> str: return "Directory Enumeration"
    @property
    def mitre_technique(self) -> str: return "T1083"
    @property
    def mitre_tactic(self) -> str: return "Discovery"
    @property
    def recommendation(self) -> str: return "Monitor for excessive 404s from this IP. Ensure sensitive directories are protected."
    @property
    def risk_score(self) -> float: return 30.0
    @property
    def title(self) -> str: return "Directory Enumeration Attempt"
