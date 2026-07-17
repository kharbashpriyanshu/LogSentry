from abc import ABC, abstractmethod
from typing import Optional
import re
from app.schemas.log_event import LogEvent
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity
from app.config.settings import settings

class BaseRule(ABC):
    @property
    @abstractmethod
    def rule_name(self) -> str: pass
    
    @property
    @abstractmethod
    def rule_version(self) -> str: pass
    
    @property
    @abstractmethod
    def description(self) -> str: pass
    
    @property
    @abstractmethod
    def severity(self) -> Severity: pass

    @abstractmethod
    def match(self, event: LogEvent) -> bool:
        """Returns True if the event matches the rule."""
        pass
        
    @abstractmethod
    def generate_alert(self, event: LogEvent) -> DetectionAlert:
        """Generates an alert from the matched event."""
        pass

class RegexDetectionRule(BaseRule):
    """Base class for detection rules that rely on Regular Expressions against the endpoint."""
    
    @property
    @abstractmethod
    def pattern(self) -> re.Pattern: pass
    
    @property
    @abstractmethod
    def attack_type(self) -> str: pass
    
    @property
    @abstractmethod
    def mitre_technique(self) -> str: pass
    
    @property
    @abstractmethod
    def mitre_tactic(self) -> str: pass

    @property
    @abstractmethod
    def recommendation(self) -> str: pass
    
    @property
    @abstractmethod
    def risk_score(self) -> float: pass

    @property
    @abstractmethod
    def title(self) -> str: pass

    def match(self, event: LogEvent) -> bool:
        if not event.endpoint:
            return False
        return bool(self.pattern.search(event.endpoint))
        
    def generate_alert(self, event: LogEvent) -> DetectionAlert:
        return DetectionAlert(
            rule_name=self.rule_name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=settings.DETECTION_DEFAULT_CONFIDENCE,
            risk_score=self.risk_score,
            title=self.title,
            description=f"Potential {self.attack_type} attempt detected from {event.source_ip} targeting {event.endpoint}",
            source_ip=event.source_ip,
            endpoint=event.endpoint,
            attack_type=self.attack_type,
            mitre_technique=self.mitre_technique,
            mitre_tactic=self.mitre_tactic,
            recommendation=self.recommendation,
            evidence={"endpoint": event.endpoint, "method": event.method},
            raw_log_reference=event.raw_log
        )
