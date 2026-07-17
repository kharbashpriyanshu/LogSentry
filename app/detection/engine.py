from typing import List
import logging
from app.schemas.log_event import LogEvent
from app.schemas.detection_alert import DetectionAlert
from app.detection.registry import RuleRegistry
from app.config.settings import settings

# Import rules to trigger registration
import app.detection.rules

logger = logging.getLogger(__name__)

class DetectionEngine:
    """Core engine that processes LogEvents against registered rules."""
    
    def __init__(self):
        # Load rules configured as enabled in settings
        enabled_rule_names = settings.DETECTION_ENABLED_RULES
        self.rules = RuleRegistry.get_rules_by_names(enabled_rule_names)
        logger.info(f"DetectionEngine initialized with {len(self.rules)} rules enabled.")
        
    def process_event(self, event: LogEvent) -> List[DetectionAlert]:
        """Process a single LogEvent through all enabled rules."""
        alerts = []
        for rule in self.rules:
            try:
                if rule.match(event):
                    alert = rule.generate_alert(event)
                    alerts.append(alert)
                    logger.warning(f"Detection Engine Alert triggered: {alert.rule_name} - {alert.title}")
            except Exception as e:
                # Isolate rule failures to prevent engine crash
                logger.error(f"Rule '{rule.rule_name}' failed during processing: {e}", exc_info=True)
        return alerts

    def process_events(self, events: List[LogEvent]) -> List[DetectionAlert]:
        """Process a batch of LogEvents."""
        alerts = []
        for event in events:
            alerts.extend(self.process_event(event))
        return alerts
