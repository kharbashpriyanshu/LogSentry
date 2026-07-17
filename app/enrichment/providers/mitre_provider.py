import logging
from typing import Optional, Dict
from app.enrichment.providers.base_provider import BaseThreatProvider
from app.schemas.detection_alert import DetectionAlert
from app.enrichment.models import ThreatEnrichment
from app.config.settings import settings

logger = logging.getLogger(__name__)

# Local static mapping for sprint 5 requirements
MITRE_MAPPING: Dict[str, dict] = {
    "T1190": {"technique": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1505": {"technique": "Server Software Component", "tactic": "Persistence"},
    "T1059": {"technique": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1110": {"technique": "Brute Force", "tactic": "Credential Access"},
    "T1083": {"technique": "File and Directory Discovery", "tactic": "Discovery"},
}

class MitreProvider(BaseThreatProvider):
    @property
    def provider_name(self) -> str:
        return "mitre"

    def health(self) -> bool:
        return settings.ENABLE_MITRE

    def enrich(self, alert: DetectionAlert) -> Optional[ThreatEnrichment]:
        if not self.health():
            return None
            
        technique_id = alert.mitre_technique
        if not technique_id or technique_id not in MITRE_MAPPING:
            return None
            
        mapping = MITRE_MAPPING[technique_id]
        
        return ThreatEnrichment(
            provider=self.provider_name,
            mitre_technique=mapping["technique"],
            mitre_tactic=mapping["tactic"],
            references=[f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"]
        )
