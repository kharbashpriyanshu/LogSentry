from fastapi import Depends
from app.services.parsing_service import ParsingService
from app.services.detection_service import DetectionService
from app.services.ai_service import AIService
from app.detection.engine import DetectionEngine
from app.ai.providers import OpenAIProvider, GeminiProvider, OllamaProvider
from app.enrichment.providers import AbuseIPDBProvider, OTXProvider, MitreProvider
from app.enrichment.cache import InMemoryCache
from app.services.enrichment_service import EnrichmentService
from app.reports.service import ReportingService
from app.reports.templates import (
    ExecutiveReportTemplate,
    TechnicalReportTemplate,
    IncidentReportTemplate,
)
from app.reports.timeline import TimelineEngine
from app.config.settings import settings

# Dependency Injection Singletons
_detection_engine = DetectionEngine()

# Initialize AI Provider
def _init_ai_provider():
    provider = settings.AI_PROVIDER.lower()
    if provider == "gemini":
        return GeminiProvider()
    elif provider == "ollama":
        return OllamaProvider()
    return OpenAIProvider()

_ai_provider = _init_ai_provider()

# Initialize Enrichment
_enrichment_cache = InMemoryCache(ttl_seconds=settings.ENRICHMENT_CACHE_TTL)
_enrichment_providers = [
    AbuseIPDBProvider(),
    OTXProvider(),
    MitreProvider()
]

def get_parsing_service() -> ParsingService:
    return ParsingService()

def get_detection_engine() -> DetectionEngine:
    return _detection_engine

def get_detection_service(engine: DetectionEngine = Depends(get_detection_engine)) -> DetectionService:
    return DetectionService(engine)

def get_ai_service() -> AIService:
    return AIService(_ai_provider)

def get_enrichment_service() -> EnrichmentService:
    return EnrichmentService(_enrichment_providers, _enrichment_cache)


# ---------------------------------------------------------------------------
# Reporting Service
# ---------------------------------------------------------------------------

_reporting_service = ReportingService(
    executive_template=ExecutiveReportTemplate(),
    technical_template=TechnicalReportTemplate(),
    incident_template=IncidentReportTemplate(),
    timeline_engine=TimelineEngine(),
)


def get_reporting_service() -> ReportingService:
    return _reporting_service
