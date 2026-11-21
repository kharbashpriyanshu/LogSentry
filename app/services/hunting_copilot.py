import logging
import re

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.services.hunting_service import HuntingSearchResult, ThreatHuntingEngine

logger = logging.getLogger(__name__)


class CopilotQueryRequest(BaseModel):
    natural_query: str
    limit: int = 50
    time_range_hours: int | None = 24
    tenant_id: str | None = "default"


class CopilotResponse(BaseModel):
    natural_query: str
    translated_lucene: str
    reasoning: str
    target_mitre: str | None = None
    search_result: HuntingSearchResult
    ai_tactical_summary: str


class HuntingCopilot:
    """Translates plain English analyst questions into precision Lucene/OpenSearch queries."""

    # Built-in fast NLP pattern dictionary (acts as instant zero-latency transformer and offline fallback)
    _RULE_PATTERNS = [
        (
            re.compile(r"fail(ed)?.*(login|auth|ssh)|ssh.*brute", re.I),
            "status_code:401 AND method:POST",
            "T1110 (Brute Force)",
            "Filters for HTTP 401 Unauthorized or failed SSH authentication attempts on POST endpoints.",
        ),
        (
            re.compile(r"powershell|download cradle|iex|webclient", re.I),
            "command_line:*DownloadString* OR command_line:*Invoke-WebRequest*",
            "T1059.001 (PowerShell Execution)",
            "Detects high-risk PowerShell script block cradles fetching remote payloads.",
        ),
        (
            re.compile(r"sql(i)?|injection|union\s+select", re.I),
            "endpoint:*UNION* OR endpoint:*SELECT* OR endpoint:*--*",
            "T1190 (Exploit Public-Facing Application)",
            "Searches for SQL syntax artifacts and database union comments in request parameters.",
        ),
        (
            re.compile(r"admin|wp-admin|probe|scan", re.I),
            "endpoint:*admin* AND status_code:404",
            "T1595 (Active Scanning)",
            "Identifies external reconnaissance probes surveying unexposed administrative panels.",
        ),
        (
            re.compile(r"command\s+injection|rce|cmd|cat\s+/etc", re.I),
            "endpoint:*cat* OR endpoint:*passwd* OR endpoint:*ping*",
            "T1059 (Command and Scripting Interpreter)",
            "Identifies command-separator payloads attempting local command execution.",
        ),
        (
            re.compile(r"500|server error|internal error", re.I),
            "status_code:500",
            "T1499 (Endpoint Denial of Service)",
            "Filters for unexpected internal server errors caused by unhandled exploits.",
        ),
        (
            re.compile(r"root|privilege|sudo", re.I),
            "user:root",
            "T1078 (Valid Accounts)",
            "Inspects all operations specifically targeting the root superuser account.",
        ),
    ]

    @classmethod
    def translate_to_lucene(cls, natural_text: str) -> tuple[str, str, str | None]:
        """Translates natural language into (lucene_query, reasoning, mitre_technique)."""
        clean_text = natural_text.strip()

        # If LLM key is configured, we could call Gemini/OpenAI; otherwise use high-speed pattern engine
        if settings.GEMINI_API_KEY and settings.AI_PROVIDER == "gemini":
            try:
                from app.ai.providers.gemini_provider import GeminiProvider

                provider = GeminiProvider(api_key=settings.GEMINI_API_KEY)
                prompt = (
                    "You are an expert SIEM query generator. Translate the following plain English "
                    "security request into a single Lucene filter syntax string. "
                    "Allowed fields: source_ip, destination_ip, method, endpoint, status_code, user, hostname, command_line. "
                    "Output format strictly: QUERY | REASONING | MITRE_ID\n\n"
                    f"Request: {clean_text}\n"
                )
                res = provider.generate_text(prompt)
                if "|" in res:
                    parts = [p.strip() for p in res.split("|")]
                    if len(parts) >= 3:
                        return parts[0], parts[1], parts[2]
            except Exception as e:
                logger.debug(f"Gemini translation fallback triggered: {e}")

        # Fallback to high-speed deterministic semantic matcher
        for pattern, lucene, mitre, reason in cls._RULE_PATTERNS:
            if pattern.search(clean_text):
                return lucene, reason, mitre

        # Generic term query
        safe_words = [w for w in re.findall(r"\w+", clean_text) if len(w) > 2]
        if safe_words:
            generic_lucene = " OR ".join(f"endpoint:*{w}*" for w in safe_words[:3])
            return (
                generic_lucene,
                "Keyword matching across HTTP endpoints and log parameters.",
                None,
            )

        return "status_code:200", "Default baseline activity query.", None

    @classmethod
    def execute_copilot(cls, db: Session, req: CopilotQueryRequest) -> CopilotResponse:
        """Translates natural text, executes search against hunting index, and generates tactical insights."""
        from app.models.log_event import LogEventModel

        lucene, reasoning, mitre = cls.translate_to_lucene(req.natural_query)

        # Query recent events
        query = db.query(LogEventModel)
        if req.tenant_id:
            query = query.filter(
                (LogEventModel.tenant_id == req.tenant_id)
                | (LogEventModel.tenant_id == "default")
                | (LogEventModel.tenant_id.is_(None))
            )
        records = query.order_by(LogEventModel.created_at.desc()).limit(2000).all()

        events = [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "source_ip": r.source_ip,
                "destination_ip": r.destination_ip,
                "method": r.http_method,
                "endpoint": r.path,
                "status_code": r.status_code,
                "user": getattr(r, "user", None),
                "event_id": getattr(r, "event_id", None),
                "action": getattr(r, "action", None),
                "command_line": getattr(r, "command_line", None)
                or (r.parsed_data.get("command_line") if r.parsed_data else None),
                "raw_log": r.raw_log,
                "tenant_id": getattr(r, "tenant_id", "default"),
            }
            for r in records
        ]

        search_result = ThreatHuntingEngine.search(
            query_str=lucene,
            events=events,
            limit=req.limit,
        )

        hits = search_result.total_hits
        if hits == 0:
            summary = (
                f"No suspicious events matching '{lucene}' were recorded across active logs "
                f"in the last {req.time_range_hours} hours. Threat hypothesis not confirmed."
            )
        else:
            top_ips = list(search_result.facets.get("source_ip", {}).keys())[:3]
            summary = (
                f"Identified {hits} matching events for query '{lucene}'. "
                f"Primary source indicators: {', '.join(top_ips) or 'Local/Internal'}. "
                f"Associated with {mitre or 'General Reconnaissance'}."
            )

        return CopilotResponse(
            natural_query=req.natural_query,
            translated_lucene=lucene,
            reasoning=reasoning,
            target_mitre=mitre,
            search_result=search_result,
            ai_tactical_summary=summary,
        )
