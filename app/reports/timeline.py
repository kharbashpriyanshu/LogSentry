"""
Timeline Engine for the LogSentry Reporting Engine.

Generates a chronological sequence of TimelineEntry objects describing
every stage of an alert's lifecycle — from log ingestion to report generation.

Design decisions:
  - The engine is stateless.  Each call to build() returns a fresh timeline.
  - Entries are independent Pydantic models so SHIELD modules can consume them.
  - The sequence field is 1-indexed and monotonically increasing.
  - Timestamps are staggered by simulated microseconds to preserve ordering even
    when all pipeline stages run within a single second.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional

from app.reports.models import TimelineEntry
from app.schemas.detection_alert import DetectionAlert
from app.enrichment.models import ThreatEnrichment
from app.ai.models import AIAnalysisResponse


class TimelineEngine:
    """
    Builds a chronological incident timeline from detection artefacts.

    Usage:
        engine = TimelineEngine()
        entries = engine.build(alert, enrichments, ai_response)

    The returned list is ready to embed in an IncidentReport or consumed
    independently by future SHIELD modules.
    """

    # Microsecond offsets per stage to guarantee ordering when timestamps collide
    _STAGE_OFFSETS_US = [0, 100, 200, 300, 400, 500]

    def build(
        self,
        alert: DetectionAlert,
        enrichments: List[ThreatEnrichment],
        ai: AIAnalysisResponse,
        report_generated_at: Optional[datetime] = None,
    ) -> List[TimelineEntry]:
        """
        Generate the full incident timeline.

        Args:
            alert: The triggering DetectionAlert.
            enrichments: List of ThreatEnrichment results.
            ai: The AIAnalysisResponse for this alert.
            report_generated_at: Timestamp the report was generated (defaults to now).

        Returns:
            Ordered list of TimelineEntry objects.
        """
        base_ts = alert.timestamp
        report_ts = report_generated_at or datetime.now(timezone.utc)

        entries: List[TimelineEntry] = [
            self._log_received(base_ts, alert),
            self._log_parsed(base_ts, alert),
            self._detection_triggered(base_ts, alert),
            self._threat_intel_enriched(base_ts, enrichments),
            self._ai_analysis_completed(base_ts, ai),
            self._report_generated(report_ts),
        ]

        return entries

    # ------------------------------------------------------------------
    # Private stage builders
    # ------------------------------------------------------------------

    def _log_received(self, base: datetime, alert: DetectionAlert) -> TimelineEntry:
        return TimelineEntry(
            sequence=1,
            event="Log Received",
            description=(
                f"Raw log ingested from source. "
                f"Reference: {alert.raw_log_reference!r}."
            ),
            timestamp=base + timedelta(microseconds=self._STAGE_OFFSETS_US[0]),
            metadata={"source_ip": alert.source_ip, "destination_ip": alert.destination_ip},
        )

    def _log_parsed(self, base: datetime, alert: DetectionAlert) -> TimelineEntry:
        return TimelineEntry(
            sequence=2,
            event="Log Parsed",
            description=(
                f"Log normalised and structured by the parsing engine. "
                f"Attack type identified as: {alert.attack_type}."
            ),
            timestamp=base + timedelta(microseconds=self._STAGE_OFFSETS_US[1]),
            metadata={"attack_type": alert.attack_type},
        )

    def _detection_triggered(self, base: datetime, alert: DetectionAlert) -> TimelineEntry:
        return TimelineEntry(
            sequence=3,
            event="Detection Triggered",
            description=(
                f"Detection rule '{alert.rule_name}' (v{alert.rule_version}) fired with "
                f"severity={alert.severity.value}, confidence={alert.confidence:.2f}, "
                f"risk_score={alert.risk_score:.2f}."
            ),
            timestamp=base + timedelta(microseconds=self._STAGE_OFFSETS_US[2]),
            metadata={
                "rule_name": alert.rule_name,
                "rule_version": alert.rule_version,
                "severity": alert.severity.value,
                "confidence": alert.confidence,
                "risk_score": alert.risk_score,
                "mitre_technique": alert.mitre_technique,
                "mitre_tactic": alert.mitre_tactic,
            },
        )

    def _threat_intel_enriched(
        self, base: datetime, enrichments: List[ThreatEnrichment]
    ) -> TimelineEntry:
        provider_names = [e.provider for e in enrichments] if enrichments else ["none"]
        reputations = {e.provider: e.reputation for e in enrichments if e.reputation}
        return TimelineEntry(
            sequence=4,
            event="Threat Intelligence Enrichment",
            description=(
                f"Threat Intelligence gathered from {len(enrichments)} provider(s): "
                f"{', '.join(provider_names)}. "
                f"Reputation results: {reputations or 'no reputation data returned'}."
            ),
            timestamp=base + timedelta(microseconds=self._STAGE_OFFSETS_US[3]),
            metadata={"providers": provider_names, "reputations": reputations},
        )

    def _ai_analysis_completed(
        self, base: datetime, ai: AIAnalysisResponse
    ) -> TimelineEntry:
        return TimelineEntry(
            sequence=5,
            event="AI Analysis Completed",
            description=(
                f"AI SOC Analyst produced analysis with confidence={ai.confidence_score:.2f}. "
                f"False-positive likelihood: {ai.false_positive_likelihood}. "
                f"Identified goal: {ai.likely_attack_goal}."
            ),
            timestamp=base + timedelta(microseconds=self._STAGE_OFFSETS_US[4]),
            metadata={
                "confidence_score": ai.confidence_score,
                "false_positive_likelihood": ai.false_positive_likelihood,
                "mitre_technique": ai.mitre_technique,
            },
        )

    def _report_generated(self, report_ts: datetime) -> TimelineEntry:
        return TimelineEntry(
            sequence=6,
            event="Report Generated",
            description=(
                "Incident report compiled by the LogSentry Reporting Engine. "
                "Ready for distribution to SOC analysts and management."
            ),
            timestamp=report_ts + timedelta(microseconds=self._STAGE_OFFSETS_US[5]),
            metadata={"engine": "LogSentry Reporting Engine", "version": "1.0.0"},
        )
