"""
ReportingService – the central orchestration layer for report generation.

This service:
  1. Validates input and report type.
  2. Delegates to the appropriate Template to assemble the report model.
  3. Delegates to the TimelineEngine for IncidentReports.
  4. NEVER performs detection or AI analysis.
  5. NEVER handles PDF/CSV/JSON export (that is the router's responsibility
     via the dedicated generator classes).

Dependency Injection:
  The service accepts its dependencies (templates, timeline engine) via
  constructor injection.  In production use app/api/dependencies.py to
  wire them.  In tests, pass mocks directly.

SOLID compliance:
  - SRP: Service only orchestrates report assembly.
  - OCP: Add new report types by adding a new template + branch here.
  - LSP: All templates implement the same .build() interface pattern.
  - ISP: Exporters are NOT injected here.
  - DIP: Service depends on abstract template objects, not concrete generators.
"""

import logging
from datetime import UTC, datetime

from app.ai.models import AIAnalysisResponse
from app.enrichment.models import ThreatEnrichment
from app.reports.exceptions import InvalidReportTypeError, MissingReportDataError
from app.reports.models import (
    ExecutiveReport,
    IncidentReport,
    ReportType,
    TechnicalReport,
)
from app.reports.templates import (
    ExecutiveReportTemplate,
    IncidentReportTemplate,
    TechnicalReportTemplate,
)
from app.reports.timeline import TimelineEngine
from app.schemas.detection_alert import DetectionAlert

logger = logging.getLogger(__name__)


class ReportingService:
    """
    Orchestrates report generation for all supported report types.

    Args:
        executive_template: Template for executive reports.
        technical_template: Template for technical reports.
        incident_template: Template for incident reports.
        timeline_engine: Engine for building incident timelines.
    """

    def __init__(
        self,
        executive_template: ExecutiveReportTemplate,
        technical_template: TechnicalReportTemplate,
        incident_template: IncidentReportTemplate,
        timeline_engine: TimelineEngine,
    ) -> None:
        self._executive = executive_template
        self._technical = technical_template
        self._incident = incident_template
        self._timeline = timeline_engine

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        report_type: str,
        alert: DetectionAlert,
        enrichments: list[ThreatEnrichment],
        ai: AIAnalysisResponse | None = None,
    ) -> ExecutiveReport | TechnicalReport | IncidentReport:
        """
        Generate a structured report of the requested type.

        Args:
            report_type: One of 'executive', 'technical', 'incident'.
            alert: The triggering DetectionAlert.
            enrichments: List of ThreatEnrichment results (may be empty).
            ai: AIAnalysisResponse from the AI SOC Analyst.

        Returns:
            A populated report model.

        Raises:
            InvalidReportTypeError: If report_type is not supported.
            MissingReportDataError: If required fields are absent.
        """
        start = datetime.now(UTC)
        self._validate_inputs(report_type, alert, ai)

        try:
            report_type_enum = ReportType(report_type.lower())
        except ValueError:
            raise InvalidReportTypeError(report_type)

        logger.info(
            "Report generation started",
            extra={
                "report_type": report_type,
                "alert_id": alert.alert_id,
                "severity": alert.severity.value,
            },
        )

        report = self._dispatch(report_type_enum, alert, enrichments, ai)

        elapsed = (datetime.now(UTC) - start).total_seconds()
        logger.info(
            "Report generation completed",
            extra={
                "report_type": report_type,
                "report_id": report.report_id,
                "elapsed_seconds": elapsed,
            },
        )
        return report

    # ------------------------------------------------------------------
    # Private Helpers
    # ------------------------------------------------------------------

    def _validate_inputs(
        self,
        report_type: str,
        alert: DetectionAlert,
        ai: AIAnalysisResponse | None,
    ) -> None:
        if not report_type or not report_type.strip():
            raise MissingReportDataError("report_type")
        if not alert.alert_id:
            raise MissingReportDataError("alert.alert_id")
        if not alert.rule_name:
            raise MissingReportDataError("alert.rule_name")

    def _dispatch(
        self,
        report_type: ReportType,
        alert: DetectionAlert,
        enrichments: list[ThreatEnrichment],
        ai: AIAnalysisResponse | None,
    ) -> ExecutiveReport | TechnicalReport | IncidentReport:
        if report_type == ReportType.EXECUTIVE:
            return self._executive.build(alert, enrichments, ai)

        if report_type == ReportType.TECHNICAL:
            return self._technical.build(alert, enrichments, ai)

        if report_type == ReportType.INCIDENT:
            timeline = self._timeline.build(alert, enrichments, ai)
            return self._incident.build(alert, enrichments, ai, timeline)

        # Should never reach here after enum validation, but defensive
        raise InvalidReportTypeError(report_type.value)
