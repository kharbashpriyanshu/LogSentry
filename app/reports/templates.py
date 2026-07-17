"""
Report Templates for the LogSentry Reporting Engine.

Templates are pure functions that accept domain objects and return
populated report model instances.  They are intentionally separated
from generation and export logic so they can be composed, overridden,
or extended without touching service or export classes.

Future templates to add here (do NOT schedule):
  - ComplianceReportTemplate
  - SOCDailyReportTemplate
  - WeeklyThreatReportTemplate
  - MonthlyExecutiveSummaryTemplate
"""

from datetime import datetime, timezone
from typing import List, Optional

from app.reports.models import (
    ExecutiveReport,
    TechnicalReport,
    IncidentReport,
    TimelineEntry,
    ExportMetadata,
    ReportType,
    ReportStatus,
)
from app.schemas.detection_alert import DetectionAlert
from app.enrichment.models import ThreatEnrichment
from app.ai.models import AIAnalysisResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _derive_business_impact(severity: str, attack_type: str) -> str:
    """
    Produce a human-readable business impact string from severity and attack type.
    Kept simple — designed to be replaced with a prompt-driven version in future sprints.
    """
    severity_map = {
        "CRITICAL": "Immediate operational disruption is possible. Executive escalation required.",
        "HIGH": "Significant risk of data exposure or service degradation. Urgent response needed.",
        "MEDIUM": "Moderate risk. May lead to privilege escalation or lateral movement if unaddressed.",
        "LOW": "Limited direct impact, but may indicate reconnaissance or early-stage activity.",
        "INFO": "Informational only. No immediate action required.",
    }
    base = severity_map.get(severity.upper(), "Impact assessment pending review.")
    return f"{base} Attack vector identified: {attack_type}."


def _derive_recommendations(alert: DetectionAlert, ai: AIAnalysisResponse) -> List[str]:
    """Combine alert recommendation with AI recommended actions into a clean list."""
    recommendations: List[str] = []
    if alert.recommendation:
        recommendations.append(alert.recommendation)
    # Split AI actions on newlines or semicolons for a clean list
    for item in ai.recommended_actions.replace(";", "\n").splitlines():
        cleaned = item.strip().lstrip("-").strip()
        if cleaned:
            recommendations.append(cleaned)
    return recommendations


def _derive_iocs(alert: DetectionAlert, enrichments: List[ThreatEnrichment]) -> List[str]:
    """Collect all indicators of compromise from alert and enrichment data."""
    iocs: List[str] = []
    if alert.source_ip:
        iocs.append(f"Source IP: {alert.source_ip}")
    if alert.destination_ip:
        iocs.append(f"Destination IP: {alert.destination_ip}")
    if alert.endpoint:
        iocs.append(f"Endpoint: {alert.endpoint}")
    for enrichment in enrichments:
        for tag in enrichment.ioc_tags:
            ioc_entry = f"IOC Tag [{enrichment.provider}]: {tag}"
            if ioc_entry not in iocs:
                iocs.append(ioc_entry)
        for ref in enrichment.references:
            ref_entry = f"Reference [{enrichment.provider}]: {ref}"
            if ref_entry not in iocs:
                iocs.append(ref_entry)
    return iocs


def _export_metadata(report_type: ReportType, export_format: str) -> ExportMetadata:
    return ExportMetadata(report_type=report_type, export_format=export_format)


def _enrichments_to_dicts(enrichments: List[ThreatEnrichment]) -> List[dict]:
    return [e.model_dump(mode="json") for e in enrichments]


# ---------------------------------------------------------------------------
# Executive Report Template
# ---------------------------------------------------------------------------

class ExecutiveReportTemplate:
    """
    Builds an ExecutiveReport from core domain objects.
    No detection logic. No AI calls. Pure assembly.
    """

    def build(
        self,
        alert: DetectionAlert,
        enrichments: List[ThreatEnrichment],
        ai: AIAnalysisResponse,
        export_format: str = "json",
    ) -> ExecutiveReport:
        return ExecutiveReport(
            title=f"Executive Security Report – {alert.title}",
            executive_summary=ai.executive_summary,
            severity=alert.severity.value,
            business_impact=_derive_business_impact(alert.severity.value, alert.attack_type),
            high_level_recommendations=_derive_recommendations(alert, ai),
            incident_status=ReportStatus.OPEN,
            alert_id=alert.alert_id,
            source_ip=alert.source_ip,
            attack_type=alert.attack_type,
            metadata=_export_metadata(ReportType.EXECUTIVE, export_format),
        )


# ---------------------------------------------------------------------------
# Technical Report Template
# ---------------------------------------------------------------------------

class TechnicalReportTemplate:
    """
    Builds a TechnicalReport from core domain objects.
    Contains full forensic detail for SOC analysts.
    """

    def build(
        self,
        alert: DetectionAlert,
        enrichments: List[ThreatEnrichment],
        ai: AIAnalysisResponse,
        export_format: str = "json",
    ) -> TechnicalReport:
        return TechnicalReport(
            title=f"Technical Incident Report – {alert.rule_name} v{alert.rule_version}",
            original_log=alert.raw_log_reference,
            detection_rule=alert.rule_name,
            rule_version=alert.rule_version,
            evidence=alert.evidence,
            threat_intelligence=_enrichments_to_dicts(enrichments),
            mitre_technique=alert.mitre_technique or ai.mitre_technique,
            mitre_tactic=alert.mitre_tactic,
            ai_technical_analysis=ai.technical_explanation,
            recommended_actions=ai.recommended_actions,
            confidence_score=ai.confidence_score,
            false_positive_likelihood=ai.false_positive_likelihood,
            metadata=_export_metadata(ReportType.TECHNICAL, export_format),
        )


# ---------------------------------------------------------------------------
# Incident Report Template
# ---------------------------------------------------------------------------

class IncidentReportTemplate:
    """
    Builds a comprehensive IncidentReport combining executive and technical layers.
    Also embeds the timeline generated by the TimelineEngine.
    """

    def build(
        self,
        alert: DetectionAlert,
        enrichments: List[ThreatEnrichment],
        ai: AIAnalysisResponse,
        timeline: List[TimelineEntry],
        export_format: str = "json",
    ) -> IncidentReport:
        mitre_mapping = {
            "technique": alert.mitre_technique or ai.mitre_technique,
            "tactic": alert.mitre_tactic,
        }
        return IncidentReport(
            title=f"Security Incident Report – {alert.title}",
            executive_summary=ai.executive_summary,
            severity=alert.severity.value,
            business_impact=_derive_business_impact(alert.severity.value, alert.attack_type),
            incident_status=ReportStatus.OPEN,
            technical_details=ai.technical_explanation,
            original_log=alert.raw_log_reference,
            detection_rule=alert.rule_name,
            evidence=alert.evidence,
            threat_intelligence=_enrichments_to_dicts(enrichments),
            ai_findings=ai.likely_attack_goal,
            analyst_notes=ai.analyst_notes,
            false_positive_likelihood=ai.false_positive_likelihood,
            confidence_score=ai.confidence_score,
            mitre_technique=alert.mitre_technique or ai.mitre_technique,
            mitre_tactic=alert.mitre_tactic,
            mitre_mapping=mitre_mapping,
            timeline=timeline,
            indicators_of_compromise=_derive_iocs(alert, enrichments),
            recommendations=_derive_recommendations(alert, ai),
            metadata=_export_metadata(ReportType.INCIDENT, export_format),
        )
