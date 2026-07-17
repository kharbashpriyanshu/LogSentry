"""
CSV Generator for the LogSentry Reporting Engine.

Exports alert data, threat intelligence, timeline, and IOC information
to a multi-sheet CSV structure (returned as a dict of sheet_name → CSV bytes).

Design decisions:
  - Each "sheet" is independent CSV bytes so callers can write them to
    separate files or a ZIP archive.
  - Nested structures are flattened; dictionaries are JSON-stringified.
  - No report-type logic bleeds into ReportingService.
"""

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Union

from app.reports.models import ExecutiveReport, TechnicalReport, IncidentReport
from app.reports.exceptions import CSVExportError

logger = logging.getLogger(__name__)


class CSVGenerator:
    """
    Exports any report type to a set of CSV sheets.

    Usage:
        generator = CSVGenerator()
        sheets = generator.generate(report)
        # sheets["alert_data"] -> bytes (CSV)
        # sheets["threat_intelligence"] -> bytes (CSV)
        # sheets["timeline"] -> bytes (CSV)  [IncidentReport only]
        # sheets["ioc"] -> bytes (CSV)       [IncidentReport only]
    """

    def generate(
        self,
        report: Union[ExecutiveReport, TechnicalReport, IncidentReport],
    ) -> Dict[str, bytes]:
        """
        Export the report to one or more CSV byte streams.

        Returns:
            Dict mapping sheet name to CSV bytes.

        Raises:
            CSVExportError: on any serialisation failure.
        """
        start = datetime.now(timezone.utc)
        logger.info(
            "CSV export started",
            extra={"report_type": report.report_type.value, "report_id": report.report_id},
        )
        try:
            sheets: Dict[str, bytes] = {}
            report_type = report.report_type.value

            sheets["alert_data"] = self._alert_sheet(report)
            sheets["threat_intelligence"] = self._threat_intel_sheet(report)

            if report_type == "incident":
                sheets["timeline"] = self._timeline_sheet(report)  # type: ignore[arg-type]
                sheets["ioc"] = self._ioc_sheet(report)              # type: ignore[arg-type]

            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            logger.info(
                "CSV export completed",
                extra={
                    "report_type": report.report_type.value,
                    "report_id": report.report_id,
                    "sheets": list(sheets.keys()),
                    "elapsed_seconds": elapsed,
                },
            )
            return sheets

        except CSVExportError:
            raise
        except Exception as exc:
            logger.error("CSV export failed: %s", exc, exc_info=True)
            raise CSVExportError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Sheet Builders
    # ------------------------------------------------------------------

    def _alert_sheet(self, report: Union[ExecutiveReport, TechnicalReport, IncidentReport]) -> bytes:
        """Flatten top-level alert / report fields into a single-row CSV."""
        buf = io.StringIO()
        row: Dict[str, str] = {
            "report_id":    report.report_id,
            "report_type":  report.report_type.value,
            "generated_at": report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "title":        report.title,
        }

        # Add fields that exist on the model (vary by report type)
        if hasattr(report, "severity"):
            row["severity"] = report.severity
        if hasattr(report, "attack_type"):
            row["attack_type"] = report.attack_type
        if hasattr(report, "source_ip"):
            row["source_ip"] = report.source_ip or ""
        if hasattr(report, "incident_status"):
            row["incident_status"] = report.incident_status.value
        if hasattr(report, "executive_summary"):
            row["executive_summary"] = report.executive_summary
        if hasattr(report, "detection_rule"):
            row["detection_rule"] = report.detection_rule
        if hasattr(report, "rule_version"):
            row["rule_version"] = report.rule_version
        if hasattr(report, "confidence_score"):
            row["confidence_score"] = str(report.confidence_score)
        if hasattr(report, "false_positive_likelihood"):
            row["false_positive_likelihood"] = report.false_positive_likelihood
        if hasattr(report, "evidence"):
            row["evidence"] = json.dumps(report.evidence)
        if hasattr(report, "mitre_technique"):
            row["mitre_technique"] = report.mitre_technique or ""
        if hasattr(report, "mitre_tactic"):
            row["mitre_tactic"] = report.mitre_tactic or ""

        writer = csv.DictWriter(buf, fieldnames=list(row.keys()))
        writer.writeheader()
        writer.writerow(row)
        return buf.getvalue().encode("utf-8")

    def _threat_intel_sheet(self, report: Union[ExecutiveReport, TechnicalReport, IncidentReport]) -> bytes:
        """Export threat intelligence list as flat CSV rows."""
        buf = io.StringIO()

        threat_list = getattr(report, "threat_intelligence", [])
        if not threat_list:
            # Write empty sheet with headers only
            writer = csv.DictWriter(buf, fieldnames=["provider", "reputation", "country", "isp",
                                                      "confidence", "pulse_count", "mitre_technique",
                                                      "mitre_tactic", "ioc_tags", "references", "timestamp"])
            writer.writeheader()
            return buf.getvalue().encode("utf-8")

        fieldnames = [
            "provider", "reputation", "country", "isp",
            "confidence", "pulse_count", "mitre_technique",
            "mitre_tactic", "ioc_tags", "references", "timestamp",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for ti in threat_list:
            flat_row = {k: ti.get(k, "") for k in fieldnames}
            # Flatten list fields
            flat_row["ioc_tags"] = "; ".join(ti.get("ioc_tags", []))
            flat_row["references"] = "; ".join(ti.get("references", []))
            writer.writerow(flat_row)

        return buf.getvalue().encode("utf-8")

    def _timeline_sheet(self, report: IncidentReport) -> bytes:
        """Export the incident timeline as a flat CSV."""
        buf = io.StringIO()
        fieldnames = ["sequence", "event", "description", "timestamp", "metadata"]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for entry in report.timeline:
            writer.writerow({
                "sequence":    entry.sequence,
                "event":       entry.event,
                "description": entry.description,
                "timestamp":   entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "metadata":    json.dumps(entry.metadata),
            })
        return buf.getvalue().encode("utf-8")

    def _ioc_sheet(self, report: IncidentReport) -> bytes:
        """Export indicators of compromise as a flat CSV."""
        buf = io.StringIO()
        fieldnames = ["index", "indicator"]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for i, ioc in enumerate(report.indicators_of_compromise, 1):
            writer.writerow({"index": i, "indicator": ioc})
        return buf.getvalue().encode("utf-8")
