"""
PDF Generator for the LogSentry Reporting Engine.

Produces professional PDF documents using the reportlab library.
Each report type gets a dedicated render method.
PDF generation logic is completely isolated from ReportingService.

Layout:
  - Cover Page  (title, severity badge, metadata)
  - Incident Summary
  - Threat Intelligence
  - Timeline
  - AI Findings
  - Recommendations
  - Footer with page numbers
"""

import io
import logging
from datetime import datetime, timezone
from typing import List, Union

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether,
    )
    from reportlab.platypus.flowables import Flowable
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False

from app.reports.models import ExecutiveReport, TechnicalReport, IncidentReport
from app.reports.exceptions import PDFGenerationError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Colour Palette
# ---------------------------------------------------------------------------

_PALETTE = {
    "primary":     colors.HexColor("#1E3A5F"),   # Deep navy
    "accent":      colors.HexColor("#00A8E8"),   # Electric blue
    "danger":      colors.HexColor("#E63946"),   # Alert red
    "warning":     colors.HexColor("#F4A261"),   # Amber
    "success":     colors.HexColor("#2A9D8F"),   # Teal
    "neutral":     colors.HexColor("#6B7280"),   # Grey
    "bg_light":    colors.HexColor("#F8FAFC"),   # Near-white
    "text":        colors.HexColor("#111827"),   # Almost black
    "white":       colors.white,
}

_SEVERITY_COLORS = {
    "CRITICAL": _PALETTE["danger"],
    "HIGH":     colors.HexColor("#FF6B35"),
    "MEDIUM":   _PALETTE["warning"],
    "LOW":      colors.HexColor("#3B82F6"),
    "INFO":     _PALETTE["neutral"],
}


# ---------------------------------------------------------------------------
# Helper – severity colour lookup
# ---------------------------------------------------------------------------

def _severity_color(severity: str) -> colors.Color:
    return _SEVERITY_COLORS.get(severity.upper(), _PALETTE["neutral"])


# ---------------------------------------------------------------------------
# PDF Generator
# ---------------------------------------------------------------------------

class PDFGenerator:
    """
    Generates professional PDF reports for all LogSentry report types.
    Must be used via generate() – do NOT subclass for export logic.
    """

    def generate(
        self,
        report: Union[ExecutiveReport, TechnicalReport, IncidentReport],
    ) -> bytes:
        """
        Render the report to PDF bytes.

        Args:
            report: Any of the three report model types.

        Returns:
            Raw PDF bytes.

        Raises:
            PDFGenerationError: If reportlab is unavailable or generation fails.
        """
        if not _REPORTLAB_AVAILABLE:
            raise PDFGenerationError(
                "reportlab is not installed. Run: pip install reportlab"
            )

        start = datetime.now(timezone.utc)
        logger.info(
            "PDF generation started",
            extra={"report_type": report.report_type.value, "report_id": report.report_id},
        )

        try:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=2 * cm,
                leftMargin=2 * cm,
                topMargin=2.5 * cm,
                bottomMargin=2.5 * cm,
                title=report.title,
                author="LogSentry Reporting Engine",
            )
            styles = self._build_styles()
            story = self._build_story(report, styles)
            doc.build(story, onFirstPage=self._add_page_decorations, onLaterPages=self._add_page_decorations)

            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            logger.info(
                "PDF generation completed",
                extra={
                    "report_type": report.report_type.value,
                    "report_id": report.report_id,
                    "elapsed_seconds": elapsed,
                },
            )
            return buffer.getvalue()

        except PDFGenerationError:
            raise
        except Exception as exc:
            logger.error("PDF generation failed: %s", exc, exc_info=True)
            raise PDFGenerationError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Style Sheet
    # ------------------------------------------------------------------

    def _build_styles(self) -> dict:
        base = getSampleStyleSheet()
        styles = {
            "title": ParagraphStyle(
                "ReportTitle",
                parent=base["Title"],
                fontSize=26,
                textColor=_PALETTE["white"],
                spaceAfter=6,
                fontName="Helvetica-Bold",
                alignment=TA_CENTER,
            ),
            "subtitle": ParagraphStyle(
                "ReportSubtitle",
                parent=base["Normal"],
                fontSize=11,
                textColor=_PALETTE["white"],
                spaceAfter=4,
                fontName="Helvetica",
                alignment=TA_CENTER,
            ),
            "section": ParagraphStyle(
                "SectionHeading",
                parent=base["Heading1"],
                fontSize=13,
                textColor=_PALETTE["primary"],
                spaceBefore=14,
                spaceAfter=6,
                fontName="Helvetica-Bold",
                borderPad=4,
            ),
            "body": ParagraphStyle(
                "BodyText",
                parent=base["Normal"],
                fontSize=10,
                textColor=_PALETTE["text"],
                spaceAfter=6,
                leading=14,
                fontName="Helvetica",
            ),
            "label": ParagraphStyle(
                "Label",
                parent=base["Normal"],
                fontSize=9,
                textColor=_PALETTE["neutral"],
                fontName="Helvetica-Bold",
                spaceAfter=2,
            ),
            "mono": ParagraphStyle(
                "Mono",
                parent=base["Code"],
                fontSize=8,
                fontName="Courier",
                textColor=_PALETTE["text"],
                backColor=_PALETTE["bg_light"],
                leftIndent=8,
                spaceAfter=6,
            ),
            "footer": ParagraphStyle(
                "Footer",
                parent=base["Normal"],
                fontSize=8,
                textColor=_PALETTE["neutral"],
                alignment=TA_CENTER,
            ),
        }
        return styles

    # ------------------------------------------------------------------
    # Page decorations (header / footer)
    # ------------------------------------------------------------------

    def _add_page_decorations(self, canvas, doc):
        """Draw footer with page numbers on every page."""
        canvas.saveState()
        page_width, page_height = A4
        # Footer line
        canvas.setStrokeColor(_PALETTE["primary"])
        canvas.setLineWidth(0.5)
        canvas.line(2 * cm, 1.8 * cm, page_width - 2 * cm, 1.8 * cm)
        # Footer text
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(_PALETTE["neutral"])
        canvas.drawString(
            2 * cm,
            1.2 * cm,
            f"LogSentry SIEM  |  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        )
        canvas.drawRightString(
            page_width - 2 * cm,
            1.2 * cm,
            f"Page {doc.page}",
        )
        canvas.restoreState()

    # ------------------------------------------------------------------
    # Story Assembly
    # ------------------------------------------------------------------

    def _build_story(
        self,
        report: Union[ExecutiveReport, TechnicalReport, IncidentReport],
        styles: dict,
    ) -> list:
        story = []
        story += self._cover_page(report, styles)
        story.append(PageBreak())

        report_type = report.report_type.value
        if report_type == "executive":
            story += self._executive_body(report, styles)  # type: ignore[arg-type]
        elif report_type == "technical":
            story += self._technical_body(report, styles)  # type: ignore[arg-type]
        elif report_type == "incident":
            story += self._incident_body(report, styles)  # type: ignore[arg-type]

        return story

    # ------------------------------------------------------------------
    # Cover Page
    # ------------------------------------------------------------------

    def _cover_page(self, report, styles: dict) -> list:
        page_width, _ = A4
        severity = getattr(report, "severity", "INFO")
        sev_color = _severity_color(severity)

        elements = []
        # Coloured header band via a single-cell table
        header_data = [
            [Paragraph(report.title, styles["title"])],
            [Paragraph(f"Report Type: {report.report_type.value.upper()}", styles["subtitle"])],
        ]
        header_table = Table(
            header_data,
            colWidths=[page_width - 4 * cm],
            rowHeights=[2 * cm, 1 * cm],
        )
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _PALETTE["primary"]),
            ("TOPPADDING",    (0, 0), (-1, -1), 16),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 0.5 * cm))

        # Severity badge
        severity_data = [[Paragraph(f"  SEVERITY: {severity}  ", ParagraphStyle(
            "Badge",
            fontSize=12,
            textColor=_PALETTE["white"],
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ))]]
        severity_table = Table(severity_data, colWidths=[6 * cm])
        severity_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), sev_color),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("ROUNDEDCORNERS", [4]),
        ]))
        elements.append(severity_table)
        elements.append(Spacer(1, 0.5 * cm))

        # Metadata table
        meta = report.metadata
        meta_rows = [
            ["Report ID",   report.report_id],
            ["Generated",   meta.generated_at.strftime("%Y-%m-%d %H:%M UTC")],
            ["Generated By", meta.generated_by],
            ["Engine Version", meta.version],
        ]
        if hasattr(report, "alert_id"):
            meta_rows.insert(0, ["Alert ID", report.alert_id])

        meta_table = Table(meta_rows, colWidths=[5 * cm, 10 * cm])
        meta_table.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME",      (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("TEXTCOLOR",     (0, 0), (0, -1), _PALETTE["primary"]),
            ("TEXTCOLOR",     (1, 0), (1, -1), _PALETTE["text"]),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_PALETTE["bg_light"], _PALETTE["white"]]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("GRID",          (0, 0), (-1, -1), 0.3, _PALETTE["neutral"]),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 0.3 * cm))
        elements.append(HRFlowable(width="100%", thickness=1, color=_PALETTE["accent"]))

        return elements

    # ------------------------------------------------------------------
    # Executive Body
    # ------------------------------------------------------------------

    def _executive_body(self, report: ExecutiveReport, styles: dict) -> list:
        el = []
        el += self._section("Executive Summary", styles)
        el.append(Paragraph(report.executive_summary, styles["body"]))

        el += self._section("Business Impact", styles)
        el.append(Paragraph(report.business_impact, styles["body"]))

        el += self._section("Incident Details", styles)
        details = [
            ["Attack Type",     report.attack_type],
            ["Source IP",       report.source_ip or "N/A"],
            ["Incident Status", report.incident_status.value.upper()],
        ]
        el.append(self._two_col_table(details))

        el += self._section("Recommendations", styles)
        for i, rec in enumerate(report.high_level_recommendations, 1):
            el.append(Paragraph(f"{i}. {rec}", styles["body"]))

        return el

    # ------------------------------------------------------------------
    # Technical Body
    # ------------------------------------------------------------------

    def _technical_body(self, report: TechnicalReport, styles: dict) -> list:
        el = []
        el += self._section("Detection Rule", styles)
        rule_data = [
            ["Rule Name",    report.detection_rule],
            ["Rule Version", report.rule_version],
            ["Confidence",   f"{report.confidence_score:.0%}"],
            ["FP Likelihood", report.false_positive_likelihood],
        ]
        el.append(self._two_col_table(rule_data))

        el += self._section("Original Log Reference", styles)
        el.append(Paragraph(report.original_log, styles["mono"]))

        el += self._section("Evidence", styles)
        for key, val in report.evidence.items():
            el.append(Paragraph(f"<b>{key}:</b> {val}", styles["body"]))

        el += self._section("Threat Intelligence", styles)
        for ti in report.threat_intelligence:
            provider = ti.get("provider", "unknown")
            rep = ti.get("reputation", "N/A")
            country = ti.get("country", "N/A")
            el.append(Paragraph(
                f"<b>{provider}</b>: reputation={rep}, country={country}",
                styles["body"],
            ))

        el += self._section("MITRE ATT&CK Mapping", styles)
        mitre_data = [
            ["Technique", report.mitre_technique or "N/A"],
            ["Tactic",    report.mitre_tactic or "N/A"],
        ]
        el.append(self._two_col_table(mitre_data))

        el += self._section("AI Technical Analysis", styles)
        el.append(Paragraph(report.ai_technical_analysis, styles["body"]))

        el += self._section("Recommended Actions", styles)
        el.append(Paragraph(report.recommended_actions, styles["body"]))

        return el

    # ------------------------------------------------------------------
    # Incident Body
    # ------------------------------------------------------------------

    def _incident_body(self, report: IncidentReport, styles: dict) -> list:
        el = []
        el += self._section("Executive Summary", styles)
        el.append(Paragraph(report.executive_summary, styles["body"]))

        el += self._section("Business Impact", styles)
        el.append(Paragraph(report.business_impact, styles["body"]))

        el += self._section("Technical Details", styles)
        el.append(Paragraph(report.technical_details, styles["body"]))

        el += self._section("Original Log Reference", styles)
        el.append(Paragraph(report.original_log, styles["mono"]))

        el += self._section("Threat Intelligence", styles)
        for ti in report.threat_intelligence:
            provider = ti.get("provider", "unknown")
            rep = ti.get("reputation", "N/A")
            el.append(Paragraph(f"<b>{provider}</b>: {rep}", styles["body"]))

        el += self._section("MITRE ATT&CK Mapping", styles)
        mitre_data = [
            ["Technique", report.mitre_technique or "N/A"],
            ["Tactic",    report.mitre_tactic or "N/A"],
        ]
        el.append(self._two_col_table(mitre_data))

        el += self._section("AI Findings", styles)
        el.append(Paragraph(report.ai_findings, styles["body"]))

        el += self._section("Analyst Notes", styles)
        el.append(Paragraph(report.analyst_notes, styles["body"]))

        # Timeline
        el.append(PageBreak())
        el += self._section("Incident Timeline", styles)
        for entry in report.timeline:
            ts_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            el.append(Paragraph(
                f"<b>[{entry.sequence}] {entry.event}</b> — {ts_str}",
                styles["label"],
            ))
            el.append(Paragraph(entry.description, styles["body"]))
            el.append(Spacer(1, 0.15 * cm))

        el += self._section("Indicators of Compromise", styles)
        for ioc in report.indicators_of_compromise:
            el.append(Paragraph(f"• {ioc}", styles["body"]))

        el += self._section("Recommendations", styles)
        for i, rec in enumerate(report.recommendations, 1):
            el.append(Paragraph(f"{i}. {rec}", styles["body"]))

        return el

    # ------------------------------------------------------------------
    # Shared Helpers
    # ------------------------------------------------------------------

    def _section(self, title: str, styles: dict) -> list:
        return [
            Spacer(1, 0.3 * cm),
            Paragraph(title, styles["section"]),
            HRFlowable(width="100%", thickness=0.5, color=_PALETTE["accent"]),
            Spacer(1, 0.1 * cm),
        ]

    def _two_col_table(self, rows: list) -> Table:
        t = Table(rows, colWidths=[5 * cm, 11 * cm])
        t.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME",      (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("TEXTCOLOR",     (0, 0), (0, -1), _PALETTE["primary"]),
            ("TEXTCOLOR",     (1, 0), (1, -1), _PALETTE["text"]),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_PALETTE["bg_light"], _PALETTE["white"]]),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.25, colors.HexColor("#D1D5DB")),
        ]))
        return t
