"""
API Router for the LogSentry Reporting Engine.

Endpoints:
  POST /api/v1/reports/generate        – Generate a structured report
  GET  /api/v1/reports/export/pdf      – Export last report as PDF
  GET  /api/v1/reports/export/csv      – Export last report as CSV (ZIP)
  GET  /api/v1/reports/export/json     – Export last report as JSON

Router design:
  - All business logic is in ReportingService, PDFGenerator, CSVGenerator, JSONGenerator.
  - This router is intentionally thin: validate, delegate, return.
  - Report state is held in-memory per process (sufficient for sprint scope).
    Persistence is a Sprint 8+ concern.
"""

import io
import zipfile
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app.reports.service import ReportingService
from app.reports.pdf_generator import PDFGenerator
from app.reports.csv_generator import CSVGenerator
from app.reports.json_generator import JSONGenerator
from app.reports.models import (
    ExecutiveReport, TechnicalReport, IncidentReport, ReportType,
)
from app.reports.exceptions import (
    InvalidReportTypeError,
    MissingReportDataError,
    PDFGenerationError,
    CSVExportError,
    JSONSerializationError,
)
from app.schemas.detection_alert import DetectionAlert
from app.enrichment.models import ThreatEnrichment
from app.ai.models import AIAnalysisResponse
from app.api.dependencies import get_reporting_service

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------------------------

from pydantic import BaseModel

class GenerateReportRequest(BaseModel):
    report_type: str
    alert: DetectionAlert
    enrichments: List[ThreatEnrichment] = []
    ai_analysis: AIAnalysisResponse


# ---------------------------------------------------------------------------
# In-Process Report Cache (last generated report per process)
# ---------------------------------------------------------------------------

_last_report: Optional[ExecutiveReport | TechnicalReport | IncidentReport] = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/generate", summary="Generate a structured incident report")
def generate_report(
    payload: GenerateReportRequest,
    service: ReportingService = Depends(get_reporting_service),
):
    """
    Generate a structured report from DetectionAlert, ThreatEnrichment, and AIAnalysisResponse.

    **report_type** must be one of: `executive`, `technical`, `incident`.

    Returns the fully populated report model as JSON.
    """
    global _last_report
    try:
        report = service.generate(
            report_type=payload.report_type,
            alert=payload.alert,
            enrichments=payload.enrichments,
            ai=payload.ai_analysis,
        )
        _last_report = report
        return report.model_dump(mode="json")

    except InvalidReportTypeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except MissingReportDataError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Unexpected error in report generation: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Report generation failed.")


@router.get(
    "/export/pdf",
    summary="Export the last generated report as a PDF",
    response_class=Response,
)
def export_pdf(service: ReportingService = Depends(get_reporting_service)):
    """
    Export the most recently generated report as a professional PDF document.
    Call `/generate` first to produce a report.
    """
    if _last_report is None:
        raise HTTPException(
            status_code=404,
            detail="No report has been generated yet. Call POST /reports/generate first.",
        )
    try:
        generator = PDFGenerator()
        pdf_bytes = generator.generate(_last_report)
        filename = f"logsentry_report_{_last_report.report_id[:8]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except PDFGenerationError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/export/csv",
    summary="Export the last generated report as CSV (ZIP archive)",
    response_class=Response,
)
def export_csv(service: ReportingService = Depends(get_reporting_service)):
    """
    Export the most recently generated report as a ZIP archive containing
    one CSV file per data sheet (alert_data, threat_intelligence, timeline, ioc).
    Call `/generate` first to produce a report.
    """
    if _last_report is None:
        raise HTTPException(
            status_code=404,
            detail="No report has been generated yet. Call POST /reports/generate first.",
        )
    try:
        generator = CSVGenerator()
        sheets = generator.generate(_last_report)

        # Pack all sheets into a ZIP archive
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for sheet_name, csv_bytes in sheets.items():
                zf.writestr(f"{sheet_name}.csv", csv_bytes)
        zip_buffer.seek(0)

        filename = f"logsentry_report_{_last_report.report_id[:8]}.zip"
        return Response(
            content=zip_buffer.read(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except CSVExportError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/export/json",
    summary="Export the last generated report as structured JSON",
    response_class=Response,
)
def export_json(service: ReportingService = Depends(get_reporting_service)):
    """
    Export the most recently generated report as a complete structured JSON document.
    All nested relationships are preserved.
    Call `/generate` first to produce a report.
    """
    if _last_report is None:
        raise HTTPException(
            status_code=404,
            detail="No report has been generated yet. Call POST /reports/generate first.",
        )
    try:
        generator = JSONGenerator()
        json_bytes = generator.generate(_last_report)
        filename = f"logsentry_report_{_last_report.report_id[:8]}.json"
        return Response(
            content=json_bytes,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except JSONSerializationError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/types", summary="List supported report types")
def list_report_types():
    """Return the list of supported report type identifiers."""
    return {
        "supported_report_types": [t.value for t in ReportType],
        "descriptions": {
            "executive": "High-level summary for management and compliance.",
            "technical": "Full forensic detail for SOC analysts.",
            "incident":  "Comprehensive report combining executive, technical, timeline, and IOCs.",
        },
    }
