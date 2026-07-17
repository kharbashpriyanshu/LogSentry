# LogSentry Reporting Engine

## Overview

The **LogSentry Reporting Engine** (Sprint 7) provides a modular, extensible system for generating enterprise-grade security incident reports. It consumes `DetectionAlert`, `ThreatEnrichment`, and `AIAnalysisResponse` objects produced by prior pipeline stages and assembles structured reports suitable for SOC analysts, management, and compliance documentation.

---

## Architecture

The Reporting Engine follows **Clean Architecture** with strict **SOLID** compliance.

```
DetectionAlert + ThreatEnrichment + AIAnalysisResponse
         │
         ▼
  ┌─────────────────┐
  │  ReportingService│  ← Orchestrator. Validates input, dispatches to templates.
  └────────┬────────┘
           │
   ┌───────┴────────┐
   │   Templates    │  ← Pure assembly classes. No side effects.
   │ ─────────────  │
   │  Executive     │
   │  Technical     │
   │  Incident      │
   └───────┬────────┘
           │
   ┌───────┴────────┐
   │ TimelineEngine │  ← Builds 6-stage chronological timeline.
   └───────┬────────┘
           │
   ┌───────┴────────┐
   │  Report Models │  ← Pydantic models: ExecutiveReport, TechnicalReport, IncidentReport
   └───────┬────────┘
           │
   ┌───────▼────────────────────────────────┐
   │          Export Layer (independent)     │
   │ ─────────────────────────────────────── │
   │  PDFGenerator   (reportlab)             │
   │  CSVGenerator   (stdlib csv)            │
   │  JSONGenerator  (pydantic + stdlib json)│
   └────────────────────────────────────────┘
```

### Key Design Decisions

| Principle | Implementation |
|-----------|---------------|
| **SRP** | Each class has one responsibility: templates assemble, exporters export, service orchestrates |
| **OCP** | Add new report types by adding a template + router branch — no existing code changes |
| **LSP** | All templates share the same `.build()` interface signature |
| **ISP** | Exporters are NOT injected into ReportingService |
| **DIP** | ReportingService depends on template abstractions injected at construction |

---

## Report Pipeline

```
POST /api/v1/reports/generate
       │
       ├── Validate report_type, alert_id, rule_name, executive_summary
       │
       ├── ReportingService.generate()
       │         │
       │         ├── "executive" → ExecutiveReportTemplate.build()
       │         ├── "technical" → TechnicalReportTemplate.build()
       │         └── "incident"  → TimelineEngine.build() → IncidentReportTemplate.build()
       │
       └── Return populated Pydantic model as JSON
```

---

## Report Types

### 1. Executive Report
**Audience:** Management, C-Suite, Compliance

| Field | Source |
|-------|--------|
| Executive Summary | `AIAnalysisResponse.executive_summary` |
| Severity | `DetectionAlert.severity` |
| Business Impact | Derived from severity + attack_type |
| High-Level Recommendations | `alert.recommendation` + `ai.recommended_actions` |
| Incident Status | Default: `open` |
| Alert ID, Source IP, Attack Type | `DetectionAlert` |

### 2. Technical Report
**Audience:** SOC Analysts, Incident Responders

| Field | Source |
|-------|--------|
| Original Log Reference | `DetectionAlert.raw_log_reference` |
| Detection Rule + Version | `DetectionAlert.rule_name/version` |
| Evidence | `DetectionAlert.evidence` |
| Threat Intelligence | `List[ThreatEnrichment]` |
| MITRE ATT&CK | `alert.mitre_technique/tactic` or `ai.mitre_technique` |
| AI Technical Analysis | `AIAnalysisResponse.technical_explanation` |
| Confidence Score | `AIAnalysisResponse.confidence_score` |

### 3. Incident Report
**Audience:** Full SOC team, audit trail

Combines executive + technical layers and adds:
- **6-stage Timeline** (from TimelineEngine)
- **Indicators of Compromise** (IPs, endpoints, IOC tags, references)
- **MITRE Mapping** (technique + tactic dict)
- **Analyst Notes** (from AI)
- **Recommendations** (merged from alert + AI)

---

## Timeline Engine

The `TimelineEngine` generates a deterministic, 6-stage incident timeline:

| Seq | Event | Key Metadata |
|-----|-------|-------------|
| 1 | **Log Received** | `source_ip`, `destination_ip` |
| 2 | **Log Parsed** | `attack_type` |
| 3 | **Detection Triggered** | `rule_name`, `severity`, `confidence`, `risk_score`, `mitre_technique` |
| 4 | **Threat Intelligence Enrichment** | `providers[]`, `reputations{}` |
| 5 | **AI Analysis Completed** | `confidence_score`, `false_positive_likelihood`, `mitre_technique` |
| 6 | **Report Generated** | `engine`, `version` |

**Design Features:**
- **Stateless**: Each `build()` call returns a fresh, independent list.
- **Microsecond staggering**: Timestamps are offset by 100µs per stage to guarantee sort order even within a single second.
- **SHIELD-ready**: `TimelineEntry.metadata` is an open `Dict[str, Any]` for future consumption by SHIELD modules.
- **Extensible**: Add stages by adding a new private builder method and inserting it into `build()`.

---

## Templates

Templates are pure **assembly functions** with no side effects, no I/O, and no AI calls.

```python
# All templates share this interface pattern:
class XxxReportTemplate:
    def build(
        self,
        alert: DetectionAlert,
        enrichments: List[ThreatEnrichment],
        ai: AIAnalysisResponse,
        # IncidentReportTemplate also accepts: timeline: List[TimelineEntry]
    ) -> XxxReport: ...
```

**Future templates** (add in later sprints — do NOT schedule):
- `ComplianceReportTemplate` — maps findings to control frameworks (NIST, ISO 27001)
- `SOCDailyReportTemplate` — aggregate view of daily alerts
- `WeeklyThreatReportTemplate` — trend analysis across 7-day window
- `MonthlyExecutiveSummaryTemplate` — KPI-driven monthly view

---

## Exporters

All three exporters are **completely independent** from `ReportingService`.

| Exporter | Output | Library |
|----------|--------|---------|
| `PDFGenerator` | Professional PDF bytes | `reportlab` |
| `CSVGenerator` | Dict of `sheet_name → bytes` | `csv` (stdlib) |
| `JSONGenerator` | UTF-8 JSON bytes (pretty-printed) | `json` (stdlib) |

### PDF Generator
- **Cover Page**: Navy header band, severity badge (colour-coded), metadata table
- **Body**: Section headings with blue accent rules, evidence tables, timeline entries
- **Footer**: Page numbers + generation timestamp on every page
- Gracefully raises `PDFGenerationError` if `reportlab` is not installed

### CSV Generator
Returns a dictionary of sheets — each is an independent CSV byte stream. Sheets:
- `alert_data` — all top-level report fields (available for all report types)
- `threat_intelligence` — one row per enrichment provider (all report types)
- `timeline` — one row per `TimelineEntry` (IncidentReport only)
- `ioc` — one row per indicator of compromise (IncidentReport only)

The API endpoint packs all sheets into a **ZIP archive** for download.

### JSON Generator
Uses `pydantic.model_dump(mode="json")` for full datetime/enum serialisation, then pretty-prints with `indent=2`. All nested relationships (`timeline`, `evidence`, `threat_intelligence`) are preserved in the output.

---

## API Reference

### `POST /api/v1/reports/generate`
Generate a structured incident report.

**Request body:**
```json
{
  "report_type": "executive | technical | incident",
  "alert": { ...DetectionAlert fields... },
  "enrichments": [ ...ThreatEnrichment objects... ],
  "ai_analysis": { ...AIAnalysisResponse fields... }
}
```

**Response:** Populated report model as JSON.

**Error codes:**
| Code | Condition |
|------|-----------|
| 400  | Invalid `report_type` |
| 422  | Missing required field (`alert_id`, `rule_name`, `executive_summary`) |
| 500  | Internal generation failure |

---

### `GET /api/v1/reports/export/pdf`
Download the last generated report as a PDF file.  
Returns `application/pdf`. HTTP 404 if no report has been generated.

### `GET /api/v1/reports/export/csv`
Download the last generated report as a ZIP archive containing CSV sheets.  
Returns `application/zip`. HTTP 404 if no report has been generated.

### `GET /api/v1/reports/export/json`
Download the last generated report as a structured JSON file.  
Returns `application/json`. HTTP 404 if no report has been generated.

### `GET /api/v1/reports/types`
Returns the list of supported report type identifiers and their descriptions.

---

## Error Handling

| Exception | Raised By | HTTP Code |
|-----------|-----------|-----------|
| `InvalidReportTypeError` | `ReportingService` | 400 |
| `MissingReportDataError` | `ReportingService` | 422 |
| `PDFGenerationError` | `PDFGenerator` | 500 |
| `CSVExportError` | `CSVGenerator` | 500 |
| `JSONSerializationError` | `JSONGenerator` | 500 |

All exceptions inherit from `ReportingError` for uniform handler registration.

---

## Dependency Injection

`ReportingService` uses **constructor injection**:

```python
service = ReportingService(
    executive_template=ExecutiveReportTemplate(),
    technical_template=TechnicalReportTemplate(),
    incident_template=IncidentReportTemplate(),
    timeline_engine=TimelineEngine(),
)
```

The singleton is wired in `app/api/dependencies.py` via `get_reporting_service()` and injected into the router using FastAPI's `Depends()`.

---

## Logging

The reporting engine logs the following events (never logs sensitive data):

| Event | Level | Fields |
|-------|-------|--------|
| Report generation started | INFO | `report_type`, `alert_id`, `severity` |
| Report generation completed | INFO | `report_type`, `report_id`, `elapsed_seconds` |
| PDF generation started | INFO | `report_type`, `report_id` |
| PDF generation completed | INFO | `elapsed_seconds` |
| CSV export completed | INFO | `sheets[]`, `elapsed_seconds` |
| JSON export completed | INFO | `bytes`, `elapsed_seconds` |
| Any export failure | ERROR | exception message (exc_info=True) |

---

## Installation

```bash
pip install reportlab>=4.0.0
```

Or install all dependencies:
```bash
pip install -r requirements.txt
```

---

## Running Tests

```bash
pytest tests/test_reports.py -v
```

---

## File Structure

```
app/
└── reports/
    ├── __init__.py          # Public package surface
    ├── models.py            # Pydantic report models + enums
    ├── templates.py         # Report assembly templates
    ├── service.py           # ReportingService (orchestrator)
    ├── timeline.py          # TimelineEngine (6-stage pipeline)
    ├── pdf_generator.py     # PDF export (reportlab)
    ├── csv_generator.py     # CSV export (stdlib)
    ├── json_generator.py    # JSON export (pydantic + stdlib)
    └── exceptions.py        # Custom exception hierarchy

app/
└── services/
    └── reporting_service.py # Re-export facade (services layer)

app/
└── api/v1/routers/
    └── reports.py           # Thin FastAPI router

tests/
└── test_reports.py          # Full test suite
```
