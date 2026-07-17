"""
services/reporting_service.py

Application-layer facade that re-exports ReportingService for use in
the services package.  This file exists so that the DI container in
app/api/dependencies.py can import from the canonical services location,
consistent with the pattern used by ai_service, detection_service, etc.

The actual implementation lives in app/reports/service.py.
"""

from app.reports.service import ReportingService  # noqa: F401 — re-export

__all__ = ["ReportingService"]
