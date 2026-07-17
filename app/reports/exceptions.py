"""
Custom exceptions for the Reporting module.
Follows the established exception hierarchy of LogSentry.
"""


class ReportingError(Exception):
    """Base exception for all reporting errors."""
    pass


class InvalidReportTypeError(ReportingError):
    """Raised when an unsupported or invalid report type is requested."""

    def __init__(self, report_type: str) -> None:
        self.report_type = report_type
        super().__init__(f"Invalid report type: '{report_type}'. Supported types: executive, technical, incident.")


class MissingReportDataError(ReportingError):
    """Raised when required data is missing to generate a report."""

    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(f"Required report data is missing: '{field}'.")


class PDFGenerationError(ReportingError):
    """Raised when PDF generation fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"PDF generation failed: {reason}")


class CSVExportError(ReportingError):
    """Raised when CSV export fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"CSV export failed: {reason}")


class JSONSerializationError(ReportingError):
    """Raised when JSON serialization fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"JSON serialization failed: {reason}")
