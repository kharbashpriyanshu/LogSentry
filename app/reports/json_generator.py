"""
JSON Generator for the LogSentry Reporting Engine.

Exports the complete structured report preserving all nested relationships.
Returns UTF-8 encoded JSON bytes.

Design decisions:
  - Uses Pydantic's model_dump(mode="json") to handle datetime serialisation.
  - Emits pretty-printed JSON (indent=2) for human readability.
  - No report-type-specific logic; works generically across all three report types.
  - Completely isolated from ReportingService.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Union

from app.reports.models import ExecutiveReport, TechnicalReport, IncidentReport
from app.reports.exceptions import JSONSerializationError

logger = logging.getLogger(__name__)


class JSONGenerator:
    """
    Exports any report model to structured JSON bytes.

    Usage:
        generator = JSONGenerator()
        json_bytes = generator.generate(report)
    """

    def generate(
        self,
        report: Union[ExecutiveReport, TechnicalReport, IncidentReport],
    ) -> bytes:
        """
        Serialise the report to indented JSON bytes.

        Args:
            report: Any LogSentry report model instance.

        Returns:
            UTF-8 encoded JSON bytes.

        Raises:
            JSONSerializationError: on any serialisation failure.
        """
        start = datetime.now(timezone.utc)
        logger.info(
            "JSON export started",
            extra={"report_type": report.report_type.value, "report_id": report.report_id},
        )
        try:
            # model_dump(mode="json") converts datetime → ISO string, enums → values
            payload = report.model_dump(mode="json")
            output = json.dumps(payload, indent=2, ensure_ascii=False)
            encoded = output.encode("utf-8")

            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            logger.info(
                "JSON export completed",
                extra={
                    "report_type": report.report_type.value,
                    "report_id": report.report_id,
                    "bytes": len(encoded),
                    "elapsed_seconds": elapsed,
                },
            )
            return encoded

        except JSONSerializationError:
            raise
        except Exception as exc:
            logger.error("JSON export failed: %s", exc, exc_info=True)
            raise JSONSerializationError(str(exc)) from exc
