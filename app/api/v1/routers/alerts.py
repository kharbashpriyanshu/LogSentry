from fastapi import APIRouter
from typing import List
from app.schemas.detection_alert import DetectionAlert
from app.schemas.severity import Severity

router = APIRouter()

@router.get("/example", response_model=List[DetectionAlert])
def get_example_alerts():
    """Temporary endpoint returning example alerts."""
    return [
        DetectionAlert(
            rule_name="sqli",
            rule_version="1.1.0",
            severity=Severity.HIGH,
            confidence=0.9,
            risk_score=85.0,
            title="SQL Injection Example",
            description="Detected UNION SELECT in endpoint.",
            source_ip="192.168.1.5",
            endpoint="/api/users?id=1 UNION SELECT",
            attack_type="SQL Injection",
            raw_log_reference="192.168.1.5 - - [10/Oct] GET /api/users..."
        )
    ]
