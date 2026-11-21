import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_detection_service
from app.core.rbac import UserContext, UserRole, get_current_user
from app.models.log_event import LogEventModel
from app.schemas.log_event import LogEvent
from app.services.detection_service import DetectionService

logger = logging.getLogger(__name__)
router = APIRouter()


class ServerPingRequest(BaseModel):
    server_name: str = Field(..., description="Corporate hostname e.g. prod-web-01")
    server_ip: str = Field(..., description="Server IPv4/IPv6 address")
    platform: str = Field(
        "linux", description="OS type: linux | windows | network | cloud | k8s"
    )
    parser: str = Field(
        "nginx",
        description="Parser format: nginx | apache | linux_auth | windows_event | cloudtrail",
    )
    sample_log: str | None = None
    tenant_id: str = "default"


@router.get("/servers")
def get_connected_servers(
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Lists all enterprise servers currently or recently transmitting telemetry to LogSentry."""
    base_query = db.query(
        LogEventModel.source,
        LogEventModel.source_ip,
        LogEventModel.source_type,
        func.count(LogEventModel.id).label("total_events"),
        func.max(LogEventModel.created_at).label("last_seen"),
    )
    if user.role != UserRole.ADMIN:
        base_query = base_query.filter(
            (LogEventModel.tenant_id == user.tenant_id)
            | (LogEventModel.tenant_id == "default")
            | (LogEventModel.tenant_id.is_(None))
        )
    results = base_query.group_by(
        LogEventModel.source, LogEventModel.source_ip, LogEventModel.source_type
    ).all()

    now = datetime.now(UTC)
    servers = []

    for r in results:
        hostname = r[0] or f"srv-{r[1]}"
        ip = r[1] or "Unknown IP"
        parser = r[2] or "generic"
        count = r[3]
        last_seen = r[4]

        # Determine online status: active in last 10 minutes = online
        is_online = False
        if last_seen:
            # Handle naive datetime from SQLite
            last_seen_dt = (
                last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=UTC)
            )
            is_online = (now - last_seen_dt) < timedelta(minutes=10)

        # Platform inference
        platform_type = "linux"
        if "windows" in parser:
            platform_type = "windows"
        elif "cloud" in parser:
            platform_type = "cloud"
        elif parser in ("apache", "nginx"):
            platform_type = "web"

        servers.append(
            {
                "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{hostname}-{ip}-{parser}")),
                "hostname": hostname,
                "ip": ip,
                "parser": parser,
                "platform": platform_type,
                "total_events": count,
                "last_seen": last_seen.isoformat() if last_seen else now.isoformat(),
                "status": "streaming" if is_online else "idle",
            }
        )

    # Sort so active/streaming servers appear first, then by event count
    servers.sort(
        key=lambda s: (s["status"] == "streaming", s["total_events"]), reverse=True
    )
    return servers


@router.post("/test-ping")
def test_server_ping(
    req: ServerPingRequest,
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
    detection_service: DetectionService = Depends(get_detection_service),
) -> dict[str, Any]:
    """Simulates or accepts a live verification probe from a newly connected enterprise server."""
    now_iso = datetime.now(UTC).isoformat()
    raw = (
        req.sample_log
        or f'{req.server_ip} - - [{now_iso}] "GET /health-check HTTP/1.1" 200 64'
    )

    log_event = LogEvent(
        timestamp=datetime.now(UTC),
        source_ip=req.server_ip,
        hostname=req.server_name,
        method="GET",
        endpoint="/health-check",
        status_code=200,
        raw_log=raw,
        parser_name=req.parser,
        tenant_id=req.tenant_id,
    )

    # Persist and run detection
    model = LogEventModel(
        timestamp=log_event.timestamp,
        source=req.server_name,
        source_type=req.parser,
        raw_log=raw,
        parsed_data=log_event.model_dump(mode="json"),
        source_ip=req.server_ip,
        http_method="GET",
        path="/health-check",
        status_code="200",
    )
    db.add(model)
    db.commit()

    alerts = detection_service.analyze_event(log_event)

    return {
        "status": "connected",
        "message": f"Successfully verified ingestion stream from {req.server_name} ({req.server_ip}).",
        "server_name": req.server_name,
        "server_ip": req.server_ip,
        "parser": req.parser,
        "timestamp": now_iso,
        "alerts_triggered": len(alerts),
    }


@router.get("/ingestion-info")
def get_ingestion_info() -> dict[str, Any]:
    """Returns connection strings and active listener endpoints for company IT teams."""
    return {
        "api_endpoint": "http://localhost:8000/api/v1/detection/analyze",
        "syslog_udp": "127.0.0.1:1514",
        "syslog_tcp": "127.0.0.1:1514",
        "supported_platforms": [
            {
                "id": "linux",
                "name": "Linux Servers",
                "distros": "Ubuntu, RHEL, CentOS, Debian, Rocky Linux",
                "methods": ["Native Rsyslog", "LogSentry Python Shipper", "Vector"],
            },
            {
                "id": "windows",
                "name": "Windows Servers & Active Directory",
                "distros": "Windows Server 2019/2022/2025, Windows 10/11",
                "methods": ["Winlogbeat Service", "PowerShell Host Agent", "NXLog"],
            },
            {
                "id": "network",
                "name": "Firewalls & Network Appliances",
                "distros": "Palo Alto, Fortinet, Cisco ASA, pfSense, F5",
                "methods": ["Agentless RFC 5424 Syslog UDP 1514", "TCP 1514"],
            },
            {
                "id": "cloud",
                "name": "Cloud Infrastructure",
                "distros": "AWS CloudTrail, Azure Activity, Google Cloud Audit",
                "methods": ["S3 Lambda Forwarder", "EventBridge Webhook"],
            },
            {
                "id": "k8s",
                "name": "Kubernetes & Containers",
                "distros": "EKS, GKE, OpenShift, Docker Swarm",
                "methods": ["FluentBit DaemonSet", "Vector DaemonSet"],
            },
        ],
    }
