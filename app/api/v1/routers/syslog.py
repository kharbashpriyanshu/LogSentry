from typing import Any

from fastapi import APIRouter, HTTPException

from app.services.syslog_service import syslog_service

router = APIRouter()


@router.get("/status", response_model=dict[str, Any])
def get_syslog_status():
    """Retrieve status, configuration, and traffic statistics of the Syslog UDP listener."""
    return syslog_service.get_status()


@router.post("/start")
async def start_syslog_listener():
    """Start the asynchronous background Syslog listener (UDP 1514)."""
    success = await syslog_service.start()
    if not success:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start Syslog listener on udp://{syslog_service.host}:{syslog_service.port}",
        )
    return {"status": "started", "config": syslog_service.get_status()}


@router.post("/stop")
def stop_syslog_listener():
    """Stop the background Syslog listener."""
    syslog_service.stop()
    return {"status": "stopped", "is_running": syslog_service.is_running}
