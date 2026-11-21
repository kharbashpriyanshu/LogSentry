import logging
from typing import Any

from fastapi import WebSocket

from app.core.events import event_bus

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Multi-tenant WebSocket connection manager enforcing real-time tenant event isolation."""

    def __init__(self):
        # Maps WebSocket connection -> {"tenant_id": str, "is_admin": bool}
        self.connections: dict[WebSocket, dict[str, Any]] = {}

        # Subscribe to all events we care about
        event_bus.subscribe("alert.created", self.broadcast_event)
        event_bus.subscribe("alert.updated", self.broadcast_event)
        event_bus.subscribe("incident.created", self.broadcast_event)
        event_bus.subscribe("incident.updated", self.broadcast_event)
        event_bus.subscribe("log.created", self.broadcast_event)

    @property
    def active_connections(self) -> list[WebSocket]:
        return list(self.connections.keys())

    async def connect(
        self,
        websocket: WebSocket,
        tenant_id: str = "default",
        is_admin: bool = False,
    ):
        await websocket.accept()
        self.connections[websocket] = {
            "tenant_id": tenant_id,
            "is_admin": is_admin,
        }
        logger.info(
            f"WebSocket connected for tenant '{tenant_id}' (admin={is_admin}). "
            f"Total active: {len(self.connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.connections:
            del self.connections[websocket]
            logger.info(
                f"WebSocket disconnected. Total active: {len(self.connections)}"
            )

    async def broadcast_event(self, event: dict[str, Any]):
        dead_connections = []
        event_data = (
            event.get("data", {}) if isinstance(event.get("data"), dict) else {}
        )
        event_tenant = (
            event.get("tenant_id")
            or event_data.get("tenant_id")
            or "default"
        )

        for connection, info in list(self.connections.items()):
            # Enforce tenant isolation: send only if connection is Admin or matches event tenant
            if not info["is_admin"] and info["tenant_id"] != event_tenant and info["tenant_id"] != "*":
                continue

            try:
                await connection.send_json(event)
            except Exception as e:
                logger.error(f"Failed to send to websocket: {e}")
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)


manager = ConnectionManager()
