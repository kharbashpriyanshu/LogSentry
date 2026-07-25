from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import logging
import asyncio
from app.core.events import event_bus

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        
        # Subscribe to all events we care about
        event_bus.subscribe("alert.created", self.broadcast_event)
        event_bus.subscribe("alert.updated", self.broadcast_event)
        event_bus.subscribe("incident.created", self.broadcast_event)
        event_bus.subscribe("incident.updated", self.broadcast_event)
        event_bus.subscribe("log.created", self.broadcast_event)

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast_event(self, event: Dict[str, Any]):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(event)
            except Exception as e:
                logger.error(f"Failed to send to websocket: {e}")
                dead_connections.append(connection)
                
        for dead in dead_connections:
            self.disconnect(dead)

manager = ConnectionManager()
