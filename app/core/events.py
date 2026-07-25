from typing import Dict, List, Any, Callable
import asyncio
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}

    def subscribe(self, event_type: str, callback: Callable):
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    def publish(self, event_type: str, data: Any):
        event = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data
        }
        if event_type in self._subscribers:
            for callback in self._subscribers[event_type]:
                try:
                    # If it's a coroutine, run it as a task
                    if asyncio.iscoroutinefunction(callback):
                        asyncio.create_task(callback(event))
                    else:
                        callback(event)
                except Exception as e:
                    logger.error(f"Error in event subscriber for {event_type}: {e}")

# Global EventBus singleton
event_bus = EventBus()
