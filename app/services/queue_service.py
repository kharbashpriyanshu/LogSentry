import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any

from app.detection.engine import DetectionEngine
from app.schemas.detection_alert import DetectionAlert
from app.schemas.log_event import LogEvent

logger = logging.getLogger(__name__)


class StreamingQueueService:
    """Enterprise asynchronous streaming buffer & batch processing queue."""

    def __init__(
        self, maxsize: int = 50000, batch_size: int = 100, flush_interval: float = 0.05
    ):
        self.maxsize = maxsize
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._queue: asyncio.Queue[LogEvent] = asyncio.Queue(maxsize=maxsize)
        self._consumer_task: asyncio.Task | None = None
        self._is_running = False
        self.engine: DetectionEngine | None = None

        # Telemetry metrics
        self.total_enqueued = 0
        self.total_processed = 0
        self.total_dropped = 0
        self.peak_queue_size = 0
        self._throughput_window: list[float] = []

    def start_worker(self, engine: DetectionEngine | None = None):
        """Start the background async consumer worker."""
        if self._is_running:
            return
        self.engine = engine or DetectionEngine()
        self._is_running = True
        try:
            loop = asyncio.get_running_loop()
            self._consumer_task = loop.create_task(self._batch_consumer_loop())
            logger.info(
                f"Streaming Queue Service worker started (capacity={self.maxsize}, batch={self.batch_size})."
            )
        except RuntimeError:
            logger.warning(
                "No running asyncio event loop to start QueueService consumer worker."
            )

    def stop_worker(self):
        """Stop the background consumer worker."""
        self._is_running = False
        if self._consumer_task:
            self._consumer_task.cancel()
            self._consumer_task = None
        logger.info("Streaming Queue Service worker stopped.")

    def enqueue(self, event: LogEvent) -> bool:
        """Enqueue an event with backpressure drop protection if full."""
        try:
            self._queue.put_nowait(event)
            self.total_enqueued += 1
            cur_size = self._queue.qsize()
            if cur_size > self.peak_queue_size:
                self.peak_queue_size = cur_size
            return True
        except asyncio.QueueFull:
            self.total_dropped += 1
            logger.warning(
                f"Ingestion queue full ({self.maxsize} events). Dropping event to prevent backpressure."
            )
            return False

    def enqueue_batch(self, events: list[LogEvent]) -> int:
        """Enqueue multiple events, returning count of successfully enqueued."""
        success_count = 0
        for ev in events:
            if self.enqueue(ev):
                success_count += 1
        return success_count

    async def _batch_consumer_loop(self):
        """Continuous consumer that drains batches for high-speed processing."""
        while self._is_running:
            batch: list[LogEvent] = []
            start_time = asyncio.get_event_loop().time()

            while len(batch) < self.batch_size:
                timeout = max(
                    0.001,
                    self.flush_interval
                    - (asyncio.get_event_loop().time() - start_time),
                )
                try:
                    event = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                    batch.append(event)
                    self._queue.task_done()
                except TimeoutError:
                    break

            if batch:
                await self._process_batch(batch)
            else:
                await asyncio.sleep(0.01)

    async def _process_batch(self, batch: list[LogEvent]) -> list[DetectionAlert]:
        """Dispatch a batch through the detection engine."""
        now = time.time()
        self.total_processed += len(batch)
        self._throughput_window.append(now)

        # Retain last 5 seconds of throughput window
        cutoff = now - 5.0
        self._throughput_window = [t for t in self._throughput_window if t > cutoff]

        alerts: list[DetectionAlert] = []
        if self.engine:
            try:
                alerts = self.engine.process_events(batch)
            except Exception as e:
                logger.error(f"Error processing queue batch: {e}")
        return alerts

    def get_metrics(self) -> dict[str, Any]:
        """Return real-time queue health & throughput metrics."""
        now = time.time()
        cutoff = now - 5.0
        recent_count = len([t for t in self._throughput_window if t > cutoff])
        throughput_eps = round(recent_count / 5.0, 1)

        return {
            "is_running": self._is_running,
            "current_queue_depth": self._queue.qsize(),
            "max_capacity": self.maxsize,
            "peak_queue_depth": self.peak_queue_size,
            "total_enqueued": self.total_enqueued,
            "total_processed": self.total_processed,
            "total_dropped": self.total_dropped,
            "throughput_eps": throughput_eps,
            "timestamp": datetime.now(UTC).isoformat(),
        }


# Singleton queue service instance
queue_service = StreamingQueueService()
