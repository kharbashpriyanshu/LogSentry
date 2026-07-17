from abc import ABC, abstractmethod
from typing import Optional, List
from app.schemas.log_event import LogEvent
import logging

logger = logging.getLogger(__name__)

class BaseParser(ABC):
    """Abstract base class for all log parsers."""
    
    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Name of the parser."""
        pass

    @property
    @abstractmethod
    def parser_version(self) -> str:
        """Version of the parser."""
        pass
        
    @property
    @abstractmethod
    def supported_formats(self) -> List[str]:
        """List of log formats supported by this parser."""
        pass
        
    @property
    @abstractmethod
    def description(self) -> str:
        """Description of what this parser handles."""
        pass
    
    @abstractmethod
    def validate(self, log_line: str) -> bool:
        """Validate if a log line matches the expected format for this parser."""
        pass
        
    @abstractmethod
    def parse_line(self, log_line: str) -> Optional[LogEvent]:
        """Parse a single log line into a LogEvent object."""
        pass
        
    def parse_file(self, file_path: str) -> List[LogEvent]:
        """Parse an entire file of logs, gracefully skipping invalid lines."""
        events = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    event = self.parse_line(line)
                    if event:
                        events.append(event)
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}", exc_info=True)
        return events
