from typing import List, Tuple
import os
import tempfile
import uuid
from fastapi import UploadFile
from app.parsers.factory import ParserFactory
from app.schemas.log_event import LogEvent

class ParsingService:
    def parse_line(self, parser_name: str, log_line: str) -> LogEvent:
        parser = ParserFactory.get_parser(parser_name)
        event = parser.parse_line(log_line)
        if not event:
            raise ValueError("Log line format does not match the selected parser.")
        return event

    async def parse_file(self, parser_name: str, file: UploadFile) -> Tuple[int, int, int, List[LogEvent]]:
        parser = ParserFactory.get_parser(parser_name)
        
        # Save temp file
        temp_filename = f"{uuid.uuid4()}_{file.filename}"
        temp_dir = tempfile.gettempdir()
        temp_file_path = os.path.join(temp_dir, temp_filename)
        
        try:
            with open(temp_file_path, "wb") as buffer:
                content = await file.read()
                buffer.write(content)
                
            events = parser.parse_file(temp_file_path)
            
            # Simple stats simulation since `parse_file` skips malformed lines automatically
            successful = len(events)
            with open(temp_file_path, "r", encoding="utf-8", errors="replace") as f:
                total_lines = sum(1 for line in f if line.strip())
            
            failed = total_lines - successful
            
            return total_lines, successful, failed, events
            
        finally:
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except Exception:
                    pass
