from typing import Dict, Type, List
from app.parsers.base import BaseParser
from app.parsers.apache import ApacheParser
from app.parsers.nginx import NginxParser
from app.parsers.exceptions import UnsupportedParserError, ParserValidationError
import logging

logger = logging.getLogger(__name__)

class ParserFactory:
    """Factory for creating and retrieving appropriate parsers."""
    
    # Store singleton instances to avoid allocation overhead on guessing and retrieval
    _registry: Dict[str, BaseParser] = {}
    
    @classmethod
    def register_parser(cls, parser_class: Type[BaseParser]) -> None:
        """Register a new parser dynamically via its class."""
        parser_instance = parser_class()
        name = parser_instance.parser_name
        if not name:
            raise ParserValidationError("Parser must have a valid parser_name.")
        cls._registry[name.lower()] = parser_instance
        logger.info(f"Registered new parser: {name} v{parser_instance.parser_version}")
        
    @classmethod
    def get_parser(cls, name: str) -> BaseParser:
        """Retrieve a parser instance by name."""
        parser_instance = cls._registry.get(name.lower())
        if not parser_instance:
            raise UnsupportedParserError(f"Parser '{name}' is not registered.")
        return parser_instance
        
    @classmethod
    def guess_parser(cls, log_line: str) -> BaseParser:
        """Attempt to guess the correct parser based on a log line."""
        for name, parser_instance in cls._registry.items():
            if parser_instance.validate(log_line):
                return parser_instance
        raise UnsupportedParserError("Could not determine appropriate parser for the given log line.")

    @classmethod
    def get_all_parsers(cls) -> List[BaseParser]:
        """Return all registered parser instances."""
        return list(cls._registry.values())

# Initialize standard parsers immediately
ParserFactory.register_parser(ApacheParser)
ParserFactory.register_parser(NginxParser)
