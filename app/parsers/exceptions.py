class ParserError(Exception):
    """Base exception for all parsing-related errors."""
    pass

class InvalidLogFormatError(ParserError):
    """Raised when a log line does not match the expected format for a parser."""
    pass

class UnsupportedParserError(ParserError):
    """Raised when an unrecognized parser is requested from the factory."""
    pass

class MalformedTimestampError(ParserError):
    """Raised when a timestamp in a log cannot be parsed."""
    pass

class ParserValidationError(ParserError):
    """Raised when validation of parser configurations or inputs fails."""
    pass
