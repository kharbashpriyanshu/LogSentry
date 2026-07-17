import re
from typing import List
from app.parsers.regex import RegexLogParser

APACHE_COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

class ApacheParser(RegexLogParser):
    """Parser for Apache Combined Log Format."""
    
    @property
    def pattern(self) -> re.Pattern:
        return APACHE_COMBINED_PATTERN
        
    @property
    def parser_name(self) -> str:
        return "apache"
        
    @property
    def parser_version(self) -> str:
        return "1.2.0"
        
    @property
    def supported_formats(self) -> List[str]:
        return ["combined"]
        
    @property
    def description(self) -> str:
        return "Parses Apache access logs in the Combined Log Format."
