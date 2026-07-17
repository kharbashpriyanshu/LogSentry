import re
from typing import List
from app.parsers.regex import RegexLogParser

NGINX_COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

class NginxParser(RegexLogParser):
    """Parser for Nginx Combined Access Log Format."""
    
    @property
    def pattern(self) -> re.Pattern:
        return NGINX_COMBINED_PATTERN
        
    @property
    def parser_name(self) -> str:
        return "nginx"
        
    @property
    def parser_version(self) -> str:
        return "1.2.0"
        
    @property
    def supported_formats(self) -> List[str]:
        return ["combined"]
        
    @property
    def description(self) -> str:
        return "Parses Nginx default access logs."
