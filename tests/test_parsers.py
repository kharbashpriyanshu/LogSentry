import pytest
from app.parsers.factory import ParserFactory
from app.parsers.apache import ApacheParser
from app.parsers.nginx import NginxParser
from app.parsers.exceptions import UnsupportedParserError, ParserValidationError
from datetime import datetime, timezone

def test_apache_parser_valid_line():
    parser = ApacheParser()
    line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"'
    assert parser.validate(line) is True
    event = parser.parse_line(line)
    assert event is not None
    assert event.source_ip == "127.0.0.1"
    assert event.method == "GET"
    assert event.endpoint == "/apache_pb.gif"
    assert event.status_code == 200
    assert event.response_size == 2326
    assert event.parser_name == "apache"
    
    # Check timestamp normalization
    assert event.timestamp is not None
    assert event.timestamp.year == 2000
    assert event.timestamp.month == 10
    assert event.timestamp.tzinfo == timezone.utc

def test_apache_parser_invalid_line():
    parser = ApacheParser()
    line = "just some random garbage"
    assert parser.validate(line) is False
    event = parser.parse_line(line)
    assert event is None

def test_apache_parser_malformed_timestamp():
    parser = ApacheParser()
    line = '127.0.0.1 - frank [Invalid/Time:Stamp] "GET / HTTP/1.0" 200 2326 "-" "-"'
    assert parser.validate(line) is True
    event = parser.parse_line(line)
    assert event is not None
    assert event.timestamp is None  # Handled gracefully

def test_nginx_parser_valid_line():
    parser = NginxParser()
    line = '10.0.0.5 - - [15/Jan/2024:08:22:10 +0000] "GET /index.html HTTP/2.0" 200 512 "-" "Mozilla/5.0"'
    assert parser.validate(line) is True
    event = parser.parse_line(line)
    assert event is not None
    assert event.source_ip == "10.0.0.5"
    assert event.method == "GET"
    assert event.status_code == 200
    assert event.response_size == 512

def test_factory_get_parser():
    parser = ParserFactory.get_parser("apache")
    assert isinstance(parser, ApacheParser)
    
    with pytest.raises(UnsupportedParserError):
        ParserFactory.get_parser("unknown")

def test_factory_guess_parser():
    apache_line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "-" "-"'
    parser = ParserFactory.guess_parser(apache_line)
    assert isinstance(parser, (ApacheParser, NginxParser))
    
    with pytest.raises(UnsupportedParserError):
        ParserFactory.guess_parser("invalid line")

def test_parse_file():
    parser = ApacheParser()
    events = parser.parse_file("sample_logs/apache/valid.log")
    assert len(events) == 3

    events_malformed = parser.parse_file("sample_logs/apache/malformed.log")
    assert len(events_malformed) == 0

def test_parser_metadata():
    parser = ApacheParser()
    assert parser.parser_name == "apache"
    assert parser.parser_version == "1.2.0"
    assert "combined" in parser.supported_formats
    assert "Apache" in parser.description

def test_parse_empty_file():
    parser = ApacheParser()
    events = parser.parse_file("sample_logs/apache/empty.log")
    assert len(events) == 0

def test_parse_mixed_file():
    parser = ApacheParser()
    events = parser.parse_file("sample_logs/apache/mixed.log")
    # mixed.log has 2 valid, 2 invalid
    assert len(events) == 2

def test_parse_extremely_long_line():
    parser = ApacheParser()
    long_ua = "A" * 10000
    line = f'127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 2326 "-" "{long_ua}"'
    assert parser.validate(line) is True
    event = parser.parse_line(line)
    assert event is not None
    assert event.user_agent == long_ua

def test_parse_invalid_utf8():
    parser = ApacheParser()
    # file contains invalid utf-8, open with errors="replace" should prevent crash
    events = parser.parse_file("sample_logs/apache/invalid_utf8.log")
    assert len(events) == 0  # it's invalid content anyway, but it shouldn't crash
