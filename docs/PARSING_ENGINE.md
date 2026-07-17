# Core Log Parsing Engine

The LogSentry Core Log Parsing Engine is responsible for normalizing unstructured log data from various sources into structured `LogEvent` Python objects. This module is built emphasizing extensibility and robustness.

## Strategy Pattern Implementation
The parsing engine leverages the **Strategy Pattern**. Each log format corresponds to a specific parser class (the "strategy") that inherits from `BaseParser`.
- `BaseParser`: An abstract base class defining the contract (`validate()`, `parse_line()`, `parse_file()`) and parser metadata (`parser_name`, `parser_version`, `supported_formats`, `description`).
- `ApacheParser` & `NginxParser`: Concrete implementations of the strategy that parse specific Combined Log Formats.

## Factory Design & Registration
To adhere to the Open/Closed Principle, we use a **Parser Factory** (`ParserFactory`).
- The factory abstracts the instantiation of parsers.
- An internal `_registry` manages the supported parsers.
- Parsers can be retrieved by name (`get_parser()`).
- The factory can attempt to dynamically identify the correct parser based on a raw log line (`guess_parser()`).
- New parsers can be registered dynamically via `ParserFactory.register_parser(parser_class)` without modifying the core factory code.

## Normalization Process
Regardless of the log format, the parsers produce a standardized `LogEvent` object, ensuring downstream systems only interact with normalized data.
- **Timestamps**: Parsed into UTC timezone-aware `datetime` objects to guarantee cross-system alignment and eliminate regional timezone issues.
- Missing fields in specific log formats are gracefully set to `None`.

## Error Handling & Exceptions
The module enforces a strict separation of parsing concerns using a dedicated `app/parsers/exceptions.py` module containing:
- `ParserError`
- `InvalidLogFormatError`
- `UnsupportedParserError`
- `MalformedTimestampError`
- `ParserValidationError`

Robust error handling ensures the platform never crashes due to a single malformed log entry. Invalid lines are logged as warnings using the centralized logging system. 

## Performance Optimizations
- **Regex Caching**: Regular expressions used to evaluate log entries are compiled once at the module level using `re.compile()`, drastically lowering the CPU overhead of initializing patterns on every parse.

## Extending the Parser Framework
To add a new parser (e.g., `SyslogParser`):
1. Create a new class extending `BaseParser`.
2. Implement metadata properties (`parser_name`, `parser_version`, etc.) and the parsing methods (`validate()`, `parse_line()`).
3. Import the new parser in `app/parsers/__init__.py`.
4. Register the new parser in the `ParserFactory` via `ParserFactory.register_parser()`.
