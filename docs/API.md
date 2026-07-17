# LogSentry REST API v1

The LogSentry API exposes the internal Parsing and Detection engines over HTTP, providing a standardized JSON interface for clients and external integrations.

## Architecture
- **Framework**: FastAPI
- **Serialization**: Pydantic v2
- **Middleware**: GZip compression, CORS, Request Logging, Security Headers.
- **Dependency Injection**: Services (`ParsingService`, `DetectionService`) are injected into routers, keeping routers thin and easily testable.

## Global Features
- **Correlation IDs**: Every response includes an `X-Correlation-ID` header. This ID is logged across the stack for distributed tracing.
- **Performance Metrics**: Every response includes an `X-Process-Time` header.
- **Standardized Errors**: All HTTP 4xx and 5xx errors return a consistent schema:
  ```json
  {
    "error": "Error Type",
    "details": "Detailed description",
    "correlation_id": "uuid"
  }
  ```

## Endpoints

### `GET /api/v1/health`
Retrieves system health, uptime, and engine capabilities.

### `POST /api/v1/parser/parse-line`
Parses a single log line.
**Request Body:**
```json
{
  "parser_name": "apache",
  "log_line": "127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] \"GET / HTTP/1.0\" 200 2326 \"-\" \"-\""
}
```

### `POST /api/v1/parser/parse-file`
Parses an entire uploaded file.
**Format:** `multipart/form-data`
**Fields:**
- `parser_name`: (string) e.g., `apache`
- `file`: (binary) The log file.

### `POST /api/v1/detection/analyze`
Accepts a structured `LogEvent` directly and returns any generated `DetectionAlerts`.

### `POST /api/v1/detection/analyze-file`
End-to-end pipeline. Parses a file and runs it through the detection engine, returning all triggered alerts.

### `GET /api/v1/alerts/example`
Returns example schema output for a `DetectionAlert`.
