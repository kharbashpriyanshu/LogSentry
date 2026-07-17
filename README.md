# LogSentry SIEM

LogSentry is an enterprise-grade Security Information and Event Management (SIEM) system. It focuses on robust log parsing, intelligent threat detection, AI-powered insights, and scalable architecture. 

## Project Overview
This project provides a comprehensive foundation for ingesting, processing, and analyzing security logs. Built using modern Python frameworks, LogSentry emphasizes high performance, code quality, and maintainability.

## API Backend (FastAPI)
LogSentry provides a fully documented REST API.
To start the API Server:
```bash
uvicorn app.main:app --reload
```
Once running, navigate to `http://127.0.0.1:8000/docs` to view the interactive Swagger UI.

### Example Request
```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/api/v1/parser/parse-line' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "parser_name": "apache",
  "log_line": "127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] \"GET / HTTP/1.0\" 200 2326 \"-\" \"-\""
}'
```

For detailed architecture instructions:
- [docs/PARSING_ENGINE.md](docs/PARSING_ENGINE.md)
- [docs/DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md)
- [docs/API.md](docs/API.md)

## Installation
### Prerequisites
- Python 3.11+

### Setup
1. Clone the repository.
2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements-dev.txt
   pip install fastapi uvicorn pydantic-settings python-multipart
   ```

## Development Workflow
We use `pre-commit` to enforce code quality. To set it up:
```bash
pre-commit install
```

To run tests:
```bash
pytest
```

## Project Roadmap
- **Sprint 0**: Project Foundation (Completed)
- **Sprint 1**: Core Log Parsing Engine (Completed)
- **Sprint 2**: Detection Engine & Rule Framework (Completed)
- **Sprint 3**: FastAPI Backend & REST API (Completed)
- **Sprint 4**: AI Features Integration
- **Sprint 5**: Dashboard & Reporting

## License
MIT License.
