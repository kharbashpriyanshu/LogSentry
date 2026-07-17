# LogSentry SIEM Architecture

## Clean Architecture Principles
LogSentry is built upon Clean Architecture principles, ensuring a separation of concerns, scalability, and high maintainability. The codebase is organized into discrete layers where inner layers define core business logic and outward layers manage external interfaces like databases, APIs, and frameworks.

## Dependency Flow
Dependencies always point inwards. 
- `models/` and `schemas/` contain the core business entities and types.
- `repositories/` abstract database interactions.
- `services/`, `parsers/`, and `detection/` implement the business logic and orchestrate operations using interfaces defined by inner layers.
- `api/` provides the external HTTP interfaces, communicating primarily with `services/`.

## Package Responsibilities

- **`app/api/`**: Contains all FastAPI routers, endpoints, and dependency injections specific to HTTP requests.
- **`app/core/`**: Core utilities, application setup, and enterprise logging configuration.
- **`app/config/`**: Centralized configuration management using Pydantic Settings, loaded from environment variables.
- **`app/database/`**: Database connection setup, session management, and SQLAlchemy Base model.
- **`app/models/`**: SQLAlchemy declarative models (Database schemas).
- **`app/schemas/`**: Pydantic models (Data Transfer Objects) for request validation and response serialization.
- **`app/repositories/`**: Data access layer to isolate database operations from business logic.
- **`app/services/`**: Business logic layer that connects API endpoints with repositories and other sub-systems.
- **`app/parsers/`**: Log parsing logic tailored to various log formats.
- **`app/detection/`**: Core security detection algorithms and threat correlation logic.
- **`app/enrichment/`**: Modules for enriching parsed logs with contextual data (e.g., GeoIP, Threat Intel).
- **`app/ai/`**: AI/ML integrations for anomaly detection, intent processing, or automated responses.
- **`app/reports/`**: Logic for generating analytics, dashboards, and automated security reports.
- **`app/utils/`**: Shared helper functions and generic utilities.

## Future Scalability
The modular design allows sub-systems (like parsing or detection) to be scaled independently, potentially extracted into microservices or distributed workers as the platform grows.
