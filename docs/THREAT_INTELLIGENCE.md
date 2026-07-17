# Threat Intelligence Engine

The Threat Intelligence Engine (Sprint 5) provides a modular, provider-agnostic framework to enrich `DetectionAlert` objects with external contextual data. It acts as a bridge between the Detection Engine and the AI SOC Analyst.

## Architecture

The Enrichment Engine follows SOLID and Clean Architecture principles:
- **`BaseThreatProvider`**: Abstract interface enforcing `provider_name()`, `health()`, and `enrich()`.
- **`EnrichmentService`**: Aggregates providers, manages caching, and prevents exceptions from crashing the enrichment pipeline.
- **Dependency Injection**: FastAPI injects the `EnrichmentService` which itself is injected with a list of configured providers and an in-memory cache.

## Provider Abstraction

Each threat provider (e.g., AbuseIPDB, OTX, MITRE) inherits from `BaseThreatProvider`. This design ensures the application never depends on a concrete provider implementation. The system simply loops through enabled providers and calls `enrich()`. If a provider fails or times out, the error is caught, logged, and the next provider is called.

## Caching

To reduce API latency and avoid rate limits, the `InMemoryCache` stores enrichment results based on the indicator (e.g., IP address or MITRE technique) and the provider name. The cache respects a configurable TTL (`ENRICHMENT_CACHE_TTL`). The cache logic is encapsulated, meaning it can easily be swapped with Redis in a future iteration.

## Configuration

Settings are managed via `.env` variables mapped into `app.config.settings.Settings`:
- `ABUSEIPDB_API_KEY`: AbuseIPDB credentials.
- `OTX_API_KEY`: AlienVault OTX credentials.
- `ENRICHMENT_CACHE_TTL`: Cache expiration in seconds (default 3600).
- `ENABLE_ABUSEIPDB`, `ENABLE_OTX`, `ENABLE_MITRE`: Toggles for individual providers.
- `ENRICHMENT_REQUEST_TIMEOUT`: Global HTTP timeout for provider requests.

## MITRE Mapping

The MITRE ATT&CK provider currently operates using a local static JSON mapping (`MITRE_MAPPING`) rather than an external API. This ensures rapid tactic/technique resolution without network overhead.

## Future Roadmap
- Integration of a Redis-backed distributed cache for horizontally scaled environments.
- Support for VirusTotal and Shodan providers.
- Asynchronous provider execution for improved performance.
