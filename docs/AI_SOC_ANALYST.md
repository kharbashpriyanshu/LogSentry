# AI SOC Analyst

The LogSentry AI SOC Analyst is a provider-agnostic, enterprise-grade AI integration that consumes structured `DetectionAlert` objects from the Detection Engine and outputs structured, JSON-based security analysis.

## Architecture

The AI layer adheres to SOLID principles and Clean Architecture:
- **`BaseAIProvider`**: An abstract interface defining the contract that all LLM providers must fulfill (`analyze_alert`, `health`).
- **`AIService`**: The business logic layer that handles metrics, logging, and error propagation. It strictly depends on the abstract provider, never the concrete implementation.
- **Dependency Injection**: FastAPI injects the selected provider into the `AIService` at startup based on the `AI_PROVIDER` environment variable.

## Supported Providers
Currently, the system is designed to support:
1. **OpenAI** (Fully implemented via standard HTTP to avoid SDK bloat)
2. **Google Gemini** (Placeholder stub)
3. **Ollama** (Placeholder stub for localized, air-gapped deployments)

## Prompt Strategy
Prompts are isolated from the business logic in `app/ai/prompts.py`. 
We use a **System Prompt** to define the persona (Tier-3 SOC Analyst) and a strict **User Prompt Template** that injects the `DetectionAlert` properties. We enforce structural outputs by passing a JSON schema directly in the prompt and requesting `json_object` responses from the provider.

## Error Handling
The AI Service defines granular exceptions:
- `AIProviderUnavailableError` -> HTTP 503
- `AITimeoutError` -> HTTP 504
- `AIRateLimitError` -> HTTP 429
- `AIInvalidResponseError` -> HTTP 502

## Security & Privacy
- API Keys are NEVER logged.
- The AI Service operates *only* on normalized alerts, not raw files.
- Ensure your data classification policies permit sending `evidence` dictionaries to 3rd party providers before using cloud LLMs. For strict privacy, use the `ollama` provider.
