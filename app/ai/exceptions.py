class AIError(Exception):
    """Base exception for all AI operations."""
    pass

class AIProviderUnavailableError(AIError):
    """Raised when the AI provider cannot be reached."""
    pass

class AITimeoutError(AIError):
    """Raised when the AI provider times out."""
    pass

class AIRateLimitError(AIError):
    """Raised when the AI provider rate limits the request."""
    pass

class AIInvalidResponseError(AIError):
    """Raised when the AI provider returns an unparseable or invalid response."""
    pass

class AIPromptError(AIError):
    """Raised when there is a failure formatting or handling the prompt."""
    pass
