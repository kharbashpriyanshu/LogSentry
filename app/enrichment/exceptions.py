class EnrichmentError(Exception):
    """Base exception for all enrichment operations."""
    pass

class ProviderUnavailableError(EnrichmentError):
    """Raised when the provider is unreachable."""
    pass

class ProviderTimeoutError(EnrichmentError):
    """Raised when the provider times out."""
    pass

class ProviderRateLimitError(EnrichmentError):
    """Raised when the provider rate limit is exceeded."""
    pass

class InvalidIOCError(EnrichmentError):
    """Raised when the provided IOC is invalid for the provider."""
    pass

class MalformedResponseError(EnrichmentError):
    """Raised when the provider returns an unparseable response."""
    pass
