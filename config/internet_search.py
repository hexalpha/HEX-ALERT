"""Validated preferences for read-only public internet search."""
from typing import Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, Field, field_validator

SearchProvider = Literal['google', 'tavily', 'serper', 'brave', 'bing_compatible', 'custom']

class InternetSearchOptions(BaseModel):
    enabled: bool = False
    primary_provider: SearchProvider = 'google'
    fallback_provider: Literal['disabled', 'google', 'tavily', 'serper', 'brave', 'bing_compatible', 'custom'] = 'disabled'
    max_results: int = Field(default=5, ge=1, le=10)
    timeout_seconds: int = Field(default=12, ge=3, le=30)
    safe_search: bool = True
    trust_domain_filtering: bool = True
    cache_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    requests_per_minute: int = Field(default=6, ge=1, le=30)
    custom_endpoint: str = Field(default='', max_length=500)
    bing_compatible_endpoint: str = Field(default='', max_length=500)

    @field_validator('custom_endpoint', 'bing_compatible_endpoint')
    @classmethod
    def public_https_endpoint(cls, value):
        if not value:
            return value
        parts = urlsplit(value)
        if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError('Use an HTTPS API endpoint without credentials, query or fragment')
        return value.rstrip('/')


def get_search_options() -> InternetSearchOptions:
    from config.runtime_config import get_runtime_config
    raw = get_runtime_config().get('INTERNET_SEARCH_SETTINGS', {})
    return InternetSearchOptions.model_validate(raw if isinstance(raw, dict) else {})
