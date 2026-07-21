"""Deterministic, side-effect-free provider used for local shadow tests."""

from __future__ import annotations

from collections.abc import Callable

from .base import ProviderAdapter, ProviderRequest, ProviderResult, TokenUsage


MockResponseFactory = Callable[[ProviderRequest], str]


class MockProviderAdapter(ProviderAdapter):
    """Return a fixed value or a deterministic value derived from the request."""

    def __init__(
        self,
        response: str | MockResponseFactory = "{}",
        *,
        provider: str = "mock",
        model: str = "mock-v1",
        usage: TokenUsage | None = TokenUsage(
            input_tokens=1,
            output_tokens=1,
            total_tokens=2,
        ),
    ) -> None:
        if not isinstance(response, str) and not callable(response):
            raise TypeError("response must be text or a callable")
        if not provider.strip() or not model.strip():
            raise ValueError("provider and model must not be blank")
        self._response = response
        self.provider = provider
        self.model = model
        self.usage = usage
        self.requests: list[ProviderRequest] = []

    def generate(self, request: ProviderRequest) -> ProviderResult:
        self.requests.append(request)
        text = self._response(request) if callable(self._response) else self._response
        if not isinstance(text, str):
            raise TypeError("mock response factory must return text")
        return ProviderResult(
            provider=self.provider,
            model=self.model,
            text=text,
            response_id=f"mock-{len(self.requests):04d}",
            provider_request_id=None,
            client_request_id=request.client_request_id,
            status="completed",
            usage=self.usage,
        )


MockAdapter = MockProviderAdapter
