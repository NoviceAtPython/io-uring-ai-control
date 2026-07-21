"""Anthropic Messages API adapter for the Claude Sonnet 5 reviewer."""

from __future__ import annotations

from typing import Any, Mapping

from ..schemas import anthropic_portable_schema
from .base import (
    DEFAULT_TIMEOUT_SECONDS,
    HttpTransport,
    ProviderAdapter,
    ProviderProtocolError,
    ProviderRefusalError,
    ProviderRequest,
    ProviderResult,
    ProviderStateError,
    StdlibHttpTransport,
    TokenUsage,
    header_value,
    optional_nonnegative_int,
    parse_json_object,
    raise_for_http_error,
    required_nonnegative_int,
)


ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-5"
ANTHROPIC_ALLOWED_MODELS = frozenset(
    {"claude-sonnet-5", "claude-fable-5", "claude-opus-4-8"}
)
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_MAX_TOKENS = 16_000


class AnthropicMessagesAdapter(ProviderAdapter):
    """One-shot, schema-constrained independent reviewer adapter."""

    provider = "anthropic"
    model = ANTHROPIC_MODEL

    def __init__(
        self,
        api_key: str,
        *,
        model: str = ANTHROPIC_MODEL,
        transport: HttpTransport | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_output_tokens: int = ANTHROPIC_MAX_TOKENS,
        reasoning_effort: str = "high",
    ) -> None:
        if not api_key.strip():
            raise ValueError("Anthropic API key must not be blank")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if model not in ANTHROPIC_ALLOWED_MODELS:
            raise ValueError("Anthropic model is not approved for this controller")
        if isinstance(max_output_tokens, bool) or max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be positive")
        if reasoning_effort not in {"low", "medium", "high"}:
            raise ValueError("Anthropic reasoning effort is not approved")
        self._api_key = api_key
        self.model = model
        self._transport = transport or StdlibHttpTransport()
        self._timeout_seconds = timeout_seconds
        self._max_output_tokens = max_output_tokens
        self._reasoning_effort = reasoning_effort

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(model={self.model!r}, "
            f"timeout_seconds={self._timeout_seconds!r})"
        )

    def generate(self, request: ProviderRequest) -> ProviderResult:
        try:
            schema = anthropic_portable_schema(request.json_schema)
        except ValueError as exc:
            raise ProviderProtocolError(
                "Anthropic request schema cannot be made portable"
            ) from exc
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self._max_output_tokens,
            "system": [{"type": "text", "text": request.system_prompt}],
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": request.input_text}],
                }
            ],
            "thinking": {"type": "adaptive"},
            "output_config": {
                "effort": self._reasoning_effort,
                "format": {
                    "type": "json_schema",
                    "schema": schema,
                },
            },
        }
        if request.principal_id is not None:
            payload["metadata"] = {"user_id": request.principal_id}

        response = self._transport.post_json(
            ANTHROPIC_MESSAGES_URL,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            payload=payload,
            timeout_seconds=self._timeout_seconds,
        )
        raise_for_http_error(self.provider, response)
        body = parse_json_object(response.body, provider=self.provider)

        stop_reason = body.get("stop_reason")
        if stop_reason == "refusal" or _contains_refusal(body.get("content")):
            raise ProviderRefusalError("Anthropic refused the request")
        if stop_reason != "end_turn":
            raise ProviderStateError("Anthropic response did not end normally")
        text = _extract_final_text(body.get("content"))

        response_id = body.get("id")
        if response_id is not None and not isinstance(response_id, str):
            raise ProviderProtocolError("Anthropic returned an invalid response id")
        response_model = body.get("model")
        if response_model is not None and not isinstance(response_model, str):
            raise ProviderProtocolError("Anthropic returned an invalid model id")

        return ProviderResult(
            provider=self.provider,
            model=response_model or self.model,
            text=text,
            response_id=response_id,
            provider_request_id=header_value(response.headers, "request-id"),
            client_request_id=request.client_request_id,
            status=stop_reason,
            usage=_extract_usage(body.get("usage")),
        )


def _contains_refusal(content: Any) -> bool:
    if not isinstance(content, list):
        return False
    return any(isinstance(block, Mapping) and block.get("type") == "refusal" for block in content)


def _extract_final_text(content: Any) -> str:
    if not isinstance(content, list):
        raise ProviderProtocolError("Anthropic returned invalid content")
    texts: list[str] = []
    for block in content:
        if not isinstance(block, Mapping):
            raise ProviderProtocolError("Anthropic returned an invalid content block")
        if block.get("type") == "text":
            text = block.get("text")
            if not isinstance(text, str) or not text:
                raise ProviderProtocolError("Anthropic returned an invalid text block")
            texts.append(text)
    if not texts:
        raise ProviderProtocolError("Anthropic response did not contain final text")
    return texts[-1]


def _extract_usage(value: Any) -> TokenUsage | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ProviderProtocolError("Anthropic returned invalid usage metadata")

    input_tokens = required_nonnegative_int(
        value.get("input_tokens"), provider="Anthropic", field_name="input_tokens"
    )
    output_tokens = required_nonnegative_int(
        value.get("output_tokens"), provider="Anthropic", field_name="output_tokens"
    )
    cached_tokens = optional_nonnegative_int(
        value.get("cache_read_input_tokens"),
        provider="Anthropic",
        field_name="cache_read_input_tokens",
    )
    cache_creation_tokens = optional_nonnegative_int(
        value.get("cache_creation_input_tokens"),
        provider="Anthropic",
        field_name="cache_creation_input_tokens",
    )
    return TokenUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_input_tokens=cached_tokens,
        cache_creation_input_tokens=cache_creation_tokens,
        # Anthropic includes thinking in output_tokens rather than reporting a
        # separate reasoning-token field.
        reasoning_tokens=0,
        total_tokens=input_tokens + output_tokens,
    )


AnthropicAdapter = AnthropicMessagesAdapter
