"""OpenAI Responses API adapter for the GPT-5.6 Sol planner."""

from __future__ import annotations

from typing import Any, Mapping

from .base import (
    DEFAULT_TIMEOUT_SECONDS,
    HttpTransport,
    ProviderAdapter,
    ProviderIncompleteError,
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


OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
OPENAI_MODEL = "gpt-5.6-sol"
OPENAI_MAX_OUTPUT_TOKENS = 16_000


class OpenAIResponsesAdapter(ProviderAdapter):
    """One-shot, schema-constrained planner adapter.

    The API key stays in this object's private memory and is never included in
    ``repr`` or returned metadata.
    """

    provider = "openai"
    model = OPENAI_MODEL

    def __init__(
        self,
        api_key: str,
        *,
        model: str = OPENAI_MODEL,
        transport: HttpTransport | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_output_tokens: int = OPENAI_MAX_OUTPUT_TOKENS,
        reasoning_effort: str = "high",
    ) -> None:
        if not api_key.strip():
            raise ValueError("OpenAI API key must not be blank")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if model != OPENAI_MODEL:
            raise ValueError("OpenAI model is not approved for this controller")
        if isinstance(max_output_tokens, bool) or max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be positive")
        if reasoning_effort not in {"low", "medium", "high", "xhigh", "max"}:
            raise ValueError("OpenAI reasoning effort is not approved")
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
        payload: dict[str, Any] = {
            "model": self.model,
            "instructions": request.system_prompt,
            "input": [
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": request.input_text}],
                }
            ],
            "reasoning": {"effort": self._reasoning_effort},
            "max_output_tokens": self._max_output_tokens,
            "text": {
                "verbosity": "low",
                "format": {
                    "type": "json_schema",
                    "name": request.schema_name,
                    "description": request.schema_description,
                    "schema": dict(request.json_schema),
                    "strict": True,
                },
            },
            "store": False,
            "truncation": "disabled",
        }
        if request.principal_id is not None:
            payload["safety_identifier"] = request.principal_id

        response = self._transport.post_json(
            OPENAI_RESPONSES_URL,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "X-Client-Request-Id": request.client_request_id,
            },
            payload=payload,
            timeout_seconds=self._timeout_seconds,
        )
        raise_for_http_error(self.provider, response)
        body = parse_json_object(response.body, provider=self.provider)

        status = body.get("status")
        if status == "incomplete":
            raise ProviderIncompleteError("OpenAI response was incomplete")
        if status != "completed":
            raise ProviderStateError("OpenAI response was not completed")

        if _contains_refusal(body.get("output")):
            raise ProviderRefusalError("OpenAI refused the request")
        text = _extract_single_output_text(body.get("output"))

        response_id = body.get("id")
        if response_id is not None and not isinstance(response_id, str):
            raise ProviderProtocolError("OpenAI returned an invalid response id")

        return ProviderResult(
            provider=self.provider,
            model=self.model,
            text=text,
            response_id=response_id,
            provider_request_id=header_value(response.headers, "x-request-id"),
            client_request_id=request.client_request_id,
            status=status,
            usage=_extract_usage(body.get("usage")),
        )


def _walk(value: Any):
    if isinstance(value, Mapping):
        yield value
        for nested in value.values():
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested)


def _contains_refusal(output: Any) -> bool:
    return any(item.get("type") == "refusal" for item in _walk(output))


def _extract_single_output_text(output: Any) -> str:
    texts: list[str] = []
    for item in _walk(output):
        if item.get("type") == "output_text":
            text = item.get("text")
            if not isinstance(text, str) or not text:
                raise ProviderProtocolError("OpenAI returned an invalid output_text block")
            texts.append(text)
    if len(texts) != 1:
        raise ProviderProtocolError(
            "OpenAI response must contain exactly one output_text block"
        )
    return texts[0]


def _extract_usage(value: Any) -> TokenUsage | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ProviderProtocolError("OpenAI returned invalid usage metadata")

    input_tokens = required_nonnegative_int(
        value.get("input_tokens"), provider="OpenAI", field_name="input_tokens"
    )
    output_tokens = required_nonnegative_int(
        value.get("output_tokens"), provider="OpenAI", field_name="output_tokens"
    )
    input_details = value.get("input_tokens_details")
    if input_details is not None and not isinstance(input_details, Mapping):
        raise ProviderProtocolError("OpenAI returned invalid input token details")
    output_details = value.get("output_tokens_details")
    if output_details is not None and not isinstance(output_details, Mapping):
        raise ProviderProtocolError("OpenAI returned invalid output token details")

    cached_tokens = optional_nonnegative_int(
        input_details.get("cached_tokens") if input_details else None,
        provider="OpenAI",
        field_name="cached_tokens",
    )
    reasoning_tokens = optional_nonnegative_int(
        output_details.get("reasoning_tokens") if output_details else None,
        provider="OpenAI",
        field_name="reasoning_tokens",
    )
    total_tokens = optional_nonnegative_int(
        value.get("total_tokens"), provider="OpenAI", field_name="total_tokens"
    )
    if "total_tokens" not in value:
        total_tokens = input_tokens + output_tokens

    return TokenUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_input_tokens=cached_tokens,
        reasoning_tokens=reasoning_tokens,
        total_tokens=total_tokens,
    )


# Short aliases make configuration and imports less verbose.
OpenAIAdapter = OpenAIResponsesAdapter
