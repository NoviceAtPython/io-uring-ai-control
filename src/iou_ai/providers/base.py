"""Provider-neutral request, result, transport, and error contracts.

The adapters deliberately expose only parsed text and accounting metadata.  Raw
provider responses are not retained because they can contain telemetry or model
output that must not leak into logs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping, Protocol
from urllib import error as urllib_error
from urllib import request as urllib_request


# Frontier reasoning calls can legitimately take longer than two minutes. Keep
# this bounded below the outer service deadline, and never retry an uncertain
# request: the budget ledger must continue to treat it as dispatched.
DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    """One schema-constrained generation request.

    ``principal_id`` must be an opaque, stable identifier rather than a name,
    email address, path, or other identifying data.
    """

    system_prompt: str
    input_text: str
    json_schema: Mapping[str, Any]
    schema_name: str
    client_request_id: str
    principal_id: str | None = None
    schema_description: str = "Machine-readable output for the fuzzing controller."

    def __post_init__(self) -> None:
        for field_name in (
            "system_prompt",
            "input_text",
            "schema_name",
            "client_request_id",
            "schema_description",
        ):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} must not be blank")
        if not isinstance(self.json_schema, Mapping):
            raise TypeError("json_schema must be a mapping")
        if self.principal_id is not None and not self.principal_id.strip():
            raise ValueError("principal_id must be non-blank when provided")


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Normalized token counts used by the budget ledger."""

    input_tokens: int
    output_tokens: int
    cached_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0

    def __post_init__(self) -> None:
        for field_name in (
            "input_tokens",
            "output_tokens",
            "cached_input_tokens",
            "cache_creation_input_tokens",
            "reasoning_tokens",
            "total_tokens",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class ProviderResult:
    """A successfully completed provider response."""

    provider: str
    model: str
    text: str
    response_id: str | None
    provider_request_id: str | None
    client_request_id: str
    status: str
    usage: TokenUsage | None

    @property
    def output_text(self) -> str:
        """Compatibility alias that makes the parsed payload explicit."""

        return self.text


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class HttpTransport(Protocol):
    """Minimal injectable HTTP surface; implementations make exactly one call."""

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> HttpResponse: ...


class ProviderError(RuntimeError):
    """Base class for fail-closed provider failures."""


class ProviderTransportError(ProviderError):
    """The single HTTP attempt did not yield a response."""


class ProviderTimeoutError(ProviderTransportError):
    """The single HTTP attempt exceeded its bounded response window."""


class ProviderConnectionError(ProviderTransportError):
    """The single HTTP attempt failed before yielding an HTTP response."""


class ProviderProtocolError(ProviderError):
    """The provider response did not satisfy the expected wire contract."""


class ProviderStateError(ProviderError):
    """The response was valid but not in the required completed state."""


class ProviderIncompleteError(ProviderStateError):
    """Generation ended before producing a complete structured response."""


class ProviderRefusalError(ProviderStateError):
    """The provider refused the request; callers must not retry unchanged."""


class ProviderHTTPError(ProviderError):
    """A sanitized non-success HTTP response.

    The response body is intentionally omitted to avoid propagating request or
    response content into exception logs.
    """

    def __init__(
        self,
        provider: str,
        status_code: int,
        *,
        error_type: str | None = None,
        error_code: str | None = None,
        error_param: str | None = None,
        request_id: str | None = None,
    ) -> None:
        self.provider = provider
        self.status_code = status_code
        self.error_type = error_type
        self.error_code = error_code
        self.error_param = error_param
        self.request_id = request_id
        self.retryable = status_code in {408, 409, 429} or status_code >= 500
        details = [error_type or "unknown_error"]
        if error_code:
            details.append(f"code={error_code}")
        if error_param:
            details.append(f"param={error_param}")
        if request_id:
            details.append(f"request_id={request_id}")
        super().__init__(f"{provider} HTTP {status_code} ({'; '.join(details)})")


class ProviderAuthenticationError(ProviderHTTPError):
    """Authentication or authorization failed."""


class ProviderRateLimitError(ProviderHTTPError):
    """The provider rejected the single attempt due to a rate limit."""


class StdlibHttpTransport:
    """Small urllib transport with no automatic retry behavior."""

    def __init__(self, *, max_response_bytes: int = MAX_HTTP_RESPONSE_BYTES) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self._max_response_bytes = max_response_bytes

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> HttpResponse:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ProviderProtocolError("request payload is not valid JSON") from exc

        req = urllib_request.Request(
            url,
            data=encoded,
            headers=dict(headers),
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=timeout_seconds) as response:
                body = self._read_bounded(response.read)
                return HttpResponse(
                    status_code=int(response.status),
                    headers={str(k): str(v) for k, v in response.headers.items()},
                    body=body,
                )
        except urllib_error.HTTPError as exc:
            body = self._read_bounded(exc.read)
            headers_out = (
                {str(k): str(v) for k, v in exc.headers.items()}
                if exc.headers is not None
                else {}
            )
            return HttpResponse(
                status_code=int(exc.code),
                headers=headers_out,
                body=body,
            )
        except TimeoutError as exc:
            # TimeoutError is an OSError subclass, so it must be classified
            # before the broader connection-failure branch.
            raise ProviderTimeoutError("provider request timed out") from exc
        except urllib_error.URLError as exc:
            # urllib wraps socket timeouts in URLError on some platforms.
            # Inspect only the exception type and never propagate exception
            # prose into service logs.
            if isinstance(exc.reason, TimeoutError):
                raise ProviderTimeoutError("provider request timed out") from exc
            raise ProviderConnectionError("provider connection failed") from exc
        except OSError as exc:
            raise ProviderConnectionError("provider connection failed") from exc

    def _read_bounded(self, reader: Callable[[int], bytes]) -> bytes:
        body = reader(self._max_response_bytes + 1)
        if len(body) > self._max_response_bytes:
            raise ProviderTransportError("provider response exceeded the size limit")
        return body


class ProviderAdapter(ABC):
    """Common interface implemented by planner, reviewer, and mock adapters."""

    @abstractmethod
    def generate(self, request: ProviderRequest) -> ProviderResult:
        """Make one request and either return a completed result or raise."""

    def complete(self, request: ProviderRequest) -> ProviderResult:
        """Readable alias used by coordinator code."""

        return self.generate(request)


def header_value(headers: Mapping[str, str], name: str) -> str | None:
    target = name.casefold()
    for key, value in headers.items():
        if str(key).casefold() == target:
            return str(value)
    return None


def parse_json_object(body: bytes, *, provider: str) -> dict[str, Any]:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderProtocolError(f"{provider} returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise ProviderProtocolError(f"{provider} returned a non-object JSON response")
    return value


def raise_for_http_error(provider: str, response: HttpResponse) -> None:
    if 200 <= response.status_code < 300:
        return

    error_type: str | None = None
    error_code: str | None = None
    error_param: str | None = None
    try:
        value = json.loads(response.body.decode("utf-8"))
        if isinstance(value, dict):
            error = value.get("error")
            if isinstance(error, dict):
                error_type = _safe_error_token(error.get("type"))
                error_code = _safe_error_token(error.get("code"))
                error_param = _safe_error_token(error.get("param"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    kwargs = {
        "error_type": error_type,
        "error_code": error_code,
        "error_param": error_param,
        "request_id": _safe_error_token(
            header_value(response.headers, "request-id")
            or header_value(response.headers, "x-request-id")
        ),
    }
    if response.status_code in {401, 403}:
        raise ProviderAuthenticationError(provider, response.status_code, **kwargs)
    if response.status_code == 429:
        raise ProviderRateLimitError(provider, response.status_code, **kwargs)
    raise ProviderHTTPError(provider, response.status_code, **kwargs)


def _safe_error_token(value: object) -> str | None:
    """Retain diagnostic identifiers without logging provider-controlled prose."""

    if not isinstance(value, str) or not value:
        return None
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
        return None
    return value


def required_nonnegative_int(
    value: Any,
    *,
    provider: str,
    field_name: str,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProviderProtocolError(
            f"{provider} returned an invalid {field_name} token count"
        )
    return value


def optional_nonnegative_int(
    value: Any,
    *,
    provider: str,
    field_name: str,
) -> int:
    if value is None:
        return 0
    return required_nonnegative_int(value, provider=provider, field_name=field_name)
