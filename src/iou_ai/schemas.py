"""Provider JSON-schema adapters derived from the canonical Pydantic models."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, TypeVar

from pydantic import BaseModel

from .models import PlannerProposal, ReviewerVerdict


ModelT = TypeVar("ModelT", bound=BaseModel)


def _close_object_schemas(node: Any) -> None:
    """Recursively close every object and require every declared property.

    OpenAI strict structured outputs require all properties to be required and
    all objects to reject additional properties.  Anthropic benefits from the
    same unambiguous contract.  Local Pydantic validation remains authoritative.
    """

    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            node["type"] = "object"
            node["additionalProperties"] = False
            node["required"] = list(properties)
        for value in node.values():
            _close_object_schemas(value)
    elif isinstance(node, list):
        for value in node:
            _close_object_schemas(value)


def strict_json_schema(model: type[ModelT]) -> dict[str, Any]:
    """Return a provider-portable, deeply closed schema for ``model``."""

    schema = deepcopy(model.model_json_schema(mode="validation"))
    _close_object_schemas(schema)
    return schema


_ANTHROPIC_PORTABLE_KEYS = frozenset(
    {
        "additionalProperties",
        "allOf",
        "anyOf",
        "description",
        "enum",
        "items",
        "oneOf",
        "properties",
        "required",
        "type",
    }
)


def _anthropic_constraint_description(node: Mapping[str, Any]) -> str | None:
    """Describe constraints Anthropic cannot enforce in its output grammar.

    Anthropic's structured-output SDKs remove unsupported JSON Schema keywords,
    copy their meaning into field descriptions, and validate the original schema
    locally.  The controller uses the direct HTTP API, so it must perform that
    middle step itself.  These descriptions are guidance only; the unchanged
    Pydantic model remains the authoritative fail-closed validator.
    """

    constraints: list[str] = []

    minimum_length = node.get("minLength")
    maximum_length = node.get("maxLength")
    if isinstance(minimum_length, int) and isinstance(maximum_length, int):
        constraints.append(
            f"String length must be between {minimum_length} and {maximum_length} characters."
        )
    elif isinstance(minimum_length, int):
        constraints.append(f"String length must be at least {minimum_length} characters.")
    elif isinstance(maximum_length, int):
        constraints.append(f"String length must be at most {maximum_length} characters.")

    pattern = node.get("pattern")
    if isinstance(pattern, str) and pattern:
        constraints.append(f"String must match this regular expression exactly: {pattern}.")

    minimum_items = node.get("minItems")
    maximum_items = node.get("maxItems")
    if isinstance(minimum_items, int) and isinstance(maximum_items, int):
        constraints.append(
            f"Array length must be between {minimum_items} and {maximum_items} items."
        )
    elif isinstance(minimum_items, int):
        constraints.append(f"Array length must be at least {minimum_items} items.")
    elif isinstance(maximum_items, int):
        constraints.append(f"Array length must be at most {maximum_items} items.")

    minimum = node.get("minimum")
    maximum = node.get("maximum")
    if isinstance(minimum, (int, float)) and not isinstance(minimum, bool):
        constraints.append(f"Numeric value must be at least {minimum}.")
    if isinstance(maximum, (int, float)) and not isinstance(maximum, bool):
        constraints.append(f"Numeric value must be at most {maximum}.")

    exclusive_minimum = node.get("exclusiveMinimum")
    exclusive_maximum = node.get("exclusiveMaximum")
    if isinstance(exclusive_minimum, (int, float)) and not isinstance(
        exclusive_minimum, bool
    ):
        constraints.append(f"Numeric value must be greater than {exclusive_minimum}.")
    if isinstance(exclusive_maximum, (int, float)) and not isinstance(
        exclusive_maximum, bool
    ):
        constraints.append(f"Numeric value must be less than {exclusive_maximum}.")

    if node.get("uniqueItems") is True:
        constraints.append("Array items must be unique.")

    if not constraints:
        return None
    return " ".join(constraints)


def anthropic_portable_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Return a conservative JSON Schema view for Anthropic structured output.

    The direct Messages API does not apply the schema transformation provided by
    Anthropic's SDKs.  In particular, length and numeric constraints generated
    by Pydantic are not universally accepted for grammar compilation.  We send
    only the portable structural subset and keep the complete Pydantic model as
    the authoritative post-response validator.  Local ``$defs`` references are
    inlined so the provider sees one self-contained grammar.
    """

    source = deepcopy(dict(schema))
    definitions = source.pop("$defs", {})
    if not isinstance(definitions, dict):
        raise ValueError("$defs must be an object when present")

    def inline(node: Any, active_refs: frozenset[str] = frozenset()) -> Any:
        if isinstance(node, list):
            return [inline(item, active_refs) for item in node]
        if not isinstance(node, dict):
            return node

        ref = node.get("$ref")
        if ref is not None:
            if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
                raise ValueError("schema contains an unsupported reference")
            name = ref.removeprefix("#/$defs/")
            if name not in definitions or name in active_refs:
                raise ValueError("schema contains an unresolved or cyclic reference")
            target = definitions[name]
            if not isinstance(target, dict):
                raise ValueError("schema definition must be an object")
            merged = deepcopy(target)
            for key, value in node.items():
                if key != "$ref":
                    merged[key] = value
            return inline(merged, active_refs | {name})

        result: dict[str, Any] = {}
        if "const" in node:
            # ``enum`` is the portable representation of a single literal.
            result["enum"] = [inline(node["const"], active_refs)]
        for key, value in node.items():
            if key not in _ANTHROPIC_PORTABLE_KEYS:
                continue
            if key == "properties":
                if not isinstance(value, dict):
                    raise ValueError("schema properties must be an object")
                result[key] = {
                    str(name): inline(child, active_refs)
                    for name, child in value.items()
                }
            elif key in {"items", "additionalProperties"}:
                result[key] = inline(value, active_refs)
            elif key in {"allOf", "anyOf", "oneOf"}:
                if not isinstance(value, list):
                    raise ValueError(f"schema {key} must be an array")
                result[key] = [inline(item, active_refs) for item in value]
            else:
                result[key] = deepcopy(value)

        constraint_description = _anthropic_constraint_description(node)
        if constraint_description is not None:
            existing_description = result.get("description")
            if isinstance(existing_description, str) and existing_description:
                result["description"] = (
                    existing_description.rstrip() + " " + constraint_description
                )
            else:
                result["description"] = constraint_description
        return result

    portable = inline(source)
    if not isinstance(portable, dict):
        raise ValueError("schema root must be an object")
    return portable


def openai_json_schema_format(
    model: type[ModelT],
    *,
    name: str,
    description: str,
) -> dict[str, Any]:
    """Build the value for Responses API ``text.format``."""

    return {
        "type": "json_schema",
        "name": name,
        "description": description,
        "schema": strict_json_schema(model),
        "strict": True,
    }


def anthropic_json_schema_format(model: type[ModelT]) -> dict[str, Any]:
    """Build the value for Messages API ``output_config.format``."""

    return {
        "type": "json_schema",
        "schema": anthropic_portable_schema(strict_json_schema(model)),
    }


def planner_openai_format() -> dict[str, Any]:
    return openai_json_schema_format(
        PlannerProposal,
        name="io_uring_fuzz_plan_v1",
        description=(
            "Semantic io_uring fuzzing proposal IR. It is never executable directly "
            "and must pass local validation, independent review, compilation, and canarying."
        ),
    )


def reviewer_anthropic_format() -> dict[str, Any]:
    return anthropic_json_schema_format(ReviewerVerdict)


__all__ = [
    "anthropic_json_schema_format",
    "anthropic_portable_schema",
    "openai_json_schema_format",
    "planner_openai_format",
    "reviewer_anthropic_format",
    "strict_json_schema",
]
