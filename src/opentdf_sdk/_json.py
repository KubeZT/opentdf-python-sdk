import json
from typing import Any

from ._kas import TdfError


def json_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TdfError("Expected a JSON object")
    return value


def _unique_object(entries: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, part in entries:
        if key in value:
            raise TdfError("Duplicate JSON field")
        value[key] = part
    return value


def _reject_constant(value: str) -> None:
    raise TdfError("Invalid JSON number")


def parse_object(data: bytes) -> dict[str, Any]:
    return json_object(
        json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    )
