"""Strict JSON and canonical hashing helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NoReturn, TypeAlias, cast

JSONValue: TypeAlias = (
    bool | int | float | str | None | Sequence["JSONValue"] | Mapping[str, "JSONValue"]
)


class StrictJSONError(ValueError):
    """Raised when JSON is ambiguous or non-standard."""


def _reject_constant(value: str) -> NoReturn:
    raise StrictJSONError(f"non-standard numeric constant is not allowed: {value}")


def _object_pairs(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate object key: {key}")
        result[key] = value
    return result


def loads_strict(text: str) -> JSONValue:
    try:
        return cast(
            JSONValue,
            json.loads(
                text,
                object_pairs_hook=_object_pairs,
                parse_constant=_reject_constant,
            ),
        )
    except json.JSONDecodeError as exc:
        raise StrictJSONError(f"invalid JSON at line {exc.lineno}, column {exc.colno}") from exc


def load_json(path: str | Path) -> JSONValue:
    return loads_strict(Path(path).read_text(encoding="utf-8"))


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise StrictJSONError("value is not canonical JSON") from exc


def digest_json(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_json(path: str | Path, value: object) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
