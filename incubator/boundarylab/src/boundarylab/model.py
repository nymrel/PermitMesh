"""Validated policy, profile, and result models."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Literal, cast

from boundarylab.io import JSONValue

AUTH_SCHEMA = "nymrel.boundarylab.authorization.v1"
PROFILE_SCHEMA = "nymrel.boundarylab.profile.v1"
RECEIPT_SCHEMA = "nymrel.boundarylab.receipt.v1"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
ADAPTERS = frozenset({"local", "command", "docker", "vercel"})
OPS = frozenset(
    {
        "observe",
        "equals",
        "not_equals",
        "contains",
        "not_contains",
        "lte",
        "gte",
        "one_of",
    }
)
ResultStatus = Literal[
    "pass",
    "fail",
    "unsupported",
    "untested",
    "inconclusive",
    "error",
]


class BoundaryLabError(ValueError):
    """A bounded, user-actionable BoundaryLab failure."""


def _mapping(value: JSONValue, label: str) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise BoundaryLabError(f"{label} must be an object")
    return value


def _list(value: JSONValue, label: str) -> list[JSONValue]:
    if not isinstance(value, list):
        raise BoundaryLabError(f"{label} must be an array")
    return value


def _string(value: JSONValue, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise BoundaryLabError(
            f"{label} must be a non-empty string of at most {maximum} characters"
        )
    return value


def _identifier(value: JSONValue, label: str) -> str:
    candidate = _string(value, label, maximum=128)
    if not _ID_RE.fullmatch(candidate):
        raise BoundaryLabError(f"{label} contains unsupported characters")
    return candidate


def _boolean(value: JSONValue, label: str) -> bool:
    if not isinstance(value, bool):
        raise BoundaryLabError(f"{label} must be a boolean")
    return value


def _integer(
    value: JSONValue,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise BoundaryLabError(f"{label} must be an integer from {minimum} through {maximum}")
    return value


def _decimal(
    value: JSONValue,
    label: str,
    minimum: Decimal,
    maximum: Decimal,
) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise BoundaryLabError(f"{label} must be a finite decimal")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise BoundaryLabError(f"{label} must be a finite decimal") from exc
    if not result.is_finite() or not minimum <= result <= maximum:
        raise BoundaryLabError(f"{label} must be from {minimum} through {maximum}")
    return result


def _exact_keys(
    value: dict[str, JSONValue],
    label: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    allowed = required | (optional or set())
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - allowed)
    if missing:
        raise BoundaryLabError(f"{label} is missing required fields: {', '.join(missing)}")
    if unknown:
        raise BoundaryLabError(f"{label} contains unknown fields: {', '.join(unknown)}")


def _timestamp(value: JSONValue, label: str) -> datetime:
    text = _string(value, label, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BoundaryLabError(f"{label} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise BoundaryLabError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _host(value: JSONValue, label: str) -> str:
    text = _string(value, label, maximum=253).lower().rstrip(".")
    if any(token in text for token in ("*", "/", "://", "@", " ", "\t", "\n")):
        raise BoundaryLabError(f"{label} must be one exact hostname or IP address")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        if not _HOST_RE.fullmatch(text):
            raise BoundaryLabError(f"{label} must be one exact hostname or IP address") from None
        return text


@dataclass(frozen=True)
class Limits:
    max_duration_seconds: int
    max_output_bytes: int
    max_parallel: int
    max_cost_usd: Decimal

    @classmethod
    def from_json(cls, value: JSONValue) -> Limits:
        data = _mapping(value, "limits")
        _exact_keys(
            data,
            "limits",
            required={
                "max_duration_seconds",
                "max_output_bytes",
                "max_parallel",
                "max_cost_usd",
            },
        )
        return cls(
            max_duration_seconds=_integer(
                data["max_duration_seconds"],
                "limits.max_duration_seconds",
                1,
                1800,
            ),
            max_output_bytes=_integer(
                data["max_output_bytes"],
                "limits.max_output_bytes",
                1024,
                1_000_000,
            ),
            max_parallel=_integer(
                data["max_parallel"],
                "limits.max_parallel",
                1,
                8,
            ),
            max_cost_usd=_decimal(
                data["max_cost_usd"],
                "limits.max_cost_usd",
                Decimal("0"),
                Decimal("100"),
            ),
        )

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "max_cost_usd": format(self.max_cost_usd, "f"),
            "max_duration_seconds": self.max_duration_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_parallel": self.max_parallel,
        }


@dataclass(frozen=True)
class NetworkTarget:
    target_id: str
    host: str
    port: int
    expected: Literal["allowed", "blocked"]
    public: bool

    @classmethod
    def from_json(cls, value: JSONValue) -> NetworkTarget:
        data = _mapping(value, "network target")
        _exact_keys(
            data,
            "network target",
            required={"id", "host", "port", "expected", "public"},
        )
        expected = _string(
            data["expected"],
            "network target.expected",
            maximum=16,
        )
        if expected not in {"allowed", "blocked"}:
            raise BoundaryLabError("network target.expected must be allowed or blocked")
        return cls(
            target_id=_identifier(data["id"], "network target.id"),
            host=_host(data["host"], "network target.host"),
            port=_integer(data["port"], "network target.port", 1, 65535),
            expected=cast(Literal["allowed", "blocked"], expected),
            public=_boolean(data["public"], "network target.public"),
        )

    def guest_json(self) -> dict[str, JSONValue]:
        return {
            "expected": self.expected,
            "host": self.host,
            "id": self.target_id,
            "port": self.port,
        }

    def to_json(self) -> dict[str, JSONValue]:
        return {**self.guest_json(), "public": self.public}


@dataclass(frozen=True)
class AdapterConfig:
    command_prefix: tuple[str, ...] | None
    docker_image: str
    vercel_project_id: str | None

    @classmethod
    def from_json(cls, value: JSONValue) -> AdapterConfig:
        data = _mapping(value, "adapter_config")
        _exact_keys(
            data,
            "adapter_config",
            required=set(),
            optional={"command_prefix", "docker_image", "vercel_project_id"},
        )
        prefix: tuple[str, ...] | None = None
        if "command_prefix" in data:
            items = _list(
                data["command_prefix"],
                "adapter_config.command_prefix",
            )
            if not 1 <= len(items) <= 16:
                raise BoundaryLabError(
                    "adapter_config.command_prefix must contain 1 through 16 arguments"
                )
            prefix = tuple(_string(item, "command argument", maximum=256) for item in items)
        image = _string(
            data.get("docker_image", "python:3.13-slim"),
            "adapter_config.docker_image",
            maximum=200,
        )
        if any(char.isspace() for char in image):
            raise BoundaryLabError("adapter_config.docker_image may not contain whitespace")
        project_value = data.get("vercel_project_id")
        project_id = (
            None
            if project_value is None
            else _string(
                project_value,
                "adapter_config.vercel_project_id",
                maximum=128,
            )
        )
        return cls(prefix, image, project_id)

    def to_json(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {"docker_image": self.docker_image}
        if self.command_prefix is not None:
            result["command_prefix"] = list(self.command_prefix)
        if self.vercel_project_id is not None:
            result["vercel_project_id"] = self.vercel_project_id
        return result


@dataclass(frozen=True)
class Authorization:
    authorization_id: str
    owner: str
    environment: Literal["local", "development", "test"]
    expires_at: datetime
    third_party_testing: bool
    destructive_tests: bool
    allowed_adapters: tuple[str, ...]
    network_targets: tuple[NetworkTarget, ...]
    limits: Limits
    adapter_config: AdapterConfig

    @classmethod
    def from_json(cls, value: JSONValue) -> Authorization:
        data = _mapping(value, "authorization")
        _exact_keys(
            data,
            "authorization",
            required={
                "schema",
                "authorization_id",
                "owner",
                "environment",
                "expires_at",
                "third_party_testing",
                "destructive_tests",
                "allowed_adapters",
                "network_targets",
                "limits",
                "adapter_config",
            },
        )
        if data["schema"] != AUTH_SCHEMA:
            raise BoundaryLabError(f"authorization.schema must equal {AUTH_SCHEMA}")
        third_party = _boolean(
            data["third_party_testing"],
            "authorization.third_party_testing",
        )
        destructive = _boolean(
            data["destructive_tests"],
            "authorization.destructive_tests",
        )
        if third_party:
            raise BoundaryLabError("public v0.1 rejects third-party testing")
        if destructive:
            raise BoundaryLabError("public v0.1 rejects destructive tests")
        environment = _string(
            data["environment"],
            "authorization.environment",
            maximum=32,
        )
        if environment not in {"local", "development", "test"}:
            raise BoundaryLabError("authorization.environment must be local, development, or test")
        adapter_values = _list(
            data["allowed_adapters"],
            "authorization.allowed_adapters",
        )
        adapters = tuple(_string(item, "adapter", maximum=32) for item in adapter_values)
        if not adapters or len(adapters) != len(set(adapters)):
            raise BoundaryLabError("authorization.allowed_adapters must be a non-empty unique list")
        unknown_adapters = sorted(set(adapters) - ADAPTERS)
        if unknown_adapters:
            raise BoundaryLabError(f"unsupported adapters: {', '.join(unknown_adapters)}")
        targets = tuple(
            NetworkTarget.from_json(item)
            for item in _list(
                data["network_targets"],
                "authorization.network_targets",
            )
        )
        target_ids = [target.target_id for target in targets]
        if len(target_ids) != len(set(target_ids)):
            raise BoundaryLabError("network target IDs must be unique")
        return cls(
            authorization_id=_identifier(
                data["authorization_id"],
                "authorization.authorization_id",
            ),
            owner=_string(
                data["owner"],
                "authorization.owner",
                maximum=200,
            ),
            environment=cast(
                Literal["local", "development", "test"],
                environment,
            ),
            expires_at=_timestamp(
                data["expires_at"],
                "authorization.expires_at",
            ),
            third_party_testing=third_party,
            destructive_tests=destructive,
            allowed_adapters=adapters,
            network_targets=targets,
            limits=Limits.from_json(data["limits"]),
            adapter_config=AdapterConfig.from_json(data["adapter_config"]),
        )

    def validate_active(self, now: datetime | None = None) -> None:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if self.expires_at <= current:
            raise BoundaryLabError("authorization has expired")

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "adapter_config": self.adapter_config.to_json(),
            "allowed_adapters": list(self.allowed_adapters),
            "authorization_id": self.authorization_id,
            "destructive_tests": self.destructive_tests,
            "environment": self.environment,
            "expires_at": self.expires_at.isoformat().replace(
                "+00:00",
                "Z",
            ),
            "limits": self.limits.to_json(),
            "network_targets": [target.to_json() for target in self.network_targets],
            "owner": self.owner,
            "schema": AUTH_SCHEMA,
            "third_party_testing": self.third_party_testing,
        }


@dataclass(frozen=True)
class Expectation:
    op: str
    value: JSONValue = None

    @classmethod
    def from_json(cls, value: JSONValue, label: str) -> Expectation:
        data = _mapping(value, label)
        op = _string(data.get("op"), f"{label}.op", maximum=32)
        if op not in OPS:
            raise BoundaryLabError(f"{label}.op is unsupported")
        required = {"op"} if op == "observe" else {"op", "value"}
        _exact_keys(data, label, required=required)
        return cls(op=op, value=data.get("value"))

    def to_json(self) -> dict[str, JSONValue]:
        if self.op == "observe":
            return {"op": self.op}
        return {"op": self.op, "value": self.value}


@dataclass(frozen=True)
class Profile:
    profile_id: str
    description: str
    probes: tuple[str, ...]
    expectations: dict[str, Expectation]

    @classmethod
    def from_json(
        cls,
        value: JSONValue,
        known_probes: set[str],
    ) -> Profile:
        data = _mapping(value, "profile")
        _exact_keys(
            data,
            "profile",
            required={
                "schema",
                "profile_id",
                "description",
                "probes",
                "expectations",
            },
        )
        if data["schema"] != PROFILE_SCHEMA:
            raise BoundaryLabError(f"profile.schema must equal {PROFILE_SCHEMA}")
        raw_probes = _list(data["probes"], "profile.probes")
        probes = tuple(_string(item, "profile probe", maximum=128) for item in raw_probes)
        if probes == ("*",):
            probes = tuple(sorted(known_probes))
        if not probes or len(probes) != len(set(probes)):
            raise BoundaryLabError("profile.probes must be a non-empty unique list")
        unknown = sorted(set(probes) - known_probes)
        if unknown:
            raise BoundaryLabError(f"profile references unknown probes: {', '.join(unknown)}")
        raw_expectations = _mapping(
            data["expectations"],
            "profile.expectations",
        )
        outside = sorted(raw_expectations.keys() - set(probes))
        if outside:
            raise BoundaryLabError(
                "expectations reference probes outside the profile: " + ", ".join(outside)
            )
        expectations = {
            probe_id: Expectation.from_json(
                expectation,
                f"expectations.{probe_id}",
            )
            for probe_id, expectation in raw_expectations.items()
        }
        return cls(
            profile_id=_identifier(data["profile_id"], "profile.profile_id"),
            description=_string(
                data["description"],
                "profile.description",
                maximum=500,
            ),
            probes=probes,
            expectations=expectations,
        )

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "description": self.description,
            "expectations": {
                key: value.to_json() for key, value in sorted(self.expectations.items())
            },
            "probes": list(self.probes),
            "profile_id": self.profile_id,
            "schema": PROFILE_SCHEMA,
        }


@dataclass(frozen=True)
class ProbeResult:
    probe_id: str
    category: str
    status: ResultStatus
    expected: dict[str, JSONValue]
    observed: JSONValue
    reason_code: str | None = None

    def to_json(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "category": self.category,
            "expected": self.expected,
            "observed": self.observed,
            "probe_id": self.probe_id,
            "status": self.status,
        }
        if self.reason_code is not None:
            result["reason_code"] = self.reason_code
        return result


@dataclass(frozen=True)
class AdapterOutcome:
    adapter: str
    status: Literal["ok", "unsupported", "error"]
    observations: dict[str, JSONValue]
    runtime: dict[str, JSONValue]
    reason_code: str | None = None
