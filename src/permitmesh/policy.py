from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal
from fnmatch import fnmatchcase
from typing import Any, Protocol

SUPPORTED_VERSION = "0.2"
IMPLEMENTATION_VERSION = "0.2.0"
MAX_CANONICAL_DEPTH = 64
MAX_CANONICAL_NODES = 10_000
MAX_CANONICAL_STRING_CHARS = 65_536
MAX_CANONICAL_NUMBER_CHARS = 1_024
MAX_COLLECTION_ITEMS = 256
MAX_REPLAY_NONCES = 100_000
MAX_PATH_CHARS = 4_096
MAX_PATH_SEGMENTS = 128
MAX_PATH_SEGMENT_CHARS = 255
MAX_PATTERN_CHARS = 1_024
MAX_PATTERN_ITEMS = 128
PATH_REQUIRED_CAPABILITIES = {"read", "edit"}
HIGH_RISK_CAPABILITIES = {"shell", "test", "commit", "deploy", "publish", "spend"}
KNOWN_CAPABILITIES = {
    "read",
    "edit",
    "shell",
    "test",
    "commit",
    "review",
    "deploy",
    "publish",
    "spend",
}
TOP_LEVEL_FIELDS = {
    "contract_version",
    "issuer",
    "subject",
    "scope",
    "capabilities",
    "validity",
    "limits",
    "approval_gates",
    "operation_constraints",
    "lifecycle",
    "validation",
    "signature",
}
RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
WINDOWS_SHORT_NAME_PATTERN = re.compile(r"~[1-9][0-9]*(?:\.|$)", re.IGNORECASE)


# Closed vocabulary for authorize/verify_completion predicates. Human
# `violations` may change wording; these codes are the replay contract.
REASON_CODES = (
    "CONTRACT_INVALID",
    "REQUEST_INVALID",
    "NOT_YET_VALID",
    "EXPIRED",
    "SUBJECT_MISMATCH",
    "CHANNEL_OUT_OF_SCOPE",
    "CAPABILITY_NOT_GRANTED",
    "PATH_REQUIRED",
    "OPERATION_BINDING_REQUIRED",
    "OPERATION_DIGEST_MISMATCH",
    "NONCE_INVALID",
    "NONCE_CONSUMED",
    "REPOSITORY_OUT_OF_SCOPE",
    "REF_OUT_OF_SCOPE",
    "PATH_DENIED",
    "LIMIT_FILES_EXCEEDED",
    "LIMIT_COMMANDS_EXCEEDED",
    "LIMIT_COST_EXCEEDED",
    "CLAIM_MISMATCH",
    "FENCING_GENERATION_STALE",
    "APPROVAL_REQUIRED",
    "COMPLETION_EVIDENCE_MISSING",
)
REASON_CODE_SET = frozenset(REASON_CODES)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    contract_digest: str
    reason_codes: tuple[str, ...]
    violations: tuple[str, ...]
    checks: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class _Findings:
    """Deterministic (code, human-detail) sink. Helpers may `.append(detail)`."""

    def __init__(self, default_code: str = "REQUEST_INVALID") -> None:
        if default_code not in REASON_CODE_SET:
            raise ValueError(f"unknown reason code: {default_code}")
        self.default_code = default_code
        self._items: list[tuple[str, str]] = []

    def add(self, code: str, detail: str) -> None:
        if code not in REASON_CODE_SET:
            raise ValueError(f"unknown reason code: {code}")
        self._items.append((code, detail))

    def append(self, detail: str) -> None:
        self.add(self.default_code, detail)

    def extend(self, code: str, details: tuple[str, ...] | list[str]) -> None:
        for detail in details:
            self.add(code, detail)

    @property
    def details(self) -> tuple[str, ...]:
        return tuple(detail for _, detail in self._items)

    @property
    def codes(self) -> tuple[str, ...]:
        seen: set[str] = set()
        ordered: list[str] = []
        for code, _ in self._items:
            if code not in seen:
                seen.add(code)
                ordered.append(code)
        return tuple(ordered)

    def __bool__(self) -> bool:
        return bool(self._items)


def _decision(digest: str, findings: _Findings, checks: list[str] | tuple[str, ...]) -> Decision:
    return Decision(
        allowed=not findings,
        contract_digest=digest,
        reason_codes=findings.codes,
        violations=findings.details,
        checks=tuple(checks),
    )


def decision_digest(decision: Decision) -> str:
    """Replay digest over version + allow/deny + contract digest + reason codes."""
    return hashlib.sha256(
        canonical_json(
            {
                "implementation_version": IMPLEMENTATION_VERSION,
                "allowed": decision.allowed,
                "contract_digest": decision.contract_digest,
                "reason_codes": list(decision.reason_codes),
            }
        ).encode("utf-8")
    ).hexdigest()


def _canonical_json(value: Any, *, depth: int, remaining_nodes: list[int]) -> str:
    if depth > MAX_CANONICAL_DEPTH:
        raise ValueError(f"canonical JSON exceeds maximum depth {MAX_CANONICAL_DEPTH}")
    remaining_nodes[0] -= 1
    if remaining_nodes[0] < 0:
        raise ValueError(f"canonical JSON exceeds maximum node count {MAX_CANONICAL_NODES}")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        if len(value) > MAX_CANONICAL_STRING_CHARS:
            raise ValueError(
                f"canonical JSON string exceeds maximum length {MAX_CANONICAL_STRING_CHARS}"
            )
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        if value.bit_length() > 3_400:
            raise ValueError("canonical JSON integer is too large")
        rendered = str(value)
        if len(rendered) > MAX_CANONICAL_NUMBER_CHARS:
            raise ValueError("canonical JSON integer is too large")
        return rendered
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("canonical JSON numbers must be finite")
        if value.is_zero():
            return "0"
        sign, raw_digits, exponent = value.as_tuple()
        if not isinstance(exponent, int):
            raise ValueError("canonical JSON numbers must be finite")
        if len(raw_digits) > MAX_CANONICAL_NUMBER_CHARS:
            raise ValueError("canonical JSON number is too precise")
        digits = "".join(str(digit) for digit in raw_digits)
        while len(digits) > 1 and digits.endswith("0"):
            digits = digits[:-1]
            exponent += 1
        adjusted_exponent = len(digits) + exponent - 1
        if -6 <= adjusted_exponent < 21:
            point = len(digits) + exponent
            if point <= 0:
                number = "0." + ("0" * -point) + digits
            elif point >= len(digits):
                number = digits + ("0" * (point - len(digits)))
            else:
                number = digits[:point] + "." + digits[point:]
        else:
            mantissa = digits[0]
            if len(digits) > 1:
                mantissa += "." + digits[1:]
            exponent_sign = "+" if adjusted_exponent >= 0 else ""
            number = f"{mantissa}e{exponent_sign}{adjusted_exponent}"
        rendered = ("-" if sign else "") + number
        if len(rendered) > MAX_CANONICAL_NUMBER_CHARS:
            raise ValueError("canonical JSON number is too large")
        return rendered
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON numbers must be finite")
        return _canonical_json(Decimal(str(value)), depth=depth, remaining_nodes=remaining_nodes)
    if isinstance(value, (list, tuple)):
        return (
            "["
            + ",".join(
                _canonical_json(item, depth=depth + 1, remaining_nodes=remaining_nodes)
                for item in value
            )
            + "]"
        )
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        return (
            "{"
            + ",".join(
                f"{_canonical_json(key, depth=depth + 1, remaining_nodes=remaining_nodes)}:"
                f"{_canonical_json(value[key], depth=depth + 1, remaining_nodes=remaining_nodes)}"
                for key in sorted(value)
            )
            + "}"
        )
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return _canonical_json(
        value,
        depth=0,
        remaining_nodes=[MAX_CANONICAL_NODES],
    )


def contract_digest(contract: Any) -> str:
    payload = dict(contract) if isinstance(contract, dict) else contract
    if isinstance(payload, dict):
        payload.pop("signature", None)
        payload.pop("contract_digest", None)
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def operation_digest(action: str, operation: dict[str, Any]) -> str:
    """Bind a capability name to the exact canonical tool-and-arguments envelope."""
    payload = {"action": action, "operation": operation}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class _MessageSink(Protocol):
    def append(self, detail: str) -> None: ...


def _parse_time(value: Any, field: str, violations: _MessageSink) -> datetime | None:
    if not isinstance(value, str) or RFC3339_PATTERN.fullmatch(value) is None:
        violations.append(f"{field} must be an RFC 3339 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        violations.append(f"{field} must be an RFC 3339 timestamp")
        return None
    if parsed.tzinfo is None:
        violations.append(f"{field} must include a timezone")
        return None
    return parsed.astimezone(UTC)


def _is_safe_relative_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    return (
        bool(value)
        and len(value) <= MAX_PATH_CHARS
        and len(parts) <= MAX_PATH_SEGMENTS
        and "\x00" not in value
        and all(len(part) <= MAX_PATH_SEGMENT_CHARS for part in parts)
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
        and re.match(r"^[A-Za-z]:", normalized) is None
        and not normalized.startswith("/")
        and all(part not in {"", ".", ".."} for part in parts)
        and all(":" not in part for part in parts)
        and all(not part.endswith((".", " ")) for part in parts)
        and all(WINDOWS_SHORT_NAME_PATTERN.search(part) is None for part in parts)
        and all(part.split(".", 1)[0].casefold() not in WINDOWS_RESERVED_NAMES for part in parts)
    )


def _validate_patterns(
    patterns: Any, field: str, violations: list[str], *, allow_empty: bool = False
) -> None:
    if not isinstance(patterns, list) or (not patterns and not allow_empty):
        requirement = "an array" if allow_empty else "a non-empty array"
        violations.append(f"{field} must be {requirement}")
        return
    if len(patterns) > MAX_PATTERN_ITEMS:
        violations.append(f"{field} must contain at most {MAX_PATTERN_ITEMS} patterns")
        return
    for index, pattern in enumerate(patterns):
        if (
            not isinstance(pattern, str)
            or len(pattern) > MAX_PATTERN_CHARS
            or not _is_safe_relative_path(pattern)
        ):
            violations.append(f"{field}[{index}] must be a safe relative path pattern")
    if all(isinstance(pattern, str) for pattern in patterns) and len(patterns) != len(
        set(patterns)
    ):
        violations.append(f"{field} must not contain duplicates")


def _reject_unknown_fields(
    value: dict[str, Any], allowed: set[str], field: str, violations: _MessageSink
) -> None:
    for unknown in sorted(value.keys() - allowed, key=str):
        violations.append(f"{field} contains unknown field: {unknown}")


def _too_many_items(
    value: list[Any] | tuple[Any, ...] | set[Any] | frozenset[Any],
    field: str,
    violations: _MessageSink,
    *,
    maximum: int = MAX_COLLECTION_ITEMS,
) -> bool:
    if len(value) <= maximum:
        return False
    violations.append(f"{field} must contain at most {maximum} items")
    return True


def _is_bounded_text(value: Any, *, maximum: int = MAX_CANONICAL_STRING_CHARS) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= maximum
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def validate_contract(contract: Any) -> tuple[str, ...]:
    violations: list[str] = []
    if not isinstance(contract, dict):
        return ("contract must be a JSON object",)
    required = {
        "contract_version",
        "issuer",
        "subject",
        "scope",
        "capabilities",
        "validity",
        "limits",
        "approval_gates",
        "operation_constraints",
        "lifecycle",
        "validation",
    }
    missing = sorted(required - contract.keys())
    violations.extend(f"missing required field: {field}" for field in missing)
    if missing:
        return tuple(violations)
    _reject_unknown_fields(contract, TOP_LEVEL_FIELDS, "contract", violations)

    if contract["contract_version"] != SUPPORTED_VERSION:
        violations.append(
            f"contract_version must be {SUPPORTED_VERSION!r}, got {contract['contract_version']!r}"
        )

    for field in ("issuer", "subject"):
        value = contract[field]
        if not isinstance(value, dict) or not isinstance(value.get("id"), str) or not value["id"]:
            violations.append(f"{field}.id must be a non-empty string")
        elif isinstance(value, dict):
            _reject_unknown_fields(value, {"id", "display_name"}, field, violations)
            if "display_name" in value and not isinstance(value["display_name"], str):
                violations.append(f"{field}.display_name must be a string")

    capabilities = contract["capabilities"]
    if not isinstance(capabilities, list) or not capabilities:
        violations.append("capabilities must be a non-empty array")
    elif _too_many_items(capabilities, "capabilities", violations):
        pass
    elif not all(isinstance(capability, str) for capability in capabilities):
        violations.append("capabilities must contain strings")
    else:
        unknown = sorted(set(capabilities) - KNOWN_CAPABILITIES)
        if unknown:
            violations.append(f"capabilities contains unknown values: {', '.join(unknown)}")
        if len(capabilities) != len(set(capabilities)):
            violations.append("capabilities must not contain duplicates")

    scope = contract["scope"]
    if not isinstance(scope, dict):
        violations.append("scope must be an object")
    else:
        _reject_unknown_fields(scope, {"repositories", "channels"}, "scope", violations)
        repositories = scope.get("repositories")
        if not isinstance(repositories, list) or not repositories:
            violations.append("scope.repositories must be a non-empty array")
        elif _too_many_items(repositories, "scope.repositories", violations):
            pass
        else:
            names: set[str] = set()
            for index, repo in enumerate(repositories):
                prefix = f"scope.repositories[{index}]"
                if not isinstance(repo, dict):
                    violations.append(f"{prefix} must be an object")
                    continue
                _reject_unknown_fields(
                    repo,
                    {"name", "refs", "allow_paths", "deny_paths"},
                    prefix,
                    violations,
                )
                name = repo.get("name")
                if not isinstance(name, str) or not name:
                    violations.append(f"{prefix}.name must be a non-empty string")
                elif name in names:
                    violations.append(f"{prefix}.name duplicates repository {name!r}")
                else:
                    names.add(name)
                refs = repo.get("refs")
                if not isinstance(refs, list) or not refs:
                    violations.append(f"{prefix}.refs must be a non-empty string array")
                elif _too_many_items(refs, f"{prefix}.refs", violations, maximum=MAX_PATTERN_ITEMS):
                    pass
                elif not all(_is_bounded_text(ref, maximum=MAX_PATTERN_CHARS) for ref in refs):
                    violations.append(f"{prefix}.refs must be a non-empty string array")
                elif len(refs) != len(set(refs)):
                    violations.append(f"{prefix}.refs must not contain duplicates")
                _validate_patterns(repo.get("allow_paths"), f"{prefix}.allow_paths", violations)
                _validate_patterns(
                    repo.get("deny_paths"),
                    f"{prefix}.deny_paths",
                    violations,
                    allow_empty=True,
                )

        channels = scope.get("channels")
        if not isinstance(channels, list) or not all(
            isinstance(channel, str) and channel for channel in channels
        ):
            violations.append("scope.channels must be a string array")
        elif _too_many_items(channels, "scope.channels", violations):
            pass
        elif len(channels) != len(set(channels)):
            violations.append("scope.channels must not contain duplicates")

    validity = contract["validity"]
    if not isinstance(validity, dict):
        violations.append("validity must be an object")
    else:
        _reject_unknown_fields(validity, {"not_before", "expires_at"}, "validity", violations)
        not_before = _parse_time(validity.get("not_before"), "validity.not_before", violations)
        expires_at = _parse_time(validity.get("expires_at"), "validity.expires_at", violations)
        if not_before and expires_at and expires_at <= not_before:
            violations.append("validity.expires_at must be after validity.not_before")

    limits = contract["limits"]
    if not isinstance(limits, dict):
        violations.append("limits must be an object")
    else:
        _reject_unknown_fields(
            limits,
            {"max_files_changed", "max_commands", "max_cost_usd"},
            "limits",
            violations,
        )
        for field in ("max_files_changed", "max_commands"):
            value = limits.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                violations.append(f"limits.{field} must be a non-negative integer")
        cost = limits.get("max_cost_usd")
        if not _is_finite_nonnegative_number(cost):
            violations.append("limits.max_cost_usd must be a finite non-negative number")

    gates = contract["approval_gates"]
    if not isinstance(gates, list):
        violations.append("approval_gates must be an array")
    elif _too_many_items(gates, "approval_gates", violations):
        pass
    else:
        for index, gate in enumerate(gates):
            prefix = f"approval_gates[{index}]"
            if not isinstance(gate, dict):
                violations.append(f"{prefix} must be an object")
                continue
            _reject_unknown_fields(
                gate, {"actions", "min_approvals", "approvers"}, prefix, violations
            )
            actions = gate.get("actions")
            if (
                not isinstance(actions, list)
                or not actions
                or not all(isinstance(action, str) for action in actions)
                or not set(actions) <= KNOWN_CAPABILITIES
            ):
                violations.append(f"{prefix}.actions must contain known capabilities")
            elif len(actions) != len(set(actions)):
                violations.append(f"{prefix}.actions must not contain duplicates")
            minimum = gate.get("min_approvals")
            if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
                violations.append(f"{prefix}.min_approvals must be a positive integer")
            approvers = gate.get("approvers")
            if (
                not isinstance(approvers, list)
                or not approvers
                or not all(isinstance(approver, str) and approver for approver in approvers)
            ):
                violations.append(f"{prefix}.approvers must be a non-empty string array")
            elif _too_many_items(approvers, f"{prefix}.approvers", violations):
                pass
            else:
                if len(approvers) != len(set(approvers)):
                    violations.append(f"{prefix}.approvers must not contain duplicates")
                if isinstance(minimum, int) and minimum > len(set(approvers)):
                    violations.append(f"{prefix}.min_approvals exceeds unique approvers")

    constraints = contract["operation_constraints"]
    constrained_actions: set[str] = set()
    seen_nonces: set[str] = set()
    if not isinstance(constraints, list):
        violations.append("operation_constraints must be an array")
    elif _too_many_items(constraints, "operation_constraints", violations):
        pass
    else:
        for index, constraint in enumerate(constraints):
            prefix = f"operation_constraints[{index}]"
            if not isinstance(constraint, dict):
                violations.append(f"{prefix} must be an object")
                continue
            _reject_unknown_fields(
                constraint,
                {"action", "operation_digest", "nonce"},
                prefix,
                violations,
            )
            action = constraint.get("action")
            digest = constraint.get("operation_digest")
            nonce = constraint.get("nonce")
            if not isinstance(action, str) or action not in HIGH_RISK_CAPABILITIES:
                violations.append(f"{prefix}.action must be a high-risk capability")
            elif not isinstance(capabilities, list) or action not in capabilities:
                violations.append(f"{prefix}.action must be granted by capabilities")
            else:
                constrained_actions.add(action)
            if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
                violations.append(f"{prefix}.operation_digest must be lowercase SHA-256 hex")
            if not isinstance(nonce, str) or NONCE_PATTERN.fullmatch(nonce) is None:
                violations.append(f"{prefix}.nonce must be 16-128 safe characters")
            elif nonce in seen_nonces:
                violations.append(f"{prefix}.nonce must be unique")
            else:
                seen_nonces.add(nonce)
        granted_high_risk = (
            set(capabilities).intersection(HIGH_RISK_CAPABILITIES)
            if isinstance(capabilities, list)
            and all(isinstance(capability, str) for capability in capabilities)
            else set()
        )
        for action in sorted(granted_high_risk - constrained_actions):
            violations.append(
                f"operation_constraints must bind granted high-risk capability {action!r}"
            )

    lifecycle = contract["lifecycle"]
    if not isinstance(lifecycle, dict):
        violations.append("lifecycle must be an object")
    else:
        _reject_unknown_fields(
            lifecycle, {"claim_id", "fencing_generation"}, "lifecycle", violations
        )
        if not isinstance(lifecycle.get("claim_id"), str) or not lifecycle["claim_id"]:
            violations.append("lifecycle.claim_id must be a non-empty string")
        generation = lifecycle.get("fencing_generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            violations.append("lifecycle.fencing_generation must be a positive integer")

    validation = contract["validation"]
    if not isinstance(validation, dict):
        violations.append("validation must be an object")
    else:
        _reject_unknown_fields(
            validation,
            {"required_commands", "required_artifacts"},
            "validation",
            violations,
        )
        for field in ("required_commands", "required_artifacts"):
            value = validation.get(field)
            if not isinstance(value, list) or not all(
                isinstance(item, str) and item for item in value
            ):
                violations.append(f"validation.{field} must be a string array")
            elif _too_many_items(value, f"validation.{field}", violations):
                pass
            elif len(value) != len(set(value)):
                violations.append(f"validation.{field} must not contain duplicates")

    signature = contract.get("signature")
    if signature is not None:
        if not isinstance(signature, dict):
            violations.append("signature must be an object")
        else:
            _reject_unknown_fields(
                signature, {"algorithm", "public_key", "value"}, "signature", violations
            )
            for field in ("algorithm", "public_key", "value"):
                if not isinstance(signature.get(field), str) or not signature[field]:
                    violations.append(f"signature.{field} must be a non-empty string")

    return tuple(violations)


def _is_finite_nonnegative_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return False
    if isinstance(value, Decimal):
        return value.is_finite() and value >= 0
    return math.isfinite(value) and value >= 0


def _as_decimal(value: float | Decimal) -> Decimal:
    return value if isinstance(value, Decimal) else Decimal(str(value))


def _matches_glob(value: str, pattern: str) -> bool:
    value_parts = tuple(value.replace("\\", "/").split("/"))
    pattern_parts = tuple(pattern.replace("\\", "/").split("/"))
    previous = [False] * (len(value_parts) + 1)
    previous[0] = True
    for pattern_part in pattern_parts:
        current = [False] * (len(value_parts) + 1)
        if pattern_part == "**":
            current[0] = previous[0]
            for value_index in range(1, len(value_parts) + 1):
                current[value_index] = previous[value_index] or current[value_index - 1]
        else:
            for value_index in range(1, len(value_parts) + 1):
                current[value_index] = previous[value_index - 1] and fnmatchcase(
                    value_parts[value_index - 1], pattern_part
                )
        previous = current
    return previous[len(value_parts)]


def _trusted_now(now: datetime | None, violations: _MessageSink) -> datetime | None:
    if now is None:
        return datetime.now(UTC)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        violations.append("evaluator time must include a timezone")
        return None
    return now.astimezone(UTC)


def authorize(
    contract: Any,
    request: Any,
    *,
    now: datetime | None = None,
    consumed_nonces: frozenset[str] | set[str] | None = None,
) -> Decision:
    findings = _Findings()
    try:
        digest = contract_digest(contract)
    except (TypeError, ValueError):
        findings.add("CONTRACT_INVALID", "contract must contain canonical JSON values")
        return _decision("", findings, ())
    contract_violations = validate_contract(contract)
    checks: list[str] = []
    if contract_violations:
        findings.extend("CONTRACT_INVALID", contract_violations)
        return _decision(digest, findings, checks)
    if not isinstance(request, dict):
        findings.add("REQUEST_INVALID", "request must be a JSON object")
        return _decision(digest, findings, checks)
    if len(request) > MAX_COLLECTION_ITEMS:
        findings.add(
            "REQUEST_INVALID",
            f"request must contain at most {MAX_COLLECTION_ITEMS} fields",
        )
        return _decision(digest, findings, checks)
    request_fields = {
        "subject_id",
        "action",
        "channel",
        "repository",
        "ref",
        "path",
        "files_changed",
        "commands_used",
        "cost_usd",
        "claim_id",
        "fencing_generation",
        "approvals",
        "operation",
        "operation_nonce",
        "at",
    }
    _reject_unknown_fields(request, request_fields, "request", findings)
    required_request_fields = request_fields - {
        "path",
        "at",
        "channel",
        "operation",
        "operation_nonce",
    }
    for field in sorted(required_request_fields - request.keys()):
        findings.add("REQUEST_INVALID", f"missing required request field: {field}")
    for field, maximum in {
        "subject_id": MAX_CANONICAL_STRING_CHARS,
        "repository": MAX_CANONICAL_STRING_CHARS,
        "ref": MAX_PATTERN_CHARS,
        "claim_id": MAX_CANONICAL_STRING_CHARS,
    }.items():
        if field in request and not _is_bounded_text(request[field], maximum=maximum):
            findings.add(
                "REQUEST_INVALID",
                f"request.{field} must be a bounded non-empty string",
            )

    # The evaluator's clock is authoritative. A request's self-declared time is
    # parsed for receipt quality but can never extend or revive authorization.
    effective_now = _trusted_now(now, findings)
    if "at" in request:
        _parse_time(request["at"], "request.at", findings)
    not_before = _parse_time(
        contract["validity"]["not_before"], "validity.not_before", findings
    )
    expires_at = _parse_time(
        contract["validity"]["expires_at"], "validity.expires_at", findings
    )
    if not_before and effective_now is not None and effective_now < not_before:
        findings.add("NOT_YET_VALID", "contract is not active yet")
    if expires_at and effective_now is not None and effective_now >= expires_at:
        findings.add("EXPIRED", "contract has expired")
    checks.append("validity_window")

    if request.get("subject_id") != contract["subject"]["id"]:
        findings.add("SUBJECT_MISMATCH", "subject_id does not match the active contract")
    checks.append("subject")

    configured_channels = contract["scope"]["channels"]
    requested_channel = request.get("channel")
    if "channel" in request and (not _is_bounded_text(requested_channel)):
        findings.add("REQUEST_INVALID", "request.channel must be a non-empty string")
    if configured_channels and requested_channel not in configured_channels:
        findings.add("CHANNEL_OUT_OF_SCOPE", f"channel {requested_channel!r} is outside scope")
    checks.append("channel")

    action = request.get("action")
    if not isinstance(action, str):
        findings.add("REQUEST_INVALID", "request.action must be a known capability string")
    elif action not in contract["capabilities"]:
        findings.add("CAPABILITY_NOT_GRANTED", f"capability {action!r} is not granted")
    if (
        isinstance(action, str)
        and action in PATH_REQUIRED_CAPABILITIES
        and request.get("path") is None
    ):
        findings.add("PATH_REQUIRED", f"request.path is required for {action}")
    checks.append("capability")

    if isinstance(action, str) and action in HIGH_RISK_CAPABILITIES:
        raw_operation = request.get("operation")
        operation: dict[str, Any] | None = (
            raw_operation if isinstance(raw_operation, dict) else None
        )
        nonce = request.get("operation_nonce")
        operation_is_valid = operation is not None
        if operation is None:
            findings.add(
                "OPERATION_BINDING_REQUIRED",
                f"request.operation is required for high-risk action {action!r}",
            )
        else:
            _reject_unknown_fields(
                operation, {"tool", "arguments"}, "request.operation", findings
            )
            if not _is_bounded_text(operation.get("tool")):
                findings.add(
                    "REQUEST_INVALID",
                    "request.operation.tool must be a bounded non-empty string",
                )
                operation_is_valid = False
            if not isinstance(operation.get("arguments"), dict):
                findings.add("REQUEST_INVALID", "request.operation.arguments must be an object")
                operation_is_valid = False
        if not isinstance(nonce, str) or NONCE_PATTERN.fullmatch(nonce) is None:
            findings.add(
                "NONCE_INVALID",
                "request.operation_nonce must be 16-128 safe characters",
            )
        elif consumed_nonces is None:
            findings.add(
                "OPERATION_BINDING_REQUIRED",
                "high-risk authorization requires an explicit consumed_nonces set",
            )
        elif not isinstance(consumed_nonces, (set, frozenset)) or not all(
            isinstance(item, str) for item in consumed_nonces
        ):
            findings.add("REQUEST_INVALID", "consumed_nonces must be a set of strings")
        elif len(consumed_nonces) > MAX_REPLAY_NONCES:
            findings.add(
                "REQUEST_INVALID",
                f"consumed_nonces must contain at most {MAX_REPLAY_NONCES} items",
            )
        elif nonce in consumed_nonces:
            findings.add("NONCE_CONSUMED", "request.operation_nonce has already been consumed")

        if operation_is_valid and operation is not None and isinstance(nonce, str):
            try:
                requested_operation_digest = operation_digest(action, operation)
            except (TypeError, ValueError):
                findings.add(
                    "REQUEST_INVALID",
                    "request.operation must contain canonical JSON values",
                )
            else:
                matching_constraint = any(
                    constraint.get("action") == action
                    and constraint.get("operation_digest") == requested_operation_digest
                    and constraint.get("nonce") == nonce
                    for constraint in contract["operation_constraints"]
                    if isinstance(constraint, dict)
                )
                if not matching_constraint:
                    findings.add(
                        "OPERATION_DIGEST_MISMATCH",
                        "request operation and nonce do not match an approved constraint",
                    )
    elif "operation" in request or "operation_nonce" in request:
        findings.add(
            "REQUEST_INVALID",
            "operation binding fields are only valid for high-risk actions",
        )
    checks.append("operation_binding")

    repository_name = request.get("repository")
    repository = next(
        (
            candidate
            for candidate in contract["scope"]["repositories"]
            if candidate["name"] == repository_name
        ),
        None,
    )
    if repository is None:
        findings.add(
            "REPOSITORY_OUT_OF_SCOPE",
            f"repository {repository_name!r} is outside scope",
        )
    else:
        requested_ref = request.get("ref")
        if isinstance(requested_ref, str) and _is_bounded_text(
            requested_ref, maximum=MAX_PATTERN_CHARS
        ):
            ref_allowed = any(
                _matches_glob(requested_ref, pattern) for pattern in repository["refs"]
            )
        else:
            ref_allowed = False
        if not ref_allowed:
            findings.add("REF_OUT_OF_SCOPE", f"ref {requested_ref!r} is outside scope")

        if "path" in request:
            requested_path = request["path"]
            if not isinstance(requested_path, str) or not _is_safe_relative_path(requested_path):
                findings.add("REQUEST_INVALID", "request.path must be a safe relative path")
            else:
                denied = any(
                    _matches_glob(requested_path.casefold(), pattern.casefold())
                    for pattern in repository.get("deny_paths", [])
                )
                allowed = any(
                    _matches_glob(requested_path, pattern) for pattern in repository["allow_paths"]
                )
                if denied:
                    findings.add("PATH_DENIED", f"path {requested_path!r} matches a deny rule")
                elif not allowed:
                    findings.add(
                        "PATH_DENIED",
                        f"path {requested_path!r} is outside allowed paths",
                    )
    checks.append("repository_ref_path")

    limits = contract["limits"]
    request_limits = {
        "files_changed": "max_files_changed",
        "commands_used": "max_commands",
        "cost_usd": "max_cost_usd",
    }
    limit_codes = {
        "files_changed": "LIMIT_FILES_EXCEEDED",
        "commands_used": "LIMIT_COMMANDS_EXCEEDED",
        "cost_usd": "LIMIT_COST_EXCEEDED",
    }
    for request_field, limit_field in request_limits.items():
        value = request.get(request_field, 0)
        if request_field == "cost_usd":
            valid_number = _is_finite_nonnegative_number(value)
        else:
            valid_number = isinstance(value, int) and not isinstance(value, bool) and value >= 0
        if not valid_number:
            findings.add(
                "REQUEST_INVALID",
                f"request.{request_field} must be a finite non-negative number",
            )
        elif (
            request_field == "cost_usd" and _as_decimal(value) > _as_decimal(limits[limit_field])
        ) or (request_field != "cost_usd" and value > limits[limit_field]):
            findings.add(
                limit_codes[request_field],
                f"request.{request_field}={value} exceeds {limit_field}={limits[limit_field]}",
            )
    checks.append("budgets")

    lifecycle = contract["lifecycle"]
    if request.get("claim_id") != lifecycle["claim_id"]:
        findings.add("CLAIM_MISMATCH", "claim_id does not match the active contract")
    if request.get("fencing_generation") != lifecycle["fencing_generation"]:
        findings.add(
            "FENCING_GENERATION_STALE",
            "fencing_generation does not match the active contract",
        )
    checks.append("claim_and_fence")

    raw_approvals = request.get("approvals")
    if not isinstance(raw_approvals, list) or not all(
        _is_bounded_text(approval) for approval in raw_approvals
    ):
        findings.add("REQUEST_INVALID", "request.approvals must be a string array")
        supplied_approvals: set[str] = set()
    elif _too_many_items(raw_approvals, "request.approvals", findings):
        supplied_approvals = set()
    else:
        if len(raw_approvals) != len(set(raw_approvals)):
            findings.add("REQUEST_INVALID", "request.approvals must not contain duplicates")
        supplied_approvals = set(raw_approvals)
    for gate in contract["approval_gates"]:
        if action in gate["actions"]:
            qualified = supplied_approvals.intersection(gate["approvers"])
            if len(qualified) < gate["min_approvals"]:
                findings.add(
                    "APPROVAL_REQUIRED",
                    f"action {action!r} requires {gate['min_approvals']} approval(s) "
                    f"from the configured approvers",
                )
    checks.append("approval_gates")

    return _decision(digest, findings, checks)


def verify_completion(
    contract: Any,
    report: Any,
    *,
    now: datetime | None = None,
) -> Decision:
    findings = _Findings()
    try:
        digest = contract_digest(contract)
    except (TypeError, ValueError):
        findings.add("CONTRACT_INVALID", "contract must contain canonical JSON values")
        return _decision("", findings, ())
    contract_violations = validate_contract(contract)
    checks: list[str] = []
    if contract_violations:
        findings.extend("CONTRACT_INVALID", contract_violations)
        return _decision(digest, findings, checks)
    if not isinstance(report, dict):
        findings.add("REQUEST_INVALID", "completion report must be a JSON object")
        return _decision(digest, findings, ())
    if len(report) > MAX_COLLECTION_ITEMS:
        findings.add(
            "REQUEST_INVALID",
            f"completion report must contain at most {MAX_COLLECTION_ITEMS} fields",
        )
        return _decision(digest, findings, ())

    report_fields = {
        "subject_id",
        "claim_id",
        "fencing_generation",
        "commands_passed",
        "artifacts_present",
    }
    _reject_unknown_fields(report, report_fields, "completion report", findings)
    for field in sorted(report_fields - report.keys()):
        findings.add("REQUEST_INVALID", f"missing required completion field: {field}")
    for field in ("subject_id", "claim_id"):
        if field in report and not _is_bounded_text(report[field]):
            findings.add(
                "REQUEST_INVALID",
                f"completion report.{field} must be a bounded non-empty string",
            )

    effective_now = _trusted_now(now, findings)
    not_before = _parse_time(
        contract["validity"]["not_before"], "validity.not_before", findings
    )
    expires_at = _parse_time(
        contract["validity"]["expires_at"], "validity.expires_at", findings
    )
    if not_before and effective_now is not None and effective_now < not_before:
        findings.add("NOT_YET_VALID", "contract is not active yet")
    if expires_at and effective_now is not None and effective_now >= expires_at:
        findings.add("EXPIRED", "contract has expired")
    checks.append("validity_window")

    if report.get("subject_id") != contract["subject"]["id"]:
        findings.add("SUBJECT_MISMATCH", "subject_id does not match the active contract")
    checks.append("subject")

    lifecycle = contract["lifecycle"]
    if report.get("claim_id") != lifecycle["claim_id"]:
        findings.add("CLAIM_MISMATCH", "claim_id does not match the active contract")
    if report.get("fencing_generation") != lifecycle["fencing_generation"]:
        findings.add(
            "FENCING_GENERATION_STALE",
            "fencing_generation does not match the active contract",
        )
    checks.append("claim_and_fence")

    evidence_fields = {
        "commands_passed": "required_commands",
        "artifacts_present": "required_artifacts",
    }
    for report_field, contract_field in evidence_fields.items():
        supplied = report.get(report_field)
        if not isinstance(supplied, list) or not all(_is_bounded_text(item) for item in supplied):
            findings.add(
                "REQUEST_INVALID",
                f"completion report.{report_field} must be a string array",
            )
            supplied_set: set[str] = set()
        elif _too_many_items(supplied, f"completion report.{report_field}", findings):
            supplied_set = set()
        else:
            supplied_set = set(supplied)
            if len(supplied) != len(supplied_set):
                findings.add(
                    "REQUEST_INVALID",
                    f"completion report.{report_field} must not contain duplicates",
                )
        for missing in sorted(set(contract["validation"][contract_field]) - supplied_set):
            findings.add("COMPLETION_EVIDENCE_MISSING", f"missing {contract_field}: {missing}")
        checks.append(contract_field)

    return _decision(digest, findings, checks)


def to_nostr_event_template(
    contract: dict[str, Any], *, created_at: int | None = None
) -> dict[str, Any]:
    violations = validate_contract(contract)
    if violations:
        raise ValueError("; ".join(violations))
    for principal in ("issuer", "subject"):
        identifier = contract[principal]["id"]
        if re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
            raise ValueError(
                f"{principal}.id must be a 64-character lowercase hex Nostr public key"
            )
    digest = contract_digest(contract)
    if created_at is None:
        event_created_at = int(datetime.now(UTC).timestamp())
    elif not isinstance(created_at, int) or isinstance(created_at, bool) or created_at < 0:
        raise ValueError("created_at must be a non-negative integer")
    else:
        event_created_at = created_at
    return {
        "status": "unsigned_template",
        "instruction": (
            "Compute the NIP-01 id and signature with the issuer's Nostr key before publishing."
        ),
        "event": {
            "kind": 30078,
            "created_at": event_created_at,
            "tags": [
                ["d", f"permitmesh:contract:{digest}"],
                ["t", "permitmesh"],
                ["p", contract["subject"]["id"]],
                ["x", digest],
            ],
            "content": canonical_json(contract),
            "pubkey": contract["issuer"]["id"],
            "id": "",
            "sig": "",
        },
    }
