"""Copied, single-process host example; not part of the PermitMesh core API.

Only the trusted application constructs this object, registers a handler and
updates context. The demonstration handler changes an in-memory list only.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from threading import RLock
from typing import Any, Literal

from permitmesh import authorize, operation_digest, validate_contract

MAX_ARGUMENT_CHARS = 16_384
MAX_HOST_CHARS = 65_536
MAX_DEPTH = 32
MAX_NODES = 4_096
MAX_ITEMS = 256
MAX_NUMBER_CHARS = 1_024


def _object(text: str, maximum: int) -> dict[str, Any]:
    """Bound immutable JSON before parsing, then reject ambiguity and excess shape."""
    if type(text) is not str or len(text) > maximum:
        raise ValueError("invalid JSON input")
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("invalid JSON input")
        elif char in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if len(items) > MAX_ITEMS:
            raise ValueError("invalid JSON input")
        for key, value in items:
            if key in result:
                raise ValueError("invalid JSON input")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > MAX_NUMBER_CHARS:
            raise ValueError("invalid JSON input")
        return int(token)

    def number(token: str) -> Decimal:
        if len(token) > MAX_NUMBER_CHARS:
            raise ValueError("invalid JSON input")
        try:
            return Decimal(token)
        except InvalidOperation as error:
            raise ValueError("invalid JSON input") from error

    def constant(_token: str) -> None:
        raise ValueError("invalid JSON input")

    value = json.loads(
        text,
        object_pairs_hook=pairs,
        parse_int=integer,
        parse_float=number,
        parse_constant=constant,
    )
    remaining = MAX_NODES

    def check(item: Any) -> None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise ValueError("invalid JSON input")
        if isinstance(item, (dict, list)):
            if len(item) > MAX_ITEMS:
                raise ValueError("invalid JSON input")
            for child in item.values() if isinstance(item, dict) else item:
                check(child)
        elif isinstance(item, Decimal) and not item.is_finite():
            raise ValueError("invalid JSON input")

    check(value)
    if not isinstance(value, dict):
        raise ValueError("invalid JSON input")
    return value


@dataclass(frozen=True)
class DispatchResult:
    state: Literal["DENIED", "RETURNED", "UNKNOWN"]
    reason_codes: tuple[str, ...]
    operation_digest: str = ""
    contract_digest: str = ""


class TestDispatcher:
    """One trusted host instance, one fixed test handler, one local replay set.

    The lock serializes this instance's context changes and callback admission.
    It does not transact with an external claim store or protected resource.
    """

    def __init__(
        self,
        *,
        contract_json: str,
        context_json: str,
        tool_name: str,
        handler: Callable[[dict[str, Any]], Any],
        clock: Callable[[], datetime],
    ) -> None:
        self._contract = _object(contract_json, MAX_HOST_CHARS)
        if validate_contract(self._contract):
            raise ValueError("invalid host contract")
        if type(tool_name) is not str or not tool_name or len(tool_name) > 256:
            raise ValueError("invalid host tool")
        self._tool = tool_name
        self._handler = handler
        self._clock = clock
        self._lock = RLock()
        self._in_dispatch = False
        self._reserved: set[str] = set()
        self.replace_context(context_json)

    def replace_context(self, context_json: str) -> None:
        """Trusted-host update only; this is not a caller authentication endpoint."""
        context = _object(context_json, MAX_HOST_CHARS)
        if {"action", "operation", "operation_nonce", "at"}.intersection(context):
            raise ValueError("host context contains dispatcher-owned fields")
        with self._lock:
            if self._in_dispatch:
                raise ValueError("host context update during dispatch")
            self._context = context

    def dispatch(self, arguments_json: str, nonce: str) -> DispatchResult:
        """Evaluate fresh host context and call the fixed handler with that snapshot."""
        try:
            arguments = _object(arguments_json, MAX_ARGUMENT_CHARS)
            if type(nonce) is not str:
                raise ValueError("invalid nonce")
            operation = {"tool": self._tool, "arguments": arguments}
            digest = operation_digest("test", operation)
        except (TypeError, ValueError, RecursionError):
            return DispatchResult("DENIED", ("HOST_INPUT_INVALID",))

        with self._lock:
            if self._in_dispatch:
                return DispatchResult("DENIED", ("HOST_REENTRY",))
            self._in_dispatch = True
            try:
                request = {
                    **self._context,
                    "action": "test",
                    "operation": operation,
                    "operation_nonce": nonce,
                }
                try:
                    now = self._clock()
                    if (
                        not isinstance(now, datetime)
                        or now.tzinfo is None
                        or now.utcoffset() is None
                    ):
                        raise ValueError("host clock must return an aware datetime")
                    decision = authorize(
                        self._contract,
                        request,
                        now=now,
                        consumed_nonces=self._reserved,
                    )
                except Exception:
                    # No handler entered. Never disclose host exception text.
                    return DispatchResult("DENIED", ("HOST_EVALUATION_UNAVAILABLE",))
                if not decision.allowed:
                    return DispatchResult(
                        "DENIED", decision.reason_codes, digest, decision.contract_digest
                    )

                # Reservation and handler admission share the host-owned lock. Retain
                # the reservation even when a callback raises or its effect is unknown.
                self._reserved.add(nonce)
                try:
                    self._handler(arguments)
                except Exception:
                    return DispatchResult(
                        "UNKNOWN",
                        ("HOST_HANDLER_OUTCOME_UNKNOWN",),
                        digest,
                        decision.contract_digest,
                    )
                return DispatchResult("RETURNED", (), digest, decision.contract_digest)
            finally:
                self._in_dispatch = False


def fixture_inputs() -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Rights-cleared synthetic fixture; no shell, files, network or provider calls."""
    arguments = {"target": "README.md"}
    operation = {"tool": "fixture.check", "arguments": arguments}
    nonce = "fixture-test-once-001"
    contract = {
        "contract_version": "0.2",
        "issuer": {"id": "fixture-owner"},
        "subject": {"id": "fixture-agent"},
        "scope": {
            "repositories": [
                {
                    "name": "fixture",
                    "refs": ["main"],
                    "allow_paths": ["README.md"],
                    "deny_paths": [".env"],
                }
            ],
            "channels": ["fixture/check"],
        },
        "capabilities": ["test"],
        "validity": {"not_before": "2030-01-01T00:00:00Z", "expires_at": "2030-01-02T00:00:00Z"},
        "limits": {"max_files_changed": 0, "max_commands": 1, "max_cost_usd": 0},
        "approval_gates": [
            {"actions": ["test"], "min_approvals": 1, "approvers": ["fixture-owner"]}
        ],
        "operation_constraints": [
            {
                "action": "test",
                "operation_digest": operation_digest("test", operation),
                "nonce": nonce,
            }
        ],
        "lifecycle": {"claim_id": "fixture-claim", "fencing_generation": 1},
        "validation": {"required_commands": [], "required_artifacts": []},
    }
    context = {
        "subject_id": "fixture-agent",
        "channel": "fixture/check",
        "repository": "fixture",
        "ref": "main",
        "path": "README.md",
        "files_changed": 0,
        "commands_used": 1,
        "cost_usd": 0,
        "claim_id": "fixture-claim",
        "fencing_generation": 1,
        "approvals": ["fixture-owner"],
    }
    return contract, context, json.dumps(arguments), nonce


if __name__ == "__main__":
    contract, context, arguments_json, nonce = fixture_inputs()
    entered: list[dict[str, Any]] = []
    dispatcher = TestDispatcher(
        contract_json=json.dumps(contract),
        context_json=json.dumps(context),
        tool_name="fixture.check",
        handler=entered.append,
        clock=lambda: datetime(2030, 1, 1, 12, tzinfo=UTC),
    )
    first = dispatcher.dispatch(arguments_json, nonce)
    duplicate = dispatcher.dispatch(arguments_json, nonce)
    print(
        json.dumps(
            {
                "first": first.state,
                "duplicate": duplicate.state,
                "duplicate_codes": duplicate.reason_codes,
                "handler_entries": len(entered),
                "scope": "synthetic single-instance callback admission; no external effects",
            }
        )
    )
