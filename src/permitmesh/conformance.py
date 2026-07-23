from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
from typing import Any

from .buzz import authorize_buzz
from .policy import (
    IMPLEMENTATION_VERSION,
    RFC3339_PATTERN,
    authorize,
    canonical_json,
    verify_completion,
)


SUPPORTED_SUITE_VERSION = "0.2"


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def load_json_file(path: str | Path) -> Any:
    source = Path(path)
    try:
        return json.loads(
            source.read_text(encoding="utf-8"),
            parse_constant=_reject_nonfinite,
            parse_float=Decimal,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"could not read {str(source)!r}: {exc}") from exc


def _fixture_path(suite_dir: Path, relative_path: Any) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise ValueError("fixture path must be a non-empty string")
    candidate = (suite_dir / relative_path).resolve()
    try:
        candidate.relative_to(suite_dir.resolve())
    except ValueError as exc:
        raise ValueError(
            f"fixture path escapes suite directory: {relative_path!r}"
        ) from exc
    return candidate


def _outcome_for(case: dict[str, Any], suite_dir: Path) -> tuple[str, dict[str, Any]]:
    try:
        try:
            contract = load_json_file(_fixture_path(suite_dir, case.get("contract")))
        except ValueError as exc:
            detail = str(exc).split(": ", 1)[-1]
            raise ValueError(f"contract fixture malformed: {detail}") from exc
        try:
            request = load_json_file(_fixture_path(suite_dir, case.get("request")))
        except ValueError as exc:
            detail = str(exc).split(": ", 1)[-1]
            raise ValueError(f"request fixture malformed: {detail}") from exc
        evaluation_time = case.get("evaluation_time")
        if (
            not isinstance(evaluation_time, str)
            or RFC3339_PATTERN.fullmatch(evaluation_time) is None
        ):
            raise ValueError("evaluation_time must be an RFC 3339 string")
        try:
            now = datetime.fromisoformat(evaluation_time.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("evaluation_time must be an RFC 3339 string") from exc
        if now.tzinfo is None:
            raise ValueError("evaluation_time must include a timezone")
        if not isinstance(contract, dict):
            raise ValueError("contract fixture must be a JSON object")
        operation = case.get("operation", "authorize")
        if operation == "authorize":
            consumed_nonces = case.get("consumed_nonces")
            if consumed_nonces is not None and (
                not isinstance(consumed_nonces, list)
                or not all(isinstance(nonce, str) for nonce in consumed_nonces)
                or len(consumed_nonces) != len(set(consumed_nonces))
            ):
                raise ValueError("consumed_nonces must be a unique string array")
            decision = authorize(
                contract,
                request,
                now=now.astimezone(timezone.utc),
                consumed_nonces=(
                    frozenset(consumed_nonces) if consumed_nonces is not None else None
                ),
            )
        elif operation == "authorize_buzz":
            try:
                context = load_json_file(
                    _fixture_path(suite_dir, case.get("buzz_context"))
                )
            except ValueError as exc:
                detail = str(exc).split(": ", 1)[-1]
                raise ValueError(f"buzz context fixture malformed: {detail}") from exc
            consumed_nonces = case.get("consumed_nonces")
            if consumed_nonces is not None and (
                not isinstance(consumed_nonces, list)
                or not all(isinstance(nonce, str) for nonce in consumed_nonces)
                or len(consumed_nonces) != len(set(consumed_nonces))
            ):
                raise ValueError("consumed_nonces must be a unique string array")
            context_auth_key = case.get("buzz_context_auth_key")
            if (
                not isinstance(context_auth_key, str)
                or len(context_auth_key.encode("utf-8")) < 32
            ):
                raise ValueError(
                    "buzz_context_auth_key must encode to at least 32 bytes"
                )
            expected_community_uri = case.get("buzz_expected_community_uri")
            if not isinstance(expected_community_uri, str):
                raise ValueError("buzz_expected_community_uri must be a string")
            expected_repository_event_id = case.get("buzz_expected_repository_event_id")
            if not isinstance(expected_repository_event_id, str):
                raise ValueError("buzz_expected_repository_event_id must be a string")
            decision = authorize_buzz(
                contract,
                request,
                context,
                context_auth_key=context_auth_key.encode("utf-8"),
                expected_community_uri=expected_community_uri,
                expected_repository_announcement_event_id=(
                    expected_repository_event_id
                ),
                now=now.astimezone(timezone.utc),
                consumed_nonces=(
                    frozenset(consumed_nonces) if consumed_nonces is not None else None
                ),
            )
        elif operation == "verify_completion":
            decision = verify_completion(
                contract,
                request,
                now=now.astimezone(timezone.utc),
            )
        else:
            raise ValueError(f"unsupported conformance operation: {operation!r}")
        return ("allow" if decision.allowed else "deny"), {
            "decision": decision.to_dict()
        }
    except ValueError as exc:
        return "malformed", {"error": str(exc)}


def run_conformance(
    suite_path: str | Path,
    *,
    enforcement_boundary: str = "policy-decision-only; no tool execution",
) -> dict[str, Any]:
    source = Path(suite_path).resolve()
    suite = load_json_file(source)
    if not isinstance(suite, dict):
        raise ValueError("conformance suite must be a JSON object")
    if suite.get("suite_version") != SUPPORTED_SUITE_VERSION:
        raise ValueError(f"suite_version must be {SUPPORTED_SUITE_VERSION!r}")
    cases = suite.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("cases must be a non-empty array")
    if not isinstance(enforcement_boundary, str) or not enforcement_boundary.strip():
        raise ValueError("enforcement_boundary must be a non-empty string")

    seen_ids: set[str] = set()
    results: list[dict[str, Any]] = []
    for index, raw_case in enumerate(cases):
        if not isinstance(raw_case, dict):
            raise ValueError(f"cases[{index}] must be an object")
        case_id = raw_case.get("id")
        expected = raw_case.get("expected_outcome")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"cases[{index}].id must be a non-empty string")
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        if expected not in {"allow", "deny", "malformed"}:
            raise ValueError(
                f"cases[{index}].expected_outcome must be allow, deny, or malformed"
            )

        observed, details = _outcome_for(raw_case, source.parent)
        required_fragments = raw_case.get("expected_violations_contain", [])
        if not isinstance(required_fragments, list) or not all(
            isinstance(fragment, str) and fragment for fragment in required_fragments
        ):
            raise ValueError(
                f"cases[{index}].expected_violations_contain must be a string array"
            )
        observed_violations = details.get("decision", {}).get("violations", [])
        fragments_found = all(
            any(fragment in violation for violation in observed_violations)
            for fragment in required_fragments
        )
        passed = observed == expected and fragments_found
        results.append(
            {
                "id": case_id,
                "expected_outcome": expected,
                "observed_outcome": observed,
                "passed": passed,
                **details,
            }
        )

    passed_count = sum(1 for result in results if result["passed"])
    suite_digest = hashlib.sha256(canonical_json(suite).encode("utf-8")).hexdigest()
    return {
        "receipt_version": "0.2",
        "implementation": {"name": "permitmesh", "version": IMPLEMENTATION_VERSION},
        "suite": {
            "name": suite.get("name", source.name),
            "version": suite["suite_version"],
            "digest": suite_digest,
        },
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "enforcement_boundary": enforcement_boundary.strip(),
        "summary": {
            "total": len(results),
            "passed": passed_count,
            "failed": len(results) - passed_count,
        },
        "cases": results,
    }
