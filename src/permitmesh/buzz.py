from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
from typing import Any

from .policy import Decision, RFC3339_PATTERN, authorize, canonical_json


BUZZ_CONTEXT_VERSION = "0.1"
BUZZ_COMPUTE_CONTEXT_VERSION = "0.1"
MAX_CONTEXT_AGE = timedelta(minutes=5)
MAX_COMPUTE_CONTEXT_AGE = timedelta(minutes=2)
MAX_MESH_STATUS_AGE = timedelta(seconds=120)
HEX_32_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMUNITY_URI_PATTERN = re.compile(
    r"^(?:https|wss)://"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?$"
)
PRODUCER_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]{3,128}$")
MESH_ENDPOINT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
MESH_MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+~-]{0,511}$")
BUZZ_CONTEXT_FIELDS = {
    "context_version",
    "community_uri",
    "contract_digest",
    "producer_id",
    "context_mac",
    "owner_pubkey",
    "agent_pubkey",
    "owner_attestation_event_id",
    "repository_announcement_event_id",
    "nip_oa_verified",
    "repository",
    "ref",
    "channel",
    "protection_checked",
    "verified_at",
}
BUZZ_COMPUTE_CONTEXT_FIELDS = {
    "compute_context_version",
    "contract_digest",
    "base_context_mac",
    "producer_id",
    "compute_context_mac",
    "membership_event_id",
    "status_event_id",
    "status_created_at",
    "member_pubkey",
    "mesh_owner_id",
    "mesh_owner_verifying_key",
    "endpoint_id",
    "endpoint_token_sha256",
    "model_id",
    "membership_verified",
    "owner_binding_verified",
    "endpoint_binding_verified",
    "roster_enforced",
    "transport_policy_checked",
    "status_fresh",
    "input_tokens",
    "output_tokens",
    "prompt_visibility",
    "model_integrity",
    "verified_at",
}


def _valid_community_uri(value: Any) -> bool:
    return isinstance(value, str) and COMMUNITY_URI_PATTERN.fullmatch(value) is not None


def compute_buzz_context_mac(context: dict[str, Any], key: bytes) -> str:
    """Authenticate a context envelope produced by the trusted integration."""
    if not isinstance(context, dict):
        raise ValueError("buzz context must be a JSON object")
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("buzz context authentication key must be at least 32 bytes")
    payload = dict(context)
    payload.pop("context_mac", None)
    return hmac.new(
        key,
        canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def compute_buzz_compute_context_mac(context: dict[str, Any], key: bytes) -> str:
    """Authenticate shared-compute route facts from the trusted integration."""
    if not isinstance(context, dict):
        raise ValueError("buzz compute context must be a JSON object")
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError(
            "buzz compute context authentication key must be at least 32 bytes"
        )
    payload = dict(context)
    payload.pop("compute_context_mac", None)
    message = b"permitmesh-buzz-compute-context-v1\x00" + canonical_json(
        payload
    ).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _valid_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _parse_context_time(
    value: Any, field: str, violations: list[str]
) -> datetime | None:
    if not isinstance(value, str) or RFC3339_PATTERN.fullmatch(value) is None:
        violations.append(f"buzz compute {field} must be an RFC 3339 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        violations.append(f"buzz compute {field} must be an RFC 3339 timestamp")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        violations.append(f"buzz compute {field} must include a timezone")
        return None
    return parsed.astimezone(timezone.utc)


def validate_buzz_compute_context(context: Any) -> tuple[str, ...]:
    """Validate trusted facts about the exact Buzz shared-compute route.

    This validates a gateway-produced envelope. It does not verify Nostr
    signatures, MeshLLM ownership signatures, endpoint tokens, model weights,
    transport encryption, or token accounting itself.
    """
    if not isinstance(context, dict):
        return ("buzz compute context must be a JSON object",)

    violations: list[str] = []
    missing = sorted(BUZZ_COMPUTE_CONTEXT_FIELDS - context.keys())
    violations.extend(
        f"missing required buzz compute context field: {field}" for field in missing
    )
    for unknown in sorted(context.keys() - BUZZ_COMPUTE_CONTEXT_FIELDS, key=str):
        violations.append(f"buzz compute context contains unknown field: {unknown}")

    if context.get("compute_context_version") != BUZZ_COMPUTE_CONTEXT_VERSION:
        violations.append(
            f"buzz compute context_version must be {BUZZ_COMPUTE_CONTEXT_VERSION!r}"
        )
    if (
        not isinstance(context.get("producer_id"), str)
        or PRODUCER_ID_PATTERN.fullmatch(context["producer_id"]) is None
    ):
        violations.append("buzz compute producer_id must be 3-128 safe characters")

    for field in (
        "contract_digest",
        "base_context_mac",
        "compute_context_mac",
        "membership_event_id",
        "status_event_id",
        "member_pubkey",
        "mesh_owner_id",
        "mesh_owner_verifying_key",
        "endpoint_token_sha256",
    ):
        if (
            not isinstance(context.get(field), str)
            or HEX_32_PATTERN.fullmatch(context[field]) is None
        ):
            violations.append(
                f"buzz compute {field} must be 64 lowercase hexadecimal characters"
            )

    owner_id = context.get("mesh_owner_id")
    owner_key = context.get("mesh_owner_verifying_key")
    if (
        isinstance(owner_id, str)
        and HEX_32_PATTERN.fullmatch(owner_id) is not None
        and isinstance(owner_key, str)
        and HEX_32_PATTERN.fullmatch(owner_key) is not None
        and hashlib.sha256(bytes.fromhex(owner_key)).hexdigest() != owner_id
    ):
        violations.append(
            "buzz compute mesh_owner_id does not match mesh_owner_verifying_key"
        )

    endpoint_id = context.get("endpoint_id")
    if (
        not isinstance(endpoint_id, str)
        or MESH_ENDPOINT_ID_PATTERN.fullmatch(endpoint_id) is None
    ):
        violations.append(
            "buzz compute endpoint_id must be 16-128 canonical safe characters"
        )
    model_id = context.get("model_id")
    if (
        not isinstance(model_id, str)
        or MESH_MODEL_ID_PATTERN.fullmatch(model_id) is None
    ):
        violations.append("buzz compute model_id must be a canonical model reference")

    for field in (
        "membership_verified",
        "owner_binding_verified",
        "endpoint_binding_verified",
        "roster_enforced",
        "transport_policy_checked",
        "status_fresh",
    ):
        if context.get(field) is not True:
            violations.append(f"buzz compute {field} must be true")

    for field in ("input_tokens", "output_tokens"):
        if not _valid_nonnegative_integer(context.get(field)):
            violations.append(f"buzz compute {field} must be a non-negative integer")

    if context.get("prompt_visibility") != "serving_member":
        violations.append("buzz compute prompt_visibility must be 'serving_member'")
    if context.get("model_integrity") != "advertised_only":
        violations.append("buzz compute model_integrity must be 'advertised_only'")

    _parse_context_time(
        context.get("status_created_at"), "status_created_at", violations
    )
    _parse_context_time(context.get("verified_at"), "verified_at", violations)
    return tuple(violations)


def validate_buzz_context(context: Any) -> tuple[str, ...]:
    """Validate facts supplied by a trusted Buzz integration boundary.

    This function validates the context envelope. It does not fetch events or
    verify Nostr signatures, NIP-OA attestations, or buzz-protect state.
    """
    if not isinstance(context, dict):
        return ("buzz context must be a JSON object",)

    violations: list[str] = []
    missing = sorted(BUZZ_CONTEXT_FIELDS - context.keys())
    violations.extend(
        f"missing required buzz context field: {field}" for field in missing
    )
    for unknown in sorted(context.keys() - BUZZ_CONTEXT_FIELDS, key=str):
        violations.append(f"buzz context contains unknown field: {unknown}")

    if context.get("context_version") != BUZZ_CONTEXT_VERSION:
        violations.append(f"buzz context_version must be {BUZZ_CONTEXT_VERSION!r}")
    if not _valid_community_uri(context.get("community_uri")):
        violations.append(
            "buzz community_uri must be a canonical HTTPS or WSS community endpoint"
        )
    if (
        not isinstance(context.get("producer_id"), str)
        or PRODUCER_ID_PATTERN.fullmatch(context["producer_id"]) is None
    ):
        violations.append("buzz producer_id must be 3-128 safe characters")

    for field in (
        "contract_digest",
        "context_mac",
        "owner_pubkey",
        "agent_pubkey",
        "owner_attestation_event_id",
        "repository_announcement_event_id",
    ):
        if (
            not isinstance(context.get(field), str)
            or HEX_32_PATTERN.fullmatch(context[field]) is None
        ):
            violations.append(
                f"buzz {field} must be 64 lowercase hexadecimal characters"
            )

    if context.get("nip_oa_verified") is not True:
        violations.append(
            "buzz nip_oa_verified must be true at the trusted integration boundary"
        )
    if context.get("protection_checked") is not True:
        violations.append(
            "buzz protection_checked must be true at the trusted integration boundary"
        )

    for field in ("repository", "ref", "channel"):
        if not isinstance(context.get(field), str) or not context[field]:
            violations.append(f"buzz {field} must be a non-empty string")

    verified_at = context.get("verified_at")
    if (
        not isinstance(verified_at, str)
        or RFC3339_PATTERN.fullmatch(verified_at) is None
    ):
        violations.append("buzz verified_at must be an RFC 3339 timestamp")
    else:
        try:
            parsed = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
        except ValueError:
            violations.append("buzz verified_at must be an RFC 3339 timestamp")
        else:
            if parsed.tzinfo is None:
                violations.append("buzz verified_at must include a timezone")

    return tuple(violations)


def authorize_buzz(
    contract: dict[str, Any],
    request: dict[str, Any],
    context: Any,
    *,
    context_auth_key: bytes,
    expected_community_uri: str,
    expected_repository_announcement_event_id: str,
    now: datetime | None = None,
    consumed_nonces: frozenset[str] | set[str] | None = None,
) -> Decision:
    """Authorize a request and bind it to trusted Buzz integration facts."""
    base = authorize(
        contract,
        request,
        now=now,
        consumed_nonces=consumed_nonces,
    )
    violations = list(base.violations)
    checks = (*base.checks, "buzz_context")
    context_violations = validate_buzz_context(context)
    violations.extend(context_violations)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        violations.append(
            "buzz freshness requires a timezone-aware trusted evaluator time"
        )

    if isinstance(context, dict):
        try:
            expected_mac = compute_buzz_context_mac(context, context_auth_key)
        except (TypeError, ValueError):
            violations.append(
                "buzz context authentication key must be at least 32 bytes"
            )
        else:
            supplied_mac = context.get("context_mac")
            if not isinstance(supplied_mac, str) or not hmac.compare_digest(
                supplied_mac, expected_mac
            ):
                violations.append("buzz context_mac authentication failed")
        if not _valid_community_uri(expected_community_uri):
            violations.append(
                "expected_community_uri must be a canonical HTTPS or WSS community endpoint"
            )
        elif context.get("community_uri") != expected_community_uri:
            violations.append(
                "buzz community_uri does not match the configured community"
            )
        if (
            not isinstance(expected_repository_announcement_event_id, str)
            or HEX_32_PATTERN.fullmatch(expected_repository_announcement_event_id)
            is None
        ):
            violations.append(
                "expected_repository_announcement_event_id must be 64 lowercase hexadecimal characters"
            )
        elif (
            context.get("repository_announcement_event_id")
            != expected_repository_announcement_event_id
        ):
            violations.append(
                "buzz repository_announcement_event_id does not match the configured repository"
            )
        if context.get("contract_digest") != base.contract_digest:
            violations.append("buzz contract_digest does not match the active contract")
        issuer = contract.get("issuer") if isinstance(contract, dict) else None
        subject = contract.get("subject") if isinstance(contract, dict) else None
        if context.get("owner_pubkey") != (
            issuer.get("id") if isinstance(issuer, dict) else None
        ):
            violations.append("buzz owner_pubkey does not match contract issuer.id")
        if context.get("agent_pubkey") != (
            subject.get("id") if isinstance(subject, dict) else None
        ):
            violations.append("buzz agent_pubkey does not match contract subject.id")
        for field in ("repository", "ref", "channel"):
            requested = request.get(field) if isinstance(request, dict) else None
            if context.get(field) != requested:
                violations.append(f"buzz {field} does not match the action request")

        verified_at = context.get("verified_at")
        if (
            isinstance(verified_at, str)
            and RFC3339_PATTERN.fullmatch(verified_at) is not None
            and isinstance(now, datetime)
        ):
            try:
                verified_time = datetime.fromisoformat(
                    verified_at.replace("Z", "+00:00")
                )
            except ValueError:
                pass
            else:
                if verified_time.tzinfo is not None:
                    effective_now = (
                        now.astimezone(timezone.utc)
                        if now.tzinfo is not None and now.utcoffset() is not None
                        else None
                    )
                    if effective_now is not None:
                        verified_time = verified_time.astimezone(timezone.utc)
                        if verified_time > effective_now:
                            violations.append(
                                "buzz verified_at must not be in the future"
                            )
                        elif effective_now - verified_time > MAX_CONTEXT_AGE:
                            violations.append(
                                "buzz verification is older than five minutes"
                            )

    return Decision(
        allowed=not violations,
        contract_digest=base.contract_digest,
        violations=tuple(violations),
        checks=checks,
    )


def _validated_allowlist(
    values: frozenset[str] | set[str],
    *,
    field: str,
    pattern: re.Pattern[str],
    violations: list[str],
) -> set[str]:
    if not isinstance(values, (set, frozenset)) or not values:
        violations.append(f"{field} must be a non-empty set")
        return set()
    if not all(
        isinstance(value, str) and pattern.fullmatch(value) is not None
        for value in values
    ):
        violations.append(f"{field} contains a malformed value")
        return set()
    return set(values)


def authorize_buzz_compute(
    contract: dict[str, Any],
    request: dict[str, Any],
    context: Any,
    compute_context: Any,
    *,
    context_auth_key: bytes,
    expected_community_uri: str,
    expected_repository_announcement_event_id: str,
    allowed_compute_member_pubkeys: frozenset[str] | set[str],
    allowed_mesh_owner_ids: frozenset[str] | set[str],
    allowed_model_ids: frozenset[str] | set[str],
    max_input_tokens: int,
    max_output_tokens: int,
    now: datetime | None = None,
    consumed_nonces: frozenset[str] | set[str] | None = None,
) -> Decision:
    """Bind a Buzz action decision to one trusted shared-compute route.

    The route is a prerequisite fact about the model invocation that produced
    or reviewed the action. This remains a policy decision; it does not proxy
    inference or enforce execution.
    """
    base = authorize_buzz(
        contract,
        request,
        context,
        context_auth_key=context_auth_key,
        expected_community_uri=expected_community_uri,
        expected_repository_announcement_event_id=(
            expected_repository_announcement_event_id
        ),
        now=now,
        consumed_nonces=consumed_nonces,
    )
    violations = list(base.violations)
    checks = (*base.checks, "buzz_shared_compute")
    violations.extend(validate_buzz_compute_context(compute_context))

    members = _validated_allowlist(
        allowed_compute_member_pubkeys,
        field="allowed_compute_member_pubkeys",
        pattern=HEX_32_PATTERN,
        violations=violations,
    )
    owners = _validated_allowlist(
        allowed_mesh_owner_ids,
        field="allowed_mesh_owner_ids",
        pattern=HEX_32_PATTERN,
        violations=violations,
    )
    models = _validated_allowlist(
        allowed_model_ids,
        field="allowed_model_ids",
        pattern=MESH_MODEL_ID_PATTERN,
        violations=violations,
    )
    if (
        not isinstance(max_input_tokens, int)
        or isinstance(max_input_tokens, bool)
        or max_input_tokens < 1
    ):
        violations.append("max_input_tokens must be a positive integer")
    if (
        not isinstance(max_output_tokens, int)
        or isinstance(max_output_tokens, bool)
        or max_output_tokens < 1
    ):
        violations.append("max_output_tokens must be a positive integer")

    if isinstance(compute_context, dict):
        try:
            expected_mac = compute_buzz_compute_context_mac(
                compute_context, context_auth_key
            )
        except (TypeError, ValueError):
            violations.append(
                "buzz compute context authentication key must be at least 32 bytes"
            )
        else:
            supplied_mac = compute_context.get("compute_context_mac")
            if not isinstance(supplied_mac, str) or not hmac.compare_digest(
                supplied_mac, expected_mac
            ):
                violations.append("buzz compute context_mac authentication failed")

        if compute_context.get("contract_digest") != base.contract_digest:
            violations.append(
                "buzz compute contract_digest does not match the active contract"
            )
        base_context_mac = (
            context.get("context_mac") if isinstance(context, dict) else None
        )
        if compute_context.get("base_context_mac") != base_context_mac:
            violations.append(
                "buzz compute base_context_mac does not match the Buzz context"
            )
        if members and compute_context.get("member_pubkey") not in members:
            violations.append("buzz compute member_pubkey is not allowed")
        if owners and compute_context.get("mesh_owner_id") not in owners:
            violations.append("buzz compute mesh_owner_id is not allowed")
        if models and compute_context.get("model_id") not in models:
            violations.append("buzz compute model_id is not allowed")

        input_tokens = compute_context.get("input_tokens")
        output_tokens = compute_context.get("output_tokens")
        if (
            isinstance(input_tokens, int)
            and not isinstance(input_tokens, bool)
            and input_tokens >= 0
            and isinstance(max_input_tokens, int)
            and not isinstance(max_input_tokens, bool)
            and max_input_tokens >= 1
            and input_tokens > max_input_tokens
        ):
            violations.append("buzz compute input_tokens exceeds the configured limit")
        if (
            isinstance(output_tokens, int)
            and not isinstance(output_tokens, bool)
            and output_tokens >= 0
            and isinstance(max_output_tokens, int)
            and not isinstance(max_output_tokens, bool)
            and max_output_tokens >= 1
            and output_tokens > max_output_tokens
        ):
            violations.append("buzz compute output_tokens exceeds the configured limit")

        status_time_violations: list[str] = []
        status_time = _parse_context_time(
            compute_context.get("status_created_at"),
            "status_created_at",
            status_time_violations,
        )
        verified_time = _parse_context_time(
            compute_context.get("verified_at"),
            "verified_at",
            status_time_violations,
        )
        if (
            status_time is not None
            and verified_time is not None
            and status_time > verified_time
        ):
            violations.append(
                "buzz compute status_created_at must not be after verified_at"
            )
        elif (
            status_time is not None
            and verified_time is not None
            and verified_time - status_time > MAX_MESH_STATUS_AGE
        ):
            violations.append("buzz compute mesh status is older than 120 seconds")

        if (
            isinstance(now, datetime)
            and now.tzinfo is not None
            and now.utcoffset() is not None
            and verified_time is not None
        ):
            effective_now = now.astimezone(timezone.utc)
            if verified_time > effective_now:
                violations.append("buzz compute verified_at must not be in the future")
            elif effective_now - verified_time > MAX_COMPUTE_CONTEXT_AGE:
                violations.append("buzz compute verification is older than two minutes")

    return Decision(
        allowed=not violations,
        contract_digest=base.contract_digest,
        violations=tuple(violations),
        checks=checks,
    )
