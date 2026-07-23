from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
from typing import Any

from .policy import Decision, RFC3339_PATTERN, authorize, canonical_json


BUZZ_CONTEXT_VERSION = "0.1"
MAX_CONTEXT_AGE = timedelta(minutes=5)
HEX_32_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMUNITY_URI_PATTERN = re.compile(
    r"^(?:https|wss)://"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?$"
)
PRODUCER_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]{3,128}$")
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
            and isinstance(now, (datetime, type(None)))
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
                        datetime.now(timezone.utc)
                        if now is None
                        else now.astimezone(timezone.utc)
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
