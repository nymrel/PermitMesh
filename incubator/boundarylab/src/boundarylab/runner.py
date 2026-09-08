"""BoundaryLab conformance orchestration."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from boundarylab._version import __version__
from boundarylab.adapters import make_adapter
from boundarylab.io import JSONValue, digest_bytes, digest_json, load_json, write_json
from boundarylab.model import (
    RECEIPT_SCHEMA,
    AdapterOutcome,
    Authorization,
    BoundaryLabError,
    ProbeResult,
    Profile,
    ResultStatus,
)
from boundarylab.probes import (
    PROBE_BY_ID,
    error_results,
    evaluate_observations,
    known_probe_ids,
    unsupported_results,
)

OBSERVATIONS_SCHEMA = "nymrel.boundarylab.observations.v1"


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _network_result(
    authorization: Authorization,
    profile: Profile,
    observations: dict[str, JSONValue],
    *,
    enabled: bool,
) -> ProbeResult:
    probe_id = "network.exact_targets"
    expectation = profile.expectations.get(probe_id)
    expected_json: dict[str, JSONValue] = (
        {"op": "observe"} if expectation is None else expectation.to_json()
    )
    if not enabled:
        return ProbeResult(
            probe_id=probe_id,
            category=PROBE_BY_ID[probe_id].category,
            status="untested",
            expected=expected_json,
            observed={"tested": False, "targets": []},
            reason_code="network-probes-disabled",
        )
    raw = observations.get(probe_id)
    if not isinstance(raw, dict):
        return ProbeResult(
            probe_id=probe_id,
            category=PROBE_BY_ID[probe_id].category,
            status="error",
            expected=expected_json,
            observed=None,
            reason_code="network-observation-missing",
        )
    tested = raw.get("tested")
    raw_targets = raw.get("targets")
    if tested is not True or not isinstance(raw_targets, list):
        return ProbeResult(
            probe_id=probe_id,
            category=PROBE_BY_ID[probe_id].category,
            status="error",
            expected=expected_json,
            observed=raw,
            reason_code="network-observation-invalid",
        )
    observed_by_id: dict[str, bool] = {}
    for item in raw_targets:
        if not isinstance(item, dict):
            continue
        target_id = item.get("id")
        connected = item.get("connected")
        if isinstance(target_id, str) and isinstance(connected, bool):
            observed_by_id[target_id] = connected
    expected_targets: list[dict[str, JSONValue]] = []
    observed_targets: list[dict[str, JSONValue]] = []
    missing = False
    mismatched = False
    for target in authorization.network_targets:
        should_connect = target.expected == "allowed"
        expected_targets.append(
            {
                "connected": should_connect,
                "id": target.target_id,
            }
        )
        connected = observed_by_id.get(target.target_id)
        if connected is None:
            missing = True
            observed_targets.append(
                {
                    "connected": None,
                    "id": target.target_id,
                }
            )
            continue
        observed_targets.append(
            {
                "connected": connected,
                "id": target.target_id,
            }
        )
        if connected != should_connect:
            mismatched = True
    if missing:
        status: ResultStatus = "error"
        reason_code = "network-target-result-missing"
    elif mismatched:
        status = "fail"
        reason_code = "network-policy-mismatch"
    else:
        status = "pass"
        reason_code = None
    return ProbeResult(
        probe_id=probe_id,
        category=PROBE_BY_ID[probe_id].category,
        status=status,
        expected={"op": "policy", "targets": expected_targets},
        observed={"tested": True, "targets": observed_targets},
        reason_code=reason_code,
    )


def _results_for_outcome(
    authorization: Authorization,
    profile: Profile,
    outcome: AdapterOutcome,
    *,
    network_probes: bool,
) -> list[ProbeResult]:
    if outcome.status == "unsupported":
        return unsupported_results(
            profile.probes,
            outcome.reason_code or "adapter-unsupported",
        )
    if outcome.status == "error":
        return error_results(
            profile.probes,
            outcome.reason_code or "adapter-error",
        )
    results = evaluate_observations(
        profile.probes,
        profile.expectations,
        outcome.observations,
    )
    if "network.exact_targets" in profile.probes:
        replacement = _network_result(
            authorization,
            profile,
            outcome.observations,
            enabled=network_probes,
        )
        results = [
            replacement if item.probe_id == replacement.probe_id else item for item in results
        ]
    return results


def _summary(results: list[ProbeResult]) -> dict[str, JSONValue]:
    counts = Counter(result.status for result in results)
    statuses: tuple[ResultStatus, ...] = (
        "pass",
        "fail",
        "unsupported",
        "untested",
        "inconclusive",
        "error",
    )
    return {
        "counts": {status: counts.get(status, 0) for status in statuses},
        "total": len(results),
    }


def run_conformance(
    authorization_path: str | Path,
    profile_path: str | Path,
    *,
    adapter_name: str,
    output_directory: str | Path,
    allow_network_probes: bool = False,
    allow_public_network: bool = False,
    now: datetime | None = None,
) -> tuple[dict[str, JSONValue], Path]:
    """Run one authorized conformance observation and write its evidence."""

    authorization = Authorization.from_json(load_json(authorization_path))
    profile = Profile.from_json(load_json(profile_path), known_probe_ids())
    current = (now or datetime.now(UTC)).astimezone(UTC)
    authorization.validate_active(current)
    if adapter_name not in authorization.allowed_adapters:
        raise BoundaryLabError(f"adapter {adapter_name!r} is not authorized by this manifest")
    if allow_network_probes and not authorization.network_targets:
        raise BoundaryLabError("network probes require at least one exact authorized target")
    if allow_network_probes:
        public_targets = [
            target.target_id for target in authorization.network_targets if target.public
        ]
        if public_targets and not allow_public_network:
            raise BoundaryLabError(
                "public targets require the separate --allow-public-network opt-in"
            )
    elif allow_public_network:
        raise BoundaryLabError("--allow-public-network requires --allow-network-probes")

    run_id = str(uuid4())
    started_at = datetime.now(UTC)
    adapter = make_adapter(adapter_name)
    outcome = adapter.run(
        authorization,
        run_id,
        network_probes=allow_network_probes,
    )
    completed_at = datetime.now(UTC)
    results = _results_for_outcome(
        authorization,
        profile,
        outcome,
        network_probes=allow_network_probes,
    )

    run_directory = Path(output_directory) / run_id
    run_directory.mkdir(parents=True, exist_ok=False)
    observations_path = run_directory / "observations.json"
    observations_document: dict[str, JSONValue] = {
        "adapter": outcome.adapter,
        "observations": outcome.observations,
        "run_id": run_id,
        "schema": OBSERVATIONS_SCHEMA,
    }
    write_json(observations_path, observations_document)
    observation_bytes = observations_path.read_bytes()

    receipt_without_integrity: dict[str, JSONValue] = {
        "artifacts": [
            {
                "path": "observations.json",
                "sha256": digest_bytes(observation_bytes),
                "size_bytes": len(observation_bytes),
            }
        ],
        "authorization": {
            "authorization_id": authorization.authorization_id,
            "digest": digest_json(authorization.to_json()),
            "environment": authorization.environment,
            "owner": authorization.owner,
        },
        "claims": {
            "certification": False,
            "description": (
                "Bounded evidence for the listed probes, runtime metadata, "
                "configuration, and observation interval only."
            ),
            "production_admission": False,
        },
        "completed_at": _timestamp(completed_at),
        "profile": {
            "digest": digest_json(profile.to_json()),
            "profile_id": profile.profile_id,
        },
        "results": [result.to_json() for result in results],
        "run_id": run_id,
        "runtime": {
            **outcome.runtime,
            "boundarylab_version": __version__,
        },
        "schema": RECEIPT_SCHEMA,
        "started_at": _timestamp(started_at),
        "summary": _summary(results),
    }
    receipt: dict[str, JSONValue] = {
        **receipt_without_integrity,
        "integrity": {
            "algorithm": "sha256",
            "content_digest": digest_json(receipt_without_integrity),
            "signature": None,
        },
    }
    receipt_path = run_directory / "receipt.json"
    write_json(receipt_path, receipt)
    return receipt, receipt_path
