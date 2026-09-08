"""Independent verification for BoundaryLab receipts and artifacts."""

from __future__ import annotations

import hmac
from collections import Counter
from pathlib import Path, PurePosixPath

from boundarylab.io import JSONValue, digest_bytes, digest_json, load_json
from boundarylab.model import RECEIPT_SCHEMA, BoundaryLabError

_STATUSES = frozenset(
    {
        "pass",
        "fail",
        "unsupported",
        "untested",
        "inconclusive",
        "error",
    }
)
_TOP_LEVEL_FIELDS = frozenset(
    {
        "artifacts",
        "authorization",
        "claims",
        "completed_at",
        "integrity",
        "profile",
        "results",
        "run_id",
        "runtime",
        "schema",
        "started_at",
        "summary",
    }
)


def _object(value: JSONValue, label: str) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise BoundaryLabError(f"{label} must be an object")
    return value


def _array(value: JSONValue, label: str) -> list[JSONValue]:
    if not isinstance(value, list):
        raise BoundaryLabError(f"{label} must be an array")
    return value


def _text(value: JSONValue, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise BoundaryLabError(f"{label} must be a non-empty string")
    return value


def _integer(value: JSONValue, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BoundaryLabError(f"{label} must be a non-negative integer")
    return value


def _safe_artifact_path(receipt_directory: Path, value: JSONValue) -> Path:
    text = _text(value, "artifact.path")
    pure = PurePosixPath(text)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise BoundaryLabError("artifact.path must be a safe relative path")
    target = receipt_directory.joinpath(*pure.parts).resolve()
    root = receipt_directory.resolve()
    if target != root and root not in target.parents:
        raise BoundaryLabError("artifact.path escapes the receipt directory")
    return target


def _verify_summary(receipt: dict[str, JSONValue]) -> None:
    results = _array(receipt["results"], "receipt.results")
    counts: Counter[str] = Counter()
    for index, item in enumerate(results):
        result = _object(item, f"receipt.results[{index}]")
        status = _text(result.get("status"), f"receipt.results[{index}].status")
        if status not in _STATUSES:
            raise BoundaryLabError(f"unsupported result status: {status}")
        counts[status] += 1
    summary = _object(receipt["summary"], "receipt.summary")
    if set(summary) != {"counts", "total"}:
        raise BoundaryLabError("receipt.summary contains unexpected fields")
    total = _integer(summary["total"], "receipt.summary.total")
    if total != len(results):
        raise BoundaryLabError("receipt.summary.total does not match results")
    recorded_counts = _object(summary["counts"], "receipt.summary.counts")
    if set(recorded_counts) != _STATUSES:
        raise BoundaryLabError("receipt.summary.counts must list every status")
    for status in _STATUSES:
        value = _integer(
            recorded_counts[status],
            f"receipt.summary.counts.{status}",
        )
        if value != counts.get(status, 0):
            raise BoundaryLabError(f"receipt.summary count does not match status {status}")


def verify_receipt(path: str | Path) -> dict[str, JSONValue]:
    """Verify canonical content integrity plus every referenced artifact."""

    receipt_path = Path(path)
    receipt = _object(load_json(receipt_path), "receipt")
    if set(receipt) != _TOP_LEVEL_FIELDS:
        missing = sorted(_TOP_LEVEL_FIELDS - receipt.keys())
        unknown = sorted(receipt.keys() - _TOP_LEVEL_FIELDS)
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if unknown:
            details.append("unknown=" + ",".join(unknown))
        raise BoundaryLabError(
            "receipt fields do not match the schema (" + "; ".join(details) + ")"
        )
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise BoundaryLabError(f"receipt.schema must equal {RECEIPT_SCHEMA}")

    integrity = _object(receipt["integrity"], "receipt.integrity")
    if set(integrity) != {"algorithm", "content_digest", "signature"}:
        raise BoundaryLabError("receipt.integrity contains unexpected fields")
    if integrity["algorithm"] != "sha256":
        raise BoundaryLabError("receipt integrity algorithm must be sha256")
    expected_digest = _text(
        integrity["content_digest"],
        "receipt.integrity.content_digest",
    )
    if len(expected_digest) != 64:
        raise BoundaryLabError("receipt content digest must be SHA-256 hex")
    unsigned = {key: value for key, value in receipt.items() if key != "integrity"}
    observed_digest = digest_json(unsigned)
    if not hmac.compare_digest(expected_digest, observed_digest):
        raise BoundaryLabError("receipt content digest mismatch")

    artifacts = _array(receipt["artifacts"], "receipt.artifacts")
    seen_paths: set[str] = set()
    for index, item in enumerate(artifacts):
        artifact = _object(item, f"receipt.artifacts[{index}]")
        if set(artifact) != {"path", "sha256", "size_bytes"}:
            raise BoundaryLabError("artifact contains unexpected fields")
        relative_path = _text(artifact["path"], "artifact.path")
        if relative_path in seen_paths:
            raise BoundaryLabError("receipt references an artifact more than once")
        seen_paths.add(relative_path)
        target = _safe_artifact_path(receipt_path.parent, relative_path)
        if not target.is_file():
            raise BoundaryLabError(f"artifact does not exist: {relative_path}")
        content = target.read_bytes()
        expected_size = _integer(artifact["size_bytes"], "artifact.size_bytes")
        if len(content) != expected_size:
            raise BoundaryLabError(f"artifact size mismatch: {relative_path}")
        expected_hash = _text(artifact["sha256"], "artifact.sha256")
        if len(expected_hash) != 64 or not hmac.compare_digest(
            expected_hash,
            digest_bytes(content),
        ):
            raise BoundaryLabError(f"artifact hash mismatch: {relative_path}")

    _verify_summary(receipt)
    return receipt
