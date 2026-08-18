"""Human-readable, CI, and comparison views over verified receipts."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from boundarylab.io import JSONValue, write_json
from boundarylab.model import BoundaryLabError


def _object(value: JSONValue, label: str) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise BoundaryLabError(f"{label} must be an object")
    return value


def _array(value: JSONValue, label: str) -> list[JSONValue]:
    if not isinstance(value, list):
        raise BoundaryLabError(f"{label} must be an array")
    return value


def _text(value: JSONValue, label: str) -> str:
    if not isinstance(value, str):
        raise BoundaryLabError(f"{label} must be a string")
    return value


def _markdown_cell(value: object) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(receipt: dict[str, JSONValue]) -> str:
    """Render a receipt as a bounded Markdown report."""

    authorization = _object(receipt["authorization"], "authorization")
    profile = _object(receipt["profile"], "profile")
    runtime = _object(receipt["runtime"], "runtime")
    summary = _object(receipt["summary"], "summary")
    counts = _object(summary["counts"], "summary.counts")
    results = _array(receipt["results"], "results")
    lines = [
        "# BoundaryLab conformance receipt",
        "",
        f"- Run: `{_text(receipt['run_id'], 'run_id')}`",
        f"- Authorization: `{_text(authorization['authorization_id'], 'authorization_id')}`",
        f"- Profile: `{_text(profile['profile_id'], 'profile_id')}`",
        f"- Adapter: `{_text(runtime['adapter'], 'runtime.adapter')}`",
        f"- Started: `{_text(receipt['started_at'], 'started_at')}`",
        f"- Completed: `{_text(receipt['completed_at'], 'completed_at')}`",
        "- Claim boundary: bounded observation evidence; not certification or production admission.",
        "",
        "## Summary",
        "",
        "| Pass | Fail | Unsupported | Untested | Inconclusive | Error | Total |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {counts['pass']} | {counts['fail']} | {counts['unsupported']} | "
            f"{counts['untested']} | {counts['inconclusive']} | {counts['error']} | "
            f"{summary['total']} |"
        ),
        "",
        "## Probe results",
        "",
        "| Probe | Category | Status | Expected | Observed | Reason |",
        "|---|---|---|---|---|---|",
    ]
    for index, value in enumerate(results):
        result = _object(value, f"results[{index}]")
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{_text(result['probe_id'], 'probe_id')}`",
                    _text(result["category"], "category"),
                    f"**{_text(result['status'], 'status')}**",
                    _markdown_cell(result["expected"]),
                    _markdown_cell(result["observed"]),
                    _markdown_cell(result.get("reason_code", "")),
                )
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Runtime metadata",
            "",
            "```json",
            json.dumps(runtime, indent=2, sort_keys=True, ensure_ascii=False),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def render_junit(receipt: dict[str, JSONValue]) -> str:
    """Render a receipt as a single JUnit test suite."""

    results = _array(receipt["results"], "results")
    failures = 0
    errors = 0
    skipped = 0
    cases: list[str] = []
    for index, value in enumerate(results):
        result = _object(value, f"results[{index}]")
        probe_id = _text(result["probe_id"], "probe_id")
        category = _text(result["category"], "category")
        status = _text(result["status"], "status")
        reason = _text(result.get("reason_code", ""), "reason_code")
        details = json.dumps(
            {
                "expected": result["expected"],
                "observed": result["observed"],
                "reason_code": reason or None,
            },
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        body: str
        if status == "fail":
            failures += 1
            body = (
                f'<failure message="{escape(reason or "expectation mismatch", quote=True)}">'
                f"{escape(details)}</failure>"
            )
        elif status == "error":
            errors += 1
            body = (
                f'<error message="{escape(reason or "probe error", quote=True)}">'
                f"{escape(details)}</error>"
            )
        elif status in {"unsupported", "untested", "inconclusive"}:
            skipped += 1
            body = (
                f'<skipped message="{escape(reason or status, quote=True)}"/>'
                f"<system-out>{escape(details)}</system-out>"
            )
        else:
            body = f"<system-out>{escape(details)}</system-out>"
        cases.append(
            f'<testcase classname="boundarylab.{escape(category, quote=True)}" '
            f'name="{escape(probe_id, quote=True)}">{body}</testcase>'
        )
    run_id = escape(_text(receipt["run_id"], "run_id"), quote=True)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="boundarylab" id="{run_id}" tests="{len(results)}" '
        f'failures="{failures}" errors="{errors}" skipped="{skipped}">'
        + "".join(cases)
        + "</testsuite>\n"
    )


def export_receipt(
    receipt: dict[str, JSONValue],
    output_path: str | Path,
    *,
    export_format: str,
) -> Path:
    """Write one supported representation of a verified receipt."""

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if export_format == "markdown":
        destination.write_text(render_markdown(receipt), encoding="utf-8")
    elif export_format == "junit":
        destination.write_text(render_junit(receipt), encoding="utf-8")
    elif export_format == "json":
        write_json(destination, receipt)
    else:
        raise BoundaryLabError(
            "export format must be json, markdown, or junit"
        )
    return destination


def _results_by_probe(
    receipt: dict[str, JSONValue],
) -> dict[str, dict[str, JSONValue]]:
    indexed: dict[str, dict[str, JSONValue]] = {}
    for index, value in enumerate(_array(receipt["results"], "results")):
        result = _object(value, f"results[{index}]")
        probe_id = _text(result["probe_id"], "probe_id")
        if probe_id in indexed:
            raise BoundaryLabError(f"duplicate probe result: {probe_id}")
        indexed[probe_id] = result
    return indexed


def compare_receipts(
    baseline: dict[str, JSONValue],
    candidate: dict[str, JSONValue],
) -> dict[str, JSONValue]:
    """Compare probe status changes without manufacturing a scalar score."""

    left = _results_by_probe(baseline)
    right = _results_by_probe(candidate)
    added = sorted(right.keys() - left.keys())
    removed = sorted(left.keys() - right.keys())
    changed: list[dict[str, JSONValue]] = []
    unchanged: list[str] = []
    for probe_id in sorted(left.keys() & right.keys()):
        before = _text(left[probe_id]["status"], "baseline status")
        after = _text(right[probe_id]["status"], "candidate status")
        if before == after:
            unchanged.append(probe_id)
        else:
            changed.append(
                {
                    "after": after,
                    "before": before,
                    "probe_id": probe_id,
                }
            )
    return {
        "added": added,
        "baseline_run_id": baseline["run_id"],
        "candidate_run_id": candidate["run_id"],
        "removed": removed,
        "schema": "nymrel.boundarylab.comparison.v1",
        "status_changed": changed,
        "unchanged": unchanged,
    }
