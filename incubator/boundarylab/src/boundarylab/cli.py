"""BoundaryLab command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from boundarylab._version import __version__
from boundarylab.export import compare_receipts, export_receipt
from boundarylab.io import JSONValue, StrictJSONError, write_json
from boundarylab.model import AUTH_SCHEMA, PROFILE_SCHEMA, BoundaryLabError
from boundarylab.probes import PROBES
from boundarylab.receipt import verify_receipt
from boundarylab.runner import run_conformance


def _default_authorization() -> dict[str, JSONValue]:
    expires_at = datetime.now(UTC) + timedelta(days=30)
    return {
        "adapter_config": {"docker_image": "python:3.13-slim"},
        "allowed_adapters": ["local", "docker"],
        "authorization_id": "local-boundarylab-evaluation",
        "destructive_tests": False,
        "environment": "local",
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "limits": {
            "max_cost_usd": "0",
            "max_duration_seconds": 120,
            "max_output_bytes": 262144,
            "max_parallel": 1,
        },
        "network_targets": [],
        "owner": "replace-with-environment-owner",
        "schema": AUTH_SCHEMA,
        "third_party_testing": False,
    }


def _default_profile() -> dict[str, JSONValue]:
    return {
        "description": (
            "Observe every safe built-in probe without asserting provider-specific policy."
        ),
        "expectations": {},
        "probes": ["*"],
        "profile_id": "core-observation",
        "schema": PROFILE_SCHEMA,
    }


def _configure_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boundarylab",
        description=("Authorized, provider-neutral sandbox conformance evidence."),
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser(
        "init",
        help="write reviewed starter authorization and profile files",
    )
    init_parser.add_argument(
        "--directory",
        default=".boundarylab",
        help="destination directory (default: .boundarylab)",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="replace existing starter files",
    )

    probes_parser = commands.add_parser(
        "probes",
        help="list built-in bounded probes",
    )
    probes_parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON",
    )

    run_parser = commands.add_parser(
        "run",
        help="run one authorized conformance observation",
    )
    run_parser.add_argument("--authorization", required=True)
    run_parser.add_argument("--profile", required=True)
    run_parser.add_argument(
        "--adapter",
        required=True,
        choices=("local", "command", "docker", "vercel"),
    )
    run_parser.add_argument("--out", default=".boundarylab/runs")
    run_parser.add_argument(
        "--allow-network-probes",
        action="store_true",
        help="enable exact-target, payload-free TCP policy probes",
    )
    run_parser.add_argument(
        "--allow-public-network",
        action="store_true",
        help="separate opt-in when an authorized target is public",
    )

    verify_parser = commands.add_parser(
        "verify",
        help="verify a receipt and all referenced artifacts",
    )
    verify_parser.add_argument("receipt")
    verify_parser.add_argument(
        "--json",
        action="store_true",
        help="print the verified receipt",
    )

    export_parser = commands.add_parser(
        "export",
        help="export a verified receipt",
    )
    export_parser.add_argument("receipt")
    export_parser.add_argument(
        "--format",
        required=True,
        choices=("json", "markdown", "junit"),
    )
    export_parser.add_argument("--out", required=True)

    compare_parser = commands.add_parser(
        "compare",
        help="compare statuses in two verified receipts",
    )
    compare_parser.add_argument("baseline")
    compare_parser.add_argument("candidate")
    compare_parser.add_argument("--out")
    return parser


def _command_init(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    files = {
        directory / "authorization.json": _default_authorization(),
        directory / "profile.json": _default_profile(),
    }
    existing = [str(path) for path in files if path.exists()]
    if existing and not args.force:
        raise BoundaryLabError("refusing to replace existing files: " + ", ".join(existing))
    for path, value in files.items():
        write_json(path, value)
    print(directory)
    return 0


def _command_probes(args: argparse.Namespace) -> int:
    records: list[dict[str, JSONValue]] = [
        {
            "category": probe.category,
            "description": probe.description,
            "probe_id": probe.probe_id,
        }
        for probe in PROBES
    ]
    if args.json:
        print(json.dumps(records, indent=2, sort_keys=True))
    else:
        for record in records:
            print(f"{record['probe_id']}\t{record['category']}\t{record['description']}")
    return 0


def _command_run(args: argparse.Namespace) -> int:
    receipt, receipt_path = run_conformance(
        args.authorization,
        args.profile,
        adapter_name=args.adapter,
        output_directory=args.out,
        allow_network_probes=args.allow_network_probes,
        allow_public_network=args.allow_public_network,
    )
    print(receipt_path)
    summary = receipt["summary"]
    if isinstance(summary, dict):
        counts = summary.get("counts")
        if isinstance(counts, dict):
            failures = counts.get("fail", 0)
            errors = counts.get("error", 0)
            if isinstance(failures, int) and isinstance(errors, int):
                return 1 if failures + errors else 0
    return 2


def _command_verify(args: argparse.Namespace) -> int:
    receipt = verify_receipt(args.receipt)
    if args.json:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    else:
        print(f"verified {args.receipt}")
    return 0


def _command_export(args: argparse.Namespace) -> int:
    receipt = verify_receipt(args.receipt)
    destination = export_receipt(
        receipt,
        args.out,
        export_format=args.format,
    )
    print(destination)
    return 0


def _command_compare(args: argparse.Namespace) -> int:
    baseline = verify_receipt(args.baseline)
    candidate = verify_receipt(args.candidate)
    comparison = compare_receipts(baseline, candidate)
    if args.out:
        write_json(args.out, comparison)
        print(args.out)
    else:
        print(json.dumps(comparison, indent=2, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _configure_parser()
    args = parser.parse_args(argv)
    handlers = {
        "compare": _command_compare,
        "export": _command_export,
        "init": _command_init,
        "probes": _command_probes,
        "run": _command_run,
        "verify": _command_verify,
    }
    try:
        return handlers[args.command](args)
    except (BoundaryLabError, StrictJSONError, OSError) as exc:
        print(f"boundarylab: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
