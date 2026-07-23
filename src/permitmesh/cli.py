from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any

from .buzz import authorize_buzz
from .conformance import load_json_file, run_conformance
from .policy import (
    RFC3339_PATTERN,
    authorize,
    contract_digest,
    to_nostr_event_template,
    validate_contract,
    verify_completion,
)


def _load_json(path: str) -> Any:
    return load_json_file(path)


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _evaluation_time(value: str) -> datetime:
    if RFC3339_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("must include a timezone")
    return parsed.astimezone(timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permitmesh",
        description="Validate capability contracts and authorize agent actions.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate one contract.")
    validate_parser.add_argument("contract")

    digest_parser = subparsers.add_parser(
        "digest", help="Print the canonical contract digest."
    )
    digest_parser.add_argument("contract")

    authorize_parser = subparsers.add_parser(
        "authorize", help="Evaluate one action request against a contract."
    )
    authorize_parser.add_argument("contract")
    authorize_parser.add_argument("request")
    authorize_parser.add_argument(
        "--evaluation-time",
        type=_evaluation_time,
        help="Trusted evaluator time override for deterministic tests and replay.",
    )

    buzz_parser = subparsers.add_parser(
        "authorize-buzz",
        help="Evaluate one action against a contract and trusted Buzz context.",
    )
    buzz_parser.add_argument("contract")
    buzz_parser.add_argument("request")
    buzz_parser.add_argument("context")
    buzz_parser.add_argument(
        "--context-key-env",
        required=True,
        help="Name of the environment variable containing the context HMAC key.",
    )
    buzz_parser.add_argument("--expected-community-uri", required=True)
    buzz_parser.add_argument(
        "--expected-repository-event-id",
        required=True,
        help="Expected repository-announcement event id.",
    )
    buzz_parser.add_argument(
        "--evaluation-time",
        type=_evaluation_time,
        required=True,
        help="Timezone-aware trusted evaluator time.",
    )

    completion_parser = subparsers.add_parser(
        "verify-completion",
        help="Check declared completion evidence against a contract.",
    )
    completion_parser.add_argument("contract")
    completion_parser.add_argument("report")
    completion_parser.add_argument(
        "--evaluation-time",
        type=_evaluation_time,
        help="Trusted evaluator time override for deterministic tests and replay.",
    )

    event_parser = subparsers.add_parser(
        "to-event", help="Create an unsigned Nostr application-data event template."
    )
    event_parser.add_argument("contract")
    event_parser.add_argument("--created-at", type=int)

    conformance_parser = subparsers.add_parser(
        "conformance", help="Run a portable conformance suite and emit a receipt."
    )
    conformance_parser.add_argument("suite")
    conformance_parser.add_argument(
        "--receipt",
        help="Optional path for a JSON receipt. The receipt is always printed.",
    )
    conformance_parser.add_argument(
        "--enforcement-boundary",
        default="policy-decision-only; no tool execution",
        help="Truthful description of what the runner actually enforced.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "conformance":
            receipt = run_conformance(
                args.suite,
                enforcement_boundary=args.enforcement_boundary,
            )
            if args.receipt:
                Path(args.receipt).write_text(
                    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            _emit(receipt)
            return 0 if receipt["summary"]["failed"] == 0 else 4

        contract = _load_json(args.contract)
        if not isinstance(contract, dict):
            raise ValueError("contract must be a JSON object")

        if args.command == "validate":
            violations = validate_contract(contract)
            _emit(
                {
                    "valid": not violations,
                    "contract_digest": contract_digest(contract),
                    "violations": violations,
                }
            )
            return 0 if not violations else 2

        if args.command == "digest":
            violations = validate_contract(contract)
            if violations:
                raise ValueError("; ".join(violations))
            print(contract_digest(contract))
            return 0

        if args.command == "authorize":
            request = _load_json(args.request)
            decision = authorize(contract, request, now=args.evaluation_time)
            _emit(decision.to_dict())
            return 0 if decision.allowed else 3

        if args.command == "authorize-buzz":
            request = _load_json(args.request)
            context = _load_json(args.context)
            context_key = os.environ.get(args.context_key_env)
            if context_key is None:
                raise ValueError(
                    f"context authentication key environment variable is not set: "
                    f"{args.context_key_env}"
                )
            decision = authorize_buzz(
                contract,
                request,
                context,
                context_auth_key=context_key.encode("utf-8"),
                expected_community_uri=args.expected_community_uri,
                expected_repository_announcement_event_id=(
                    args.expected_repository_event_id
                ),
                now=args.evaluation_time,
            )
            _emit(decision.to_dict())
            return 0 if decision.allowed else 3

        if args.command == "verify-completion":
            report = _load_json(args.report)
            decision = verify_completion(
                contract,
                report,
                now=args.evaluation_time,
            )
            _emit(decision.to_dict())
            return 0 if decision.allowed else 3

        if args.command == "to-event":
            _emit(to_nostr_event_template(contract, created_at=args.created_at))
            return 0

    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    return 1
