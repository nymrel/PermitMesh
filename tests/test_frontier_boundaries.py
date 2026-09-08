from __future__ import annotations

import io
import json
import runpy
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from permitmesh.cli import main
from permitmesh.conformance import (
    MAX_CONFORMANCE_CASES,
    MAX_ENFORCEMENT_BOUNDARY_CHARS,
    MAX_EXPECTED_FRAGMENTS,
    _outcome_for,
    run_conformance,
)
from permitmesh.policy import (
    MAX_CANONICAL_NODES,
    MAX_CANONICAL_NUMBER_CHARS,
    MAX_CANONICAL_STRING_CHARS,
    MAX_COLLECTION_ITEMS,
    MAX_PATTERN_CHARS,
    MAX_PATTERN_ITEMS,
    MAX_REPLAY_NONCES,
    authorize,
    canonical_json,
    validate_contract,
    verify_completion,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
EVALUATION_TIME = datetime(2026, 7, 23, 12, tzinfo=UTC)


def load_example(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def single_case_suite() -> dict:
    suite = json.loads((EXAMPLES / "conformance-suite.json").read_text(encoding="utf-8"))
    suite["cases"] = [deepcopy(suite["cases"][0])]
    return suite


def stage_suite(directory: Path, suite: object) -> Path:
    path = directory / "suite.json"
    path.write_text(json.dumps(suite), encoding="utf-8")
    for fixture in ("contract.valid.json", "request.allowed.json"):
        (directory / fixture).write_text(
            (EXAMPLES / fixture).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    return path


def invoke(*argv: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(list(argv))
    return code, stdout.getvalue(), stderr.getvalue()


class CanonicalInputBudgetTests(unittest.TestCase):
    def test_canonical_scalars_and_tuples_are_deterministic(self) -> None:
        self.assertEqual(canonical_json((None, True, False, Decimal("-0"))), "[null,true,false,0]")

    def test_canonical_input_budgets_reject_resource_exhaustion(self) -> None:
        values = (
            ("node count", "node count", [None] * MAX_CANONICAL_NODES),
            ("string", "string", "x" * (MAX_CANONICAL_STRING_CHARS + 1)),
            ("integer", "integer", 1 << 3_401),
            (
                "precision",
                "too precise",
                Decimal("0." + ("1" * (MAX_CANONICAL_NUMBER_CHARS + 1))),
            ),
            (
                "rendered number",
                "too large",
                Decimal(
                    "-"
                    + ("1" * MAX_CANONICAL_NUMBER_CHARS)
                    + f"e-{MAX_CANONICAL_NUMBER_CHARS - 20}"
                ),
            ),
        )
        for label, message, value in values:
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, message):
                canonical_json(value)

    def test_canonical_input_rejects_non_json_values(self) -> None:
        for value, error in (
            (Decimal("NaN"), "finite"),
            (float("inf"), "finite"),
            ({1: "value"}, "keys must be strings"),
            (object(), "unsupported canonical JSON value"),
        ):
            with (
                self.subTest(value=type(value).__name__),
                self.assertRaisesRegex((TypeError, ValueError), error),
            ):
                canonical_json(value)


class ContractCollectionBudgetTests(unittest.TestCase):
    def test_contract_collection_budgets_are_enforced(self) -> None:
        cases: list[tuple[str, dict, str]] = []

        contract = load_example("contract.valid.json")
        contract["capabilities"] = ["read"] * (MAX_COLLECTION_ITEMS + 1)
        cases.append(("capabilities", contract, "capabilities must contain at most"))

        contract = load_example("contract.valid.json")
        contract["scope"]["repositories"] = [deepcopy(contract["scope"]["repositories"][0])] * (
            MAX_COLLECTION_ITEMS + 1
        )
        cases.append(("repositories", contract, "scope.repositories must contain at most"))

        contract = load_example("contract.valid.json")
        contract["scope"]["repositories"][0]["refs"] = ["feature/*"] * (MAX_PATTERN_ITEMS + 1)
        cases.append(("refs", contract, ".refs must contain at most"))

        contract = load_example("contract.valid.json")
        contract["scope"]["repositories"][0]["allow_paths"] = ["src/**"] * (MAX_PATTERN_ITEMS + 1)
        cases.append(("patterns", contract, ".allow_paths must contain at most"))

        contract = load_example("contract.valid.json")
        contract["scope"]["channels"] = ["channel"] * (MAX_COLLECTION_ITEMS + 1)
        cases.append(("channels", contract, "scope.channels must contain at most"))

        contract = load_example("contract.valid.json")
        contract["approval_gates"] = [{}] * (MAX_COLLECTION_ITEMS + 1)
        cases.append(("gates", contract, "approval_gates must contain at most"))

        contract = load_example("contract.valid.json")
        contract["operation_constraints"] = [{}] * (MAX_COLLECTION_ITEMS + 1)
        cases.append(("constraints", contract, "operation_constraints must contain at most"))

        contract = load_example("contract.valid.json")
        contract["validation"]["required_commands"] = ["command"] * (MAX_COLLECTION_ITEMS + 1)
        cases.append(("validation", contract, "validation.required_commands must contain at most"))

        for label, candidate, expected in cases:
            with self.subTest(label=label):
                self.assertTrue(any(expected in item for item in validate_contract(candidate)))

    def test_contract_rejects_oversized_ref_and_malformed_signature(self) -> None:
        contract = load_example("contract.valid.json")
        contract["scope"]["repositories"][0]["refs"] = ["x" * (MAX_PATTERN_CHARS + 1)]
        contract["signature"] = {"algorithm": "", "public_key": "", "value": "", "extra": True}
        violations = validate_contract(contract)
        self.assertIn(
            "scope.repositories[0].refs must be a non-empty string array",
            violations,
        )
        self.assertIn("signature contains unknown field: extra", violations)
        self.assertIn("signature.algorithm must be a non-empty string", violations)

        contract["signature"] = "not-an-object"
        self.assertIn("signature must be an object", validate_contract(contract))


class DecisionBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_example("contract.valid.json")
        self.request = load_example("request.allowed.json")
        self.report = load_example("completion.valid.json")

    def test_request_and_report_envelopes_are_bounded(self) -> None:
        request = {f"field-{index}": index for index in range(MAX_COLLECTION_ITEMS + 1)}
        decision = authorize(self.contract, request, now=EVALUATION_TIME)
        self.assertIn("request must contain at most", decision.violations[0])

        report = {f"field-{index}": index for index in range(MAX_COLLECTION_ITEMS + 1)}
        decision = verify_completion(self.contract, report, now=EVALUATION_TIME)
        self.assertIn("completion report must contain at most", decision.violations[0])

    def test_non_object_envelopes_fail_closed(self) -> None:
        self.assertIn(
            "request must be a JSON object",
            authorize(self.contract, None, now=EVALUATION_TIME).violations,
        )
        self.assertIn(
            "completion report must be a JSON object",
            verify_completion(self.contract, None, now=EVALUATION_TIME).violations,
        )

    def test_request_text_and_approval_budgets_are_enforced(self) -> None:
        self.request["ref"] = "x" * (MAX_PATTERN_CHARS + 1)
        self.request["approvals"] = [
            f"approver-{index}" for index in range(MAX_COLLECTION_ITEMS + 1)
        ]
        decision = authorize(self.contract, self.request, now=EVALUATION_TIME)
        self.assertIn("request.ref must be a bounded non-empty string", decision.violations)
        self.assertTrue(
            any("request.approvals must contain at most" in item for item in decision.violations)
        )

    def test_high_risk_operation_and_replay_boundaries_fail_closed(self) -> None:
        self.request.update(
            {
                "action": "shell",
                "operation": {"tool": "", "arguments": []},
                "operation_nonce": "permitmesh-boundary-001",
            }
        )
        invalid = authorize(self.contract, self.request, now=EVALUATION_TIME, consumed_nonces=[])
        self.assertIn(
            "request.operation.tool must be a bounded non-empty string",
            invalid.violations,
        )
        self.assertIn("request.operation.arguments must be an object", invalid.violations)
        self.assertIn("consumed_nonces must be a set of strings", invalid.violations)

        self.request["operation"] = {"tool": "python", "arguments": {"bad": object()}}
        canonical = authorize(
            self.contract,
            self.request,
            now=EVALUATION_TIME,
            consumed_nonces=frozenset(),
        )
        self.assertIn("request.operation must contain canonical JSON values", canonical.violations)

    def test_replay_state_has_a_hard_cardinality_cap(self) -> None:
        self.request.update(
            {
                "action": "shell",
                "operation": {"tool": "python", "arguments": {}},
                "operation_nonce": "permitmesh-boundary-002",
            }
        )
        consumed = {f"nonce-{index:016d}" for index in range(MAX_REPLAY_NONCES + 1)}
        decision = authorize(
            self.contract,
            self.request,
            now=EVALUATION_TIME,
            consumed_nonces=consumed,
        )
        self.assertTrue(
            any("consumed_nonces must contain at most" in item for item in decision.violations)
        )

    def test_low_risk_requests_cannot_smuggle_operation_bindings(self) -> None:
        self.request["operation"] = {"tool": "ignored", "arguments": {}}
        self.request["operation_nonce"] = "permitmesh-boundary-003"
        decision = authorize(self.contract, self.request, now=EVALUATION_TIME)
        self.assertIn(
            "operation binding fields are only valid for high-risk actions",
            decision.violations,
        )

    def test_completion_evidence_collections_are_bounded_and_unique(self) -> None:
        self.report["commands_passed"] = [
            f"command-{index}" for index in range(MAX_COLLECTION_ITEMS + 1)
        ]
        self.report["artifacts_present"] = ["artifact", "artifact"]
        decision = verify_completion(self.contract, self.report, now=EVALUATION_TIME)
        self.assertTrue(
            any(
                "completion report.commands_passed must contain at most" in item
                for item in decision.violations
            )
        )
        self.assertIn(
            "completion report.artifacts_present must not contain duplicates",
            decision.violations,
        )

    def test_noncanonical_contracts_fail_closed_for_both_decisions(self) -> None:
        contract = {"unsupported": object()}
        self.assertIn(
            "contract must contain canonical JSON values",
            authorize(contract, self.request, now=EVALUATION_TIME).violations,
        )
        self.assertIn(
            "contract must contain canonical JSON values",
            verify_completion(contract, self.report, now=EVALUATION_TIME).violations,
        )


class ConformanceBoundaryTests(unittest.TestCase):
    def test_outcome_classifies_malformed_fixtures_and_cases(self) -> None:
        cases = [
            ({**single_case_suite()["cases"][0], "contract": "missing.json"}, "contract fixture"),
            ({**single_case_suite()["cases"][0], "request": "missing.json"}, "request fixture"),
            ({**single_case_suite()["cases"][0], "contract": "../escape.json"}, "escapes"),
            ({**single_case_suite()["cases"][0], "evaluation_time": "not-a-date"}, "RFC 3339"),
            (
                {**single_case_suite()["cases"][0], "evaluation_time": "2026-99-23T12:00:00Z"},
                "RFC 3339",
            ),
            ({**single_case_suite()["cases"][0], "operation": "unknown"}, "unsupported"),
            ({**single_case_suite()["cases"][0], "consumed_nonces": ["same", "same"]}, "unique"),
            (
                {
                    **single_case_suite()["cases"][0],
                    "consumed_nonces": [
                        f"nonce-{index}" for index in range(MAX_COLLECTION_ITEMS + 1)
                    ],
                },
                "at most",
            ),
        ]
        for case, expected in cases:
            with self.subTest(expected=expected):
                outcome, details = _outcome_for(case, EXAMPLES)
                self.assertEqual(outcome, "malformed")
                self.assertIn(expected, details["error"])

    def test_outcome_rejects_non_object_contract_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "contract.json").write_text("[]", encoding="utf-8")
            (directory / "request.json").write_text(
                (EXAMPLES / "request.allowed.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            case = {
                "contract": "contract.json",
                "request": "request.json",
                "evaluation_time": "2026-07-23T12:00:00Z",
            }
            outcome, details = _outcome_for(case, directory)
            self.assertEqual(outcome, "malformed")
            self.assertIn("contract fixture must be a JSON object", details["error"])

    def test_suite_schema_and_receipt_inputs_are_strict(self) -> None:
        base = single_case_suite()
        invalid: list[tuple[str, object, str, str | None]] = []

        invalid.append(("object", [], "JSON object", None))
        suite = deepcopy(base)
        suite["suite_version"] = "0.1"
        invalid.append(("version", suite, "suite_version", None))
        suite = deepcopy(base)
        suite["name"] = ""
        invalid.append(("name", suite, "bounded non-empty", None))
        suite = deepcopy(base)
        suite["cases"] = []
        invalid.append(("cases", suite, "non-empty array", None))
        suite = deepcopy(base)
        suite["cases"] = [deepcopy(base["cases"][0])] * (MAX_CONFORMANCE_CASES + 1)
        invalid.append(("case cap", suite, "at most", None))
        suite = deepcopy(base)
        suite["cases"] = ["not-an-object"]
        invalid.append(("case object", suite, "must be an object", None))
        suite = deepcopy(base)
        suite["cases"][0]["unknown"] = True
        invalid.append(("unknown field", suite, "unknown fields", None))
        suite = deepcopy(base)
        del suite["cases"][0]["request"]
        invalid.append(("missing field", suite, "missing required fields", None))
        suite = deepcopy(base)
        suite["cases"][0]["id"] = ""
        invalid.append(("case id", suite, "non-empty string", None))
        suite = deepcopy(base)
        suite["cases"] = [deepcopy(base["cases"][0]), deepcopy(base["cases"][0])]
        invalid.append(("duplicate id", suite, "duplicate case id", None))
        suite = deepcopy(base)
        suite["cases"][0]["expected_outcome"] = "maybe"
        invalid.append(("expected", suite, "must be allow, deny, or malformed", None))
        suite = deepcopy(base)
        suite["cases"][0]["expected_violations_contain"] = "not-an-array"
        invalid.append(("fragments", suite, "must be a string array", None))
        suite = deepcopy(base)
        suite["cases"][0]["expected_violations_contain"] = ["x"] * (MAX_EXPECTED_FRAGMENTS + 1)
        invalid.append(("fragment cap", suite, "must contain at most", None))
        suite = deepcopy(base)
        suite["cases"][0]["expected_violations_contain"] = ["x", "x"]
        invalid.append(("duplicate fragment", suite, "must not contain duplicates", None))
        invalid.append(("boundary blank", base, "enforcement_boundary", ""))
        invalid.append(
            (
                "boundary cap",
                base,
                "enforcement_boundary",
                "x" * (MAX_ENFORCEMENT_BOUNDARY_CHARS + 1),
            )
        )

        for label, suite, error, boundary in invalid:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw_directory:
                path = stage_suite(Path(raw_directory), suite)
                kwargs = {} if boundary is None else {"enforcement_boundary": boundary}
                with self.assertRaisesRegex(ValueError, error):
                    run_conformance(path, **kwargs)


class CliBoundaryTests(unittest.TestCase):
    def test_success_paths_emit_machine_readable_results(self) -> None:
        commands = [
            ("validate", str(EXAMPLES / "contract.valid.json")),
            ("digest", str(EXAMPLES / "contract.valid.json")),
            (
                "verify-completion",
                str(EXAMPLES / "contract.valid.json"),
                str(EXAMPLES / "completion.valid.json"),
                "--evaluation-time",
                "2026-07-23T12:00:00Z",
            ),
            ("to-event", str(EXAMPLES / "contract.valid.json"), "--created-at", "0"),
        ]
        for command in commands:
            with self.subTest(command=command[0]):
                code, stdout, stderr = invoke(*command)
                self.assertEqual(code, 0)
                self.assertTrue(stdout.strip())
                self.assertEqual(stderr, "")

    def test_conformance_writes_a_successful_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            suite_path = stage_suite(directory, single_case_suite())
            receipt_path = directory / "receipt.json"
            code, stdout, stderr = invoke(
                "conformance",
                str(suite_path),
                "--receipt",
                str(receipt_path),
            )
            self.assertEqual(code, 0)
            self.assertIn('"failed": 0', stdout)
            self.assertEqual(stderr, "")
            self.assertEqual(
                json.loads(receipt_path.read_text(encoding="utf-8"))["summary"]["passed"], 1
            )

    def test_cli_reports_read_write_and_contract_shape_errors(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            non_object = directory / "contract.json"
            non_object.write_text("[]", encoding="utf-8")
            code, _, stderr = invoke("validate", str(non_object))
            self.assertEqual(code, 2)
            self.assertIn("contract must be a JSON object", stderr)

            code, _, stderr = invoke("validate", str(directory / "missing.json"))
            self.assertEqual(code, 2)
            self.assertIn("could not read", stderr)

            suite_path = stage_suite(directory, single_case_suite())
            code, _, stderr = invoke(
                "conformance",
                str(suite_path),
                "--receipt",
                str(directory),
            )
            self.assertEqual(code, 2)
            self.assertIn("could not write conformance receipt", stderr)

    def test_invalid_calendar_date_reaches_argparse_error_path(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            invoke(
                "authorize",
                str(EXAMPLES / "contract.valid.json"),
                str(EXAMPLES / "request.allowed.json"),
                "--evaluation-time",
                "2026-99-23T12:00:00Z",
            )
        self.assertEqual(raised.exception.code, 2)

    def test_module_entrypoint_delegates_to_cli(self) -> None:
        stdout = io.StringIO()
        with (
            patch.object(sys, "argv", ["permitmesh", "--version"]),
            redirect_stdout(stdout),
            self.assertRaises(SystemExit) as raised,
        ):
            runpy.run_module("permitmesh.__main__", run_name="__main__")
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(stdout.getvalue().strip(), "permitmesh 0.2.0")


if __name__ == "__main__":
    unittest.main()
