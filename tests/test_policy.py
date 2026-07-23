from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from decimal import Decimal
import io
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator, FormatChecker

from permitmesh.conformance import load_json_file, run_conformance
from permitmesh.cli import main
from permitmesh.policy import (
    authorize,
    canonical_json,
    contract_digest,
    operation_digest,
    to_nostr_event_template,
    validate_contract,
    verify_completion,
)


ROOT = Path(__file__).resolve().parents[1]
MUTATION_VALUES = [
    None,
    True,
    False,
    0,
    -1,
    1.5,
    "",
    "x",
    [],
    {},
    [None],
    {"x": 1},
]


def load_example(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


def leaf_paths(
    value: object, path: tuple[object, ...] = ()
) -> list[tuple[object, ...]]:
    paths: list[tuple[object, ...]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            paths.extend(leaf_paths(item, path + (key,)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            paths.extend(leaf_paths(item, path + (index,)))
    else:
        paths.append(path)
    return paths


def all_child_paths(
    value: object, path: tuple[object, ...] = ()
) -> list[tuple[object, ...]]:
    paths: list[tuple[object, ...]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = path + (key,)
            paths.append(child)
            paths.extend(all_child_paths(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            child = path + (index,)
            paths.append(child)
            paths.extend(all_child_paths(item, child))
    return paths


def replace_path(document: object, path: tuple[object, ...], value: object) -> None:
    target = document
    for part in path[:-1]:
        target = target[part]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]


def delete_path(document: object, path: tuple[object, ...]) -> None:
    target = document
    for part in path[:-1]:
        target = target[part]  # type: ignore[index]
    del target[path[-1]]  # type: ignore[index]


class ContractValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_example("contract.valid.json")

    def test_valid_contract(self) -> None:
        self.assertEqual(validate_contract(self.contract), ())

    def test_digest_is_stable_and_ignores_signature(self) -> None:
        original = contract_digest(self.contract)
        signed = deepcopy(self.contract)
        signed["signature"] = {
            "algorithm": "example-only",
            "public_key": "abc",
            "value": "def",
        }
        self.assertEqual(original, contract_digest(signed))

    def test_rejects_traversal_in_contract_pattern(self) -> None:
        self.contract["scope"]["repositories"][0]["allow_paths"] = ["../other/**"]
        self.assertIn(
            "scope.repositories[0].allow_paths[0] must be a safe relative path pattern",
            validate_contract(self.contract),
        )

    def test_rejects_impossible_approval_threshold(self) -> None:
        self.contract["approval_gates"][0]["min_approvals"] = 2
        self.assertIn(
            "approval_gates[0].min_approvals exceeds unique approvers",
            validate_contract(self.contract),
        )

    def test_rejects_unknown_contract_field(self) -> None:
        self.contract["surprise"] = True
        self.assertIn(
            "contract contains unknown field: surprise",
            validate_contract(self.contract),
        )

    def test_rejects_non_finite_cost_limit(self) -> None:
        self.contract["limits"]["max_cost_usd"] = float("nan")
        self.assertIn(
            "limits.max_cost_usd must be a finite non-negative number",
            validate_contract(self.contract),
        )

    def test_malformed_capability_value_fails_closed(self) -> None:
        self.contract["capabilities"] = [{"unexpected": True}]
        self.assertIn(
            "capabilities must contain strings",
            validate_contract(self.contract),
        )

    def test_malformed_capability_container_fails_closed(self) -> None:
        self.contract["capabilities"] = None
        self.assertIn(
            "capabilities must be a non-empty array",
            validate_contract(self.contract),
        )

    def test_duplicate_gate_action_is_rejected(self) -> None:
        self.contract["approval_gates"][0]["actions"] = ["deploy", "deploy"]
        self.assertIn(
            "approval_gates[0].actions must not contain duplicates",
            validate_contract(self.contract),
        )

    def test_granted_high_risk_capability_requires_operation_constraint(self) -> None:
        self.contract["operation_constraints"] = [
            constraint
            for constraint in self.contract["operation_constraints"]
            if constraint["action"] != "deploy"
        ]
        self.assertIn(
            "operation_constraints must bind granted high-risk capability 'deploy'",
            validate_contract(self.contract),
        )

    def test_test_capability_is_treated_as_code_execution(self) -> None:
        self.contract["operation_constraints"] = [
            constraint
            for constraint in self.contract["operation_constraints"]
            if constraint["action"] != "test"
        ]
        self.assertIn(
            "operation_constraints must bind granted high-risk capability 'test'",
            validate_contract(self.contract),
        )

    def test_missing_channels_is_rejected(self) -> None:
        self.contract["scope"].pop("channels")
        self.assertIn(
            "scope.channels must be a string array",
            validate_contract(self.contract),
        )

    def test_missing_deny_paths_is_rejected(self) -> None:
        self.contract["scope"]["repositories"][0].pop("deny_paths")
        self.assertIn(
            "scope.repositories[0].deny_paths must be an array",
            validate_contract(self.contract),
        )

    def test_non_string_display_name_is_rejected(self) -> None:
        self.contract["issuer"]["display_name"] = 7
        self.assertIn(
            "issuer.display_name must be a string",
            validate_contract(self.contract),
        )

    def test_duplicate_path_patterns_are_rejected(self) -> None:
        repository = self.contract["scope"]["repositories"][0]
        repository["allow_paths"] = ["src/**", "src/**"]
        repository["deny_paths"] = [".env", ".env"]
        violations = validate_contract(self.contract)
        self.assertIn(
            "scope.repositories[0].allow_paths must not contain duplicates",
            violations,
        )
        self.assertIn(
            "scope.repositories[0].deny_paths must not contain duplicates",
            violations,
        )

    def test_contract_timestamps_require_strict_rfc3339(self) -> None:
        for timestamp in (
            "2026-07-23 00:00:00Z",
            "2026-07-23T00:00:00",
            "2026-07-23",
        ):
            with self.subTest(timestamp=timestamp):
                contract = deepcopy(self.contract)
                contract["validity"]["not_before"] = timestamp
                self.assertIn(
                    "validity.not_before must be an RFC 3339 timestamp",
                    validate_contract(contract),
                )

    def test_canonical_numbers_are_representation_stable(self) -> None:
        self.assertEqual(canonical_json(25), "25")
        self.assertEqual(canonical_json(25.0), "25")
        self.assertEqual(canonical_json(Decimal("25.000")), "25")
        self.assertEqual(canonical_json(Decimal("-0.000")), "0")
        self.assertEqual(
            canonical_json(Decimal("1.234567890123456789012345678901")),
            "1.234567890123456789012345678901",
        )
        self.assertEqual(canonical_json(Decimal("1e1000000")), "1e+1000000")

    def test_digest_is_stable_across_equivalent_number_spellings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            one = Path(directory) / "one.json"
            two = Path(directory) / "two.json"
            one.write_text(
                json.dumps(self.contract).replace(
                    '"max_cost_usd": 25', '"max_cost_usd": 25.0'
                ),
                encoding="utf-8",
            )
            two.write_text(json.dumps(self.contract), encoding="utf-8")
            self.assertEqual(
                contract_digest(load_json_file(one)),
                contract_digest(load_json_file(two)),
            )


class SchemaRuntimeParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_example("contract.valid.json")
        cls.request = load_example("request.allowed.json")
        cls.report = load_example("completion.valid.json")
        cls.now = datetime(2026, 7, 23, 12, tzinfo=timezone.utc)

    def validator(self, name: str) -> Draft202012Validator:
        schema = json.loads((ROOT / "schema" / name).read_text(encoding="utf-8"))
        return Draft202012Validator(schema, format_checker=FormatChecker())

    def test_contract_required_field_deletions_never_false_allow(self) -> None:
        validator = self.validator("permitmesh-contract.schema.json")
        object_paths: list[tuple[object, ...]] = []

        def collect(value: object, path: tuple[object, ...] = ()) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    object_paths.append(path + (key,))
                    collect(item, path + (key,))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    collect(item, path + (index,))

        collect(self.contract)
        for path in object_paths:
            with self.subTest(path=path):
                mutated = deepcopy(self.contract)
                delete_path(mutated, path)
                if not validator.is_valid(mutated):
                    self.assertNotEqual(validate_contract(mutated), ())

    def test_contract_type_mutations_never_false_allow(self) -> None:
        validator = self.validator("permitmesh-contract.schema.json")
        for path in all_child_paths(self.contract):
            for value in MUTATION_VALUES:
                with self.subTest(path=path, value=repr(value)):
                    mutated = deepcopy(self.contract)
                    replace_path(mutated, path, value)
                    if not validator.is_valid(mutated):
                        self.assertNotEqual(validate_contract(mutated), ())

    def test_request_type_mutations_never_false_allow(self) -> None:
        validator = self.validator("permitmesh-request.schema.json")
        for path in leaf_paths(self.request):
            for value in MUTATION_VALUES:
                with self.subTest(path=path, value=repr(value)):
                    mutated = deepcopy(self.request)
                    replace_path(mutated, path, value)
                    if not validator.is_valid(mutated):
                        self.assertFalse(
                            authorize(self.contract, mutated, now=self.now).allowed
                        )

    def test_completion_type_mutations_never_false_allow(self) -> None:
        validator = self.validator("permitmesh-completion-report.schema.json")
        for path in leaf_paths(self.report):
            for value in MUTATION_VALUES:
                with self.subTest(path=path, value=repr(value)):
                    mutated = deepcopy(self.report)
                    replace_path(mutated, path, value)
                    if not validator.is_valid(mutated):
                        self.assertFalse(
                            verify_completion(
                                self.contract,
                                mutated,
                                now=self.now,
                            ).allowed
                        )


class AuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_example("contract.valid.json")
        self.request = load_example("request.allowed.json")
        self.now = datetime(2026, 7, 23, 12, tzinfo=timezone.utc)

    def test_allows_in_scope_action(self) -> None:
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.violations, ())
        self.assertEqual(
            decision.checks,
            (
                "validity_window",
                "subject",
                "channel",
                "capability",
                "operation_binding",
                "repository_ref_path",
                "budgets",
                "claim_and_fence",
                "approval_gates",
            ),
        )

    def test_denial_explains_every_violation(self) -> None:
        denied = load_example("request.denied.json")
        decision = authorize(self.contract, denied, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertGreaterEqual(len(decision.violations), 7)
        self.assertTrue(any("approval" in item for item in decision.violations))
        self.assertTrue(any("deny rule" in item for item in decision.violations))
        self.assertTrue(
            any("fencing_generation" in item for item in decision.violations)
        )

    def test_expired_contract_fails_closed(self) -> None:
        future = datetime(2026, 8, 1, tzinfo=timezone.utc)
        decision = authorize(self.contract, self.request, now=future)
        self.assertFalse(decision.allowed)
        self.assertIn("contract has expired", decision.violations)

    def test_backdated_request_cannot_revive_expired_contract(self) -> None:
        self.request["at"] = "2026-07-23T00:00:00Z"
        future = datetime(2026, 8, 1, tzinfo=timezone.utc)
        decision = authorize(self.contract, self.request, now=future)
        self.assertFalse(decision.allowed)
        self.assertIn("contract has expired", decision.violations)

    def test_path_traversal_fails_closed(self) -> None:
        self.request["path"] = "../other-repo/secrets.txt"
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn("request.path must be a safe relative path", decision.violations)

    def test_request_is_bound_to_contract_subject(self) -> None:
        self.request["subject_id"] = "different-agent"
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "subject_id does not match the active contract",
            decision.violations,
        )

    def test_request_channel_must_be_in_scope(self) -> None:
        self.request["channel"] = "other/work"
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn("channel 'other/work' is outside scope", decision.violations)

    def test_single_segment_glob_does_not_match_descendants(self) -> None:
        self.contract["scope"]["repositories"][0]["allow_paths"] = ["src/*"]
        self.request["path"] = "src/permitmesh/policy.py"
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "path 'src/permitmesh/policy.py' is outside allowed paths",
            decision.violations,
        )

    def test_windows_drive_path_fails_closed(self) -> None:
        self.request["path"] = "C:\\secrets.txt"
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn("request.path must be a safe relative path", decision.violations)

    def test_deploy_requires_approval(self) -> None:
        self.request["action"] = "deploy"
        self.request["operation"] = {
            "tool": "release.publish",
            "arguments": {
                "artifact_sha256": "a" * 64,
                "environment": "staging",
            },
        }
        self.request["operation_nonce"] = "permitmesh-demo-deploy-001"
        decision = authorize(
            self.contract,
            self.request,
            now=self.now,
            consumed_nonces=frozenset(),
        )
        self.assertFalse(decision.allowed)
        self.request["approvals"] = [
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ]
        self.assertTrue(
            (
                decision := authorize(
                    self.contract,
                    self.request,
                    now=self.now,
                    consumed_nonces=frozenset(),
                )
            ).allowed
        )
        self.assertEqual(decision.contract_digest, contract_digest(self.contract))

    def test_high_risk_action_is_bound_to_exact_operation(self) -> None:
        self.request["action"] = "deploy"
        self.request["operation"] = {
            "tool": "release.publish",
            "arguments": {
                "artifact_sha256": "b" * 64,
                "environment": "production",
            },
        }
        self.request["operation_nonce"] = "permitmesh-demo-deploy-001"
        self.request["approvals"] = [
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ]
        decision = authorize(
            self.contract,
            self.request,
            now=self.now,
            consumed_nonces=frozenset(),
        )
        self.assertFalse(decision.allowed)
        self.assertIn(
            "request operation and nonce do not match an approved constraint",
            decision.violations,
        )

    def test_high_risk_action_requires_replay_state_and_unused_nonce(self) -> None:
        self.request["action"] = "deploy"
        self.request["operation"] = {
            "tool": "release.publish",
            "arguments": {
                "artifact_sha256": "a" * 64,
                "environment": "staging",
            },
        }
        self.request["operation_nonce"] = "permitmesh-demo-deploy-001"
        self.request["approvals"] = [
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ]
        without_state = authorize(self.contract, self.request, now=self.now)
        self.assertIn(
            "high-risk authorization requires an explicit consumed_nonces set",
            without_state.violations,
        )
        replay = authorize(
            self.contract,
            self.request,
            now=self.now,
            consumed_nonces={"permitmesh-demo-deploy-001"},
        )
        self.assertIn(
            "request.operation_nonce has already been consumed",
            replay.violations,
        )

    def test_malformed_operation_values_fail_closed_without_exception(self) -> None:
        self.request["action"] = "deploy"
        self.request["operation_nonce"] = "permitmesh-demo-deploy-001"
        self.request["approvals"] = [
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ]
        for arguments in (
            {"cost": float("nan")},
            {7: "non-string key"},
        ):
            with self.subTest(arguments=arguments):
                request = deepcopy(self.request)
                request["operation"] = {
                    "tool": "release.publish",
                    "arguments": arguments,
                }
                decision = authorize(
                    self.contract,
                    request,
                    now=self.now,
                    consumed_nonces=frozenset(),
                )
                self.assertFalse(decision.allowed)
                self.assertIn(
                    "request.operation must contain canonical JSON values",
                    decision.violations,
                )

    def test_noncanonical_contract_values_fail_closed_without_exception(self) -> None:
        self.contract["limits"]["max_cost_usd"] = float("nan")
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.violations,
            ("contract must contain canonical JSON values",),
        )

    def test_operation_digest_binds_action_tool_and_arguments(self) -> None:
        operation = {"tool": "shell", "arguments": {"argv": ["pytest"]}}
        base = operation_digest("shell", operation)
        self.assertNotEqual(base, operation_digest("deploy", operation))
        changed = {"tool": "shell", "arguments": {"argv": ["pytest", "-q"]}}
        self.assertNotEqual(base, operation_digest("shell", changed))

    def test_stale_fence_fails_closed(self) -> None:
        self.request["fencing_generation"] = 2
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "fencing_generation does not match the active contract",
            decision.violations,
        )

    def test_missing_request_fields_fail_closed(self) -> None:
        decision = authorize(self.contract, {"action": "edit"}, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn("missing required request field: repository", decision.violations)
        self.assertIn("request.path is required for edit", decision.violations)

    def test_read_requires_a_path(self) -> None:
        self.request["action"] = "read"
        self.request.pop("path")
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn("request.path is required for read", decision.violations)

    def test_malformed_approvals_fail_closed(self) -> None:
        self.request["approvals"] = (
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn("request.approvals must be a string array", decision.violations)

    def test_duplicate_approvals_fail_closed(self) -> None:
        approval = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        self.request["approvals"] = [approval, approval]
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "request.approvals must not contain duplicates",
            decision.violations,
        )

    def test_non_object_contract_fails_closed(self) -> None:
        decision = authorize([], self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.violations, ("contract must be a JSON object",))

    def test_non_finite_request_cost_fails_closed(self) -> None:
        self.request["cost_usd"] = float("inf")
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "request.cost_usd must be a finite non-negative number",
            decision.violations,
        )

    def test_malformed_action_types_fail_closed_without_exception(self) -> None:
        for value in ({}, [], 7, True, None):
            with self.subTest(value=value):
                request = deepcopy(self.request)
                request["action"] = value
                decision = authorize(self.contract, request, now=self.now)
                self.assertFalse(decision.allowed)
                self.assertIn(
                    "request.action must be a known capability string",
                    decision.violations,
                )

    def test_root_path_pattern_does_not_match_nested_basename(self) -> None:
        repository = self.contract["scope"]["repositories"][0]
        repository["allow_paths"] = ["README.md"]
        self.request["path"] = "docs/README.md"
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "path 'docs/README.md' is outside allowed paths",
            decision.violations,
        )

    def test_recursive_pattern_matches_root_and_nested_files(self) -> None:
        repository = self.contract["scope"]["repositories"][0]
        repository["allow_paths"] = ["**/README.md"]
        for path in ("README.md", "docs/README.md", "a/b/README.md"):
            with self.subTest(path=path):
                request = deepcopy(self.request)
                request["path"] = path
                self.assertTrue(authorize(self.contract, request, now=self.now).allowed)

    def test_single_segment_ref_glob_does_not_match_nested_ref(self) -> None:
        self.request["ref"] = "feature/team/topic"
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "ref 'feature/team/topic' is outside scope",
            decision.violations,
        )

    def test_recursive_ref_glob_matches_nested_ref(self) -> None:
        self.contract["scope"]["repositories"][0]["refs"] = ["feature/**"]
        self.request["ref"] = "feature/team/topic"
        self.assertTrue(authorize(self.contract, self.request, now=self.now).allowed)

    def test_deny_pattern_overrides_allow_pattern(self) -> None:
        repository = self.contract["scope"]["repositories"][0]
        repository["allow_paths"] = ["src/**"]
        repository["deny_paths"] = ["src/permitmesh/**"]
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "path 'src/permitmesh/policy.py' matches a deny rule",
            decision.violations,
        )

    def test_noncanonical_paths_fail_closed(self) -> None:
        for path in (
            "src//permitmesh/policy.py",
            "src/./permitmesh/policy.py",
            ".env.",
            ".env::$DATA",
            "CON/config",
            "SECRET~1/key.txt",
            "",
            None,
        ):
            with self.subTest(path=path):
                request = deepcopy(self.request)
                request["path"] = path
                decision = authorize(self.contract, request, now=self.now)
                self.assertFalse(decision.allowed)
                self.assertIn(
                    "request.path must be a safe relative path",
                    decision.violations,
                )

    def test_deny_paths_are_case_insensitive_for_portable_safety(self) -> None:
        repository = self.contract["scope"]["repositories"][0]
        repository["allow_paths"] = ["**"]
        for path in (".ENV", "SRC/secrets/key.txt"):
            with self.subTest(path=path):
                request = deepcopy(self.request)
                request["path"] = path
                decision = authorize(self.contract, request, now=self.now)
                self.assertFalse(decision.allowed)
                self.assertIn("matches a deny rule", " ".join(decision.violations))

    def test_present_optional_metadata_must_be_well_formed(self) -> None:
        for field, value, expected in (
            ("at", None, "request.at must be an RFC 3339 timestamp"),
            ("channel", None, "request.channel must be a non-empty string"),
        ):
            with self.subTest(field=field):
                request = deepcopy(self.request)
                request[field] = value
                decision = authorize(self.contract, request, now=self.now)
                self.assertFalse(decision.allowed)
                self.assertIn(expected, decision.violations)

    def test_decimal_cost_boundary_is_exact(self) -> None:
        at_limit = deepcopy(self.request)
        at_limit["cost_usd"] = Decimal("25.0000000000000000000")
        self.assertTrue(authorize(self.contract, at_limit, now=self.now).allowed)

        over_limit = deepcopy(self.request)
        over_limit["cost_usd"] = Decimal("25.0000000000000000001")
        decision = authorize(self.contract, over_limit, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertTrue(
            any("exceeds max_cost_usd" in item for item in decision.violations)
        )

    def test_naive_evaluator_time_fails_closed(self) -> None:
        decision = authorize(
            self.contract,
            self.request,
            now=datetime(2026, 7, 23, 12),
        )
        self.assertFalse(decision.allowed)
        self.assertIn("evaluator time must include a timezone", decision.violations)

    def test_request_value_mutations_never_raise(self) -> None:
        values = [None, True, 0, -1, "", [], {}, float("inf"), float("nan")]
        for field in self.request:
            for value in values:
                with self.subTest(field=field, value=repr(value)):
                    request = deepcopy(self.request)
                    request[field] = value
                    decision = authorize(self.contract, request, now=self.now)
                    self.assertIsInstance(decision.allowed, bool)


class NostrAdapterTests(unittest.TestCase):
    def test_event_is_explicitly_unsigned(self) -> None:
        contract = load_example("contract.valid.json")
        envelope = to_nostr_event_template(contract, created_at=1784800000)
        event = envelope["event"]
        self.assertEqual(event["kind"], 30078)
        self.assertEqual(event["created_at"], 1784800000)
        self.assertEqual(event["sig"], "")
        self.assertEqual(envelope["status"], "unsigned_template")
        digest = contract_digest(contract)
        self.assertIn(["x", digest], event["tags"])

    def test_event_adapter_rejects_non_nostr_principal(self) -> None:
        contract = load_example("contract.valid.json")
        contract["subject"]["id"] = "agent@example.com"
        with self.assertRaisesRegex(ValueError, "subject.id must be"):
            to_nostr_event_template(contract, created_at=1784800000)

    def test_zero_created_at_is_preserved(self) -> None:
        contract = load_example("contract.valid.json")
        envelope = to_nostr_event_template(contract, created_at=0)
        self.assertEqual(envelope["event"]["created_at"], 0)

    def test_invalid_created_at_is_rejected(self) -> None:
        contract = load_example("contract.valid.json")
        for created_at in (-1, True, 1.5):
            with self.subTest(created_at=created_at):
                with self.assertRaisesRegex(
                    ValueError, "created_at must be a non-negative integer"
                ):
                    to_nostr_event_template(contract, created_at=created_at)


class ConformanceTests(unittest.TestCase):
    def test_reference_suite_passes(self) -> None:
        receipt = run_conformance(ROOT / "examples" / "conformance-suite.json")
        self.assertEqual(receipt["summary"], {"total": 45, "passed": 45, "failed": 0})
        self.assertEqual(
            receipt["enforcement_boundary"],
            "policy-decision-only; no tool execution",
        )

    def test_nonfinite_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nonfinite.json"
            path.write_text('{"cost": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "non-standard JSON numeric constant"
            ):
                load_json_file(path)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"action":"edit","action":"deploy"}', encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "duplicate JSON object key: action"
            ):
                load_json_file(path)

    def test_json_decimals_keep_exact_precision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decimal.json"
            path.write_text('{"cost_usd":25.0000000000000000001}', encoding="utf-8")
            loaded = load_json_file(path)
            self.assertEqual(
                loaded["cost_usd"],
                Decimal("25.0000000000000000001"),
            )


class CompletionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_example("contract.valid.json")
        self.report = load_example("completion.valid.json")
        self.now = datetime(2026, 7, 23, 12, tzinfo=timezone.utc)

    def test_all_required_evidence_is_accepted(self) -> None:
        decision = verify_completion(self.contract, self.report, now=self.now)
        self.assertTrue(decision.allowed)

    def test_missing_required_evidence_is_denied(self) -> None:
        report = load_example("completion.missing.json")
        decision = verify_completion(self.contract, report, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertTrue(
            any("missing required_commands" in v for v in decision.violations)
        )
        self.assertTrue(
            any("missing required_artifacts" in v for v in decision.violations)
        )

    def test_completion_is_bound_to_subject_claim_and_fence(self) -> None:
        self.report["subject_id"] = "different-agent"
        self.report["claim_id"] = "stale-claim"
        self.report["fencing_generation"] = 2
        decision = verify_completion(self.contract, self.report, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "subject_id does not match the active contract", decision.violations
        )
        self.assertIn(
            "claim_id does not match the active contract", decision.violations
        )
        self.assertIn(
            "fencing_generation does not match the active contract",
            decision.violations,
        )

    def test_naive_evaluator_time_fails_closed(self) -> None:
        decision = verify_completion(
            self.contract,
            self.report,
            now=datetime(2026, 7, 23, 12),
        )
        self.assertFalse(decision.allowed)
        self.assertIn("evaluator time must include a timezone", decision.violations)


class CliTests(unittest.TestCase):
    def invoke(self, *argv: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_invalid_contract_cannot_be_digested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text('{"contract_version":"0.1"}', encoding="utf-8")
            code, stdout, stderr = self.invoke("digest", str(path))
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("missing required field", stderr)

    def test_duplicate_json_key_is_malformed_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"a":1,"a":2}', encoding="utf-8")
            code, stdout, stderr = self.invoke("validate", str(path))
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("duplicate JSON object key", stderr)

    def test_denied_request_uses_exit_code_three(self) -> None:
        code, stdout, stderr = self.invoke(
            "authorize",
            str(ROOT / "examples" / "contract.valid.json"),
            str(ROOT / "examples" / "request.denied.json"),
            "--evaluation-time",
            "2026-07-23T12:00:00Z",
        )
        self.assertEqual(code, 3)
        self.assertIn('"allowed": false', stdout)
        self.assertEqual(stderr, "")

    def test_allowed_request_uses_exit_code_zero(self) -> None:
        code, stdout, stderr = self.invoke(
            "authorize",
            str(ROOT / "examples" / "contract.valid.json"),
            str(ROOT / "examples" / "request.allowed.json"),
            "--evaluation-time",
            "2026-07-23T12:00:00Z",
        )
        self.assertEqual(code, 0)
        self.assertIn('"allowed": true', stdout)
        self.assertEqual(stderr, "")

    def test_invalid_event_timestamp_uses_exit_code_two(self) -> None:
        code, stdout, stderr = self.invoke(
            "to-event",
            str(ROOT / "examples" / "contract.valid.json"),
            "--created-at",
            "-1",
        )
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("created_at must be a non-negative integer", stderr)

    def test_failed_conformance_uses_exit_code_four(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            suite = json.loads(
                (ROOT / "examples" / "conformance-suite.json").read_text(
                    encoding="utf-8"
                )
            )
            suite["cases"] = [deepcopy(suite["cases"][0])]
            suite["cases"][0]["expected_outcome"] = "deny"
            suite_path = Path(directory) / "suite.json"
            suite_path.write_text(json.dumps(suite), encoding="utf-8")
            for fixture in ("contract.valid.json", "request.allowed.json"):
                source = ROOT / "examples" / fixture
                (Path(directory) / fixture).write_text(
                    source.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            code, stdout, stderr = self.invoke("conformance", str(suite_path))
            self.assertEqual(code, 4)
            self.assertIn('"failed": 1', stdout)
            self.assertEqual(stderr, "")

    def test_evaluation_time_rejects_non_rfc3339_separator(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            self.invoke(
                "authorize",
                str(ROOT / "examples" / "contract.valid.json"),
                str(ROOT / "examples" / "request.allowed.json"),
                "--evaluation-time",
                "2026-07-23 12:00:00Z",
            )
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
