from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker

from permitmesh.buzz import authorize_buzz, validate_buzz_context
from permitmesh.cli import main


ROOT = Path(__file__).resolve().parents[1]
MUTATION_VALUES = [None, True, False, 0, -1, 1.5, "", "x", [], {}]


def load_example(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


class BuzzContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_example("contract.valid.json")
        self.request = load_example("request.allowed.json")
        self.context = load_example("buzz-context.valid.json")
        self.now = datetime(2026, 7, 23, 12, tzinfo=timezone.utc)

    def test_valid_context_allows_in_scope_request(self) -> None:
        decision = authorize_buzz(
            self.contract,
            self.request,
            self.context,
            now=self.now,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.violations, ())
        self.assertIn("buzz_context", decision.checks)

    def test_context_is_strict_and_fail_closed(self) -> None:
        context = deepcopy(self.context)
        context["trusted"] = True
        decision = authorize_buzz(
            self.contract,
            self.request,
            context,
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertIn(
            "buzz context contains unknown field: trusted",
            decision.violations,
        )

    def test_unverified_nip_oa_is_denied(self) -> None:
        self.context["nip_oa_verified"] = False
        decision = authorize_buzz(
            self.contract,
            self.request,
            self.context,
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(
            any("nip_oa_verified must be true" in item for item in decision.violations)
        )

    def test_unchecked_protection_is_denied(self) -> None:
        self.context["protection_checked"] = False
        decision = authorize_buzz(
            self.contract,
            self.request,
            self.context,
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(
            any(
                "protection_checked must be true" in item
                for item in decision.violations
            )
        )

    def test_owner_agent_and_work_bindings_are_enforced(self) -> None:
        mutations = {
            "contract_digest": "2" * 64,
            "owner_pubkey": "0" * 64,
            "agent_pubkey": "1" * 64,
            "repository": "different",
            "ref": "main",
            "channel": "different/channel",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                context = deepcopy(self.context)
                context[field] = value
                decision = authorize_buzz(
                    self.contract,
                    self.request,
                    context,
                    now=self.now,
                )
                self.assertFalse(decision.allowed)
                self.assertTrue(
                    any(field in item for item in decision.violations),
                    decision.violations,
                )

    def test_malformed_identifiers_and_community_are_denied(self) -> None:
        for field, value in (
            ("owner_pubkey", "ABC"),
            ("owner_attestation_event_id", "a" * 63),
            ("repository_announcement_event_id", "g" * 64),
            ("community", "wss://user:secret@relay.example.com/path"),
            ("verified_at", "2026-07-23 12:00:00Z"),
        ):
            with self.subTest(field=field):
                context = deepcopy(self.context)
                context[field] = value
                self.assertNotEqual(validate_buzz_context(context), ())

    def test_stale_or_future_verification_is_denied(self) -> None:
        for verified_at, fragment in (
            ("2026-07-23T11:54:59Z", "older than five minutes"),
            ("2026-07-23T12:00:01Z", "must not be in the future"),
        ):
            with self.subTest(verified_at=verified_at):
                context = deepcopy(self.context)
                context["verified_at"] = verified_at
                decision = authorize_buzz(
                    self.contract,
                    self.request,
                    context,
                    now=self.now,
                )
                self.assertFalse(decision.allowed)
                self.assertTrue(
                    any(fragment in item for item in decision.violations),
                    decision.violations,
                )

    def test_schema_and_runtime_accept_the_same_valid_fixture(self) -> None:
        validator = self.context_validator()
        self.assertTrue(validator.is_valid(self.context))
        self.assertEqual(validate_buzz_context(self.context), ())

    def test_required_field_deletions_never_false_allow(self) -> None:
        validator = self.context_validator()
        for field in self.context:
            with self.subTest(field=field):
                context = deepcopy(self.context)
                del context[field]
                self.assertFalse(validator.is_valid(context))
                self.assertNotEqual(validate_buzz_context(context), ())

    def test_schema_invalid_types_never_false_allow(self) -> None:
        validator = self.context_validator()
        for field in self.context:
            for value in MUTATION_VALUES:
                with self.subTest(field=field, value=repr(value)):
                    context = deepcopy(self.context)
                    context[field] = value
                    if not validator.is_valid(context):
                        self.assertNotEqual(validate_buzz_context(context), ())

    @staticmethod
    def context_validator() -> Draft202012Validator:
        schema = json.loads(
            (ROOT / "schema" / "permitmesh-buzz-context.schema.json").read_text(
                encoding="utf-8"
            )
        )
        return Draft202012Validator(schema, format_checker=FormatChecker())

    def test_cli_authorize_buzz(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "authorize-buzz",
                    str(ROOT / "examples" / "contract.valid.json"),
                    str(ROOT / "examples" / "request.allowed.json"),
                    str(ROOT / "examples" / "buzz-context.valid.json"),
                    "--evaluation-time",
                    "2026-07-23T12:00:00Z",
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn('"allowed": true', stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
