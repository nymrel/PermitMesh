from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker

from permitmesh.buzz import (
    authorize_buzz,
    compute_buzz_context_mac,
    validate_buzz_context,
)
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
        self.context_key = b"permitmesh-public-conformance-key-not-secret"
        self.community_uri = "wss://relay.example.com/permitmesh"
        self.repository_event_id = "b" * 64
        self.now = datetime(2026, 7, 23, 12, tzinfo=timezone.utc)

    def test_valid_context_allows_in_scope_request(self) -> None:
        decision = authorize_buzz(
            self.contract,
            self.request,
            self.context,
            context_auth_key=self.context_key,
            expected_community_uri=self.community_uri,
            expected_repository_announcement_event_id=self.repository_event_id,
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
            context_auth_key=self.context_key,
            expected_community_uri=self.community_uri,
            expected_repository_announcement_event_id=self.repository_event_id,
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
            context_auth_key=self.context_key,
            expected_community_uri=self.community_uri,
            expected_repository_announcement_event_id=self.repository_event_id,
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
            context_auth_key=self.context_key,
            expected_community_uri=self.community_uri,
            expected_repository_announcement_event_id=self.repository_event_id,
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
                    context_auth_key=self.context_key,
                    expected_community_uri=self.community_uri,
                    expected_repository_announcement_event_id=(
                        self.repository_event_id
                    ),
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
            ("community_uri", "wss://user:secret@relay.example.com/path"),
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
                    context_auth_key=self.context_key,
                    expected_community_uri=self.community_uri,
                    expected_repository_announcement_event_id=(
                        self.repository_event_id
                    ),
                    now=self.now,
                )
                self.assertFalse(decision.allowed)
                self.assertTrue(
                    any(fragment in item for item in decision.violations),
                    decision.violations,
                )

    def test_naive_trusted_time_explicitly_fails_closed(self) -> None:
        decision = authorize_buzz(
            self.contract,
            self.request,
            self.context,
            context_auth_key=self.context_key,
            expected_community_uri=self.community_uri,
            expected_repository_announcement_event_id=self.repository_event_id,
            now=datetime(2026, 7, 23, 12),
        )
        self.assertFalse(decision.allowed)
        self.assertIn(
            "buzz freshness requires a timezone-aware trusted evaluator time",
            decision.violations,
        )

    def test_repository_ref_and_channel_aliases_fail_closed(self) -> None:
        aliases = {
            "repository": "PermitMesh",
            "ref": "feature//agent-contract",
            "channel": "permitmesh\\feature-agent-contract",
        }
        for field, alias in aliases.items():
            with self.subTest(field=field):
                request = deepcopy(self.request)
                context = deepcopy(self.context)
                request[field] = alias
                context[field] = alias
                context["context_mac"] = compute_buzz_context_mac(
                    context, self.context_key
                )
                decision = authorize_buzz(
                    self.contract,
                    request,
                    context,
                    context_auth_key=self.context_key,
                    expected_community_uri=self.community_uri,
                    expected_repository_announcement_event_id=(
                        self.repository_event_id
                    ),
                    now=self.now,
                )
                self.assertFalse(decision.allowed)

    def test_buzz_context_cannot_bypass_core_deny_rules(self) -> None:
        request = deepcopy(self.request)
        request["path"] = ".env"
        decision = authorize_buzz(
            self.contract,
            request,
            self.context,
            context_auth_key=self.context_key,
            expected_community_uri=self.community_uri,
            expected_repository_announcement_event_id=self.repository_event_id,
            now=self.now,
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(
            any("matches a deny rule" in item for item in decision.violations)
        )

    def test_buzz_composition_preserves_exact_operation_binding(self) -> None:
        request = load_example("conformance/request.deploy-bound.json")
        allowed = authorize_buzz(
            self.contract,
            request,
            self.context,
            context_auth_key=self.context_key,
            expected_community_uri=self.community_uri,
            expected_repository_announcement_event_id=self.repository_event_id,
            now=self.now,
            consumed_nonces=frozenset(),
        )
        self.assertTrue(allowed.allowed)

        request["operation"]["arguments"]["environment"] = "production"
        denied = authorize_buzz(
            self.contract,
            request,
            self.context,
            context_auth_key=self.context_key,
            expected_community_uri=self.community_uri,
            expected_repository_announcement_event_id=self.repository_event_id,
            now=self.now,
            consumed_nonces=frozenset(),
        )
        self.assertFalse(denied.allowed)
        self.assertTrue(
            any(
                "do not match an approved constraint" in item
                for item in denied.violations
            )
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

    def test_schema_and_runtime_uri_and_time_rules_are_aligned(self) -> None:
        validator = self.context_validator()
        valid_variants = (
            ("community_uri", "https://relay.example.com"),
            ("community_uri", "wss://relay.example.com/path/to/community"),
            ("verified_at", "2026-07-23T12:00:00.123+00:00"),
        )
        for field, value in valid_variants:
            with self.subTest(valid=(field, value)):
                context = deepcopy(self.context)
                context[field] = value
                self.assertTrue(validator.is_valid(context))
                self.assertEqual(validate_buzz_context(context), ())

        invalid_communities = (
            "wss://user:secret@relay.example.com/path",
            "wss://relay.example.com:443/path",
            "WSS://relay.example.com/path",
            "wss://relay.example.com/path?query=yes",
            "wss://relay.example.com/path#fragment",
        )
        for value in invalid_communities:
            with self.subTest(invalid=value):
                context = deepcopy(self.context)
                context["community_uri"] = value
                self.assertFalse(validator.is_valid(context))
                self.assertNotEqual(validate_buzz_context(context), ())

    def test_context_mac_and_configured_audience_are_enforced(self) -> None:
        cases = (
            (
                {"context_mac": "0" * 64},
                self.community_uri,
                self.repository_event_id,
                "context_mac authentication failed",
            ),
            (
                {},
                "wss://other.example.com/community",
                self.repository_event_id,
                "configured community",
            ),
            (
                {},
                self.community_uri,
                "c" * 64,
                "configured repository",
            ),
        )
        for changes, community_uri, repository_event_id, fragment in cases:
            with self.subTest(fragment=fragment):
                context = deepcopy(self.context)
                context.update(changes)
                decision = authorize_buzz(
                    self.contract,
                    self.request,
                    context,
                    context_auth_key=self.context_key,
                    expected_community_uri=community_uri,
                    expected_repository_announcement_event_id=(repository_event_id),
                    now=self.now,
                )
                self.assertFalse(decision.allowed)
                self.assertTrue(
                    any(fragment in item for item in decision.violations),
                    decision.violations,
                )

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
        with (
            patch.dict(
                "os.environ",
                {
                    "PERMITMESH_BUZZ_CONTEXT_KEY": (
                        "permitmesh-public-conformance-key-not-secret"
                    )
                },
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = main(
                [
                    "authorize-buzz",
                    str(ROOT / "examples" / "contract.valid.json"),
                    str(ROOT / "examples" / "request.allowed.json"),
                    str(ROOT / "examples" / "buzz-context.valid.json"),
                    "--context-key-env",
                    "PERMITMESH_BUZZ_CONTEXT_KEY",
                    "--expected-community-uri",
                    self.community_uri,
                    "--expected-repository-event-id",
                    self.repository_event_id,
                    "--evaluation-time",
                    "2026-07-23T12:00:00Z",
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn('"allowed": true', stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
