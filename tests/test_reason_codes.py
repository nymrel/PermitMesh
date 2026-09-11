import json
import unittest
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from permitmesh.policy import (
    REASON_CODE_SET,
    authorize,
    decision_digest,
    verify_completion,
)


ROOT = Path(__file__).resolve().parents[1]
EVALUATION_TIME = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)


def load_example(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


class ReasonCodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_example("contract.valid.json")
        self.request = load_example("request.allowed.json")
        self.denied = load_example("request.denied.json")

    def test_allowed_request_has_empty_reason_codes(self) -> None:
        decision = authorize(self.contract, self.request, now=EVALUATION_TIME)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason_codes, ())
        self.assertEqual(decision.violations, ())
        self.assertTrue(set(decision.reason_codes) <= REASON_CODE_SET)

    def test_denied_request_covers_semantic_predicates(self) -> None:
        decision = authorize(self.contract, self.denied, now=EVALUATION_TIME)
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.reason_codes)
        self.assertTrue(set(decision.reason_codes) <= REASON_CODE_SET)
        for code in (
            "OPERATION_BINDING_REQUIRED",
            "NONCE_INVALID",
            "REF_OUT_OF_SCOPE",
            "PATH_DENIED",
            "CLAIM_MISMATCH",
            "FENCING_GENERATION_STALE",
            "APPROVAL_REQUIRED",
        ):
            self.assertIn(code, decision.reason_codes)
        self.assertEqual(len(decision.reason_codes), len(set(decision.reason_codes)))

    def test_wording_independent_replay_digest(self) -> None:
        denied = authorize(self.contract, self.denied, now=EVALUATION_TIME)
        mutated = deepcopy(denied)
        object.__setattr__(
            mutated,
            "violations",
            tuple(f"diagnostic rewrite {index}" for index, _ in enumerate(denied.violations)),
        )
        self.assertEqual(decision_digest(denied), decision_digest(mutated))
        self.assertNotEqual(denied.violations, mutated.violations)

    def test_semantic_predicate_changes_digest(self) -> None:
        allowed = authorize(self.contract, self.request, now=EVALUATION_TIME)
        expired = authorize(
            self.contract,
            self.request,
            now=datetime(2099, 1, 1, tzinfo=UTC),
        )
        self.assertTrue(allowed.allowed)
        self.assertFalse(expired.allowed)
        self.assertIn("EXPIRED", expired.reason_codes)
        self.assertNotEqual(decision_digest(allowed), decision_digest(expired))

    def test_capability_and_scope_codes(self) -> None:
        request = deepcopy(self.request)
        request["action"] = "publish"
        request["repository"] = "other/repo"
        decision = authorize(self.contract, request, now=EVALUATION_TIME)
        self.assertFalse(decision.allowed)
        self.assertIn("CAPABILITY_NOT_GRANTED", decision.reason_codes)
        self.assertIn("REPOSITORY_OUT_OF_SCOPE", decision.reason_codes)

    def test_budget_codes(self) -> None:
        request = deepcopy(self.request)
        request["files_changed"] = 10_000
        request["commands_used"] = 10_000
        request["cost_usd"] = 10_000
        decision = authorize(self.contract, request, now=EVALUATION_TIME)
        self.assertFalse(decision.allowed)
        self.assertIn("LIMIT_FILES_EXCEEDED", decision.reason_codes)
        self.assertIn("LIMIT_COMMANDS_EXCEEDED", decision.reason_codes)
        self.assertIn("LIMIT_COST_EXCEEDED", decision.reason_codes)

    def test_completion_evidence_code(self) -> None:
        report = {
            "subject_id": self.contract["subject"]["id"],
            "claim_id": self.contract["lifecycle"]["claim_id"],
            "fencing_generation": self.contract["lifecycle"]["fencing_generation"],
            "commands_passed": [],
            "artifacts_present": [],
        }
        decision = verify_completion(self.contract, report, now=EVALUATION_TIME)
        self.assertFalse(decision.allowed)
        self.assertIn("COMPLETION_EVIDENCE_MISSING", decision.reason_codes)
        self.assertTrue(any("missing required_commands" in item for item in decision.violations))

    def test_invalid_contract_uses_contract_invalid(self) -> None:
        decision = authorize({"not": "a contract"}, self.request, now=EVALUATION_TIME)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_codes, ("CONTRACT_INVALID",))
