from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]


class AdoptionReceiptSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema = json.loads(
            (ROOT / "schema" / "permitmesh-adoption-receipt.schema.json").read_text(
                encoding="utf-8"
            )
        )
        cls.validator = Draft202012Validator(
            schema, format_checker=FormatChecker()
        )
        cls.example = json.loads(
            (ROOT / "examples" / "adoption-receipt.example.json").read_text(
                encoding="utf-8"
            )
        )

    def assertValid(self, receipt: dict[str, object]) -> None:
        errors = sorted(
            self.validator.iter_errors(receipt),
            key=lambda error: tuple(str(part) for part in error.path),
        )
        self.assertEqual([], [error.message for error in errors])

    def test_draft_template_is_schema_valid_but_nonqualifying(self) -> None:
        self.assertValid(self.example)
        self.assertEqual("draft", self.example["status"])
        self.assertFalse(self.example["eligibility"]["counts_toward_north_star"])

    def test_verified_external_receipt_can_count(self) -> None:
        receipt = copy.deepcopy(self.example)
        receipt["status"] = "verified"
        receipt["project"]["commit_sha"] = "a" * 40
        receipt["eligibility"] = {
            "counts_toward_north_star": True,
            "reason": "Externally confirmed allowed and denied decisions with public evidence.",
        }
        self.assertValid(receipt)

    def test_draft_receipt_cannot_count(self) -> None:
        receipt = copy.deepcopy(self.example)
        receipt["eligibility"]["counts_toward_north_star"] = True
        errors = list(self.validator.iter_errors(receipt))
        self.assertTrue(any(error.validator == "const" for error in errors))

    def test_false_allow_is_rejected(self) -> None:
        receipt = copy.deepcopy(self.example)
        receipt["decisions"]["known_false_allows"] = 1
        errors = list(self.validator.iter_errors(receipt))
        self.assertTrue(any(error.validator == "const" for error in errors))

    def test_internal_team_cannot_be_mislabeled_external(self) -> None:
        receipt = copy.deepcopy(self.example)
        receipt["external_team"]["independent_from_jalen_studio"] = False
        errors = list(self.validator.iter_errors(receipt))
        self.assertTrue(any(error.validator == "const" for error in errors))

    def test_receipt_requires_an_allowed_and_denied_decision(self) -> None:
        receipt = copy.deepcopy(self.example)
        receipt["decisions"]["denied_expected"] = 0
        errors = list(self.validator.iter_errors(receipt))
        self.assertTrue(any(error.validator == "minimum" for error in errors))


if __name__ == "__main__":
    unittest.main()
