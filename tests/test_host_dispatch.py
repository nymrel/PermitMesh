from __future__ import annotations

import json
import runpy
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from threading import Event
from typing import Any

from permitmesh import operation_digest

EXAMPLE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "examples/host_dispatch.py"))
Dispatcher = EXAMPLE["TestDispatcher"]
fixture_inputs = EXAMPLE["fixture_inputs"]


class HostDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract, self.context, self.arguments, self.nonce = fixture_inputs()
        self.entered: list[dict[str, Any]] = []
        self.now = datetime(2030, 1, 1, 12, tzinfo=UTC)
        self.dispatcher = self.make_dispatcher(self.entered.append)

    def make_dispatcher(self, handler: Any, clock: Any = None) -> Any:
        return Dispatcher(
            contract_json=json.dumps(self.contract),
            context_json=json.dumps(self.context),
            tool_name="fixture.check",
            handler=handler,
            clock=clock or (lambda: self.now),
        )

    def test_allow_enters_once_with_exact_bound_arguments_then_duplicate_denies(self) -> None:
        first = self.dispatcher.dispatch(self.arguments, self.nonce)
        duplicate = self.dispatcher.dispatch(self.arguments, self.nonce)
        self.assertEqual(first.state, "RETURNED")
        self.assertEqual(self.entered, [{"target": "README.md"}])
        self.assertEqual(duplicate.state, "DENIED")
        self.assertIn("NONCE_CONSUMED", duplicate.reason_codes)

    def test_changed_arguments_deny_without_entering_or_burning_valid_nonce(self) -> None:
        denied = self.dispatcher.dispatch('{"target":".env"}', self.nonce)
        self.assertIn("OPERATION_DIGEST_MISMATCH", denied.reason_codes)
        self.assertEqual(self.entered, [])
        self.assertEqual(self.dispatcher.dispatch(self.arguments, self.nonce).state, "RETURNED")

    def test_current_host_context_not_original_mutable_input_drives_authorization(self) -> None:
        self.context["approvals"] = []
        # Constructor detached the original host dictionaries.
        self.assertEqual(self.dispatcher.dispatch(self.arguments, self.nonce).state, "RETURNED")
        current = self.make_dispatcher(self.entered.append)
        self.assertIn(
            "APPROVAL_REQUIRED", current.dispatch(self.arguments, self.nonce).reason_codes
        )
        self.assertEqual(len(self.entered), 1)

    def test_updated_claim_and_fence_are_checked_before_handler_entry(self) -> None:
        self.context.update(claim_id="new-claim", fencing_generation=2)
        self.dispatcher.replace_context(json.dumps(self.context))
        result = self.dispatcher.dispatch(self.arguments, self.nonce)
        self.assertEqual(result.state, "DENIED")
        self.assertIn("CLAIM_MISMATCH", result.reason_codes)
        self.assertIn("FENCING_GENERATION_STALE", result.reason_codes)
        self.assertEqual(self.entered, [])

    def test_clock_expiry_and_caller_shaped_authority_never_enter(self) -> None:
        self.now = datetime(2030, 1, 2, tzinfo=UTC)
        self.assertIn("EXPIRED", self.dispatcher.dispatch(self.arguments, self.nonce).reason_codes)
        self.assertEqual(self.entered, [])
        self.now = datetime(2030, 1, 1, 12, tzinfo=UTC)
        for key in ("subject_id", "approvals", "operation", "action", "at"):
            result = self.dispatcher.dispatch(
                json.dumps({"target": "README.md", key: "fake"}), self.nonce
            )
            self.assertEqual(result.state, "DENIED")
        self.assertEqual(self.entered, [])

    def test_ambiguous_effect_is_unknown_reserved_and_private_details_omitted(self) -> None:
        def partial_effect(arguments: dict[str, Any]) -> None:
            self.entered.append(arguments)
            raise RuntimeError("PRIVATE-CALLBACK-DETAILS")

        host = self.make_dispatcher(partial_effect)
        unknown = host.dispatch(self.arguments, self.nonce)
        self.assertEqual(unknown.state, "UNKNOWN")
        self.assertEqual(unknown.reason_codes, ("HOST_HANDLER_OUTCOME_UNKNOWN",))
        self.assertNotIn("PRIVATE-CALLBACK-DETAILS", repr(unknown))
        self.assertIn("NONCE_CONSUMED", host.dispatch(self.arguments, self.nonce).reason_codes)
        self.assertEqual(len(self.entered), 1)

    def test_parallel_duplicate_attempts_enter_only_one_callback(self) -> None:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(lambda _: self.dispatcher.dispatch(self.arguments, self.nonce), range(16))
            )
        self.assertEqual(sum(result.state == "RETURNED" for result in results), 1)
        self.assertEqual(len(self.entered), 1)
        self.assertTrue(all(result.state in {"RETURNED", "DENIED"} for result in results))

    def test_direct_reentry_denies_without_deadlock_or_second_handler(self) -> None:
        nested: list[Any] = []

        def callback(arguments: dict[str, Any]) -> None:
            self.entered.append(arguments)
            nested.append(host.dispatch(self.arguments, self.nonce))

        host = self.make_dispatcher(callback)
        self.assertEqual(host.dispatch(self.arguments, self.nonce).state, "RETURNED")
        self.assertEqual(nested[0].reason_codes, ("HOST_REENTRY",))
        self.assertEqual(len(self.entered), 1)

    def test_context_update_waits_for_handler_and_next_admission_sees_it(self) -> None:
        entered = Event()
        release = Event()
        attempted = Event()
        updated = Event()

        def callback(arguments: dict[str, Any]) -> None:
            self.entered.append(arguments)
            entered.set()
            self.assertTrue(release.wait(5))

        host = self.make_dispatcher(callback)

        def update() -> None:
            attempted.set()
            host.replace_context(json.dumps({**self.context, "claim_id": "new-claim"}))
            updated.set()

        with ThreadPoolExecutor(max_workers=2) as pool:
            call = pool.submit(host.dispatch, self.arguments, self.nonce)
            self.assertTrue(entered.wait(5))
            change = pool.submit(update)
            self.assertTrue(attempted.wait(5))
            self.assertFalse(updated.is_set())
            release.set()
            self.assertEqual(call.result(timeout=5).state, "RETURNED")
            change.result(timeout=5)
        self.assertTrue(updated.is_set())
        self.assertIn("CLAIM_MISMATCH", host.dispatch(self.arguments, self.nonce).reason_codes)

    def test_bad_input_shapes_are_bounded_and_do_not_reserve_nonce(self) -> None:
        invalid = [
            '{"target":"README.md","target":".env"}',
            '{"x":NaN}',
            '{"x":Infinity}',
            "[]",
            "null",
            "{",
            "x" * 16_385,
            '{"x":' + "[" * 33 + "0" + "]" * 33 + "}",
            json.dumps({"x": [0] * 257}),
            json.dumps({str(n): n for n in range(257)}),
            '{"target":' + "9" * 1_100 + "}",
            '{"target":"\\ud800"}',
        ]
        for arguments in invalid:
            with self.subTest(arguments=arguments[:40]):
                result = self.dispatcher.dispatch(arguments, self.nonce)
                self.assertEqual(result.reason_codes, ("HOST_INPUT_INVALID",))
        self.assertEqual(self.entered, [])
        self.assertEqual(self.dispatcher.dispatch(self.arguments, self.nonce).state, "RETURNED")

    def test_host_clock_failure_stays_denied_without_raw_error(self) -> None:
        def failed_clock() -> datetime:
            raise RuntimeError("PRIVATE-CLOCK-DETAILS")

        result = self.make_dispatcher(self.entered.append, failed_clock).dispatch(
            self.arguments, self.nonce
        )
        self.assertEqual(result.state, "DENIED")
        self.assertEqual(result.reason_codes, ("HOST_EVALUATION_UNAVAILABLE",))
        self.assertNotIn("PRIVATE-CLOCK-DETAILS", repr(result))
        self.assertEqual(self.entered, [])

    def test_no_handler_outputs_are_in_result(self) -> None:
        host = self.make_dispatcher(lambda _: "PRIVATE-HANDLER-RETURN")
        result = host.dispatch(self.arguments, self.nonce)
        self.assertEqual(result.state, "RETURNED")
        self.assertNotIn("PRIVATE-HANDLER-RETURN", repr(result))

    def test_absent_or_naive_host_time_denies_without_system_clock_fallback(self) -> None:
        current: list[Any] = [None]
        host = self.make_dispatcher(self.entered.append, lambda: current[0])
        for invalid in (None, datetime(2030, 1, 1, 12), "2030-01-01T12:00:00Z"):
            current[0] = invalid
            result = host.dispatch(self.arguments, self.nonce)
            self.assertEqual(result.state, "DENIED")
            self.assertEqual(result.reason_codes, ("HOST_EVALUATION_UNAVAILABLE",))
        self.assertEqual(self.entered, [])
        current[0] = self.now
        self.assertEqual(host.dispatch(self.arguments, self.nonce).state, "RETURNED")
        self.assertEqual(len(self.entered), 1)

    def test_decimal_arguments_preserve_precision_in_binding_and_callback(self) -> None:
        expected = {"target": "README.md", "ratio": Decimal("0.100000000000000001")}
        self.contract["operation_constraints"][0]["operation_digest"] = operation_digest(
            "test", {"tool": "fixture.check", "arguments": expected}
        )
        host = self.make_dispatcher(self.entered.append)
        result = host.dispatch('{"target":"README.md","ratio":0.100000000000000001}', self.nonce)
        self.assertEqual(result.state, "RETURNED")
        self.assertEqual(self.entered, [expected])
        self.assertIsInstance(self.entered[0]["ratio"], Decimal)

    def test_dispatcher_owned_context_fields_rejected(self) -> None:
        for field in ("action", "operation", "operation_nonce", "at"):
            with self.assertRaises(ValueError):
                self.dispatcher.replace_context(json.dumps({**self.context, field: "caller"}))

    def test_clock_reentry_cannot_replace_context_between_evaluation_and_entry(self) -> None:
        def changing_clock() -> datetime:
            host.replace_context(json.dumps({**self.context, "claim_id": "new-claim"}))
            return self.now

        host = self.make_dispatcher(self.entered.append, changing_clock)
        result = host.dispatch(self.arguments, self.nonce)
        self.assertEqual(result.state, "DENIED")
        self.assertEqual(result.reason_codes, ("HOST_EVALUATION_UNAVAILABLE",))
        self.assertEqual(self.entered, [])
