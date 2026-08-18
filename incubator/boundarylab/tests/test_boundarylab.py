from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from boundarylab.adapters import CommandAdapter, DockerAdapter, LocalAdapter
from boundarylab.export import compare_receipts, render_junit, render_markdown
from boundarylab.io import StrictJSONError, digest_json, load_json, loads_strict, write_json
from boundarylab.model import (
    AUTH_SCHEMA,
    PROFILE_SCHEMA,
    AdapterConfig,
    Authorization,
    BoundaryLabError,
    Expectation,
    Profile,
)
from boundarylab.probes import (
    GUEST_PROGRAM,
    PROBES,
    evaluate_observations,
    expectation_matches,
    known_probe_ids,
)
from boundarylab.receipt import verify_receipt
from boundarylab.runner import run_conformance


def authorization_document(
    *,
    adapters: list[str] | None = None,
    targets: list[dict[str, object]] | None = None,
    adapter_config: dict[str, object] | None = None,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    expiry = expires_at or (datetime.now(UTC) + timedelta(days=1))
    return {
        "adapter_config": adapter_config or {"docker_image": "python:3.13-slim"},
        "allowed_adapters": adapters or ["local", "command", "docker", "vercel"],
        "authorization_id": "test-authorization",
        "destructive_tests": False,
        "environment": "test",
        "expires_at": expiry.isoformat().replace("+00:00", "Z"),
        "limits": {
            "max_cost_usd": "0",
            "max_duration_seconds": 30,
            "max_output_bytes": 262144,
            "max_parallel": 1,
        },
        "network_targets": targets or [],
        "owner": "Nymrel tests",
        "schema": AUTH_SCHEMA,
        "third_party_testing": False,
    }


def profile_document(
    *,
    probes: list[str] | None = None,
    expectations: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "description": "Test profile",
        "expectations": expectations or {},
        "probes": probes or ["runtime.platform"],
        "profile_id": "test-profile",
        "schema": PROFILE_SCHEMA,
    }


class StrictJSONTests(unittest.TestCase):
    def test_01_duplicate_keys_are_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict('{"a":1,"a":2}')

    def test_02_nonstandard_numbers_are_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict('{"a":NaN}')

    def test_03_canonical_digest_ignores_object_key_order(self) -> None:
        self.assertEqual(digest_json({"a": 1, "b": 2}), digest_json({"b": 2, "a": 1}))


class AuthorizationTests(unittest.TestCase):
    def test_04_unknown_authorization_field_is_rejected(self) -> None:
        document = authorization_document()
        document["surprise"] = True
        with self.assertRaises(BoundaryLabError):
            Authorization.from_json(document)

    def test_05_third_party_testing_is_rejected(self) -> None:
        document = authorization_document()
        document["third_party_testing"] = True
        with self.assertRaisesRegex(BoundaryLabError, "third-party"):
            Authorization.from_json(document)

    def test_06_destructive_testing_is_rejected(self) -> None:
        document = authorization_document()
        document["destructive_tests"] = True
        with self.assertRaisesRegex(BoundaryLabError, "destructive"):
            Authorization.from_json(document)

    def test_07_expired_authorization_is_rejected(self) -> None:
        authorization = Authorization.from_json(
            authorization_document(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        with self.assertRaisesRegex(BoundaryLabError, "expired"):
            authorization.validate_active()

    def test_08_duplicate_adapters_are_rejected(self) -> None:
        with self.assertRaises(BoundaryLabError):
            Authorization.from_json(authorization_document(adapters=["local", "local"]))

    def test_09_unknown_adapter_is_rejected(self) -> None:
        with self.assertRaisesRegex(BoundaryLabError, "unsupported adapters"):
            Authorization.from_json(authorization_document(adapters=["unknown"]))

    def test_10_network_wildcard_is_rejected(self) -> None:
        targets = [
            {"id": "target-one", "host": "*.example.com", "port": 443, "expected": "blocked", "public": True}
        ]
        with self.assertRaisesRegex(BoundaryLabError, "exact hostname"):
            Authorization.from_json(authorization_document(targets=targets))

    def test_11_network_scheme_is_rejected(self) -> None:
        targets = [
            {"id": "target-one", "host": "https://example.com", "port": 443, "expected": "blocked", "public": True}
        ]
        with self.assertRaisesRegex(BoundaryLabError, "exact hostname"):
            Authorization.from_json(authorization_document(targets=targets))

    def test_12_duplicate_target_ids_are_rejected(self) -> None:
        target = {"id": "target-one", "host": "127.0.0.1", "port": 443, "expected": "blocked", "public": False}
        with self.assertRaisesRegex(BoundaryLabError, "unique"):
            Authorization.from_json(authorization_document(targets=[target, target.copy()]))

    def test_13_empty_command_prefix_is_rejected(self) -> None:
        with self.assertRaises(BoundaryLabError):
            AdapterConfig.from_json({"command_prefix": []})

    def test_14_invalid_duration_limit_is_rejected(self) -> None:
        document = authorization_document()
        limits = document["limits"]
        assert isinstance(limits, dict)
        limits["max_duration_seconds"] = 0
        with self.assertRaises(BoundaryLabError):
            Authorization.from_json(document)


class ProfileTests(unittest.TestCase):
    def test_15_star_expands_to_every_known_probe(self) -> None:
        profile = Profile.from_json(profile_document(probes=["*"]), known_probe_ids())
        self.assertEqual(set(profile.probes), known_probe_ids())

    def test_16_unknown_probe_is_rejected(self) -> None:
        with self.assertRaisesRegex(BoundaryLabError, "unknown probes"):
            Profile.from_json(profile_document(probes=["unknown.probe"]), known_probe_ids())

    def test_17_duplicate_probes_are_rejected(self) -> None:
        with self.assertRaises(BoundaryLabError):
            Profile.from_json(
                profile_document(probes=["runtime.platform", "runtime.platform"]),
                known_probe_ids(),
            )

    def test_18_expectation_outside_profile_is_rejected(self) -> None:
        with self.assertRaises(BoundaryLabError):
            Profile.from_json(
                profile_document(expectations={"runtime.kernel": {"op": "observe"}}),
                known_probe_ids(),
            )

    def test_19_unknown_expectation_operator_is_rejected(self) -> None:
        with self.assertRaises(BoundaryLabError):
            Profile.from_json(
                profile_document(expectations={"runtime.platform": {"op": "regex", "value": ".*"}}),
                known_probe_ids(),
            )


class ExpectationTests(unittest.TestCase):
    def test_20_equals_operator(self) -> None:
        self.assertTrue(expectation_matches("linux", Expectation("equals", "linux")))

    def test_21_not_equals_operator(self) -> None:
        self.assertTrue(expectation_matches("linux", Expectation("not_equals", "windows")))

    def test_22_contains_operator(self) -> None:
        self.assertTrue(expectation_matches("linux-guest", Expectation("contains", "guest")))

    def test_23_not_contains_operator(self) -> None:
        self.assertTrue(expectation_matches("linux", Expectation("not_contains", "host")))

    def test_24_one_of_operator(self) -> None:
        self.assertTrue(expectation_matches("linux", Expectation("one_of", ["linux", "darwin"])))

    def test_25_ordered_operators(self) -> None:
        self.assertTrue(expectation_matches(2, Expectation("lte", 3)))
        self.assertTrue(expectation_matches(3, Expectation("gte", 2)))

    def test_26_missing_observation_is_error(self) -> None:
        results = evaluate_observations(
            ("runtime.platform",),
            {},
            {},
        )
        self.assertEqual(results[0].status, "error")
        self.assertEqual(results[0].reason_code, "observation-missing")


class ProbeAndAdapterTests(unittest.TestCase):
    def test_27_guest_program_never_reads_canary_value(self) -> None:
        self.assertNotIn("os.environ[\"BOUNDARYLAB_CANARY_SECRET\"]", GUEST_PROGRAM)
        self.assertNotIn("getenv(\"BOUNDARYLAB_CANARY_SECRET\")", GUEST_PROGRAM)

    def test_28_registry_contains_twenty_seven_unique_probes(self) -> None:
        self.assertEqual(len(PROBES), 27)
        self.assertEqual(len({probe.probe_id for probe in PROBES}), 27)

    def test_29_local_adapter_emits_bounded_observations(self) -> None:
        authorization = Authorization.from_json(authorization_document())
        outcome = LocalAdapter().run(authorization, "test-run", network_probes=False)
        self.assertEqual(outcome.status, "ok")
        self.assertIn("runtime.platform", outcome.observations)
        self.assertNotIn("BOUNDARYLAB_CANARY_SECRET", json.dumps(outcome.observations))

    def test_30_command_adapter_requires_prefix(self) -> None:
        authorization = Authorization.from_json(authorization_document(adapter_config={}))
        outcome = CommandAdapter().run(authorization, "test-run", network_probes=False)
        self.assertEqual(outcome.status, "error")
        self.assertEqual(outcome.reason_code, "command-prefix-missing")

    def test_31_command_adapter_executes_without_shell(self) -> None:
        authorization = Authorization.from_json(
            authorization_document(
                adapter_config={"command_prefix": [sys.executable, "-I", "-c"]}
            )
        )
        completed = subprocess.CompletedProcess([], 0, stdout=b"{}", stderr=b"")
        with patch("boundarylab.adapters.subprocess.run", return_value=completed) as run:
            CommandAdapter().run(authorization, "test-run", network_probes=False)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_32_docker_adapter_is_hardened_and_never_pulls(self) -> None:
        authorization = Authorization.from_json(authorization_document())
        completed = subprocess.CompletedProcess([], 0, stdout=b"{}", stderr=b"")
        with patch("boundarylab.adapters.subprocess.run", return_value=completed) as run:
            DockerAdapter().run(authorization, "test-run", network_probes=False)
        argv = run.call_args.args[0]
        self.assertIn("--network=none", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--pull=never", argv)


class RunnerAndReceiptTests(unittest.TestCase):
    def _run_local(
        self,
        directory: Path,
        *,
        targets: list[dict[str, object]] | None = None,
        allow_network_probes: bool = False,
        allow_public_network: bool = False,
    ) -> Path:
        authorization_path = directory / "authorization.json"
        profile_path = directory / "profile.json"
        write_json(authorization_path, authorization_document(targets=targets))
        write_json(profile_path, profile_document(probes=["*"]))
        _, receipt_path = run_conformance(
            authorization_path,
            profile_path,
            adapter_name="local",
            output_directory=directory / "runs",
            allow_network_probes=allow_network_probes,
            allow_public_network=allow_public_network,
        )
        return receipt_path

    def test_33_disabled_network_probe_is_untested(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt_path = self._run_local(Path(temporary))
            receipt = verify_receipt(receipt_path)
            results = receipt["results"]
            assert isinstance(results, list)
            network = next(
                item for item in results
                if isinstance(item, dict) and item.get("probe_id") == "network.exact_targets"
            )
            self.assertEqual(network["status"], "untested")

    def test_34_public_target_requires_separate_opt_in(self) -> None:
        target = {"id": "public-target", "host": "example.com", "port": 443, "expected": "blocked", "public": True}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_json(directory / "authorization.json", authorization_document(targets=[target]))
            write_json(directory / "profile.json", profile_document())
            with self.assertRaisesRegex(BoundaryLabError, "public targets"):
                run_conformance(
                    directory / "authorization.json",
                    directory / "profile.json",
                    adapter_name="local",
                    output_directory=directory / "runs",
                    allow_network_probes=True,
                )

    def test_35_public_opt_in_requires_network_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_json(directory / "authorization.json", authorization_document())
            write_json(directory / "profile.json", profile_document())
            with self.assertRaisesRegex(BoundaryLabError, "requires --allow-network-probes"):
                run_conformance(
                    directory / "authorization.json",
                    directory / "profile.json",
                    adapter_name="local",
                    output_directory=directory / "runs",
                    allow_public_network=True,
                )

    def test_36_generated_receipt_and_artifact_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt_path = self._run_local(Path(temporary))
            receipt = verify_receipt(receipt_path)
            self.assertEqual(receipt["schema"], "nymrel.boundarylab.receipt.v1")

    def test_37_receipt_content_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt_path = self._run_local(Path(temporary))
            receipt = load_json(receipt_path)
            assert isinstance(receipt, dict)
            receipt["started_at"] = "2000-01-01T00:00:00Z"
            write_json(receipt_path, receipt)
            with self.assertRaisesRegex(BoundaryLabError, "digest mismatch"):
                verify_receipt(receipt_path)

    def test_38_artifact_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt_path = self._run_local(Path(temporary))
            (receipt_path.parent / "observations.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(BoundaryLabError, "artifact"):
                verify_receipt(receipt_path)

    def test_39_artifact_path_traversal_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt_path = self._run_local(Path(temporary))
            receipt = load_json(receipt_path)
            assert isinstance(receipt, dict)
            artifacts = receipt["artifacts"]
            assert isinstance(artifacts, list)
            artifact = artifacts[0]
            assert isinstance(artifact, dict)
            artifact["path"] = "../observations.json"
            unsigned = {key: value for key, value in receipt.items() if key != "integrity"}
            integrity = receipt["integrity"]
            assert isinstance(integrity, dict)
            integrity["content_digest"] = digest_json(unsigned)
            write_json(receipt_path, receipt)
            with self.assertRaisesRegex(BoundaryLabError, "safe relative"):
                verify_receipt(receipt_path)

    def test_40_markdown_export_preserves_claim_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = verify_receipt(self._run_local(Path(temporary)))
            markdown = render_markdown(receipt)
            self.assertIn("not certification", markdown)
            self.assertIn("network.exact_targets", markdown)

    def test_41_junit_export_does_not_count_untested_as_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = verify_receipt(self._run_local(Path(temporary)))
            junit = render_junit(receipt)
            self.assertIn("<skipped", junit)
            self.assertIn("network.exact_targets", junit)

    def test_42_receipt_comparison_reports_status_change(self) -> None:
        baseline = {
            "run_id": "baseline",
            "results": [{"probe_id": "runtime.platform", "status": "pass"}],
        }
        candidate = {
            "run_id": "candidate",
            "results": [{"probe_id": "runtime.platform", "status": "fail"}],
        }
        comparison = compare_receipts(baseline, candidate)
        changed = comparison["status_changed"]
        self.assertEqual(
            changed,
            [{"after": "fail", "before": "pass", "probe_id": "runtime.platform"}],
        )


if __name__ == "__main__":
    unittest.main()
