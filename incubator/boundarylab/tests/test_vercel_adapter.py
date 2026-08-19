from __future__ import annotations

import os
import unittest
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

from boundarylab.adapters import VercelAdapter
from boundarylab.model import AUTH_SCHEMA, Authorization
from boundarylab.probes import GUEST_PROGRAM


def authorization() -> Authorization:
    expires_at = (datetime.now(UTC) + timedelta(days=1)).isoformat().replace(
        "+00:00", "Z"
    )
    return Authorization.from_json(
        {
            "adapter_config": {"vercel_project_id": "prj_boundarylab_test"},
            "allowed_adapters": ["vercel"],
            "authorization_id": "vercel-adapter-test",
            "destructive_tests": False,
            "environment": "test",
            "expires_at": expires_at,
            "limits": {
                "max_cost_usd": "1",
                "max_duration_seconds": 30,
                "max_output_bytes": 262144,
                "max_parallel": 1,
            },
            "network_targets": [],
            "owner": "Nymrel tests",
            "schema": AUTH_SCHEMA,
            "third_party_testing": False,
        }
    )


class FakeSandbox:
    def __init__(self, *, stdout: str | None, returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.exited = False
        self.process_args: tuple[object, ...] | None = None
        self.process_kwargs: dict[str, object] | None = None

    def __enter__(self) -> FakeSandbox:
        return self

    def __exit__(self, *args: object) -> None:
        del args
        self.exited = True

    def run_process(self, *args: object, **kwargs: object) -> SimpleNamespace:
        self.process_args = args
        self.process_kwargs = kwargs
        return SimpleNamespace(stdout=self.stdout, returncode=self.returncode)


class VercelAdapterTests(unittest.TestCase):
    def _modules(
        self,
        sandbox: FakeSandbox,
        create_calls: list[dict[str, object]],
    ) -> dict[str, object]:
        def create_sandbox(**kwargs: object) -> FakeSandbox:
            create_calls.append(kwargs)
            return sandbox

        class NetworkPolicy:
            @staticmethod
            def deny_all() -> str:
                return "deny-all-policy"

        return {
            "vercel.api": SimpleNamespace(session=lambda: nullcontext()),
            "vercel.sandbox": SimpleNamespace(NetworkPolicy=NetworkPolicy),
            "vercel.sandbox.sync": SimpleNamespace(
                create_sandbox=create_sandbox
            ),
        }

    def test_sdk_contract_captures_output_and_cleans_up(self) -> None:
        sandbox = FakeSandbox(stdout='{"runtime.platform":"linux"}')
        create_calls: list[dict[str, object]] = []
        modules = self._modules(sandbox, create_calls)

        with patch.dict(os.environ, {"HOST_SECRET": "must-not-enter-guest"}):
            with patch(
                "boundarylab.adapters.importlib.import_module",
                side_effect=lambda name: modules[name],
            ):
                outcome = VercelAdapter().run(
                    authorization(),
                    "1234567890abcdef",
                    network_probes=False,
                )

        self.assertEqual(outcome.status, "ok")
        self.assertEqual(
            sandbox.process_args,
            ("python", ["-I", "-c", GUEST_PROGRAM]),
        )
        self.assertEqual(
            sandbox.process_kwargs,
            {"check": False, "capture_output": True},
        )
        self.assertTrue(sandbox.exited)
        self.assertEqual(len(create_calls), 1)
        create = create_calls[0]
        self.assertEqual(create["project_id"], "prj_boundarylab_test")
        self.assertEqual(create["network_policy"], "deny-all-policy")
        self.assertIs(create["persistent"], False)
        guest_env = create["env"]
        self.assertIsInstance(guest_env, dict)
        assert isinstance(guest_env, dict)
        self.assertNotIn("HOST_SECRET", guest_env)
        self.assertEqual(guest_env["BOUNDARYLAB_NETWORK_PROBES"], "0")

    def test_missing_capture_fails_closed(self) -> None:
        sandbox = FakeSandbox(stdout=None)
        create_calls: list[dict[str, object]] = []
        modules = self._modules(sandbox, create_calls)

        with patch(
            "boundarylab.adapters.importlib.import_module",
            side_effect=lambda name: modules[name],
        ):
            outcome = VercelAdapter().run(
                authorization(),
                "capture-missing",
                network_probes=False,
            )

        self.assertEqual(outcome.status, "error")
        self.assertEqual(outcome.reason_code, "vercel-output-not-captured")
        self.assertTrue(sandbox.exited)

    def test_provider_exception_is_not_exposed(self) -> None:
        class NetworkPolicy:
            @staticmethod
            def deny_all() -> str:
                return "deny-all-policy"

        def create_sandbox(**kwargs: object) -> None:
            del kwargs
            raise RuntimeError("provider response containing a secret")

        modules = {
            "vercel.api": SimpleNamespace(session=lambda: nullcontext()),
            "vercel.sandbox": SimpleNamespace(NetworkPolicy=NetworkPolicy),
            "vercel.sandbox.sync": SimpleNamespace(
                create_sandbox=create_sandbox
            ),
        }
        with patch(
            "boundarylab.adapters.importlib.import_module",
            side_effect=lambda name: modules[name],
        ):
            outcome = VercelAdapter().run(
                authorization(),
                "provider-error",
                network_probes=False,
            )

        self.assertEqual(outcome.status, "error")
        self.assertEqual(outcome.reason_code, "vercel-adapter-failed")
        self.assertNotIn("secret", str(outcome.runtime).lower())

    def test_missing_sdk_is_unsupported(self) -> None:
        with patch(
            "boundarylab.adapters.importlib.import_module",
            side_effect=ImportError,
        ):
            outcome = VercelAdapter().run(
                authorization(),
                "sdk-missing",
                network_probes=False,
            )

        self.assertEqual(outcome.status, "unsupported")
        self.assertEqual(outcome.reason_code, "vercel-sdk-missing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
