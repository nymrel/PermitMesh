from __future__ import annotations

import os
import subprocess
import sys
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from boundarylab.adapters import CommandAdapter, DockerAdapter
from boundarylab.model import AUTH_SCHEMA, Authorization


def authorization(*, adapter_config: dict[str, object]) -> Authorization:
    return Authorization.from_json(
        {
            "adapter_config": adapter_config,
            "allowed_adapters": ["command", "docker"],
            "authorization_id": "adapter-environment-test",
            "destructive_tests": False,
            "environment": "test",
            "expires_at": (datetime.now(UTC) + timedelta(days=1))
            .isoformat()
            .replace("+00:00", "Z"),
            "limits": {
                "max_cost_usd": "0",
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


class AdapterEnvironmentTests(unittest.TestCase):
    def test_command_adapter_does_not_inherit_host_environment(self) -> None:
        manifest = authorization(
            adapter_config={
                "command_prefix": [sys.executable, "-I", "-c"],
            }
        )
        completed = subprocess.CompletedProcess([], 0, stdout=b"{}")
        with (
            patch.dict(
                os.environ,
                {
                    "BOUNDARYLAB_TEST_HOST_SECRET": "must-not-cross",
                    "PROVIDER_API_KEY": "must-not-cross",
                },
                clear=False,
            ),
            patch(
                "boundarylab.adapters.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            outcome = CommandAdapter().run(
                manifest,
                "test-run",
                network_probes=False,
            )

        environment = run.call_args.kwargs["env"]
        self.assertEqual(
            set(environment),
            {
                "BOUNDARYLAB_NETWORK_PROBES",
                "BOUNDARYLAB_NETWORK_TARGETS",
            },
        )
        self.assertNotIn("BOUNDARYLAB_TEST_HOST_SECRET", environment)
        self.assertNotIn("PROVIDER_API_KEY", environment)
        self.assertEqual(
            outcome.runtime["environment_policy"],
            "boundarylab-control-variables-only",
        )

    def test_subprocess_adapter_discards_stderr_without_a_buffer(self) -> None:
        manifest = authorization(
            adapter_config={
                "command_prefix": [sys.executable, "-I", "-c"],
            }
        )
        completed = subprocess.CompletedProcess([], 0, stdout=b"{}")
        with patch(
            "boundarylab.adapters.subprocess.run",
            return_value=completed,
        ) as run:
            CommandAdapter().run(
                manifest,
                "test-run",
                network_probes=False,
            )

        kwargs = run.call_args.kwargs
        self.assertIs(kwargs["stdout"], subprocess.PIPE)
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn("capture_output", kwargs)
        self.assertFalse(kwargs["shell"])

    def test_docker_guest_does_not_receive_host_secret(self) -> None:
        manifest = authorization(adapter_config={"docker_image": "python:3.13-slim"})
        completed = subprocess.CompletedProcess([], 0, stdout=b"{}")
        with (
            patch.dict(
                os.environ,
                {"PROVIDER_API_KEY": "must-not-cross"},
                clear=False,
            ),
            patch(
                "boundarylab.adapters.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            outcome = DockerAdapter().run(
                manifest,
                "test-run",
                network_probes=False,
            )

        argv = run.call_args.args[0]
        self.assertNotIn("PROVIDER_API_KEY", " ".join(argv))
        self.assertEqual(
            outcome.runtime["environment_policy"],
            "boundarylab-control-variables-only",
        )


if __name__ == "__main__":
    unittest.main()
