"""Runtime adapters with fail-closed execution defaults."""

from __future__ import annotations

import importlib
import json
import os
import platform
import subprocess
import sys
from datetime import timedelta
from typing import Any, Protocol

from boundarylab.io import JSONValue, digest_json, loads_strict
from boundarylab.model import AdapterOutcome, Authorization
from boundarylab.probes import GUEST_PROGRAM


class Adapter(Protocol):
    name: str

    def run(
        self,
        authorization: Authorization,
        run_id: str,
        *,
        network_probes: bool,
    ) -> AdapterOutcome: ...


def _guest_environment(
    authorization: Authorization,
    *,
    network_probes: bool,
    inherit: bool,
) -> dict[str, str]:
    environment = dict(os.environ) if inherit else {}
    environment["BOUNDARYLAB_NETWORK_PROBES"] = "1" if network_probes else "0"
    environment["BOUNDARYLAB_NETWORK_TARGETS"] = json.dumps(
        [target.guest_json() for target in authorization.network_targets],
        sort_keys=True,
        separators=(",", ":"),
    )
    return environment


def _bounded_parse(
    stdout: bytes | str,
    maximum: int,
) -> dict[str, JSONValue] | None:
    raw = stdout.encode("utf-8") if isinstance(stdout, str) else stdout
    if len(raw) > maximum:
        return None
    try:
        decoded = raw.decode("utf-8")
        value = loads_strict(decoded)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    return value


def _subprocess_outcome(
    *,
    adapter: str,
    argv: list[str],
    environment: dict[str, str],
    authorization: Authorization,
    runtime: dict[str, JSONValue],
) -> AdapterOutcome:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            shell=False,
            timeout=authorization.limits.max_duration_seconds,
        )
    except FileNotFoundError:
        return AdapterOutcome(
            adapter,
            "unsupported",
            {},
            runtime,
            "adapter-executable-missing",
        )
    except subprocess.TimeoutExpired:
        return AdapterOutcome(
            adapter,
            "error",
            {},
            runtime,
            "duration-limit-exceeded",
        )
    except OSError:
        return AdapterOutcome(
            adapter,
            "error",
            {},
            runtime,
            "adapter-launch-failed",
        )
    if len(completed.stdout) > authorization.limits.max_output_bytes:
        return AdapterOutcome(
            adapter,
            "error",
            {},
            runtime,
            "output-limit-exceeded",
        )
    if completed.returncode != 0:
        return AdapterOutcome(
            adapter,
            "error",
            {},
            runtime,
            "guest-nonzero",
        )
    observations = _bounded_parse(
        completed.stdout,
        authorization.limits.max_output_bytes,
    )
    if observations is None:
        return AdapterOutcome(
            adapter,
            "error",
            {},
            runtime,
            "invalid-guest-output",
        )
    return AdapterOutcome(adapter, "ok", observations, runtime)


class LocalAdapter:
    name = "local"

    def run(
        self,
        authorization: Authorization,
        run_id: str,
        *,
        network_probes: bool,
    ) -> AdapterOutcome:
        del run_id
        runtime: dict[str, JSONValue] = {
            "adapter": self.name,
            "environment_policy": "host-inherited-local-observation",
            "execution": "local-observation-only",
            "platform": platform.system().lower(),
            "python": (
                f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            ),
        }
        return _subprocess_outcome(
            adapter=self.name,
            argv=[sys.executable, "-I", "-c", GUEST_PROGRAM],
            environment=_guest_environment(
                authorization,
                network_probes=network_probes,
                inherit=True,
            ),
            authorization=authorization,
            runtime=runtime,
        )


class CommandAdapter:
    name = "command"

    def run(
        self,
        authorization: Authorization,
        run_id: str,
        *,
        network_probes: bool,
    ) -> AdapterOutcome:
        del run_id
        prefix = authorization.adapter_config.command_prefix
        runtime: dict[str, JSONValue] = {
            "adapter": self.name,
            "environment_policy": "boundarylab-control-variables-only",
            "execution": "authorized-argv-prefix",
            "network_policy": "operator-provided",
        }
        if prefix is None:
            return AdapterOutcome(
                self.name,
                "error",
                {},
                runtime,
                "command-prefix-missing",
            )
        runtime["command_prefix_digest"] = digest_json(list(prefix))
        return _subprocess_outcome(
            adapter=self.name,
            argv=[*prefix, GUEST_PROGRAM],
            environment=_guest_environment(
                authorization,
                network_probes=network_probes,
                inherit=False,
            ),
            authorization=authorization,
            runtime=runtime,
        )


class DockerAdapter:
    name = "docker"

    def run(
        self,
        authorization: Authorization,
        run_id: str,
        *,
        network_probes: bool,
    ) -> AdapterOutcome:
        target_envelope = json.dumps(
            [target.guest_json() for target in authorization.network_targets],
            sort_keys=True,
            separators=(",", ":"),
        )
        argv = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=128",
            "--memory=512m",
            "--cpus=1",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
            f"--label=org.nymrel.boundarylab.run={run_id[:36]}",
            "--env",
            (f"BOUNDARYLAB_NETWORK_PROBES={'1' if network_probes else '0'}"),
            "--env",
            f"BOUNDARYLAB_NETWORK_TARGETS={target_envelope}",
            authorization.adapter_config.docker_image,
            "python",
            "-I",
            "-c",
            GUEST_PROGRAM,
        ]
        runtime: dict[str, JSONValue] = {
            "adapter": self.name,
            "container_image": authorization.adapter_config.docker_image,
            "environment_policy": "boundarylab-control-variables-only",
            "execution": "ephemeral-container",
            "network_policy": "deny-all",
            "privilege_policy": ("read-only-cap-drop-all-no-new-privileges"),
            "pull_policy": "never",
        }
        return _subprocess_outcome(
            adapter=self.name,
            argv=argv,
            environment=dict(os.environ),
            authorization=authorization,
            runtime=runtime,
        )


class VercelAdapter:
    name = "vercel"

    def run(
        self,
        authorization: Authorization,
        run_id: str,
        *,
        network_probes: bool,
    ) -> AdapterOutcome:
        runtime: dict[str, JSONValue] = {
            "adapter": self.name,
            "environment_policy": "boundarylab-control-variables-only",
            "execution": "ephemeral-microvm",
            "network_policy": "deny-all",
            "persistent": False,
        }
        project_id = authorization.adapter_config.vercel_project_id
        if project_id is None:
            return AdapterOutcome(
                self.name,
                "error",
                {},
                runtime,
                "vercel-project-id-missing",
            )
        try:
            api_module = importlib.import_module("vercel.api")
            sandbox_module = importlib.import_module("vercel.sandbox")
            sync_module = importlib.import_module("vercel.sandbox.sync")
        except ImportError:
            return AdapterOutcome(
                self.name,
                "unsupported",
                {},
                runtime,
                "vercel-sdk-missing",
            )
        environment = _guest_environment(
            authorization,
            network_probes=network_probes,
            inherit=False,
        )
        try:
            session_factory: Any = api_module.session
            network_policy: Any = sandbox_module.NetworkPolicy
            create_sandbox: Any = sync_module.create_sandbox
            with session_factory():
                with create_sandbox(
                    project_id=project_id,
                    name=f"boundarylab-{run_id[:12]}",
                    execution_time_limit=timedelta(
                        seconds=(authorization.limits.max_duration_seconds)
                    ),
                    persistent=False,
                    network_policy=network_policy.deny_all(),
                    env=environment,
                    tags={
                        "nymrel-tool": "boundarylab",
                        "run-id": run_id[:36],
                    },
                ) as sandbox:
                    process = sandbox.run_process(
                        "python",
                        ["-I", "-c", GUEST_PROGRAM],
                        check=False,
                        capture_output=True,
                    )
                    stdout = process.stdout
                    return_code = int(process.returncode)
        except Exception:
            return AdapterOutcome(
                self.name,
                "error",
                {},
                runtime,
                "vercel-adapter-failed",
            )
        if stdout is None:
            return AdapterOutcome(
                self.name,
                "error",
                {},
                runtime,
                "vercel-output-not-captured",
            )
        raw_size = len(stdout.encode("utf-8") if isinstance(stdout, str) else stdout)
        if raw_size > authorization.limits.max_output_bytes:
            return AdapterOutcome(
                self.name,
                "error",
                {},
                runtime,
                "output-limit-exceeded",
            )
        if return_code != 0:
            return AdapterOutcome(
                self.name,
                "error",
                {},
                runtime,
                "guest-nonzero",
            )
        observations = _bounded_parse(
            stdout,
            authorization.limits.max_output_bytes,
        )
        if observations is None:
            return AdapterOutcome(
                self.name,
                "error",
                {},
                runtime,
                "invalid-guest-output",
            )
        return AdapterOutcome(self.name, "ok", observations, runtime)


def make_adapter(name: str) -> Adapter:
    adapters: dict[str, Adapter] = {
        "command": CommandAdapter(),
        "docker": DockerAdapter(),
        "local": LocalAdapter(),
        "vercel": VercelAdapter(),
    }
    return adapters[name]
