"""Safe built-in observations and expectation evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from boundarylab.io import JSONValue
from boundarylab.model import Expectation, ProbeResult, ResultStatus


@dataclass(frozen=True)
class Probe:
    probe_id: str
    category: str
    description: str


PROBES: tuple[Probe, ...] = (
    Probe(
        "runtime.platform",
        "runtime",
        "Operating-system family reported by the guest.",
    ),
    Probe(
        "runtime.kernel",
        "runtime",
        "Kernel release reported by the guest.",
    ),
    Probe(
        "runtime.python",
        "runtime",
        "Python implementation and version.",
    ),
    Probe(
        "compute.cpu_count",
        "compute",
        "Guest-visible logical CPU count.",
    ),
    Probe(
        "compute.memory_limit",
        "compute",
        "Observed cgroup memory limit.",
    ),
    Probe(
        "compute.process_limit",
        "compute",
        "Observed cgroup process limit.",
    ),
    Probe(
        "filesystem.root_write",
        "filesystem",
        "Root filesystem write permission observation.",
    ),
    Probe(
        "filesystem.tmp_write",
        "filesystem",
        "Temporary-directory write permission observation.",
    ),
    Probe(
        "filesystem.home_write",
        "filesystem",
        "Home-directory write permission observation.",
    ),
    Probe(
        "filesystem.docker_socket",
        "filesystem",
        "Presence of a Docker control socket.",
    ),
    Probe(
        "filesystem.containerd_socket",
        "filesystem",
        "Presence of a containerd control socket.",
    ),
    Probe(
        "filesystem.container_markers",
        "filesystem",
        "Common container marker presence.",
    ),
    Probe(
        "isolation.uid",
        "isolation",
        "Numeric guest user identifier.",
    ),
    Probe(
        "isolation.pid1",
        "isolation",
        "Bounded identity information for PID 1.",
    ),
    Probe(
        "isolation.process_count",
        "isolation",
        "Count of guest-visible numeric processes.",
    ),
    Probe(
        "isolation.mount_namespace",
        "isolation",
        "Mount namespace identifier.",
    ),
    Probe(
        "isolation.pid_namespace",
        "isolation",
        "PID namespace identifier.",
    ),
    Probe(
        "isolation.cgroup",
        "isolation",
        "Hashed cgroup descriptor presence.",
    ),
    Probe(
        "isolation.seccomp",
        "isolation",
        "Linux seccomp mode.",
    ),
    Probe(
        "isolation.no_new_privs",
        "isolation",
        "Linux no-new-privileges flag.",
    ),
    Probe(
        "isolation.capabilities",
        "isolation",
        "Effective Linux capability bitset.",
    ),
    Probe(
        "isolation.devices",
        "isolation",
        "Bounded device-node surface summary.",
    ),
    Probe(
        "credentials.canary_env",
        "credentials",
        "Canary environment-variable presence only.",
    ),
    Probe(
        "credentials.canary_file",
        "credentials",
        "Canary file presence only.",
    ),
    Probe(
        "credentials.shell_history",
        "credentials",
        "Shell-history file presence only.",
    ),
    Probe(
        "network.resolver",
        "network",
        "Resolver configuration counts without addresses.",
    ),
    Probe(
        "network.exact_targets",
        "network",
        "Exact authorized TCP targets without payloads.",
    ),
)

PROBE_BY_ID = {probe.probe_id: probe for probe in PROBES}

# This program is fixed by the BoundaryLab package. Adapters execute it
# without a shell. It emits bounded observations only: no environment values,
# file contents, hostnames, or raw errors.
GUEST_PROGRAM = r"""
import hashlib
import json
import os
import platform
import socket
import sys
from pathlib import Path


def safe_text(path, limit=4096):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return None


def status_value(name):
    text = safe_text("/proc/self/status")
    if text is None:
        return None
    prefix = name + ":"
    for line in text.splitlines():
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip().split()[0]
    return None


def cgroup_limit(paths):
    for path in paths:
        text = safe_text(path, 128)
        if text is None:
            continue
        value = text.strip()
        if value == "max":
            return "max"
        try:
            return int(value)
        except ValueError:
            return "unparseable"
    return None


def namespace(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


def process_count():
    try:
        return sum(1 for name in os.listdir("/proc") if name.isdigit())
    except OSError:
        return None


def pid1():
    text = safe_text("/proc/1/comm", 128)
    if text is None:
        return None
    return {"name_sha256": hashlib.sha256(text.strip().encode()).hexdigest()}


def cgroup_summary():
    text = safe_text("/proc/self/cgroup")
    if text is None:
        return {"present": False}
    return {
        "present": True,
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "version2": any(line.startswith("0::") for line in text.splitlines()),
    }


def devices():
    try:
        names = set(os.listdir("/dev"))
    except OSError:
        return {"available": False}
    return {
        "available": True,
        "count": len(names),
        "docker_present": "docker" in names,
        "kvm_present": "kvm" in names,
        "mem_present": "mem" in names,
    }


def resolver():
    text = safe_text("/etc/resolv.conf")
    if text is None:
        return {"available": False}
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return {
        "available": True,
        "nameserver_count": sum(line.startswith("nameserver ") for line in lines),
        "search_line_count": sum(
            line.startswith("search ") or line.startswith("domain ")
            for line in lines
        ),
    }


def network_targets():
    if os.environ.get("BOUNDARYLAB_NETWORK_PROBES") != "1":
        return {"tested": False, "targets": []}
    try:
        targets = json.loads(os.environ.get("BOUNDARYLAB_NETWORK_TARGETS", "[]"))
    except (TypeError, ValueError):
        return {
            "tested": False,
            "targets": [],
            "reason_code": "invalid-target-envelope",
        }
    if not isinstance(targets, list) or len(targets) > 32:
        return {
            "tested": False,
            "targets": [],
            "reason_code": "invalid-target-envelope",
        }
    results = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        target_id = target.get("id")
        host = target.get("host")
        port = target.get("port")
        if (
            not isinstance(target_id, str)
            or not isinstance(host, str)
            or not isinstance(port, int)
        ):
            continue
        connected = False
        reason = None
        try:
            connection = socket.create_connection((host, port), timeout=1.0)
            connection.close()
            connected = True
        except TimeoutError:
            reason = "timeout"
        except socket.gaierror:
            reason = "dns-error"
        except ConnectionRefusedError:
            reason = "refused"
        except OSError:
            reason = "os-error"
        entry = {"connected": connected, "id": target_id}
        if reason is not None:
            entry["reason_code"] = reason
        results.append(entry)
    return {"tested": True, "targets": results}


def history_present():
    try:
        home = Path.home()
    except RuntimeError:
        return False
    return any(
        (home / name).exists()
        for name in (".bash_history", ".zsh_history")
    )


observations = {
    "runtime.platform": platform.system().lower() or "unknown",
    "runtime.kernel": platform.release(),
    "runtime.python": {
        "implementation": platform.python_implementation(),
        "version": ".".join(str(part) for part in sys.version_info[:3]),
    },
    "compute.cpu_count": os.cpu_count(),
    "compute.memory_limit": cgroup_limit(
        (
            "/sys/fs/cgroup/memory.max",
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        )
    ),
    "compute.process_limit": cgroup_limit(
        ("/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max")
    ),
    "filesystem.root_write": os.access("/", os.W_OK),
    "filesystem.tmp_write": os.access("/tmp", os.W_OK),
    "filesystem.home_write": os.access(str(Path.home()), os.W_OK),
    "filesystem.docker_socket": Path("/var/run/docker.sock").exists(),
    "filesystem.containerd_socket": any(
        Path(path).exists()
        for path in (
            "/run/containerd/containerd.sock",
            "/var/run/containerd/containerd.sock",
        )
    ),
    "filesystem.container_markers": {
        "dockerenv": Path("/.dockerenv").exists(),
        "run_containerenv": Path("/run/.containerenv").exists(),
    },
    "isolation.uid": os.getuid() if hasattr(os, "getuid") else None,
    "isolation.pid1": pid1(),
    "isolation.process_count": process_count(),
    "isolation.mount_namespace": namespace("/proc/self/ns/mnt"),
    "isolation.pid_namespace": namespace("/proc/self/ns/pid"),
    "isolation.cgroup": cgroup_summary(),
    "isolation.seccomp": status_value("Seccomp"),
    "isolation.no_new_privs": status_value("NoNewPrivs"),
    "isolation.capabilities": status_value("CapEff"),
    "isolation.devices": devices(),
    "credentials.canary_env": "BOUNDARYLAB_CANARY_SECRET" in os.environ,
    "credentials.canary_file": Path(
        os.environ.get(
            "BOUNDARYLAB_CANARY_PATH",
            "/run/boundarylab/canary",
        )
    ).exists(),
    "credentials.shell_history": history_present(),
    "network.resolver": resolver(),
    "network.exact_targets": network_targets(),
}
print(
    json.dumps(
        observations,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
)
"""


def known_probe_ids() -> set[str]:
    return set(PROBE_BY_ID)


def _contains(observed: JSONValue, expected: JSONValue) -> bool:
    if isinstance(observed, str) and isinstance(expected, str):
        return expected in observed
    if isinstance(observed, list):
        return expected in observed
    if isinstance(observed, dict) and isinstance(expected, str):
        return expected in observed
    return False


def _ordered_number(value: JSONValue) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def expectation_matches(
    observed: JSONValue,
    expectation: Expectation,
) -> bool:
    op = expectation.op
    expected = expectation.value
    if op == "observe":
        return True
    if op == "equals":
        return observed == expected
    if op == "not_equals":
        return observed != expected
    if op == "contains":
        return _contains(observed, expected)
    if op == "not_contains":
        return not _contains(observed, expected)
    if op == "one_of":
        return isinstance(expected, list) and observed in expected
    observed_number = _ordered_number(observed)
    expected_number = _ordered_number(expected)
    if observed_number is None or expected_number is None:
        return False
    if op == "lte":
        return observed_number <= expected_number
    if op == "gte":
        return observed_number >= expected_number
    return False


def evaluate_observations(
    probe_ids: tuple[str, ...],
    expectations: dict[str, Expectation],
    observations: dict[str, JSONValue],
) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    for probe_id in probe_ids:
        probe = PROBE_BY_ID[probe_id]
        expectation = expectations.get(probe_id, Expectation("observe"))
        expected_json = expectation.to_json()
        if probe_id not in observations:
            results.append(
                ProbeResult(
                    probe_id,
                    probe.category,
                    "error",
                    expected_json,
                    None,
                    "observation-missing",
                )
            )
            continue
        observed = observations[probe_id]
        status: ResultStatus = "pass" if expectation_matches(observed, expectation) else "fail"
        results.append(
            ProbeResult(
                probe_id,
                probe.category,
                status,
                expected_json,
                observed,
            )
        )
    return results


def unsupported_results(
    probe_ids: tuple[str, ...],
    reason_code: str,
) -> list[ProbeResult]:
    return [
        ProbeResult(
            probe_id=probe_id,
            category=PROBE_BY_ID[probe_id].category,
            status="unsupported",
            expected={"op": "observe"},
            observed=None,
            reason_code=reason_code,
        )
        for probe_id in probe_ids
    ]


def error_results(
    probe_ids: tuple[str, ...],
    reason_code: str,
) -> list[ProbeResult]:
    return [
        ProbeResult(
            probe_id=probe_id,
            category=PROBE_BY_ID[probe_id].category,
            status="error",
            expected={"op": "observe"},
            observed=None,
            reason_code=reason_code,
        )
        for probe_id in probe_ids
    ]
