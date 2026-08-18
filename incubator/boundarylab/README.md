# BoundaryLab

> **Incubator status:** BoundaryLab v0.1 is a governed implementation slice under PermitMesh. It is not a published package, security certification, production admission engine, or authorized mechanism for testing third-party systems.

BoundaryLab is a provider-neutral conformance and evidence harness for AI-agent sandboxes. It executes deterministic, bounded observations inside an explicitly authorized runtime, compares the observations with an optional policy profile, and emits independently verifiable receipts.

BoundaryLab answers a narrow question:

> Did this runtime configuration enforce the specific boundaries that these probes observed at this time?

It does **not** claim that a sandbox is unbreakable, generally secure, or suitable for production merely because a profile passes.

## Position in the Nymrel stack

```text
PermitMesh
  declares what an agent should be permitted to do
        ↓
BoundaryLab
  tests what the execution environment actually permits
        ↓
agent-proofchain
  can later sign or anchor the resulting evidence
        ↓
portfolio-control
  governs adoption and production use
```

The v0.1 receipt includes a canonical SHA-256 content digest and hashes every referenced artifact. The signature field is intentionally `null`; cryptographic signing and transparency anchoring remain a separate agent-proofchain integration.

## Public v0.1 boundaries

BoundaryLab fails closed around authorization:

- third-party testing is rejected;
- destructive tests are rejected;
- only `local`, `development`, and `test` environments are accepted;
- adapter use must be listed in the authorization manifest;
- duration, output, concurrency, and cost ceilings are validated;
- command adapters accept an argument vector, never a shell expression;
- raw environment values, file contents, stdout/stderr, provider logs, and credentials are not written to receipts;
- network probes are disabled by default;
- network targets must be exact host/IP and port pairs—no wildcards, URLs, CIDRs, discovery, or port ranges;
- a network probe performs one bounded TCP connection attempt and sends no application payload;
- public targets require both `--allow-network-probes` and the separate `--allow-public-network` opt-in;
- the built-in Docker adapter uses deny-all networking, a read-only root filesystem, dropped capabilities, no-new-privileges, and `--pull=never`;
- the optional Vercel adapter is ephemeral, deny-all by default, and experimental.

See [SECURITY.md](SECURITY.md), [the threat model](docs/THREAT_MODEL.md), and [probe-authoring rules](docs/PROBE_AUTHORING.md) before adding an adapter or probe.

## Built-in probes

The first release contains 27 bounded probes across six surfaces:

| Surface | Examples |
|---|---|
| Runtime | OS family, kernel release, Python implementation |
| Compute | CPU count, cgroup memory limit, process limit |
| Filesystem | write permission observations, Docker/containerd socket presence, container markers |
| Isolation | UID, bounded PID 1 identity, process count, namespaces, cgroup, seccomp, no-new-privileges, capabilities, device summary |
| Credentials | canary environment/file presence and shell-history presence—never values or contents |
| Network | resolver counts and exact authorized TCP policy targets |

List the current registry with:

```bash
boundarylab probes
boundarylab probes --json
```

## Result semantics

BoundaryLab never converts missing coverage into a pass. Every probe has one of six states:

- `pass` — the observed value matched the explicit expectation, or an observation-only probe completed;
- `fail` — the runtime contradicted an explicit expectation;
- `unsupported` — the selected adapter cannot perform the observation;
- `untested` — the probe was intentionally not executed, such as network tests without an opt-in;
- `inconclusive` — evidence exists but cannot support a directional verdict;
- `error` — the observation or evidence pipeline failed.

There is intentionally no universal security score.

## Install for local development

BoundaryLab requires Python 3.11 or newer and has no runtime dependencies.

```bash
cd incubator/boundarylab
python -m venv .venv
# Linux/macOS
. .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Create starter manifests:

```bash
boundarylab init --directory .boundarylab
```

Review and edit both generated files before execution. In particular, replace the owner, confirm the expiration date, and reduce the allowed adapters to the smallest required set.

## Run a local observation

```bash
boundarylab run \
  --authorization examples/authorization.local.json \
  --profile examples/profile.core.json \
  --adapter local \
  --out .boundarylab/runs
```

The command prints the path to `receipt.json`. Its sibling `observations.json` is hashed by the receipt.

Verify the receipt and all artifacts independently:

```bash
boundarylab verify .boundarylab/runs/<run-id>/receipt.json
```

Export CI and human views:

```bash
boundarylab export .boundarylab/runs/<run-id>/receipt.json \
  --format markdown \
  --out .boundarylab/report.md

boundarylab export .boundarylab/runs/<run-id>/receipt.json \
  --format junit \
  --out .boundarylab/junit.xml
```

Compare two verified runs without manufacturing a scalar score:

```bash
boundarylab compare \
  .boundarylab/runs/<baseline>/receipt.json \
  .boundarylab/runs/<candidate>/receipt.json \
  --out .boundarylab/comparison.json
```

## Docker adapter

The Docker adapter intentionally refuses implicit image downloads. Pre-pull and inspect the exact image yourself, then authorize its immutable reference in the manifest. A digest is preferred over a mutable tag.

```bash
docker pull python:3.13-slim
boundarylab run \
  --authorization examples/authorization.local.json \
  --profile examples/profile.docker-deny-all.json \
  --adapter docker \
  --out .boundarylab/runs
```

The adapter applies:

```text
--pull=never
--network=none
--read-only
--cap-drop=ALL
--security-opt=no-new-privileges:true
--pids-limit=128
--memory=512m
--cpus=1
--tmpfs=/tmp:rw,noexec,nosuid,size=64m
```

These settings are part of the adapter implementation and appear as bounded runtime metadata in the receipt. They are not proof that Docker or its host is invulnerable.

## Command adapter

The command adapter supports an already-authorized local executor without embedding provider-specific behavior in the core. Its manifest entry is an argument-vector prefix, for example:

```json
{
  "command_prefix": ["trusted-sandbox-exec", "--", "python", "-I", "-c"]
}
```

BoundaryLab appends its fixed guest observer as the final argument and calls the process with `shell=false`. The operator-provided executor remains responsible for sandbox creation, egress policy, lifecycle cleanup, and credential brokering.

## Vercel adapter

The optional adapter is installed separately:

```bash
python -m pip install -e '.[vercel]'
```

It is intentionally marked experimental during incubation. The implementation creates an ephemeral sandbox, requests deny-all networking, passes only BoundaryLab control variables, runs the fixed observer, and returns safe reason codes rather than provider exceptions or logs.

Live Vercel execution is excluded from standard tests and CI. It requires a separate authorization, project configuration, credentials, spending approval, and governed validation decision. The existence of the adapter is not permission to test Vercel infrastructure or submit challenge findings.

## Network probes

A network target must be explicitly listed:

```json
{
  "id": "owned-canary",
  "host": "canary.example.internal",
  "port": 443,
  "expected": "allowed",
  "public": false
}
```

Then execution requires:

```bash
boundarylab run \
  --authorization authorization.json \
  --profile profile.json \
  --adapter command \
  --allow-network-probes
```

For an authorized public target, the operator must also pass `--allow-public-network`. BoundaryLab makes a single TCP connection attempt, closes it immediately, and records only the target ID, connectivity boolean, and a coarse reason code. It does not send HTTP, TLS, DNS application payloads, exploit traffic, or discovery probes.

## Receipt claim boundary

A receipt is meaningful only together with:

- its authorization digest;
- profile digest;
- adapter and runtime metadata;
- BoundaryLab version;
- start and completion timestamps;
- explicit result state for every selected probe;
- canonical receipt digest;
- artifact paths, sizes, and SHA-256 hashes.

The correct interpretation is:

> These controls produced these observations against this runtime configuration during this interval.

The incorrect interpretation is:

> This runtime is secure, certified, or approved for production.

Production admission, risk acceptance, and policy enforcement remain external governance decisions.

## Development validation

Standard tests are deterministic and do not invoke Vercel, execute BoundaryLab network probes, pull Docker images, use credentials, approve spending, or test public targets.

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
ruff format --check .
ruff check .
mypy src
bandit -q -r src -s B404,B603,B607
python -m build
```

The subprocess exclusions are narrow and intentional: adapters execute fixed argument vectors with `shell=false`, bounded duration, and bounded output. New subprocess use requires security review.

## Governance and extraction

BoundaryLab is incubated through:

- `JalenBuildsHub/portfolio-control#34` — open-source proposal exchange;
- `JalenBuildsHub/portfolio-control#51` — BoundaryLab incubation packet;
- this draft implementation under `nymrel/PermitMesh/incubator/boundarylab`.

Extraction to a standalone `nymrel/boundarylab` repository requires a separate recorded decision after, at minimum:

1. authorization and network invariants receive focused review;
2. Linux and Windows CI are green;
3. the receipt schema and claim language stabilize;
4. Docker behavior is reproduced on a clean host;
5. any live provider adapter is validated only in an owned test environment;
6. agent-proofchain integration boundaries are agreed without coupling the core;
7. the public probe set is confirmed free of weaponized escape payloads;
8. packaging, release, signing, and production-admission decisions are separately approved.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
