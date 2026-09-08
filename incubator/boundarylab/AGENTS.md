# BoundaryLab agent instructions

These instructions apply to every file under `incubator/boundarylab`.

## Mission

Maintain a provider-neutral, deterministic conformance and evidence harness for explicitly authorized AI-agent sandboxes. BoundaryLab observes enforcement; it does not declare policy, discover targets, exploit providers, certify security, or make production-admission decisions.

## Non-negotiable invariants

1. Reject third-party and destructive testing in the public core.
2. Require a validated, unexpired authorization before any adapter executes.
3. Keep network execution disabled by default.
4. Accept only exact authorized hostname/IP and port pairs. Never add wildcards, CIDRs, ranges, target discovery, crawling, service fingerprinting, or port scanning.
5. Network probes may make one bounded connection attempt and must not send an application payload.
6. Keep public-network execution behind a separate explicit opt-in.
7. Never place secret values, environment values, file contents, raw stdout/stderr, provider logs, stack traces, or credentials in observations, errors, receipts, fixtures, or tests.
8. Execute subprocesses as argument vectors with `shell=False`. Do not accept arbitrary shell strings.
9. Keep adapters ephemeral and fail closed. Provider exceptions must become coarse safe reason codes.
10. Do not include weaponized kernel, container, hypervisor, or sandbox escape payloads.
11. Preserve all six result states. Never reinterpret `unsupported`, `untested`, `inconclusive`, or `error` as `pass`.
12. Do not introduce a universal security score.
13. Preserve canonical receipt hashing and independent artifact verification.
14. Do not describe SHA-256 integrity as a signature, attestation, certification, or proof of runtime identity.
15. Keep agent-proofchain signing optional and external to the dependency-free core.
16. Standard tests and CI must not run live provider adapters, execute BoundaryLab network probes, pull container images, require credentials, or approve spend.
17. Do not merge, publish, release, submit challenge findings, enable production admission, or extract a standalone repository without a separately recorded governance decision.

## Change requirements

Every new probe must document:

- the exact security property being observed;
- the bounded data it returns;
- unsupported-platform behavior;
- expected false-positive and false-negative modes;
- why it cannot expose secrets or become a generalized exploitation primitive;
- deterministic unit tests;
- receipt semantics.

Every new adapter must document:

- authorization binding;
- runtime creation and teardown;
- network policy;
- credential delivery or brokering;
- command construction;
- timeout and output enforcement;
- safe error mapping;
- provider cost controls;
- a rollback path.

## Validation

From this directory, run:

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
ruff format --check .
ruff check .
mypy src
bandit -q -r src -s B404,B603,B607
python -m build
```

A local test run may execute the fixed observation program in a child Python process. It must not execute BoundaryLab network probes or provider calls.

## Scope discipline

Changes in this incubator must not modify PermitMesh package behavior, published APIs, release automation, secrets, production environments, or repository ownership. Keep workflow triggers path-scoped to the incubator until extraction is approved.
