# Contributing

PermitMesh is at the problem-validation stage. The most valuable contribution is a small, redacted real-world fixture showing:

1. the action an agent attempted;
2. the narrow authority the maintainer intended;
3. whether PermitMesh allowed or denied it correctly; and
4. which runtime could enforce the decision.

Before proposing new schema fields, include an example that cannot be represented safely with the current format.

Run:

```powershell
python -m pip install --disable-pip-version-check -e ".[dev]"
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m coverage run -m pytest
python -m coverage report
python -m bandit -q -r src scripts .github\nymrel-hourly -ll -ii
python -m pip_audit --strict .
python -m permitmesh conformance examples\conformance-suite.json
```

Contributions must preserve fail-closed behavior, exhaustive denial reasons,
deterministic digests, exact high-risk operation binding, explicit replay
state, and explicit signed/unsigned states. Do not describe nonce checks as
one-time enforcement unless the enforcement point atomically consumes the
nonce with execution.

New external inputs must be bounded by size, depth, count, and string/path
length before expensive matching or receipt construction. Schema changes must
ship with runtime-parity and adversarial tests. Workflow changes must preserve
the read-only reasoning job, immutable guard binding, separate publisher,
least privilege, full-SHA action pins, and draft-only output.
