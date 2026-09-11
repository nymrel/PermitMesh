# PermitMesh

[![CI](https://github.com/nymrel/PermitMesh/actions/workflows/ci.yml/badge.svg)](https://github.com/nymrel/PermitMesh/actions/workflows/ci.yml)

**Deterministic, fail-closed capability contracts for AI agents changing software.**

> **PDP, not PEP.** PermitMesh evaluates policy. It does not authenticate an
> issuer, sandbox an agent, intercept tools, or enforce its decisions.

PermitMesh is an independent, experimental software-change profile and
conformance suite. It is not affiliated with or endorsed by Block, Buzz, the
IETF, or any standards body.

A PermitMesh contract states:

- who authorized the agent;
- which repository, ref, channel, and paths it may touch;
- which actions it may perform;
- the exact tool and arguments approved for each high-risk action;
- its file, command, time, and cost limits;
- which actions require human approval;
- which live claim and fencing generation it belongs to;
- which one-time operation nonce the enforcement point must consume; and
- what proof must exist before the work is complete.

The reference CLI evaluates proposed actions deterministically and fails closed with a machine-readable explanation.

> Status: **HYPOTHESIS — NOT ADOPTED.** Version 0.2 is an unpublished
> interoperability candidate in a public source repository, not a security
> boundary or package-release claim.

## Why this exists

[Buzz](https://github.com/block/buzz) gives people and agents cryptographic
identities in a shared event stream. PermitMesh independently explores a
complementary policy layer for software-changing agents:

> **Identity says who acted. A software-work permit describes the boundary
> an enforcement point should apply.**

PermitMesh adds work-shaped constraints that an execution boundary can apply:
paths, actions, budgets, approval gates, claims, and fencing generations. It
does not assume that Buzz will adopt this format or that identity alone
supplies trusted authorization facts.

PermitMesh does not fork Buzz, replace Nostr identity, or claim to be an accepted Buzz protocol. It is transport-neutral and includes an experimental adapter that turns a valid permit into an **unsigned** Nostr application-data event template.

This is a narrow profile, not a claim to have invented fine-grained
authorization. OAuth RAR, OPA, Cedar, Macaroons, Biscuit, ZCAP-LD, SPIFFE, MCP,
and several 2026 agent-authorization drafts cover adjacent or deeper layers.
See the candid [prior-art matrix](docs/PRIOR_ART.md).

## Thirty-second demo

Requires Python 3.11-3.14 and no runtime dependencies.

```powershell
$env:PYTHONPATH = "$PWD\src"

# Contract shape is valid.
python -m permitmesh validate examples\contract.valid.json

# An in-scope edit is allowed.
python -m permitmesh authorize examples\contract.valid.json examples\request.allowed.json --evaluation-time 2026-07-23T12:00:00Z

# A protected deploy with no exact operation binding, a stale claim,
# wrong ref, forbidden path, exceeded budgets, and no approval is denied.
python -m permitmesh authorize examples\contract.valid.json examples\request.denied.json --evaluation-time 2026-07-23T12:00:00Z
```

The allowed request returns:

```json
{
  "allowed": true,
  "contract_digest": "<sha256>",
  "reason_codes": [],
  "violations": [],
  "checks": ["validity_window", "subject", "channel", "capability"]
}
```

The denied request reports all ten violations, including:

```json
{
  "allowed": false,
  "reason_codes": [
    "OPERATION_BINDING_REQUIRED",
    "NONCE_INVALID",
    "REF_OUT_OF_SCOPE",
    "PATH_DENIED",
    "LIMIT_FILES_EXCEEDED",
    "LIMIT_COMMANDS_EXCEEDED",
    "LIMIT_COST_EXCEEDED",
    "CLAIM_MISMATCH",
    "FENCING_GENERATION_STALE",
    "APPROVAL_REQUIRED"
  ],
  "violations": [
    "request.operation is required for high-risk action 'deploy'",
    "request.operation_nonce must be 16-128 safe characters",
    "ref 'main' is outside scope",
    "path '.env' matches a deny rule",
    "request.files_changed=24 exceeds max_files_changed=20",
    "request.commands_used=120 exceeds max_commands=100",
    "request.cost_usd=40 exceeds max_cost_usd=25",
    "claim_id does not match the active contract",
    "fencing_generation does not match the active contract",
    "action 'deploy' requires 1 approval(s) from the configured approvers"
  ]
}
```

Run the complete reproducible demo:

```powershell
.\scripts\demo.ps1
```

Run the 27-case adversarial conformance suite and save a receipt:

```powershell
permitmesh conformance examples\conformance-suite.json `
  --receipt validation\conformance-local.json
```

The suite covers subject and channel mismatch, unknown and malformed actions,
root-anchored path and ref glob edges, traversal and non-canonical paths,
duplicate JSON keys, exact decimal budgets, malformed approvals, stale claims
and fences, exact high-risk operation binding, replayed operation nonces,
validity boundaries, unknown fields, non-finite input, and required completion
evidence. The runner also rejects oversized files, deeply nested JSON,
unbounded case collections, ambiguous fixture paths, and unknown suite fields
before they can become an authorization or receipt claim.

## How it fits

```mermaid
flowchart LR
    O["Owner or maintainer"] -->|"issues permit"| C["PermitMesh contract"]
    A["Agent action request"] --> E["Deterministic evaluator"]
    C --> E
    E -->|"allow"| X["Agent runtime executes"]
    E -->|"deny + reasons"| H["Human / agent revises scope"]
    X --> R["Integration-supplied event / receipt"]
    R -.->|"optional signed transport"| B["Buzz / Nostr relay"]
```

PermitMesh is the policy decision point. The runtime, relay, or tool proxy remains the enforcement point. A JSON file sitting beside an unrestricted agent does not enforce anything.

## Commands

```text
permitmesh --version
permitmesh validate <contract>
permitmesh digest <contract>
permitmesh authorize <contract> <request> [--evaluation-time RFC3339]
permitmesh verify-completion <contract> <report> [--evaluation-time RFC3339]
permitmesh to-event <contract> [--created-at UNIX_SECONDS]
permitmesh conformance <suite> [--receipt PATH] [--enforcement-boundary TEXT]
```

All decision output is JSON. Exit codes are `0` for success/allow, `2` for
malformed input or an invalid contract, `3` for a well-formed but denied
request, and `4` for a conformance suite with failed cases.

`--evaluation-time` exists for deterministic tests, replay, and trusted enforcement adapters. Never populate it from an agent-controlled field.

## Contract surface

The v0.2 contract, request, completion-report, and conformance-receipt schemas
live in [`schema/`](schema). The reference evaluator additionally checks
cross-document and semantic rules JSON Schema cannot express cleanly:

- the validity window is ordered and active;
- paths and path patterns are relative and traversal-free, with ambiguous
  Windows drive, ADS, reserved-name, trailing-dot/space, and DOS short-name
  spellings rejected;
- path and ref globs are root-anchored; `*` matches one segment and `**`
  recursively matches segments;
- deny patterns override allow patterns;
- repository and ref scope match;
- consumption stays within declared budgets;
- the live claim and fencing generation match;
- high-risk actions match a preapproved action, tool, arguments digest, and
  one-time nonce;
- approval thresholds are possible and satisfied.

In v0.2, `shell`, `test`, `commit`, `deploy`, `publish`, and `spend` are
high-risk capabilities and require that exact operation binding.

The strict loader rejects duplicate object keys, non-standard numeric
constants, oversized files, excessive nesting, and excessive structure while
preserving decimal precision for budget comparisons. Contract collections,
path patterns, request fields, completion evidence, and conformance cases have
explicit deterministic bounds. The digest is SHA-256 over bounded canonical
JSON with `signature` and `contract_digest` excluded. This digest binds
receipts and transport adapters to the effective policy document; it does not
prove authorship. `permitmesh digest` refuses structurally invalid contracts.

## Buzz/Nostr adapter

```powershell
python -m permitmesh to-event examples\contract.valid.json --created-at 1784800000
```

This emits an envelope containing a NIP-78-style kind `30078` template with a deterministic `d` tag and contract digest. The issuer `pubkey` is present while `id` and `sig` are deliberately blank. A Buzz/Nostr integration must compute the NIP-01 event ID, sign with the issuer's key, and validate that signature before treating it as authorization.

The adapter is exploratory. An upstream design conversation should decide whether capability contracts belong in application data, a Buzz-specific kind, or a broader NIP.

## Trust boundaries

- PermitMesh 0.2 validates policy; it does not sandbox tools.
- Signature metadata may be carried, but the reference CLI does not verify signatures yet.
- `request.at` is receipt metadata only and never controls authorization time. The evaluator uses its own clock; a production adapter must ensure that clock is trustworthy.
- A fencing generation is useful only if the resource being protected rejects stale generations.
- High-risk authorization requires explicit consumed-nonce state. The Python
  evaluator checks that state but does not mutate it. A real enforcement point
  must atomically reserve or consume the approved nonce and execute the exact
  tool-and-arguments operation, or another worker could reuse the same
  authorization decision.
- A relay storing a permit does not imply that an execution runtime enforced it.
- Resource bounds protect the reference process from accidental or adversarial
  input amplification, but they are not a substitute for process-level memory,
  CPU, and request-size controls at a production adapter.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the explicit boundary.

## Development

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

CI exercises maintained Python 3.11-3.14 runtimes on explicit Ubuntu and
Windows runner generations, enforces branch coverage, scans source and
workflows, verifies two byte-identical builds, and installs the resulting wheel
into a clean consumer environment. Tag pushes build candidates only. PyPI and
GitHub publication require an explicit manual dispatch on the selected tag,
the `JalenBuildsHub` release actor, the protected `pypi` environment,
provenance attestation, and every prior gate.

## Guarded maintenance workflow

The reusable Nymrel maintenance worker separates authority into three jobs:

1. a read-only admission job applies draft-PR backpressure;
2. a read-only Copilot reasoning job can inspect and edit files but has no
   shell, network, delegation, or GitHub write tools; and
3. a non-AI publisher independently reapplies the immutable patch guard before
   it can push one unique branch and open a draft pull request.

The worker pins its runner, Node runtime, npm, Copilot CLI, and third-party
actions. Its same-repository caller pins both the reusable worker and
`guard_ref` to one reviewed immutable PermitMesh commit. The worker loads the
guard from that exact commit, rejects protected paths and receipt-injecting filenames, and never copies the untrusted
agent transcript into the pull-request receipt. It does not merge, deploy,
release, publish packages, or bypass maintainer review.

## What success means

Stars are discovery, not success. The initial North Star is **verified external authorization runs**: an external maintainer executes both an allowed and a deliberately denied action against their own real agent workflow, retains the decision receipt, and reports whether the result matched intent.

The first target is five verified runs across at least two external teams, with zero known false allows.

See [docs/NORTH_STAR.md](docs/NORTH_STAR.md) for the evidence, anti-goals, and staged campaign.
External maintainers can [report a conformance run](https://github.com/nymrel/PermitMesh/issues/new?template=conformance-run.yml)
after removing secrets and sensitive workspace details.

## Project status

PermitMesh is an independent [Nymrel](https://nymrel.com) experiment. The
source repository is public, but the 0.2.0 distribution is not published on
PyPI and has no GitHub release. External adoption, enforcement quality, and
false-allow rates remain unproven. A Buzz design discussion and any package
publication remain gated on independent reproduction and explicit operator
approval; repository availability alone does not justify an upstream proposal.

Apache-2.0.
