# PermitMesh Protocol 0.2

Status: exploratory draft

## Roles

- **Issuer**: the human or system authorized to define the permit.
- **Subject**: the agent whose proposed actions are evaluated.
- **Evaluator**: the deterministic policy decision point.
- **Enforcer**: the runtime, relay, proxy, or tool host that refuses denied actions.
- **Approver**: a configured principal whose approval can satisfy a gate.

## Decision contract

For a structurally valid permit and request, an evaluator returns:

```json
{
  "allowed": false,
  "contract_digest": "<sha256>",
  "reason_codes": ["PATH_DENIED", "APPROVAL_REQUIRED"],
  "violations": ["<human-readable rule violation>"],
  "checks": ["validity_window", "capability", "repository_ref_path"]
}
```

Evaluators should collect all independently observable violations in one pass. This makes a denial useful for both humans and agents and avoids iterative “fix one thing, discover another” loops.

`reason_codes` is the stable machine contract: one semantic predicate maps to one
closed code, duplicates are normalized in first-seen order, and a replay digest
may be computed over implementation version + `allowed` + `contract_digest` +
those codes. Violation wording is diagnostic and may evolve before 1.0 without
changing `reason_codes` when the predicate is unchanged.

## Evaluation order

1. Validate the permit structure and semantic invariants.
2. Establish trusted evaluation time.
3. Bind the request subject to the permit subject.
4. Verify the requested capability.
5. Bind high-risk actions to the approved tool, arguments, and unused nonce.
6. Resolve exact repository, ref, and path scope.
7. Compare cumulative usage to declared budgets.
8. Match the active claim and fencing generation.
9. Verify action-specific approval gates.

Any violation denies the request.

When `scope.channels` is non-empty, an action request must name one configured
channel. The evaluator also binds every request to `subject.id`; a trusted
adapter must authenticate the caller before populating that field.

`read` and `edit` are file-oriented capabilities and require a path. Other
capabilities are repository-level decisions; if an adapter supplies a path, it
is still checked. A shell authorization does not implicitly authorize file
effects—the enforcement adapter must separately evaluate resulting reads or
edits or provide an equivalent trusted interception boundary.

PermitMesh is a domain profile for software-change decisions. It does not
define a new policy language, credential, delegation chain, or enforcement
protocol. An implementation may evaluate the profile directly or translate it
to a general system such as OPA, Cedar, Biscuit, or an OAuth authorization
detail. The translation must preserve fail-closed behavior.

## High-risk operation binding

The `shell`, `test`, `commit`, `deploy`, `publish`, and `spend` capabilities
are high-risk. A contract that grants one of them must include a matching
`operation_constraints` entry containing the action, a one-time nonce, and:

```text
sha256(canonical-json({
  "action": action,
  "operation": {
    "tool": tool,
    "arguments": arguments
  }
}))
```

The request must present the same action, exact tool-and-arguments envelope,
and nonce. The evaluator fails closed when consumed-nonce state is absent or
the nonce is already present.

This is still a PDP boundary. The Python API receives a snapshot of consumed
nonces and does not mutate it; the reference CLI therefore denies high-risk
actions because it has no replay store. A production PEP must atomically
reserve or consume the nonce, confirm the allow decision against that state,
and execute the bound operation. A non-atomic check followed later by
consumption is replayable and must not be described as one-time enforcement.

## Path rules

- Paths use forward-slash-separated repository-relative form.
- Absolute paths, empty segments, `.` segments, and `..` segments are invalid.
- Deny patterns win over allow patterns.
- Patterns are root-anchored and use path-segment-aware glob matching. `*`
  matches within one segment and `**` matches zero or more whole segments.
  Allow matching is case-sensitive. Deny matching is case-insensitive for
  portable safety across Windows and case-sensitive filesystems. For example,
  `README.md` does not match `docs/README.md`, and `src/*` does not match
  `src/package/module.py`; use `**/README.md` or `src/**` for those recursive
  forms.

Repository ref patterns use the same segment rules: `feature/*` matches
`feature/topic` but not `feature/team/topic`; `feature/**` matches both.

Production adapters must preserve these semantics or enforce a strictly
narrower rule. Repository identity comparison and filesystem canonicalization
must remain consistent between evaluation and enforcement.

## Claims and fencing

A `claim_id` states which unit of work owns the action. A monotonically increasing `fencing_generation` makes an older worker distinguishable after transfer or recovery.

The protected resource must compare the supplied generation with its current generation. Including the number in a permit without enforcement at the protected resource does not prevent stale writers.

## Digests and signatures

The contract digest is:

```text
sha256(UTF-8(canonical-json(contract minus signature and contract_digest)))
```

Canonical JSON uses sorted object keys, no insignificant whitespace, normalized
finite decimal numbers, and UTF-8 characters without ASCII escaping. Strict
file parsing rejects duplicate object keys and non-standard numeric constants
before digesting or evaluating a document.

The digest provides stable content identity, not authorship. Signature verification is deliberately outside the 0.2 reference core so integrations cannot accidentally confuse “hash matches” with “authorized issuer signed.”

## Nostr transport experiment

`permitmesh to-event` creates an explicitly unsigned envelope containing a kind `30078` application-data template:

- `d`: `permitmesh:contract:<digest>`
- `t`: `permitmesh`
- `p`: subject public key or principal identifier
- `x`: contract digest
- `content`: canonical contract JSON

The adapter requires lowercase hex Nostr public keys, sets the issuer `pubkey`, leaves `id` and `sig` empty, and labels the outer envelope `unsigned_template`. A Nostr implementation must compute the NIP-01 event ID and create a valid Schnorr signature before publishing the inner event.

## Conformance receipts

`permitmesh conformance` runs deterministic fixtures and emits a 0.2 receipt.
The receipt binds to the canonical suite digest and records:

- implementation name and version;
- expected and observed outcome for every case;
- the decision or malformed-input result;
- pass/fail totals; and
- a caller-supplied description of the actual enforcement boundary.

The receipt is not signed and is not proof that a runtime enforced a decision.
It is reproducible interoperability evidence. Cryptographic authorization
evidence and execution closure records belong to stronger systems such as the
emerging SCITT/WIMSE Permit work.

See `schema/permitmesh-conformance-receipt.schema.json` and
`examples/conformance-suite.json`.

## Completion evidence

`permitmesh verify-completion` checks a declared completion report against
`validation.required_commands` and `validation.required_artifacts`. The report
is bound to subject, claim, fencing generation, and the validity window.

The command checks completeness of the declaration only. It does not execute a
command, hash an artifact, authenticate an approval, or prove that the claimed
evidence is true. A production adapter must obtain those facts from trusted
execution and artifact systems.

## Compatibility questions for upstream discussion

1. Should permits be replaceable application data, a Buzz custom kind, or a new interoperable NIP?
2. Should an agent action carry the permit digest, full permit, or a relay reference?
3. Which actor supplies trusted receipt time for expiry?
4. Should NIP-OA attest owner provenance while PermitMesh constrains each task, or should the formats converge?
5. Where should revocation and the current fencing generation live?
