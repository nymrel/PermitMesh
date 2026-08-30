# Conformance

The v0.2 conformance suite is a portable set of adversarial policy-decision
cases. It tests the narrow software-change profile; it does not test identity,
signature verification, sandboxing, tool interception, or runtime enforcement.

## Run

```powershell
permitmesh conformance examples\conformance-suite.json `
  --receipt validation\conformance-local.json
```

An adapter that actually blocks tool calls should describe that boundary:

```powershell
permitmesh conformance examples\conformance-suite.json `
  --enforcement-boundary "wrapper checked every protected action"
```

Do not claim a stronger boundary than the run exercised.

`--enforcement-boundary` is a caller declaration recorded in the receipt; the
reference runner cannot verify that declaration. Reviewers must corroborate it
against the adapter and execution evidence before treating it as fact.

## Required cases

The reference suite includes:

- a valid in-scope edit;
- the inclusive `not_before` boundary;
- the exclusive `expires_at` boundary;
- a subject that does not match the contract;
- a channel outside the contract scope;
- unknown and non-string actions;
- parent traversal, dot segments, a missing read path, Windows drive paths,
  root-anchored path globs, and single-segment path/ref glob edges;
- malformed approvals;
- stale claim and stale fencing generation;
- exceeded file, command, and cost budgets;
- unknown request fields;
- a non-standard non-finite JSON number, a duplicate JSON key, and an exact
  decimal budget overage;
- an allowed high-risk action bound to the exact approved operation and an
  unused nonce;
- denial of the same high-risk operation after its nonce is marked consumed;
  and
- complete and incomplete declared validation evidence.

The final case is intentionally malformed JSON. Strict implementations should
reject it before policy evaluation.

The reference runner also bounds JSON files, nesting, canonical structure,
suite cases, expected violation fragments, identifiers, enforcement-boundary
text, and fixture paths. Unknown suite and case fields fail closed. These are
runner safety and receipt-integrity controls, not proof of runtime enforcement.

The reference conformance runner supplies deterministic nonce state to exercise
the decision contract. It does not atomically consume a nonce or execute the
bound tool operation, so a passing receipt remains policy-decision evidence,
not replay-safe enforcement proof.

Completion reports are declarations supplied by a trusted adapter. The
reference evaluator checks that every required command and artifact is named;
it does not execute commands, inspect artifact contents, or authenticate the
reporter.

## External evidence

An external run counts toward the project hypothesis only when:

1. it is tied to a real agent workflow;
2. the reporter runs both allowed and deliberately denied behavior;
3. the enforcement boundary is stated;
4. the redacted receipt is retained;
5. the reporter says whether results matched intent; and
6. any false allow is treated as a release blocker.

Use the repository's conformance issue form. Never upload secrets, private
repository names, personal data, credentials, or sensitive paths.
