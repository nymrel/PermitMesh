# Nymrel Distribution Spine Integration

Status: Phase 1 integration design; no Distribution Spine enforcement adapter is implemented here. PermitMesh remains a policy decision point. It does not authenticate Postiz, store OAuth credentials, consume nonces, intercept tools, schedule posts, publish content, or prove that the execution boundary honored a decision.

## Purpose

The Distribution Spine uses PermitMesh for consequential campaign operations after product truth, content generation, and human review are complete.

Recommended action split:

| Distribution operation | PermitMesh action | Approval | Exact operation binding |
| --- | --- | --- | --- |
| Read product context | `read` | normally no | no |
| Draft campaign or copy | `edit` | normally no | no |
| Run campaign validation | `test` | policy-dependent | yes |
| Commit approved campaign metadata | `commit` | policy-dependent | yes |
| Create a Postiz draft | `publish` | recommended | yes |
| Schedule a Postiz post | `publish` | required | yes |
| Publish immediately | `publish` | required and normally prohibited | yes |
| Change paid media budget | `spend` | required | yes |
| Contact a creator or lead | implementation-defined external-contact action | required | exact binding required by the enforcement layer |

A real enforcement adapter may use a narrower action vocabulary than the reference profile, but it must not weaken exact operation binding for schedule, publish, spend, or contact effects.

## Campaign-to-contract mapping

A campaign permit should bind at least:

- subject identity supplied by the trusted host;
- product ID;
- campaign ID;
- exact SHA-256 campaign revision hash;
- content ID;
- destination integration ID;
- platform identifier;
- operation type (`draft`, `schedule`, or `publish`);
- scheduled timestamp and timezone when applicable;
- destination URL and attribution parameters;
- media object IDs or immutable media digests;
- file, command, time, and cost limits;
- approval threshold and allowed approvers;
- active claim ID and fencing generation;
- one-time operation nonce;
- required completion evidence.

The operation digest should cover the exact tool name and canonicalized arguments sent to the enforcement point. A general approval such as “publish the campaign” is insufficient.

## Recommended contract shape

The surrounding integration should issue a short-lived permit with a narrow repository and channel scope. Conceptually:

```json
{
  "scope": {
    "repositories": [
      {
        "name": "goviral",
        "refs": ["campaign/launch-001"],
        "allow_paths": ["campaigns/launch-001/**"],
        "deny_paths": [".env", "**/secrets/**"]
      }
    ],
    "channels": ["nymrel/distribution/goviral/launch-001"]
  },
  "capabilities": ["read", "edit", "test", "commit", "publish"],
  "approval_gates": [
    {
      "actions": ["publish"],
      "min_approvals": 1,
      "approvers": ["<trusted-operator-id>"]
    }
  ],
  "lifecycle": {
    "claim_id": "campaign-launch-001",
    "fencing_generation": 1
  },
  "validation": {
    "required_commands": ["validate campaign revision and provider settings"],
    "required_artifacts": ["campaign receipt", "Postiz result", "published URL or failure evidence"]
  }
}
```

This is an explanatory fragment, not a complete signed contract. Production code must construct a schema-valid contract, compute exact operation digests using the PermitMesh implementation, and validate it before use.

## Schedule request

A schedule request should carry the ordinary PermitMesh request fields plus exact campaign context supplied by the enforcement adapter. The request must match:

- the permitted subject;
- active channel;
- product repository and approved ref;
- current claim ID and fencing generation;
- exact action `publish`;
- exact operation digest;
- unused operation nonce;
- approval threshold;
- campaign revision hash approved by the human reviewer;
- future schedule timestamp inside the permit validity window;
- declared command, file, and cost limits.

Any mismatch must deny before Postiz receives a request.

## Enforcement sequence

The tool proxy or Postiz adapter should perform these steps atomically where possible:

1. Receive the exact schedule or publish arguments.
2. Authenticate the caller and load the current active permit.
3. Canonicalize the tool name and arguments.
4. Compute the operation digest.
5. Evaluate the PermitMesh request using a trusted clock.
6. Verify the campaign approval binds to the same revision hash.
7. Atomically reserve the one-time nonce.
8. Recheck the active claim and fencing generation at the protected resource.
9. Execute the exact Postiz call.
10. Mark the nonce consumed only under the adapter's defined success/failure transaction policy.
11. Write completion evidence and an Agent ProofChain receipt.
12. Reject stale retries, altered arguments, or duplicate execution.

The current reference evaluator applies operation-constraint and replay-state checks only to its implemented high-risk action category; `publish` is outside that category today. Therefore the CLI cannot establish nonce availability, exact distribution-operation enforcement, or provider permission for this design. The future enforcement point must own the authoritative snapshot plus exact binding, atomic reservation, and consumption.

## Fail-closed conditions

The adapter should deny when any of the following is true:

- campaign revision does not match the approved revision;
- selected claim is no longer verified;
- channel is not approved by the product manifest;
- integration or platform differs from the bound operation;
- media or destination URL differs from the approved payload;
- schedule time is outside the permit or campaign window;
- human approval is missing, expired, or from an unapproved actor;
- claim or fencing generation is stale;
- nonce is absent, malformed, reserved, or consumed;
- operation digest differs;
- spend or command budget would be exceeded;
- completion evidence requirements cannot be satisfied;
- the Postiz credential belongs to another tenant.

## Completion evidence

A successful schedule or publish report should include privacy-safe references to:

- PermitMesh contract digest;
- decision receipt or evaluation output;
- consumed nonce record;
- campaign ID and revision hash;
- content ID;
- Postiz integration and post IDs;
- requested and observed schedule timestamps;
- published URL when available;
- Agent ProofChain receipt;
- studio event ID;
- redacted failure code when unsuccessful.

Do not include OAuth tokens, API keys, raw private post content, customer records, payment details, or unrestricted provider responses.

## Limits

This integration does not claim that PermitMesh:

- authenticates the issuer or subject;
- verifies signatures in the current reference CLI;
- sandboxes the Postiz client;
- intercepts or enforces tool calls by itself;
- atomically consumes nonces;
- guarantees prompt-injection detection;
- is an adopted standard or security certification.
