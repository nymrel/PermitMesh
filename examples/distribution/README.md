# Nymrel Distribution Publish Profile

This example binds one exact Postiz draft operation to one approval, brand,
integration, content fingerprint, idempotency key, source event, claim, fencing
generation, and one-time nonce.

It demonstrates the separation between:

- **human approval** — the content is approved;
- **PermitMesh decision** — this worker may execute this exact protected action;
- **enforcement** — the AdFunnel worker must atomically consume the nonce and
  execute only the matching Postiz request;
- **evidence** — ProofChain records the decision and resulting Postiz receipt.

## Deterministic policy boundary

```powershell
permitmesh validate examples/distribution/contract.postiz-draft.json
permitmesh authorize `
  examples/distribution/contract.postiz-draft.json `
  examples/distribution/request.allowed.json `
  --evaluation-time 2026-07-29T06:00:00Z
```

The contract validates. These fixtures are design inputs for a future enforcement adapter, not executable provider authorization tests: the current reference evaluator does not apply operation constraints or replay-state checks to `publish`, and the public CLI neither loads nor mutates an authoritative consumed-nonce snapshot, connects to Postiz, nor executes the request. An enforcement point must verify current replay state, exact operation binding, and own atomic reservation/consumption before treating any policy decision as permission to contact a provider.

## Tampered design fixture

```powershell
permitmesh authorize `
  examples/distribution/contract.postiz-draft.json `
  examples/distribution/request.denied-tampered.json `
  --evaluation-time 2026-07-29T06:00:00Z
```

This payload changes the integration, publish mode, and content fingerprint while reusing the nonce. A future guarded distribution worker must reject it before a provider call. Current PermitMesh CLI output for this file is not enforcement evidence.

## Important boundary

PermitMesh remains a policy decision point. It does not connect to Postiz, consume
the nonce, or enforce the decision. The guarded distribution worker is the policy
enforcement point and must fail closed if atomic nonce consumption or receipt
persistence is unavailable.
