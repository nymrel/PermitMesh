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

## Expected allow

```powershell
permitmesh authorize `
  examples/distribution/contract.postiz-draft.json `
  examples/distribution/request.allowed.json `
  --evaluation-time 2026-07-29T06:00:00Z
```

Expected: `allowed: true` when the nonce has not been consumed.

## Expected denial

```powershell
permitmesh authorize `
  examples/distribution/contract.postiz-draft.json `
  examples/distribution/request.denied-tampered.json `
  --evaluation-time 2026-07-29T06:00:00Z
```

Expected: denial because the operation changes the integration, publish mode,
and content fingerprint while attempting to reuse the approved operation nonce.

## Important boundary

PermitMesh remains a policy decision point. It does not connect to Postiz, consume
the nonce, or enforce the decision. The guarded distribution worker is the policy
enforcement point and must fail closed if atomic nonce consumption or receipt
persistence is unavailable.
