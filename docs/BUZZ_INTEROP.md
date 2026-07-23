# Buzz interoperability profile

> HYPOTHESIS - NOT ADOPTED

Status: local compatibility experiment; independent of and not endorsed by
Block or Buzz.

## Why this boundary

Buzz already has signed human and agent identities, git hosting, repository
announcements, NIP-OA owner attestations, and relay-side `buzz-protect` rules.
PermitMesh does not replace those layers. It tests a narrower question:

> Can a tool or git gateway bind Buzz identity and repository facts to an exact
> software-work permit before a consequential action executes?

The first adapter therefore uses existing Buzz facts. It does not introduce a
new Buzz event kind, ask the relay to evaluate PermitMesh policy, or treat
identity provenance as task authorization.

## Integration sequence

1. A trusted Buzz integration selects the community and repository.
2. It obtains the repository announcement and the owner's NIP-OA attestation.
3. It verifies NIP-01 event IDs and signatures, validates the owner-agent
   relationship under NIP-OA, and checks current repository protection state.
4. It emits a strict `permitmesh-buzz-context` document. That document must be
   no more than five minutes old when evaluated.
5. `permitmesh authorize-buzz` binds the context owner and agent to the
   contract, and the context repository, ref, and channel to the action request.
6. If the decision allows a high-risk action, the policy-enforcement point
   atomically consumes the approved nonce and executes the exact bound
   tool-and-arguments operation.

Example:

```powershell
permitmesh authorize-buzz `
  examples\contract.valid.json `
  examples\request.allowed.json `
  examples\buzz-context.valid.json `
  --evaluation-time 2026-07-23T12:00:00Z
```

## Trusted context

The context schema requires:

- the Buzz community URI;
- the canonical PermitMesh contract digest;
- owner and agent public keys;
- the owner-attestation and repository-announcement event IDs;
- an explicit assertion that NIP-OA verification succeeded;
- repository, ref, and channel bindings;
- an explicit assertion that current protection state was checked; and
- a trusted verification time.

Unknown fields, missing facts, malformed identifiers, stale or future
verification, unchecked protection, an unverified attestation, and every
owner/agent/work binding mismatch fail closed.

`nip_oa_verified` and `protection_checked` are assertions from the integration,
not work performed by the PermitMesh library. An unrestricted agent must never
be allowed to populate this context for itself.

## Layer ownership

| Layer | Responsible component | PermitMesh claim |
| --- | --- | --- |
| Nostr event integrity and signature | Buzz/Nostr integration | Not implemented |
| Owner-agent provenance | NIP-OA verifier | Required as a trusted fact |
| Repository hosting and protection | Buzz relay and `buzz-protect` | Required as a fresh trusted fact |
| Task path, capability, budget, approval, claim, and fence policy | PermitMesh evaluator | Implemented as a policy decision |
| Nonce consumption and tool execution | Tool or git enforcement point | Not implemented |
| Durable execution receipt | Integration | Declared receipt checks only |

## Conformance proof

The portable suite includes six Buzz-context cases:

- allow a valid, freshly verified binding;
- deny an unverified NIP-OA relationship;
- deny an owner mismatch;
- deny unchecked repository protection;
- deny a ref mismatch; and
- deny an unknown context field.

These are policy-decision tests, not evidence that a real relay or tool runtime
enforced the result.

## Current upstream fit

As of 2026-07-23, Buzz documents git hosting and relay-enforced
`buzz-protect`, while its project vision still describes further merge,
approval-execution, and job-coordination work. The repository contains job
protocol constants and readers, but the PermitMesh integration does not depend
on a job-event emitter.

That makes the compatibility adapter the bounded near-term wedge. A new event
kind or upstream protocol proposal should wait for independent reproductions
and a design-first discussion under Buzz's contribution process.

Primary references:

- [Buzz project vision](https://github.com/block/buzz/blob/main/VISION_PROJECTS.md)
- [NIP-OA](https://github.com/block/buzz/blob/main/docs/nips/NIP-OA.md)
- [Buzz contribution guide](https://github.com/block/buzz/blob/main/CONTRIBUTING.md)
