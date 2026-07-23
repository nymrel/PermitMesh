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
4. It emits a strict `permitmesh-buzz-context` document and authenticates the
   full envelope with HMAC-SHA-256 using a key held by the gateway and
   enforcement point. That document must be no more than five minutes old.
5. `permitmesh authorize-buzz` verifies the MAC, binds the configured community
   and repository-announcement event, binds the context owner and agent to the
   contract, binds repository, ref, and channel to the action request, and
   requires a timezone-aware trusted evaluator time.
6. If the decision allows a high-risk action, the policy-enforcement point
   atomically consumes the approved nonce and executes the exact bound
   tool-and-arguments operation.

Example:

```powershell
$env:PERMITMESH_BUZZ_CONTEXT_KEY = "permitmesh-public-conformance-key-not-secret"
permitmesh authorize-buzz `
  examples\contract.valid.json `
  examples\request.allowed.json `
  examples\buzz-context.valid.json `
  --context-key-env PERMITMESH_BUZZ_CONTEXT_KEY `
  --expected-community-uri wss://relay.example.com/permitmesh `
  --expected-repository-event-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --evaluation-time 2026-07-23T12:00:00Z
```

The example key is public conformance data. A deployment must generate and
protect its own key outside the agent's environment.

## Trusted context

The context schema requires:

- the canonical Buzz community endpoint;
- the canonical PermitMesh contract digest;
- the trusted context-producer identity and envelope MAC;
- owner and agent public keys;
- the owner-attestation and repository-announcement event IDs;
- an explicit assertion that NIP-OA verification succeeded;
- repository, ref, and channel bindings;
- an explicit assertion that current protection state was checked; and
- a trusted verification time.

Unknown fields, missing facts, malformed identifiers, a failed MAC, configured
community or repository-event mismatch, stale or future verification,
unchecked protection, an unverified attestation, and every owner/agent/work
binding mismatch fail closed.

`nip_oa_verified` and `protection_checked` are assertions from the integration,
not work performed by the PermitMesh library. An unrestricted agent must never
be allowed to populate this context for itself.

## Optional shared-compute route profile

Buzz now exposes a shared-compute path in which relay members can advertise a
local model and agents can use an automatically selected live model. The
official implementation uses member-signed status notes, a separate MeshLLM
owner key, signatures over member/owner and member/endpoint bindings, current
relay membership for admission, a 120-second routing freshness window, and
locally constrained Iroh transport relays.

PermitMesh remains independent of that runtime. The optional
`authorize-buzz-compute` profile binds a consequential action decision to one
gateway-verified compute route:

```powershell
$env:PERMITMESH_BUZZ_CONTEXT_KEY = "permitmesh-public-conformance-key-not-secret"
permitmesh authorize-buzz-compute `
  examples\contract.valid.json `
  examples\request.allowed.json `
  examples\buzz-context.valid.json `
  examples\buzz-compute-context.valid.json `
  --context-key-env PERMITMESH_BUZZ_CONTEXT_KEY `
  --expected-community-uri wss://relay.example.com/permitmesh `
  --expected-repository-event-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --allowed-compute-member-pubkey eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee `
  --allowed-mesh-owner-id 02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc `
  --allowed-model-id unsloth/gemma-4-26B-A4B-it-GGUF:UD-Q4_K_M `
  --max-input-tokens 2048 `
  --max-output-tokens 512 `
  --evaluation-time 2026-07-23T12:00:00Z
```

The profile intentionally does not claim that community membership is
task-scoped authorization, that a serving member cannot read prompts, or that
an advertised model ID proves which weights executed. It records
`prompt_visibility=serving_member` and
`model_integrity=advertised_only` so integrations cannot silently upgrade
those claims.

## Layer ownership

| Layer | Responsible component | PermitMesh claim |
| --- | --- | --- |
| Nostr event integrity and signature | Buzz/Nostr integration | Not implemented |
| Context-producer authentication | Buzz gateway plus enforcement point | HMAC envelope verification implemented |
| Owner-agent provenance | NIP-OA verifier | Required as a trusted fact |
| Repository hosting and protection | Buzz relay and `buzz-protect` | Required as a fresh trusted fact |
| Task path, capability, budget, approval, claim, and fence policy | PermitMesh evaluator | Implemented as a policy decision |
| Nonce consumption and tool execution | Tool or git enforcement point | Not implemented |
| Durable execution receipt | Integration | Declared receipt checks only |
| Mesh membership, status, owner, endpoint, and transport verification | Buzz/MeshLLM integration | Required as fresh trusted facts |
| Allowed serving members, owner IDs, model IDs, and token ceilings | PermitMesh evaluator | Implemented as a policy decision |
| Prompt secrecy from the serving member and model-weight attestation | Deployment/runtime | Not claimed |

## Conformance proof

The portable suite includes nine Buzz-context cases:

- allow a valid, freshly verified binding;
- deny an unverified NIP-OA relationship;
- deny an owner mismatch;
- deny unchecked repository protection;
- deny a ref mismatch;
- deny an unknown context field;
- deny an invalid context-producer MAC;
- deny community substitution; and
- deny repository-announcement substitution.

These are policy-decision tests, not evidence that a real relay or tool runtime
enforced the result.

## Current upstream fit

As of 2026-07-23, Buzz documents git hosting and relay-enforced
`buzz-protect`, while its project vision still describes further merge,
approval-execution, and job-coordination work. The repository contains job
protocol constants and readers, but the PermitMesh integration does not depend
on a job-event emitter.

The official shared-compute implementation was reviewed at Buzz main commit
`5afa16157a63c71f2cd8a80aa7276de28ce1c54c`; its mesh feature entered through
commit `54638ff4bb5af2d3d3759b44118b43052f814bb1` and pins MeshLLM `v0.73.1`.
The source is stronger than the launch copy about endpoint and membership
binding, while remaining explicit that prompts are visible to the serving
member and model identity is advertised rather than weight-attested.

That makes the compatibility adapter the bounded near-term wedge. A new event
kind or upstream protocol proposal should wait for independent reproductions
and a design-first discussion under Buzz's contribution process.

Primary references:

- [Buzz project vision](https://github.com/block/buzz/blob/main/VISION_PROJECTS.md)
- [NIP-OA](https://github.com/block/buzz/blob/main/docs/nips/NIP-OA.md)
- [Buzz contribution guide](https://github.com/block/buzz/blob/main/CONTRIBUTING.md)
- [Buzz shared-compute development proof](https://github.com/block/buzz/blob/main/docs/buzz-shared-compute-dev.md)
- [Buzz mesh vision](https://github.com/block/buzz/blob/main/VISION_MESH.md)
- [Buzz mesh discovery](https://github.com/block/buzz/blob/main/desktop/src-tauri/src/mesh_llm/discovery.rs)
- [Buzz mesh transport policy](https://github.com/block/buzz/blob/main/desktop/src-tauri/src/mesh_llm/transport_policy.rs)
