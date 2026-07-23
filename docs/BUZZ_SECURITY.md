# Buzz adapter security boundary

PermitMesh remains a policy decision point, not a Buzz verifier or execution
sandbox.

The trusted gateway must verify Nostr event IDs/signatures, NIP-OA
owner-agent provenance, the repository announcement, and current
`buzz-protect` state. It then HMAC-authenticates the canonical context with a
key unavailable to the agent.

PermitMesh verifies that MAC and independently binds:

- the configured community endpoint;
- the configured repository-announcement event ID;
- the canonical permit digest;
- owner and agent public keys;
- repository, ref, and channel; and
- a verification time no more than five minutes old, evaluated against an
  explicitly timezone-aware trusted clock.

## Shared-compute route

`authorize-buzz-compute` adds a second, domain-separated HMAC envelope for a
Buzz shared-compute route. The trusted gateway must verify:

- the current NIP-43 membership snapshot and member-signed mesh status event;
- the MeshLLM owner ID, its verifying key, and the signed member binding;
- the signed binding over the exact advertised endpoint tokens;
- the endpoint token and this machine's locally configured transport policy;
- that MeshLLM owner allowlisting was actually enabled;
- that the selected status event is no more than 120 seconds old; and
- the exact serving member, owner ID, endpoint, advertised model ID, and token
  usage returned by the route.

PermitMesh verifies the compute-context MAC, derives the owner ID from the
verifying key, binds the compute envelope to the base Buzz context and active
contract, applies explicit member/owner/model allowlists, and denies token
usage above configured input or output limits.

This is route provenance for a policy decision, not an inference proxy. The
serving member can see the prompt. Buzz's signed status identifies the
advertised model, but does not attest the model weights that actually ran, so
the only accepted integrity claim is `advertised_only`.

The enforcement point must still authenticate the caller, provide trusted
time and usage state, enforce current fencing, and atomically consume a
high-risk operation nonce with execution of the exact evaluated operation.

Source-event verification, protected key storage, persistent nonce state,
atomic tool execution, prompt redaction, model-weight attestation, transport
inspection, usage-meter verification, and end-to-end Buzz integration are not
provided by the reference package.
