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

The enforcement point must still authenticate the caller, provide trusted
time and usage state, enforce current fencing, and atomically consume a
high-risk operation nonce with execution of the exact evaluated operation.

Source-event verification, protected key storage, persistent nonce state,
atomic tool execution, and end-to-end Buzz integration are not provided by the
reference package.
