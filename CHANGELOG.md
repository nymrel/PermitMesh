# Changelog

## Unreleased

- Add a strict, fail-closed Buzz context adapter that binds freshly verified
  NIP-OA owner-agent provenance and repository protection facts to the
  PermitMesh contract and action request.
- Add a trusted-context schema, CLI command, integration guide, and six
  adversarial interoperability fixtures.
- Keep signature, attestation, and `buzz-protect` verification outside the
  reference library and explicitly assigned to the trusted integration.

## 0.2.0 - 2026-07-23

Security-boundary hardening release candidate.

- Treat Windows drive paths as unsafe and apply deny-path matching
  case-insensitively for portable safety.
- Require every granted high-risk capability (`shell`, `test`, `commit`,
  `deploy`, `publish`, and `spend`) to bind an exact action, tool, canonical
  arguments digest, and one-time nonce.
- Require explicit consumed-nonce state and deny replayed high-risk operations.
  The evaluator does not persist or atomically consume that state; a production
  enforcement point must consume the nonce and execute as one protected
  operation.
- Fail closed on noncanonical in-memory contract and operation values.
- Advance the contract, request, completion, and conformance formats to 0.2.
- Expand regression coverage to 75 unit tests and 27 portable conformance
  cases.

## 0.1.1 - 2026-07-23

Post-launch hardening release.

- Fail closed when an action is not a string instead of raising an exception.
- Require nested `scope.channels` and repository `deny_paths` fields at
  runtime, matching the published schema.
- Root-anchor path and ref globs; `*` now stays within one segment and `**`
  provides explicit recursive matching.
- Reject empty and dot path segments.
- Reject duplicate JSON object keys and preserve exact decimal budget values.
- Normalize equivalent decimal spellings in digests; contracts containing
  decimal numbers may therefore have a different digest than 0.1.0.
- Require strict RFC 3339 timestamps and timezone-aware evaluator clocks.
- Preserve a Nostr `created_at` value of zero and reject invalid timestamps.
- Refuse to digest structurally invalid contracts from the CLI.
- Expand regression coverage to 66 unit tests and 24 portable conformance
  cases.

## 0.1.0 - 2026-07-23

Initial experimental public release.
