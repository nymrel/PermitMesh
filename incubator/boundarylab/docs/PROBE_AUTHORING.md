# Probe authoring guide

BoundaryLab probes are deterministic observations, not exploits. A probe is acceptable only when it can answer a narrowly defined conformance question without exposing sensitive data or becoming a generalized attack primitive.

## Required proposal fields

Before implementation, document:

1. **Probe ID** — stable, lowercase, category-prefixed identifier.
2. **Security property** — the exact runtime claim being observed.
3. **Inputs** — every host, guest, manifest, and environment value consumed.
4. **Operation** — the complete bounded action performed.
5. **Output schema** — the smallest JSON value needed for evaluation.
6. **Sensitive-data analysis** — why the output cannot reveal credentials, contents, identities, addresses, or provider internals beyond the approved claim.
7. **Platform support** — expected behavior on Linux, Windows, macOS, containers, and microVMs as applicable.
8. **Failure mapping** — safe reason codes and when the result is `unsupported`, `untested`, `inconclusive`, or `error`.
9. **False positives and false negatives** — known limitations of the observation.
10. **Resource bound** — duration, output, files, processes, and network effects.
11. **Tests** — deterministic unit and integration fixtures.
12. **Claim language** — the strongest statement the result actually supports.

## Data minimization rules

A probe should prefer, in order:

1. boolean presence;
2. bounded count;
3. enumerated state;
4. one-way digest of a bounded value;
5. narrowly structured metadata.

The public core must not emit:

- environment-variable values;
- credential or token values;
- file contents;
- raw command output;
- raw error messages or stack traces;
- provider logs;
- IP addresses learned from resolver configuration;
- usernames, tenant names, project names, or hostnames unless they are already explicit authorized inputs;
- process command lines;
- unrestricted lists of files, processes, devices, sockets, mounts, or services.

When a digest is used, explain what correlation it permits. A hash can still expose equality across runs and is not anonymization.

## Execution rules

- Use the fixed guest observer or a reviewed, versioned equivalent.
- Never execute a shell expression.
- Never evaluate generated code.
- Never execute repository or dependency scripts as part of a probe.
- Never require elevated capabilities, privileged mode, host namespace entry, host mounts, control sockets, or device access.
- Never write outside an adapter-owned temporary location.
- Do not persist after the adapter exits.
- Bound every loop, collection, read, process, timeout, and output.
- Convert exceptions to coarse reason codes outside the evidence record.

## Network rules

Public v0.1 network probes are intentionally constrained:

- exact authorized hostname or IP;
- one exact port;
- maximum target envelope enforced by the guest;
- one connection attempt per target;
- one-second connection timeout;
- immediate close;
- no application payload;
- no HTTP request, TLS handshake customization, DNS query construction, redirects, proxying, service fingerprinting, banner collection, discovery, wildcard, CIDR, or port range;
- disabled unless the operator passes `--allow-network-probes`;
- public targets additionally require `--allow-public-network`.

A proposal that exceeds these boundaries belongs in a separate reviewed research pack, not the default public registry.

## Result semantics

Use the states precisely:

- `pass`: an executed observation matched its explicit expectation, or an observation-only probe completed and returned its bounded value;
- `fail`: an executed observation contradicted its explicit expectation;
- `unsupported`: the adapter or platform cannot make the observation;
- `untested`: policy or operator choice prevented execution;
- `inconclusive`: execution produced evidence that cannot support a directional verdict;
- `error`: the evidence pipeline malfunctioned.

Do not use `pass` to mean:

- the probe was skipped;
- the runtime returned no data;
- a platform is unsupported;
- no expectation was configured for a policy claim;
- the broader security property is guaranteed.

Observation-only profiles are useful for inventory, but their passes mean only that an observation was collected.

## Stable schema rules

- Probe IDs are API surface. Do not reuse an ID for different semantics.
- Output shape changes require a new probe ID or receipt-schema migration.
- Expectations must use the shared operator set unless a separately reviewed typed operator is added.
- Preserve deterministic JSON types across platforms where possible.
- Normalize only when normalization does not erase a meaningful policy difference.
- Add an explicit reason code rather than serializing an exception.

## Test requirements

Each new probe should include tests for:

- expected pass;
- expected mismatch;
- missing observation;
- unsupported platform or adapter;
- malformed guest output;
- timeout and output bounds when relevant;
- absence of secret values and raw errors;
- receipt serialization and verification;
- Markdown and JUnit interpretation;
- Windows and Linux behavior when the probe is cross-platform;
- network opt-in and exact-target enforcement when relevant.

Standard tests must not perform live provider calls, pull images, use credentials, execute BoundaryLab network probes, or touch public targets. Network behavior should be tested with mocked adapters or an explicitly launched local fixture in a separately approved integration job.

## Review checklist

A reviewer should be able to answer “yes” to every item:

- Is the property narrower than a general vulnerability search?
- Is the action safe against an owned but unexpectedly configured runtime?
- Is every input authorized and bounded?
- Is every output necessary and non-secret?
- Can the probe be interrupted and cleaned up?
- Does failure remain fail-closed?
- Are unsupported and untested distinguishable?
- Can a receipt consumer understand the limitation without reading source?
- Does the probe avoid creating a reusable exploit primitive?
- Do tests prove that no provider/network activity occurs in standard CI?

If any answer is uncertain, keep the probe out of the public registry until the threat model and implementation are revised.
