# BoundaryLab threat model

## Purpose

BoundaryLab observes selected enforcement properties of an explicitly authorized AI-agent sandbox and produces bounded, reproducible evidence. It is designed to reduce uncertainty about runtime boundaries without becoming an exploit framework or overstating what a test result proves.

## Protected assets

BoundaryLab is intended to help protect:

- host files, processes, devices, kernel interfaces, and orchestration controls;
- neighboring workloads and tenant data;
- credentials, tokens, environment values, and brokered provider access;
- network destinations outside the authorized policy;
- sandbox lifecycle isolation and cleanup;
- the integrity and interpretation of conformance evidence;
- operator budgets and provider resources;
- the reputation and legal authorization of the operator and Nymrel project.

## Actors

### Authorized operator

Owns or has explicit permission to test the selected environment, reviews manifests, supplies provider configuration, and interprets receipts within their stated claim boundary.

### Sandbox guest

Runs the fixed BoundaryLab observer. In future integrations this environment may also contain untrusted or AI-generated code, but v0.1 probes do not execute such code.

### Runtime or provider

Creates the execution boundary, applies compute and network controls, brokers credentials, exposes logs and metadata, and tears the environment down.

### Malicious repository content

May contain prompt injection, build scripts, vendored code, symlinks, or files intended to influence a coding agent. The v0.1 observer does not inspect or execute repository content.

### Malicious or mistaken operator

May attempt to expand targets, enable public networking, submit third-party systems, exceed approved spend, alter evidence, or misrepresent a passing receipt as certification.

### Compromised dependency or CI runner

May tamper with installed tools, source, artifacts, or runtime configuration. Standard CI minimizes this surface but does not provide a trusted-computing proof.

## Trust boundaries

```text
operator input
  authorization + profile
          │ strict validation and digest
          ▼
BoundaryLab host process
  runner + adapter + evidence writer
          │ fixed argv / bounded control variables
          ▼
sandbox guest
  fixed observer, no repository execution
          │ bounded JSON observations
          ▼
receipt builder
  canonical digest + artifact hashes
          │
          ▼
independent verifier / external signer
```

Separate boundaries also exist between:

- BoundaryLab and PermitMesh policy decisions;
- BoundaryLab and agent-proofchain signing or anchoring;
- the host and provider control plane;
- provider control plane and guest microVM/container;
- guest network namespace and each authorized destination;
- CI bootstrap traffic and BoundaryLab network-probe execution.

## Security assumptions

BoundaryLab v0.1 assumes:

1. The operator owns or is explicitly authorized to test the environment and exact network targets.
2. The BoundaryLab source and Python interpreter used on the host have not already been compromised.
3. Provider SDKs and CLIs perform the documented operations represented by their adapter.
4. Host-side process creation with `shell=False` preserves argument boundaries.
5. SHA-256 collision resistance is adequate for content-integrity comparison.
6. A local filesystem read after receipt creation observes the intended artifact bytes.
7. The fixed guest program is the only code BoundaryLab asks the adapter to execute.
8. A provider may still contain unknown vulnerabilities; observed controls are not complete assurance.

These assumptions must be reconsidered before production admission or remote attestation claims.

## Primary threats and controls

### Unauthorized target expansion

**Threat:** A manifest uses wildcards, CIDRs, URLs, redirects, port ranges, or discovery to turn BoundaryLab into a scanner.

**Controls:** Exact hostname/IP plus one port; strict schema; no URL syntax, wildcards, CIDRs, or ranges; maximum 32 guest targets; no discovery; public-target flag; two explicit execution opt-ins.

**Residual risk:** DNS for an authorized hostname can resolve differently over time. A future profile may need optional resolved-address pinning or a controlled canary identity protocol, but v0.1 does not silently infer trust from DNS.

### Network payload or proxy abuse

**Threat:** A probe sends application data, follows redirects, fingerprints services, or turns a credential route into a proxy.

**Controls:** One `socket.create_connection` attempt, immediate close, one-second timeout, no application payload, no HTTP/TLS client, no redirect logic, no response parsing, safe coarse reason codes.

**Residual risk:** A TCP handshake still creates observable traffic. Operators must use owned targets and applicable provider rules.

### Shell and command injection

**Threat:** User-controlled strings become shell syntax or alter adapter commands.

**Controls:** Argument-vector configuration; `shell=False`; strict length limits; fixed guest program; no arbitrary shell field; no interpolated command text.

**Residual risk:** The authorized command-prefix executable is itself trusted and can interpret later arguments unsafely. The command adapter labels network policy as operator-provided and cannot certify the wrapper.

### Secret disclosure

**Threat:** Environment values, credential files, logs, stack traces, or provider exceptions enter observations or receipts.

**Controls:** Canary probes emit presence booleans only; PID 1 and cgroup text are hashed or summarized; resolver addresses are not emitted; adapters discard stderr and map failures to reason codes; Vercel exceptions are not serialized; evidence stores bounded JSON only.

**Residual risk:** New probes or adapter metadata can introduce sensitive fields. Probe review and fixture tests remain mandatory.

### Host or tenant escape

**Threat:** A probe is weaponized into a container, microVM, kernel, or hypervisor escape.

**Controls:** Public probes use ordinary read-only observations and connection attempts; no exploit payloads, device interaction, namespace entry, ioctl, ptrace, mount, capability use, or host-service commands; Docker uses read-only, cap-drop-all, no-new-privileges, deny-all network, and resource limits.

**Residual risk:** Merely executing Python inside a runtime still exercises the runtime and interpreter. Unknown vulnerabilities may exist. BoundaryLab does not claim elimination of escape risk.

### Resource exhaustion and spend

**Threat:** A run consumes unbounded CPU, memory, processes, output, provider duration, or money.

**Controls:** Manifest ceilings; subprocess timeout; output-size limit; Docker CPU/memory/PID limits; Vercel execution limit; maximum configured concurrency; no implicit Docker pull; zero-cost examples; no provider calls in standard CI.

**Residual risk:** Provider billing semantics may differ, teardown can fail, and the current core does not reconcile actual provider charges. Live provider use requires external spend approval and monitoring.

### Evidence tampering

**Threat:** A receipt or artifact is edited, substituted, truncated, moved outside its run directory, or given ambiguous JSON.

**Controls:** Duplicate-key and non-standard-number rejection; canonical JSON digest; exact top-level receipt schema; safe relative artifact paths; byte size and SHA-256 verification; duplicate artifact rejection; recomputed summary counts.

**Residual risk:** Integrity is not authenticity. An attacker able to replace both source and evidence can generate a new valid unsigned receipt. External signing, identity, transparency, and trusted timestamps belong in agent-proofchain.

### Semantic overclaim

**Threat:** Operators treat an observation-only pass, unsupported control, or narrow profile as complete security certification.

**Controls:** Six states; no scalar score; claim fields explicitly set certification and production admission to false; Markdown wording preserves the boundary; comparison reports status changes only; docs prohibit categorical claims.

**Residual risk:** Downstream consumers can ignore the wording. Future integrations should enforce schema-aware rendering and signed governance decisions.

### CI and supply-chain compromise

**Threat:** Workflow actions, package installation, or a malicious contribution executes unintended network or provider activity.

**Controls:** Pinned action commits; path-scoped workflow; dependency-free runtime; narrow development dependencies; no secrets; no live adapters; no BoundaryLab network opt-ins; no Docker image pulls; compile, lint, type, static-security, unit, build, and wheel-smoke gates.

**Residual risk:** CI bootstrap downloads development tools from package registries. This traffic is distinct from BoundaryLab probe execution but remains a supply-chain dependency.

## Failure behavior

BoundaryLab should fail closed when:

- authorization is malformed, expired, destructive, third-party, or missing the adapter;
- a target is not exact or public-network approval is absent;
- an adapter executable or optional SDK is missing;
- output exceeds the limit or is invalid JSON;
- a guest process times out or exits nonzero;
- a result or artifact is missing;
- receipt integrity does not verify.

Errors use bounded reason codes. Raw provider or process output is not included in the public evidence path.

## Explicit non-goals

BoundaryLab v0.1 does not:

- discover vulnerabilities in application source;
- execute arbitrary repository code;
- generate or deliver exploit payloads;
- prove hypervisor or kernel correctness;
- perform cross-tenant testing;
- replace provider penetration tests or independent security review;
- establish cryptographic runtime identity or remote attestation;
- sign receipts;
- assign a universal provider ranking;
- approve a runtime for production;
- submit security-challenge findings;
- determine legal authorization.

## Required review triggers

A focused security review is mandatory before adding:

- any packet payload beyond a TCP handshake;
- DNS result capture or resolved-address policy;
- repository checkout, build, or execution;
- filesystem-content reads;
- environment-value reads;
- provider credential injection into a guest;
- persistent sandboxes or snapshots;
- concurrency greater than the current validated bounds;
- host mounts, devices, elevated capabilities, or privileged containers;
- kernel, hypervisor, container-runtime, or orchestration probes;
- production-admission automation;
- receipt signing, identity, or transparency claims.
