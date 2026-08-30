# Threat Model

PermitMesh 0.2 is a policy format and reference decision engine. It becomes a security control only when an enforcement point asks for a decision before every protected action and refuses denied or unverifiable requests.

## Assets

- source code and repository history;
- deployment and publishing authority;
- credentials and private workspace content;
- compute and monetary budgets;
- human approval integrity;
- attribution and audit evidence.

## Adversaries and failures

| Threat | 0.2 control | Remaining risk |
| --- | --- | --- |
| Agent acts outside assigned files | allow/deny path checks | runtime may bypass evaluator |
| Another agent reuses a permit | request subject must match permit subject | enforcer must authenticate the caller before supplying subject identity |
| Agent claims to be in another work channel | configured channels are checked | enforcer must supply a trusted canonical channel identity |
| Agent reuses stale ownership | exact claim plus fencing generation | protected resource must enforce current generation |
| Agent exceeds bounded work | file, command, and cost limits | adapter must supply trustworthy cumulative usage |
| Agent performs consequential action silently | per-action approval thresholds | approval authenticity is adapter-specific |
| Agent swaps tool arguments after approval | high-risk action, tool, and canonical arguments digest | enforcer must execute exactly the evaluated envelope |
| Agent replays an approved high-risk action | one-time operation nonce plus consumed-nonce check | enforcer must atomically consume the nonce with execution |
| Agent fabricates completion evidence | required declarations are checked | adapter must verify command results and artifact integrity |
| Agent backdates an expired permit | request timestamps never control authorization time | adapter must protect the evaluator's clock |
| Permit content is modified | canonical SHA-256 digest | digest alone does not prove issuer identity |
| Forged issuer or approval | no claimed protection in 0.2 core | signature verification is required before production |
| Path traversal and Windows aliases | absolute, parent, ADS, reserved-name, and DOS short-name rejection | symlinks and filesystem canonicalization are enforcer concerns |
| Confused deputy across repos | exact repository/ref/path match | repository identity must be bound to a trusted canonical ID |
| Resource exhaustion through policy input | file, depth, node, collection, pattern, path, and receipt bounds | production adapters still need process and rate limits |
| Repository prompt injection reaches maintenance automation | untrusted-data prompt, tool allowlist, read-only token, immutable patch guard, separate publisher | a maintainer must still review every draft and its semantic correctness |
| Agent output injects a durable receipt | transcript is neither uploaded with the patch nor copied into the pull-request body | provider logs remain an operational trust surface |

## Security invariants

1. Invalid contracts and unknown capabilities fail closed.
2. Deny rules override allow rules.
3. A request subject must match the permit subject.
4. Approval is scoped to configured actions and principals.
5. A request whose fencing generation does not equal the permit's generation
   is denied. Preventing stale writers additionally requires the protected
   resource to enforce its current generation.
6. Every granted high-risk capability is bound to an exact action, tool,
   canonical arguments digest, and unique nonce.
7. High-risk decisions fail closed without explicit consumed-nonce state.
8. The CLI never labels an unsigned event as signed.
9. No marketing claim may describe the reference validator as a sandbox.
10. Bounded malformed input must return a denial or input error rather than an
    uncaught recursion or resource-amplification path.
11. The automated reasoning job cannot run shell commands, access the network,
    delegate, push, or write GitHub state; only the separately guarded publisher
    can open a draft pull request.

## Not yet implemented

- NIP-01 or NIP-OA signature verification;
- revocation distribution;
- protected evaluator clock and relay receipt proofs;
- symlink-safe filesystem enforcement and trusted resolution of any platform aliases before applying the decision;
- integration with Buzz relay, MCP, ACP, Goose, Codex, or Claude Code;
- cumulative budget storage across requests;
- a persistent nonce store or atomic nonce-consumption plus execution boundary;
- formal verification or external security review.
- a general-purpose sandbox for untrusted repository code or test execution in
  the AI reasoning job;
- cryptographic verification that a downloaded reusable-workflow guard was
  authored by Nymrel beyond GitHub's immutable commit object and TLS transport.

These are requirements for any future production or security-boundary use, not
claims provided by the 0.2 reference core.
