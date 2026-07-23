# PermitMesh Launch Campaign

Status: v0.1.1 is public; v0.2.0 security hardening is held for council,
repository-governance review, and release proof before publication

## Positioning

- **Category:** software-change authorization profile and conformance lab
- **One line:** PermitMesh makes repo, path, budget, approval, claim-fence, and required-proof constraints portable across agent runtimes.
- **Proof:** a dependency-free evaluator, 88 unit tests, 36 adversarial
  fixtures, and a machine-readable conformance receipt.
- **Ask:** run it against a real workflow, state what actually enforced the decision, and report false allows or false denies.

## Audience

Primary:

- maintainers experimenting with Goose, Codex, Claude Code, or MCP tools;
- authorization implementers evaluating concrete agent-work profiles;
- open-source teams willing to publish a redacted conformance receipt.

Secondary:

- agent-runtime authors who need a portable policy decision format;
- security engineers working on agent authorization and provenance.

## Launch sequence

1. Publish the release candidate only after the council's prepublication gates pass.
2. Confirm the clean-install demo and CI on the public clone.
3. After council approval, publish one proof-led launch note with the runnable
   conformance command.
4. Tag or personally invite a small, relevant set of maintainers only when the
   message gives them a concrete compatibility reason to engage.
5. Wait for at least one independent maintainer reaction or reproduction.
6. Only then open one design-first Buzz discussion, if the evidence still points there.
7. Publish findings after 10-14 days, including reasons the idea may be wrong.

Do not carpet-post communities, tag unrelated users, ask for stars, or
describe the project as a security sandbox. All posts, tagging, and direct
outreach remain held until the council approves the exact release candidate
and campaign packet.

## X launch draft

### Post 1

AI-agent authorization is becoming a crowded standards field. That is good.

We built one deliberately narrow experiment: a portable software-change
profile for repo, path, budget, approval, claim-fence, and proof constraints.

It is called PermitMesh.

### Post 2

A PermitMesh contract describes:

- exact repos, refs, channels, and paths
- allowed actions
- time, file, command, and cost budgets
- human approval gates
- a live claim + fencing generation
- required validation evidence

One portable JSON document. Deterministic policy decisions.

### Post 3

The demo allows a normal source edit.

Then it denies a deploy for eight reasons at once: wrong ref, forbidden path, exceeded budgets, stale claim, stale fence, and missing approval.

No model decides. No vague “be careful” prompt.

### Post 4

It is a PDP, not a sandbox or enforcement proxy, and it is not affiliated with
Block, Buzz, or a standards body.

The repo includes a candid prior-art matrix and 36-case conformance suite.
We want maintainers to break the profile with real workflows.

## v0.2.0 update draft

PermitMesh v0.2.0 hardens the boundary exposed by our own post-launch testing:
Windows-safe deny matching plus exact action, tool, arguments, and one-time
nonce binding for high-risk operations.

The evaluator checks nonce state but does not consume it. A real enforcement
point must atomically consume the nonce and execute the exact operation.

88 tests; 36/36 conformance. Still a policy-decision profile, not enforcement.

## Upstream discussion draft

**Title:** Design question: task-scoped capability contracts for agent work

Buzz's signed identities and NIP-OA draft establish valuable provenance: an agent authors its own event, and an owner can attest that relationship under bounded event conditions.

We are exploring a complementary work-level contract for constraints that do not fit identity alone: repository/ref/path scope, action capabilities, budgets, approval gates, a live claim and fencing generation, and required validation evidence.

The local proof is transport-neutral and can emit an explicitly unsigned kind-30078 application-data template. We have not assumed that this is the right event kind or that Buzz should adopt the format.

Questions:

1. Is task-level authorization already planned elsewhere in Buzz?
2. Would this fit best as application data, a Buzz-specific event, an extension to owner attestation, or outside the relay entirely?
3. Which component should provide trusted expiry, revocation, and current fencing state?
4. Would a small conformance fixture be useful before any integration proposal?

If the direction is redundant or belongs elsewhere, that answer is useful too.

## Forty-five-second demo script

1. “This permit allows one build agent to edit source and tests on a feature ref.”
2. Run the allowed fixture and point to `"allowed": true`.
3. “Now the agent tries to deploy from main, touches `.env`, exceeds every budget, and presents a stale claim.”
4. Run the denied fixture and scan the eight reasons.
5. “The same contract can be wrapped in a Nostr event, but we deliberately leave it unsigned until a real key adapter signs it.”
6. Close: “Identity tells us who acted. PermitMesh tests whether the action was inside the job.”

## Measurement

The campaign succeeds at five verified external authorization runs across at least two teams, with zero known false allows. Views, likes, reposts, and stars are diagnostic discovery signals only.

## Authority boundary

Jalen authorized continued implementation and a measured, proof-led campaign
on 2026-07-23. Public posts and relevant-user tagging enter scope only after
the council approves the exact release candidate and campaign packet. The Buzz
maintainer discussion remains evidence-gated on one independent maintainer
reaction. Package-registry publication is a separate decision.
