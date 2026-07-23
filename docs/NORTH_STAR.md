# PermitMesh North Star

> HYPOTHESIS - NOT ADOPTED

- Status: draft
- Assessment kind: charter
- Charter version: 0.1
- As of: 2026-07-23
- Project type: open_source
- Owner: Jalen Studio
- Reviewed: latest full-context four-provider publication council is incomplete;
  release and outreach remain held
- Next review: after three external maintainer interviews or 2026-08-06

## Evidence state

| Claim | Class | Source | As of | Verification |
| --- | --- | --- | --- | --- |
| Buzz treats humans and agents as independently keyed members in one signed event workspace. | fact | [Buzz vision](https://github.com/block/buzz/blob/main/VISION.md) | 2026-07-23 | live verified |
| Buzz says tighter agent scoping remains important future work. | fact | [Jack Dorsey's launch post](https://x.com/jack) and project context | 2026-07-23 | operator-provided launch text |
| Buzz's draft NIP-OA constrains event kind and self-declared timestamps but does not enforce wall-clock expiry. | fact | [NIP-OA](https://github.com/block/buzz/blob/main/docs/nips/NIP-OA.md) | 2026-07-23 | live verified |
| Buzz now documents git hosting and relay-enforced `buzz-protect` repository rules. | fact | [Buzz project vision](https://github.com/block/buzz/blob/main/VISION_PROJECTS.md) | 2026-07-23 | live verified |
| Buzz's merge coordination and approval-execution layers remain active work. | fact | [Buzz project vision](https://github.com/block/buzz/blob/main/VISION_PROJECTS.md) | 2026-07-23 | live verified |
| Mature systems and active 2026 Internet-Drafts already cover general policy, identity, task authorization, delegation, approval, and signed receipts. | fact | [Prior-art matrix](PRIOR_ART.md) | 2026-07-23 | primary-source review |
| Exact task permits could improve trustworthy agent participation in Buzz-like workspaces. | inference | protocol gap plus Jalen Studio operating experience | 2026-07-23 | unverified externally |
| PermitMesh can become an interoperable community standard. | aspiration | none yet | 2026-07-23 | unverified |

## North Star

Help open-source maintainers safely delegate real work to agents by making authority narrow, portable, inspectable, and provable at every action boundary.

## Primary beneficiary and progress

- Primary beneficiary: a maintainer allowing AI agents to work in a shared code-and-conversation workspace.
- Job to be done: delegate useful work without granting vague, ambient authority.
- Current struggle: identity and audit logs show who acted, but do not necessarily encode or enforce the exact task boundary.
- Desired progress: express one permit once, enforce it consistently, and retain a decision receipt others can inspect.
- Emotional promise: confidence without constant supervision.

## North Star metric

- Name: Verified external authorization runs
- Definition: a run by someone outside Jalen Studio that evaluates at least one intentionally allowed and one intentionally denied action against a real workflow and retains the receipts.
- Formula: count of qualifying runs, segmented by unique external team.
- Unit: runs and unique teams
- Measurement window: rolling 30 days
- Qualifying event: external maintainer supplies a reproducible contract/request pair or public receipt and confirms the decisions matched intended scope.
- Exclusions: internal demos, synthetic CI-only repeats, stars, page views, duplicate runs by the same team on unchanged policy.
- Data source: planned public conformance receipt directory or issue template.
- Current baseline: 0
- Baseline as of: 2026-07-23
- Target: 5 runs across at least 2 external teams
- Target by: 2026-08-22
- Cadence: weekly
- Guardrails: zero known false allows; no secrets in receipts; no claim of Buzz endorsement; median setup under 10 minutes.
- How this metric can be gamed: friendly users can repeat trivial fixtures or count policy-only examples with no enforcement relevance.
- Worked example: a maintainer runs one allowed source edit and one denied production deploy through their agent proxy, publishes redacted receipts, and confirms both decisions matched intent; this counts as one run.

### Proxy metrics until the source is live

| Proxy | Why it is useful | Retire when |
| --- | --- | --- |
| External maintainer interviews completed | Tests whether the problem is real before integration work | Three maintainers have run the CLI |
| Independent installs from clean environments | Detects packaging and documentation friction | Public conformance receipts exist |
| Upstream design responses | Shows whether the protocol question is legible and relevant | A stable integration venue is chosen |

## Value loop

1. A maintainer expresses a narrow, readable work permit.
2. An agent runtime evaluates every consequential action before execution.
3. Allowed work produces useful output; denied work produces actionable explanations.
4. Signed workspace events and receipts preserve the decision context.
5. Real failures improve the shared schema and conformance tests.

## Durable moat and trust

1. A transport- and model-neutral schema with deterministic conformance behavior.
2. A public corpus of real, redacted policy decisions and edge cases.
3. Maintainer trust earned through explicit limitations, compatibility, and upstream collaboration.

## Principles

- Authorization is work-shaped, not role-shaped.
- Denials explain every discovered violation.
- Identity, permission, enforcement, and audit are separate layers.
- Deny wins; invalid input fails closed.
- Portability matters more than owning the runtime.
- Evidence outranks attention.

## Anti-goals

- Do not build another Slack, agent chat UI, or Buzz fork.
- Do not market JSON validation as sandboxing.
- Do not make GitHub stars the success metric.
- Do not add a hosted control plane before external workflows validate the format.
- Do not imply endorsement or adoption by Block or Buzz.
- Do not handle user funds or agent transactions in the first campaign.

## Three-, five-, and ten-year end state

### Three years

PermitMesh is a small, trusted interoperability layer supported by several agent runtimes and workspace systems, with conformance fixtures and independently verified enforcement adapters.

### Five years

Capability permits, revocations, receipts, and reputation move with agents across self-hosted workspaces. Maintainers can inspect and compare authority the way they inspect a code diff.

### Ten years

Narrow, machine-verifiable authority is a default primitive for human-agent institutions, making ambient credentials and unscoped autonomous execution socially and technically unacceptable.

## Economics or sustainability

- Value exchange: maintainers receive safer delegation; runtimes receive a portable policy boundary; contributors receive an open conformance target.
- Monetization or resource model: open protocol and reference core; potential future paid enforcement, policy authoring, compliance evidence, or hosted revocation only after adoption proof.
- Distribution or adoption wedge: a narrow, runnable software-change profile
  with a fail-closed Buzz compatibility context, offered to agent-runtime and
  authorization maintainers without claiming a new general authorization
  architecture or proposing a new event kind prematurely.
- Sustainability hypothesis: protocol credibility creates consulting or hosted-product opportunities without compromising the open core.

## Roadmap and gates

### Phase 0 — local proof

- Entry evidence: Buzz's identity model and scoping gap are documented.
- Done when: schema, evaluator, Buzz/Nostr event template, threat model, demo, and tests run from a clean checkout.
- Non-goals: relay integration, signatures, public launch, hosted UI.
- Disproof condition: the evaluator cannot distinguish meaningful allowed and denied work without runtime-specific policy.

### Phase 1 — public problem test

- Entry evidence: local proof passes and Jalen approves open-source publication.
- Done when: three external maintainers run the demo and one upstream design discussion produces substantive protocol feedback.
- Non-goals: broad social launch, paid product, production-security claims.
- Disproof condition: maintainers consistently prefer existing runtime-specific policy and see no value in portable receipts.

### Phase 2 — enforcement adapter

- Entry evidence: at least two external teams identify the same integration boundary.
- Done when: one adapter supplies trusted time, verifies signatures, enforces current fencing, and emits a conformance receipt.
- Non-goals: multi-platform adapter matrix.
- Disproof condition: no common enforcement boundary exists across the validated workflows.

## Risks

| Risk | Probability | Control | Evidence that changes the call |
| --- | ---: | --- | --- |
| Buzz implements a native superior model quickly | medium | stay compatible and contribute concepts upstream | accepted upstream design covering task scopes and receipts |
| Policy appears secure but is not enforced | high | repeat PDP vs PEP distinction and build adapter gates | independent end-to-end enforcement test |
| Name or framing fails to resonate | medium | test with maintainers before branding spend | repeated confusion in three interviews |
| Protocol becomes over-generalized | medium | keep the first fixtures code-work specific | external demand for a second domain |
| Attention arrives without adoption | medium | optimize for verified runs, not impressions | sustained external conformance receipts |

## Independent review

- Drafter: Codex, GPT-5.6 Sol
- Requested independent council: Claude Opus 4.8, Gemini via Antigravity,
  Cursor, and GPT-5.6 Sol
- Review record: `reviews/FRONTIER_COUNCIL_REVIEW_20260723.md`
- Council outcome: the earlier bounded review found material conditions, but
  the latest full-context four-provider review is incomplete because two
  provider lanes did not return valid evidence
- Quality score: 76/100 self-assessed charter draft; council publication scores
  ranged from 68 to 88 and were not averaged
- Material disagreement: one reviewer wanted external problem proof before
  public positioning; the owner ruling adopted that caution for Buzz outreach
- Final ruling and owner: Jalen authorized continued implementation on
  2026-07-23; publication, posts, tagging, and outreach remain gated on a
  satisfactory council; the North Star itself remains not adopted

## Next exact campaign

- Completion type: campaign
- Owner or claim expectation: one PermitMesh writer under the live release claim.
- Exact scope: validate the Buzz compatibility adapter, close the council
  gates, then publish the proof and recruit three maintainers. Gate any direct
  Buzz maintainer discussion on one independent reaction.
- Non-goals: production enforcement, public security claims, paid hosting, Buzz fork.
- Validation floor: clean-install CLI demo, all tests passing, schema validation, no false allow in adversarial fixtures, explicit unsigned-event behavior.
- Stop conditions: upstream asks us to stop; name conflict creates material confusion; three maintainers find no portable-policy need; any known false allow remains unresolved.

### 14-day attention campaign

| Window | Outcome | Proof | Stop condition |
| --- | --- | --- | --- |
| Days 0–2 | After council approval, publish a crisp release and 30-second allowed/denied Buzz-context demo | public clone and reproducible CI | clean checkout fails |
| Days 2–5 | Post one visual explanation and invite relevant agent-runtime maintainers to break the policy | runnable fixtures and issue template | messaging implies endorsement |
| Days 3–7 | Onboard three maintainers manually | redacted decision receipts | setup exceeds 10 minutes repeatedly |
| Days 7–10 | Only after one independent reaction, open one design-first Buzz discussion linking the gap, not pitching a product | maintainer response or acknowledged issue/discussion | contribution guidance says another venue |
| Days 10–14 | Publish findings, including what failed, and choose adapter/no-adapter | evidence-backed phase ruling | no repeated integration boundary |

## Change log

| Date | Change | Owner |
| --- | --- | --- |
| 2026-07-23 | Initial hypothesis and local proof campaign | Codex for Jalen Studio |
