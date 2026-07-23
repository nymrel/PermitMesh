# OSS Growth and Provider Readiness

> INTERNAL READINESS CONTROL - NOT AN APPLICATION OR OUTREACH PLAN

- As of: 2026-07-23
- Repository: `JalenBuildsHub/PermitMesh`
- Independence: PermitMesh is an independent Apache-2.0 project. It is
  complementary to Buzz but is not a Buzz fork, Block project, MeshLLM
  component, or endorsed integration.
- Global hold: do not submit applications, publish packages or campaign
  materials, post, tag, or contact anyone until the existing signing and
  council gates pass.

## Public evidence target

The minimum evidence package for the next public-readiness decision is:

1. Five verified external authorization runs across at least two independent
   teams.
2. Zero known false allows across the entire public receipt set.
3. Every qualifying run contains at least one intentionally allowed and one
   intentionally denied decision.
4. Every run has a schema-valid
   `permitmesh_adoption_receipt.v1`, redacted artifacts, digests, a passed
   secret scan, and an independently attributable maintainer confirmation.
5. Contributor evidence is reported separately: external merged pull requests,
   external issue or design reviews that change a decision, and unique external
   contributors. Bots and Jalen Studio identities do not count.
6. Adoption evidence is reported without inflating stars, page views, internal
   demos, prereleases, synthetic CI, or repeat runs from the same unchanged
   workflow into adoption.

The receipt contract is
[`schema/permitmesh-adoption-receipt.schema.json`](../schema/permitmesh-adoption-receipt.schema.json).
The bundled example is deliberately `draft` and nonqualifying.

## Current public evidence

Snapshot taken from the public GitHub API and PyPI on 2026-07-23:

| Signal | Current | Readiness interpretation |
| --- | ---: | --- |
| Verified external authorization runs | 0 | target is 5 |
| Independent external teams | 0 | target is at least 2 |
| Known false allows | 0 | guardrail passes, but there are no external runs |
| GitHub stars | 0 | context only; never a North Star metric |
| GitHub forks | 0 | no external fork evidence |
| Human repository contributors | 1 | Jalen Studio only |
| External merged contributors | 0 | no contributor adoption evidence |
| Published PyPI package | no | PyPI project lookup returned 404 |
| Public GitHub releases | 2 prereleases | release activity, not adoption |
| OpenSSF criticality score | not verified | cannot claim the Anthropic threshold |

This evidence does not support an adoption claim or a strong OSS-benefit
application today.

## Application-readiness matrix

| Route | Current status | Criteria already met | Missing or disqualifying evidence | Submit gate |
| --- | --- | --- | --- | --- |
| OpenAI Codex for Open Source | **Not ready** | active public Apache-2.0 project; primary maintainer; real maintenance work | no meaningful usage, broad adoption, or demonstrated ecosystem importance; OpenAI Organization ID and final API plan are account facts | signing + council pass; 5 runs / 2 teams; contributor/adoption receipts; account facts verified |
| OpenAI Researcher Access | **Route mismatch / not ready** | authorization safety could become a real research topic | current lane is product and OSS validation, not a defined research study; no verified research protocol, applicant affiliation, publication plan, or participant/data controls | only a genuine qualifying research project may reopen this route |
| Anthropic Claude for OSS | **Thresholds not met** | active maintainer of a public OSS repository | 0 dependent repos/packages/downloads verified; 0 qualifying external contributors; no qualifying OpenSSF score; no evidence of 100 external merged PRs by the applicant | independently verify at least one published threshold and pass global gates |
| AWS Cloud Credits for Open Source | **Not currently eligible / weak** | Apache-2.0 is OSI approved; project is actively maintained | repository is currently single-studio dominated, has no active external community, and has no demonstrated AWS customer/complement relevance or cost plan | multi-entity community evidence, AWS workload/cost plan, and global gates |
| AWS Activate Founders | **Potentially eligible; facts missing** | public working software and a public studio website exist | legal entity age, funding stage, prior credits, paid-tier AWS account, and intended workload are not verified in this packet | operator verifies company/account facts and a costed workload after global gates |
| Google for Startups Cloud Program | **Potential route; facts missing** | working MVP evidence exists | clear business model, venture intent/funding tier, matching company-domain email, billing ID, prior credits, and Google Cloud architecture are not verified | company/account facts and a costed workload verified after global gates |
| Microsoft for Startups | **Potential route; facts missing** | public software and studio identity exist | current program tier, company eligibility, account/credit history, and Azure architecture are not verified | refresh portal criteria and verify company/account facts after global gates |

## Official criteria snapshot

- [OpenAI Codex for Open Source](https://openai.com/form/codex-for-oss/)
  accepts active maintainers and reviews meaningful usage, broad adoption,
  ecosystem importance, and active maintenance. Selected maintainers may
  receive six months of ChatGPT Pro, API credits, and conditional Codex
  Security access.
- [OpenAI Researcher Access](https://openai.com/form/researcher-access-program/)
  supports research on responsible AI deployment, risk mitigation, and
  societal impact with up to $1,000 in API credits for 12 months.
- [Anthropic Claude for Open Source](https://claude.com/contact-sales/claude-for-oss)
  publishes alternative thresholds: 500 dependent repositories, 100 dependent
  packages, 200,000 combined monthly downloads, recognized core-project
  maintainership, 100 external merged PRs in 12 months, 20 unique external
  contributors in 12 months, or OpenSSF criticality at least 0.4.
- [AWS Cloud Credits for Open Source](https://aws.amazon.com/blogs/opensource/aws-cloud-credits-for-open-source-projects-affirming-our-commitment/)
  requires an OSI-approved license, no single-vendor or VC domination, active
  maintenance, and community engagement; AWS favors projects relevant to its
  customers or technical ecosystem.
- [AWS Activate](https://aws.amazon.com/startups/credits/) currently describes
  a self-funded Founders tier and a provider-backed Portfolio tier, with
  company age, funding, account, and prior-credit conditions.
- [Google for Startups Cloud Program](https://cloud.google.com/startup/faq)
  describes Start and Scale tiers, requires account and company-domain
  alignment, and excludes several organization types.
- [Microsoft for Startups](https://www.microsoft.com/en-us/startups) currently
  advertises startup credits and tools but leaves exact eligibility and tier
  assignment to the current program flow.

Criteria drift. Refresh every official page immediately before any future
submission. A draft is not permission to submit.

## Evidence and growth loop

### Before the global gate clears

- Maintain test, conformance, signature, and threat-model proof.
- Keep draft packets current when criteria materially change.
- Do not recruit, announce, publish a package, or seek provider attention.
- Count no internal or synthetic event as external adoption.

### After the global gate clears

1. Invite one bounded external team to run the clean-install allowed/denied
   workflow.
2. Generate a draft adoption receipt locally and let the external maintainer
   confirm the public/redacted evidence.
3. Validate the receipt, scan it for secrets, then mark it verified.
4. Repeat across a second independent team before optimizing outreach volume.
5. Stop immediately on any false allow and repair the authorization boundary
   before collecting more runs.

## Decision

| Option | Weight | Decision |
| --- | ---: | --- |
| Evidence-first external pilot after signing and council approval | 70% | **Recommended and long-term winner** |
| Internal company/account fact audit for startup-credit routes | 20% | useful only after global gates; no submission |
| Keep the current local-only state indefinitely | 10% | safe but loses the external validation opportunity |
| Apply or campaign now | 0% | weak evidence and explicit gates make this invalid |

Exact next move: register the configured GitHub SSH signing key through the
operator-approved account surface, verify the public signature on the exact
candidate commit, then rerun the full-context publication council. Only if
both pass should the first external-team pilot begin.
