# Security Policy

PermitMesh is pre-1.0 experimental software and is not a complete security boundary.

Please report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/nymrel/PermitMesh/security/advisories/new).
Do not include credentials, private repository data, or exploitable
third-party details in a public issue. We aim to acknowledge private reports
within five business days; this is a response target, not a remediation SLA.

## Supported versions

| Version | Security fixes |
| --- | --- |
| `main` / unpublished 0.2.0 candidate | Best effort |
| 0.1.1 and earlier public tags | No |

There is currently no PermitMesh project on PyPI and no GitHub release for
0.2.0. A source checkout, tag, passing local test, or draft pull request is not
a package-release or production-readiness claim.

The following are expected limitations in 0.2 and should not be reported as novel vulnerabilities:

- the core CLI does not verify cryptographic signatures;
- the demo request timestamp is caller-supplied;
- the core does not sandbox tools or enforce decisions;
- subject, channel, approval, usage, claim, fence, and completion facts are
  trusted adapter inputs rather than authenticated by the core;
- cumulative budget storage and revocation are not implemented;
- the core checks caller-supplied consumed-nonce state but does not persist or
  atomically consume nonces with tool execution;
- path checks reject ambiguous Windows spellings, including DOS short-name
  syntax, but a production enforcer must still resolve filesystem aliases and
  symlinks before executing against the evaluated path; and
- input size, depth, node, collection, pattern, and path limits reduce
  amplification risk in the reference process, but production adapters still
  need independent CPU, memory, request-size, and rate limits.

Unexpected false allows, path-matching escapes, operation-binding or replay
bypasses, digest inconsistencies, and misleading signed/unsigned states are in
scope.

The reusable maintenance workflow deliberately gives the AI reasoning job no
shell, network, delegation, or GitHub write tools. A separate publisher only
accepts a bounded patch after loading the guard from the exact reusable-workflow
commit. Bypasses of protected-path checks, immutable guard binding, transcript
isolation, least privilege, draft-only publication, or open-PR backpressure are
also in scope.
