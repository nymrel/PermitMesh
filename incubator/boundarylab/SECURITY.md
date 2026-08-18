# Security policy

BoundaryLab is security-sensitive infrastructure. Please report vulnerabilities privately before public discussion.

## Reporting

Send a concise report to `contact@nymrel.com` with:

- the affected BoundaryLab version or commit;
- the adapter and host/runtime involved;
- a minimal reproduction using systems you own or are explicitly authorized to test;
- the observed impact;
- whether secrets, cross-tenant data, host access, policy bypass, or receipt-integrity failure may be involved;
- any time-sensitive disclosure constraints.

Do not include real credentials, customer data, provider logs containing secrets, or destructive payloads. Use synthetic canaries and redact unrelated data.

Maintainers will acknowledge the report, reproduce it in an isolated environment when possible, classify impact, coordinate remediation, and agree on disclosure timing. No bounty is promised by this repository.

## In scope

Examples include:

- bypass of authorization, expiration, adapter, or network opt-in checks;
- target expansion beyond an exact authorized hostname/IP and port;
- application-payload transmission by a built-in network probe;
- command or shell injection;
- unsafe inheritance or disclosure of environment values and credentials;
- path traversal or artifact substitution in receipt verification;
- canonicalization ambiguity, duplicate-key acceptance, or digest bypass;
- a receipt claiming `pass` for an unexecuted, unsupported, inconclusive, or errored probe;
- live provider execution from standard tests or CI;
- incomplete sandbox teardown or an adapter violating its documented isolation policy;
- sensitive provider exceptions, stdout, stderr, logs, or stack traces entering evidence.

## Out of scope

The following are not authorized by this project:

- testing systems, providers, accounts, projects, or tenants you do not own or lack written permission to test;
- denial of service, resource exhaustion, persistence, phishing, social engineering, or credential attacks;
- automated target discovery, scanning, service fingerprinting, or exploit delivery;
- weaponized kernel, container, hypervisor, or sandbox escape development;
- reports based only on dependency-version matching without a demonstrated BoundaryLab impact;
- claims that a passing profile proves complete sandbox security.

## Safe research rules

- Use a dedicated local or owned test environment.
- Use fake canary secrets only.
- Keep public networking disabled unless the exact target is owned and separately authorized.
- Stop after demonstrating the smallest impact needed for remediation.
- Preserve evidence hashes and timestamps, but remove secret values and unrelated data.
- Do not submit findings to a third-party challenge or bounty through BoundaryLab without that program's authorization and a separate Nymrel governance decision.

## Supported versions

BoundaryLab is currently an unreleased incubator. Security fixes apply to the active draft branch until a standalone release policy is approved.
