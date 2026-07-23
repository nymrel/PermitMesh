# Buzz adapter council proof

Implementation commit: `12bdc359abc7ba7f09e2e16ac76b76d691e2fc38`

Validated locally on 2026-07-23:

- 92/92 unit tests passed.
- 36/36 portable conformance cases passed.
- Ruff format/check, mypy, Bandit, and compileall passed.
- Source distribution and wheel built successfully.
- A new virtual environment installed the wheel without an index or
  dependencies, then the installed `permitmesh` executable allowed the valid
  authenticated Buzz-context fixture.

Buzz-specific tests cover strict fields and types, contract/owner/agent/work
binding, NIP-OA and protection assertions, five-minute freshness, future time,
HMAC failure, configured-community substitution, repository-announcement
substitution, URI/time schema-runtime alignment, malformed identifiers, and
the packaged CLI. Additional council-requested cases prove that a missing or
naive trusted evaluator time fails closed, repository/ref/channel aliases do
not expand scope, Buzz context cannot bypass core deny rules, and composition
preserves exact high-risk operation binding.

The full machine receipt is `validation/conformance-buzz-local.json`, SHA-256
`d0b7542a7f4a36fa275b055310184e295a46d237e6b7dae42d096bbdba0939c3`.
