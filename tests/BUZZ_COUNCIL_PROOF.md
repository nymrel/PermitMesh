# Buzz adapter council proof

Implementation commit: `7272fa1683cb584ded360eee32e6bc0deecd11a1`

Validated locally on 2026-07-23:

- 93/93 unit tests passed.
- 41/41 portable conformance cases passed.
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

The five portable council-regression cases cover omitted and naive evaluator
time, noncanonical work aliases, a core deny-path bypass attempt, and
high-risk operation substitution.

The full machine receipt is `validation/conformance-buzz-local.json`, SHA-256
`a81ca5b811aa156d3bcf3295532aa04865090ec122350c2f2f1c3598ecdf2524`.
