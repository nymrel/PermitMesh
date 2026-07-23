# Buzz adapter council proof

Implementation commit: `3ec5093d447d4260960687618a36e159a7b83a62`

Validated locally on 2026-07-23:

- 88/88 unit tests passed.
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
the packaged CLI.

The full machine receipt is `validation/conformance-buzz-local.json`, SHA-256
`dfca6f9ea962e5286a89c9ad438f1b242e5bb66c7045dded7b93eae7468ba16f`.
