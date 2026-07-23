# Buzz release-candidate commit signatures

Verified locally with `git verify-commit` on 2026-07-23:

- implementation `7272fa1683cb584ded360eee32e6bc0deecd11a1`: good
  ED25519 signature for `contact@jalenbuilds.com`, key fingerprint
  `SHA256:z01OUOJhHHUQq2e5vHkFpFxxp5GOnfMZ6XZ+K7EtUj4`;
- proof `06952d66ccea946b45c056eca2ad61c520b8297b`: good ED25519
  signature for the same principal and key.
- signature evidence `9a8e14ec6b9c866e532bcc375750d89ccff4bac5`: good
  ED25519 signature for the same principal and key.

First-parent linkage:

- `06952d66ccea946b45c056eca2ad61c520b8297b` has implementation commit
  `7272fa1683cb584ded360eee32e6bc0deecd11a1` as its sole parent;
- `9a8e14ec6b9c866e532bcc375750d89ccff4bac5` has proof commit
  `06952d66ccea946b45c056eca2ad61c520b8297b` as its sole parent.

This records local cryptographic verification. GitHub's account-level signing
key registration and branch required-signature rule are separate repository
governance checks.
