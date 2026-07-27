#!/usr/bin/env bash
# POSIX/bash equivalent of scripts/demo.ps1 for Linux and macOS contributors.
# Mirrors the same five steps and the same exit-code contract so the demo is
# identical across every OS in the CI matrix (ubuntu-latest, windows-latest).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
previous_pythonpath="${PYTHONPATH:-}"
export PYTHONPATH="$repo_root/src"
cd "$repo_root"

cleanup() {
    export PYTHONPATH="$previous_pythonpath"
}
trap cleanup EXIT

echo "1/5 Validate the capability contract"
python -m permitmesh validate examples/contract.valid.json
[ $? -eq 0 ] || { echo "contract validation failed" >&2; exit 1; }

echo
echo "2/5 Authorize an in-scope edit"
python -m permitmesh authorize examples/contract.valid.json examples/request.allowed.json --evaluation-time 2026-07-23T12:00:00Z
[ $? -eq 0 ] || { echo "allowed request was denied" >&2; exit 1; }

echo
echo "3/5 Deny an over-scoped deploy"
set +e
python -m permitmesh authorize examples/contract.valid.json examples/request.denied.json --evaluation-time 2026-07-23T12:00:00Z
denied_status=$?
set -e
[ "$denied_status" -eq 3 ] || { echo "denied request did not return exit code 3" >&2; exit 1; }

echo
echo "4/5 Run the adversarial conformance suite"
python -m permitmesh conformance examples/conformance-suite.json
[ $? -eq 0 ] || { echo "conformance suite failed" >&2; exit 1; }

echo
echo "5/5 Build an explicitly unsigned Nostr event template"
python -m permitmesh to-event examples/contract.valid.json --created-at 1784800000
[ $? -eq 0 ] || { echo "event template generation failed" >&2; exit 1; }

echo
echo "PermitMesh demo passed."
