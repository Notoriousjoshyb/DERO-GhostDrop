#!/usr/bin/env bash
# Ghostdrop test (Linux/macOS). Runs the owned integration + acceptance suite.
# Usage: bash scripts/test.sh   (GHOSTDROP_BIG=1 for the 1 GiB proof)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> go vet (owned tests only)"
go vet ./tests/

echo "==> integration + acceptance (default 64 MiB; GHOSTDROP_BIG=1 -> 1 GiB)"
go test ./tests/ -run 'Integration|Acceptance' -count=1 -v

echo "OK: tests passed."
