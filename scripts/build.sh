#!/usr/bin/env bash
# Ghostdrop build (Linux/macOS). Builds ghostdrop, ghostdrop-cli, ghostdrop-relay into bin/.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
mkdir -p bin

echo "==> building ghostdrop"
go build -trimpath -o bin/ghostdrop ./cmd/ghostdrop
echo "==> building ghostdrop-cli"
go build -trimpath -o bin/ghostdrop-cli ./cmd/ghostdrop-cli
echo "==> building ghostdrop-relay"
go build -trimpath -o bin/ghostdrop-relay ./cmd/ghostdrop-relay

ls -la bin/
echo "OK: build complete."
