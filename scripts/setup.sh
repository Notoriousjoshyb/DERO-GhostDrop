#!/usr/bin/env bash
# Ghostdrop setup (Linux/macOS). Detects Go >= 1.24, OS package manager, and deps.
set -euo pipefail

MIN_GO="1.24"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

have() { command -v "$1" >/dev/null 2>&1; }

detect_pm() {
  if have apt-get; then echo "apt (sudo apt-get install -y golang git)";
  elif have dnf; then echo "dnf (sudo dnf install -y golang git)";
  elif have yum; then echo "yum (sudo yum install -y golang git)";
  elif have pacman; then echo "pacman (sudo pacman -S --noconfirm go git)";
  elif have zypper; then echo "zypper (sudo zypper install -y go git)";
  elif have brew; then echo "brew (brew install go git)";
  else echo "unknown (install Go >= 1.24 and git manually: https://go.dev/dl/)"; fi
}

echo "==> Ghostdrop setup"
echo "    OS: $(uname -s) $(uname -m)"

if ! have go; then
  echo "ERROR: 'go' not found on PATH."
  echo "  Your package manager: $(detect_pm)"
  exit 1
fi

GOVER="$(go version | awk '{print $3}' | sed 's/^go//')"
echo "    go: $GOVER ($(command -v go))"
if ! printf '%s\n%s\n' "$MIN_GO" "$GOVER" | sort -V -C -r 2>/dev/null; then
  # portable fallback comparison
  if [ "$(printf '%s\n%s' "$MIN_GO" "$GOVER" | sort -V | head -n1)" != "$MIN_GO" ]; then
    echo "ERROR: Go >= $MIN_GO required (found $GOVER). See https://go.dev/dl/"
    echo "  Your package manager: $(detect_pm)"
    exit 1
  fi
fi

for t in git; do
  if ! have "$t"; then echo "WARNING: '$t' missing — install via: $(detect_pm)"; fi
done

if have brew; then echo "    brew: present"; fi

echo "==> go mod download"
go mod download
echo "==> go mod tidy (allowed adds: uuid, go-qrcode, x/crypto, modernc.org/sqlite)"
go mod tidy
echo "OK: setup complete. Next: bash scripts/build.sh"
