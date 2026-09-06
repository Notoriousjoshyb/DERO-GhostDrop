#!/bin/sh
# Register ghostdrop:// URI handling on Linux (xdg).
set -eu
DESKTOP_FILE="assets/ghostdrop.desktop"
if command -v xdg-mime >/dev/null 2>&1; then
  xdg-mime default ghostdrop.desktop x-scheme-handler/ghostdrop
  echo "Registered ghostdrop:// with $(command -v ghostdrop || echo ghostdrop)"
else
  echo "xdg-mime not found; install xdg-utils" >&2
  exit 1
fi
echo "Source desktop file: $DESKTOP_FILE (install to ~/.local/share/applications/ to persist)"
