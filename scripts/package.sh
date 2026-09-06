#!/usr/bin/env bash
# Ghostdrop packaging (Linux/macOS). Produces zip/tar.gz from bin/ + notes for native formats.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="${GHOSTDROP_VERSION:-1.0.0}"
OUT="dist"
mkdir -p "$OUT"

if [ ! -d bin ] || [ -z "$(ls -A bin 2>/dev/null)" ]; then
  echo "bin/ is empty — building first."
  bash scripts/build.sh
fi

echo "==> packing ghostdrop-${VERSION} (tar.gz + zip)"
tar -czf "$OUT/ghostdrop-${VERSION}-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m).tar.gz" -C bin .
(cd bin && zip -qr "../$OUT/ghostdrop-${VERSION}.zip" .)
ls -la "$OUT/"

cat <<'NOTES'
Native package notes:
  .deb (Debian/Ubuntu): see packaging.yml — dpkg-deb layout (DEBIAN/control,
      usr/bin/ghostdrop*). Maintainer builds with: dpkg-deb --build pkg/deb
  .rpm (Fedora/RHEL): see packaging.yml — rpmbuild -bb packaging/ghostdrop.spec
      (dnf/yum install path).
  Arch (pacman): PKGBUILD in packaging/ runs scripts/build.sh + installs to
      /usr/bin. See packaging.yml.
  AppImage: linuxdeploy --appdir AppDir usr/bin/ghostdrop* + logo
      (assets/logo.png). See packaging.yml.
  .dmg (macOS): create-dmg --volname Ghostdrop bin/ghostdrop*. See packaging.yml.
NOTES
echo "OK: packaging complete."
