#!/bin/sh
# Register ghostdrop:// URI handling on macOS.
# App bundles declare CFBundleURLTypes in Info.plist; this script wires the
# CLI fallback via a lightweight URL-handler app creation hint.
set -eu
PLIST="$HOME/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist"
echo "macOS URL schemes are registered by the Ghostdrop.app bundle"
echo "(CFBundleURLTypes: ghostdrop). Build the bundle, then run:"
echo "  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Ghostdrop.app"
echo "CLI fallback: ghostdrop --open-url 'ghostdrop://drop/<id>'"
echo "Prefs plist: $PLIST"
