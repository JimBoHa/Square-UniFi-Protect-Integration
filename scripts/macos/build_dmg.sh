#!/bin/bash
# Build SquareProtect.app (menu-bar app) and wrap it in a dmg.
# Output: dist/SquareProtect.dmg
#
# Release signing (on the machine holding Apple credentials):
#   MACOS_SIGNING_IDENTITY="Developer ID Application: <TEAM>" \
#     scripts/macos/build_dmg.sh
#   xcrun notarytool submit dist/SquareProtect.dmg --keychain-profile <profile> --wait
#   xcrun stapler staple dist/SquareProtect.dmg
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build --locked --release --features menubar \
  --bin square-unifi-protect --bin square-protect-menubar
for BINARY_PATH in \
  target/release/square-unifi-protect \
  target/release/square-protect-menubar; do
  if otool -L "$BINARY_PATH" | grep -Eq '^[[:space:]]+(/opt|/usr/local|/Users|/private)/'; then
    echo "Non-portable dynamic library linked by $BINARY_PATH" >&2
    otool -L "$BINARY_PATH" >&2
    exit 1
  fi
done

APP="dist/Square Protect.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
rm -rf build "$APP" dist/SquareProtect.dmg
mkdir -p "$MACOS" "$RESOURCES/app"
cp target/release/square-protect-menubar "$MACOS/Square Protect"
cp target/release/square-unifi-protect "$RESOURCES/square-unifi-protect"
cp -R app/static "$RESOURCES/app/static"
cp scripts/macos/Info.plist "$CONTENTS/Info.plist"
chmod 755 "$MACOS/Square Protect" "$RESOURCES/square-unifi-protect"
"$MACOS/Square Protect" --validate-bundle
"$MACOS/Square Protect" --smoke-test

if [ -n "${MACOS_SIGNING_IDENTITY:-}" ]; then
  SIGNING_IDENTITY="$MACOS_SIGNING_IDENTITY"
else
  SIGNING_IDENTITY=-
fi
codesign --force --options runtime --sign "$SIGNING_IDENTITY" \
  "$RESOURCES/square-unifi-protect"
codesign --force --options runtime --sign "$SIGNING_IDENTITY" \
  "$MACOS/Square Protect"
codesign --force --options runtime --sign "$SIGNING_IDENTITY" "$APP"
codesign --verify --deep --strict "$APP"

STAGE=$(mktemp -d)
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "Square Protect" -srcfolder "$STAGE" -ov -format UDZO \
  dist/SquareProtect.dmg
rm -rf "$STAGE"
echo "Built dist/SquareProtect.dmg"
