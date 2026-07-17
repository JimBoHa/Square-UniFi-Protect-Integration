#!/bin/bash
# Build SquareProtect.app (menu-bar app) and wrap it in a dmg.
# Output: dist/SquareProtect.dmg
#
# Release signing (on the machine holding Apple credentials):
#   codesign --deep --force --options runtime \
#     --sign "Developer ID Application: <TEAM>" "dist/Square Protect.app"
#   xcrun notarytool submit dist/SquareProtect.dmg --keychain-profile <profile> --wait
#   xcrun stapler staple dist/SquareProtect.dmg
set -euo pipefail
cd "$(dirname "$0")/../.."

BUILD_VENV=.build-venv
if [ ! -x "$BUILD_VENV/bin/python" ]; then
  python3 -m venv "$BUILD_VENV"
  "$BUILD_VENV/bin/pip" install --quiet --upgrade pip
fi
"$BUILD_VENV/bin/pip" install --quiet . pyinstaller rumps

rm -rf build "dist/Square Protect.app" dist/SquareProtect.dmg
"$BUILD_VENV/bin/pyinstaller" \
  --noconfirm --clean --windowed \
  --name "Square Protect" \
  --osx-bundle-identifier com.squareprotect.app \
  --add-data "app/static:app/static" \
  scripts/macos/menubar_app.py

PLIST="dist/Square Protect.app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :LSUIElement bool true" "$PLIST" 2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Set :LSUIElement true" "$PLIST"

STAGE=$(mktemp -d)
cp -R "dist/Square Protect.app" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "Square Protect" -srcfolder "$STAGE" -ov -format UDZO \
  dist/SquareProtect.dmg
rm -rf "$STAGE"
echo "Built dist/SquareProtect.dmg"
