"""Static regression tests for macOS DMG packaging."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_macos_app_compiles_and_bundles_the_locked_rust_server():
    build_script = (
        REPO_ROOT / "scripts" / "macos" / "build_dmg.sh"
    ).read_text(encoding="utf-8")

    cargo_build = build_script.index("cargo build --locked --release")
    pyinstaller = build_script.index('"$BUILD_VENV/bin/pyinstaller"')
    bundled_binary = build_script.index(
        '--add-binary "target/release/square-unifi-protect:."'
    )

    assert cargo_build < pyinstaller < bundled_binary
    assert 'pip" install --quiet pyinstaller rumps' in build_script
    assert 'pip" install --quiet -r requirements.txt' not in build_script


def test_macos_app_is_signed_before_it_enters_dmg():
    build_script = (
        REPO_ROOT / "scripts" / "macos" / "build_dmg.sh"
    ).read_text(encoding="utf-8")

    signing_guard = build_script.index(
        'if [ -n "${MACOS_SIGNING_IDENTITY:-}" ]; then'
    )
    sign_app = build_script.index(
        '--sign "$MACOS_SIGNING_IDENTITY" "dist/Square Protect.app"',
        signing_guard,
    )
    stage_app = build_script.index('cp -R "dist/Square Protect.app"')
    create_dmg = build_script.index("hdiutil create")

    assert signing_guard < sign_app < stage_app < create_dmg


def test_unsigned_app_is_resigned_after_plist_editing():
    build_script = (
        REPO_ROOT / "scripts" / "macos" / "build_dmg.sh"
    ).read_text(encoding="utf-8")

    plist_edit = build_script.index("PlistBuddy")
    adhoc_sign = build_script.index(
        'codesign --deep --force --sign - "dist/Square Protect.app"'
    )
    verify_signature = build_script.index(
        'codesign --verify --deep --strict "dist/Square Protect.app"'
    )
    stage_app = build_script.index('cp -R "dist/Square Protect.app"')

    assert plist_edit < adhoc_sign < verify_signature < stage_app
