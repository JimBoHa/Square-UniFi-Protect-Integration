"""Static regression tests for macOS DMG packaging."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_macos_app_compiles_and_bundles_two_locked_rust_binaries():
    build_script = (
        REPO_ROOT / "scripts" / "macos" / "build_dmg.sh"
    ).read_text(encoding="utf-8")

    cargo_build = build_script.index(
        "cargo build --locked --release --features menubar"
    )
    wrapper_copy = build_script.index(
        'cp target/release/square-protect-menubar "$MACOS/Square Protect"'
    )
    server_copy = build_script.index(
        'cp target/release/square-unifi-protect "$RESOURCES/square-unifi-protect"'
    )
    bundle_validation = build_script.index(
        '"$MACOS/Square Protect" --validate-bundle'
    )
    bundle_smoke_test = build_script.index('"$MACOS/Square Protect" --smoke-test')

    assert cargo_build < wrapper_copy < server_copy < bundle_validation < bundle_smoke_test
    assert "python" not in build_script.lower()
    assert "pyinstaller" not in build_script.lower()
    assert "rumps" not in build_script.lower()
    assert "Non-portable dynamic library linked" in build_script


def test_macos_bundle_manifest_uses_native_menu_bar_mode():
    manifest = (REPO_ROOT / "scripts" / "macos" / "Info.plist").read_text(
        encoding="utf-8"
    )

    assert "<string>Square Protect</string>" in manifest
    assert "<key>LSUIElement</key>" in manifest
    assert "<true/>" in manifest


def test_macos_app_is_signed_before_it_enters_dmg():
    build_script = (
        REPO_ROOT / "scripts" / "macos" / "build_dmg.sh"
    ).read_text(encoding="utf-8")

    signing_guard = build_script.index(
        'if [ -n "${MACOS_SIGNING_IDENTITY:-}" ]; then'
    )
    codesign_start = build_script.index("codesign --force", signing_guard)
    sign_server = build_script.index(
        '"$RESOURCES/square-unifi-protect"', codesign_start
    )
    sign_wrapper = build_script.index('"$MACOS/Square Protect"', sign_server + 1)
    sign_app = build_script.index('--sign "$SIGNING_IDENTITY" "$APP"')
    stage_app = build_script.index('cp -R "$APP" "$STAGE/"')
    create_dmg = build_script.index("hdiutil create")

    assert signing_guard < sign_server < sign_wrapper < sign_app < stage_app < create_dmg


def test_unsigned_app_is_ad_hoc_signed_and_verified():
    build_script = (
        REPO_ROOT / "scripts" / "macos" / "build_dmg.sh"
    ).read_text(encoding="utf-8")

    adhoc_identity = build_script.index("SIGNING_IDENTITY=-")
    sign_app = build_script.index('--sign "$SIGNING_IDENTITY" "$APP"')
    verify_signature = build_script.index(
        'codesign --verify --deep --strict "$APP"'
    )
    stage_app = build_script.index('cp -R "$APP" "$STAGE/"')

    assert adhoc_identity < sign_app < verify_signature < stage_app


def test_ci_builds_the_native_macos_app():
    workflow = (REPO_ROOT / ".github" / "workflows" / "docker.yml").read_text(
        encoding="utf-8"
    )

    assert "macos-app:" in workflow
    assert "cargo test --locked --features menubar --bin square-protect-menubar" in workflow
    assert "scripts/macos/build_dmg.sh" in workflow
