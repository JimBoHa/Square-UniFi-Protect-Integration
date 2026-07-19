"""Static regression tests for macOS DMG packaging."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


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
