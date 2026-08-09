use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source(path: &str) -> String {
    fs::read_to_string(root().join(path)).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

#[test]
fn test_harness_contains_only_rust_sources() {
    let mut files = fs::read_dir(root().join("tests"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(!files.is_empty());
    for path in files {
        assert!(
            path.is_file(),
            "unexpected test directory: {}",
            path.display()
        );
        assert_eq!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("rs"),
            "non-Rust test source: {}",
            path.display()
        );
    }
    assert!(!root().join("pyproject.toml").exists());
}

#[test]
fn docker_image_is_a_pinned_native_rust_build() {
    let dockerfile = source("Dockerfile");
    assert!(dockerfile.contains("FROM rust:1.88-bookworm AS builder"));
    assert!(dockerfile.contains("cargo build --locked --release"));
    assert!(dockerfile.contains("FROM debian:bookworm-slim AS runtime"));
    assert!(dockerfile.contains("/target/release/square-unifi-protect"));
    assert!(!dockerfile.to_ascii_lowercase().contains("python"));
}

#[test]
fn docker_runtime_is_non_root_and_persists_only_private_data() {
    let dockerfile = source("Dockerfile");
    let entrypoint = source("docker-entrypoint.sh");
    assert!(dockerfile.contains("useradd --create-home --uid 10001"));
    assert!(dockerfile.contains("install -d -o square-protect -g square-protect -m 0700 /data"));
    assert!(dockerfile.contains("VOLUME /data"));
    assert!(entrypoint.contains("exec gosu \"$data_uid:$data_gid\" \"$@\""));
    assert!(!entrypoint.contains("SPI_BOOTSTRAP_SECRET="));
}

#[test]
fn docker_lan_bootstrap_uses_builtin_tls_and_native_healthcheck() {
    let dockerfile = source("Dockerfile");
    let compose = source("docker-compose.yml");
    assert!(dockerfile.contains("SPI_HOST=0.0.0.0"));
    assert!(dockerfile.contains("SPI_TLS=1"));
    assert!(dockerfile.contains("--healthcheck"));
    assert!(compose.contains("SPI_TLS: \"1\""));
    assert!(!compose.contains("SPI_BOOTSTRAP_SECRET"));
}

#[test]
fn docker_context_excludes_local_state_and_test_artifacts() {
    let ignore = source(".dockerignore");
    for item in ["data", "tests", ".git", "target"] {
        assert!(ignore.lines().any(|line| line == item), "missing {item}");
    }
}

#[test]
fn github_ci_runs_native_rust_and_container_smoke_tests() {
    let workflow = source(".github/workflows/docker.yml");
    for command in [
        "cargo fmt --all -- --check",
        "cargo clippy --locked --all-targets --all-features -- -D warnings",
        "cargo test --locked --all-targets",
        "docker build -t square-unifi-protect:ci .",
        "docker run -d --name spi -p 8000:8000",
        "curl -kfs https://127.0.0.1:8000/api/status",
    ] {
        assert!(workflow.contains(command), "missing CI command: {command}");
    }
}

#[test]
fn double_click_launcher_builds_locked_rust_and_bounds_ports() {
    let launcher = source("Start Square Protect.command");
    assert!(launcher.contains("cargo build --locked --release"));
    assert!(launcher.contains("target/release/square-unifi-protect"));
    assert!(launcher.contains("[ \"$PORT\" -lt 1 ]"));
    assert!(launcher.contains("[ \"$PORT\" -gt 65535 ]"));
    assert!(launcher.contains("PORT_CAP=$((PORT + 20))"));
    assert!(launcher.contains("export SPI_PORT=\"$PORT\""));
    assert!(!launcher.contains("python -m"));
}

#[test]
fn unix_service_build_is_skipped_during_uninstall() {
    let installer = source("scripts/install-service.sh");
    let guard = installer
        .find("if [ \"$UNINSTALL\" != \"--uninstall\" ]; then")
        .expect("uninstall guard");
    let build = installer
        .find("cargo build --manifest-path")
        .expect("Rust build");
    let branch = installer.find("case \"$(uname -s)\"").expect("OS branch");
    assert!(guard < build && build < branch);
}

#[test]
fn unix_lan_services_enable_tls_without_hard_coded_host_ip() {
    let installer = source("scripts/install-service.sh");
    assert!(installer.contains("<key>SPI_HOST</key><string>0.0.0.0</string>"));
    assert!(installer.contains("Environment=SPI_HOST=0.0.0.0"));
    assert!(installer.contains("<key>SPI_TLS</key><string>1</string>"));
    assert!(installer.contains("Environment=SPI_TLS=1"));
    assert!(installer.contains("https://<this-host>:8000"));
    assert!(!installer.contains("10.0.7.215"));
}

#[test]
fn windows_installer_builds_locked_rust_before_registration() {
    let installer = source("scripts/windows/install-service.ps1");
    let uninstall_exit = installer.find("if ($Uninstall)").expect("uninstall branch");
    let build = installer.find("& cargo build").expect("Rust build");
    let register = installer
        .find("Register-ScheduledTask")
        .expect("task registration");
    assert!(uninstall_exit < build && build < register);
    assert!(installer.contains("--locked --release"));
    assert!(installer.contains("square-unifi-protect.exe"));
}

#[test]
fn windows_bootstrap_secret_is_dpapi_protected_and_scrubbed() {
    let installer = source("scripts/windows/install-service.ps1");
    let runner = source("scripts/windows/run-service.ps1");
    assert!(installer.contains("ProtectedData]::Protect"));
    assert!(installer.contains("bootstrap-secret.dpapi"));
    assert!(!installer.contains("SPI_BOOTSTRAP_SECRET="));
    assert!(runner.contains("ProtectedData]::Unprotect"));
    assert!(runner.contains("Remove-Item Env:SPI_BOOTSTRAP_SECRET"));
    assert!(runner.contains("Remove-Item $BootstrapSecretFile"));
}

#[test]
fn windows_uninstall_targets_only_the_recorded_native_child() {
    let installer = source("scripts/windows/install-service.ps1");
    assert!(installer.contains("service-process.pid"));
    assert!(installer.contains("ExecutablePath"));
    assert!(installer.contains("StringComparison]::OrdinalIgnoreCase"));
    assert!(!installer.contains("Get-Process python"));
}

#[test]
fn macos_dmg_bundles_only_native_locked_binaries() {
    let build = source("scripts/macos/build_dmg.sh");
    assert!(build.contains("cargo build --locked --release --features menubar"));
    assert!(build.contains("--bin square-unifi-protect --bin square-protect-menubar"));
    assert!(build.contains("--validate-bundle"));
    assert!(build.contains("--smoke-test"));
    assert!(!build.to_ascii_lowercase().contains("python"));
}

#[test]
fn macos_dmg_rejects_nonportable_links_and_verifies_signatures() {
    let build = source("scripts/macos/build_dmg.sh");
    assert!(build.contains("otool -L"));
    assert!(build.contains("(/opt|/usr/local|/Users|/private)"));
    assert_eq!(build.matches("codesign --force").count(), 3);
    assert!(build.contains("codesign --verify --deep --strict"));
}

#[test]
fn macos_manifest_is_a_background_native_menu_bar_app() {
    let plist = source("scripts/macos/Info.plist");
    assert!(plist.contains("<string>com.squareprotect.app</string>"));
    assert!(plist.contains("<key>LSUIElement</key>\n  <true/>"));
    assert!(plist.contains("<key>LSMinimumSystemVersion</key>\n  <string>12.0</string>"));
}

#[test]
fn packaging_documentation_matches_secure_container_and_lan_urls() {
    let readme = source("README.md");
    let packaging = source("PACKAGING.md");
    assert!(packaging.contains("docker compose up -d"));
    assert!(packaging.contains("Open `https://<host>:8000`"));
    assert!(packaging.contains("plaintext setup secret"));
    assert!(readme.contains("SPI_COOKIE_SECURE=1"));
}

#[test]
fn repository_has_no_obsolete_python_runtime_entrypoint_in_packaging() {
    for path in [
        "Dockerfile",
        "docker-entrypoint.sh",
        "Start Square Protect.command",
        "scripts/install-service.sh",
        "scripts/windows/install-service.ps1",
        "scripts/windows/run-service.ps1",
        "scripts/macos/build_dmg.sh",
    ] {
        let text = source(path).to_ascii_lowercase();
        assert!(
            !text.contains("python -m app"),
            "obsolete runtime in {path}"
        );
        assert!(!text.contains("uvicorn"), "obsolete runtime in {path}");
    }
}
