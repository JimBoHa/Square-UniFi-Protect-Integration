#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("square-protect-menubar is supported only on macOS");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    macos::run()
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        env,
        fs::{self, OpenOptions},
        io::{Read as _, Write as _},
        net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
        os::unix::fs::PermissionsExt as _,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use anyhow::{Context as _, ensure};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use objc2_core_foundation::CFRunLoop;
    use rand::RngCore as _;
    use tray_icon::{
        TrayIcon, TrayIconBuilder,
        menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    };
    use winit::{
        application::ApplicationHandler,
        event::{StartCause, WindowEvent},
        event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
        platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS},
        window::WindowId,
    };
    use zeroize::Zeroizing;

    const APP_NAME: &str = "Square Protect";
    const LOOPBACK_HOST: &str = "127.0.0.1";
    const DEFAULT_PORT: u16 = 8000;
    const PORT_SEARCH_WIDTH: u16 = 20;
    const SETUP_PROBE_INTERVAL: Duration = Duration::from_secs(1);
    const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
    const BOOTSTRAP_SECRET_MIN_LENGTH: usize = 32;
    const BOOTSTRAP_SECRET_MAX_LENGTH: usize = 4096;

    #[derive(Clone, Debug)]
    struct Resources {
        root: PathBuf,
        server_binary: PathBuf,
        static_dir: PathBuf,
    }

    impl Resources {
        fn discover(executable: &Path) -> Self {
            let manifest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let contents = executable
                .parent()
                .filter(|directory| directory.file_name().is_some_and(|name| name == "MacOS"))
                .and_then(Path::parent)
                .filter(|directory| directory.file_name().is_some_and(|name| name == "Contents"));
            let (root, server_binary) = if let Some(contents) = contents {
                let root = contents.join("Resources");
                let server_binary = root.join("square-unifi-protect");
                (root, server_binary)
            } else {
                let sibling_binary = executable
                    .parent()
                    .map(|directory| directory.join("square-unifi-protect"));
                let release_binary = manifest_root
                    .join("target")
                    .join("release")
                    .join("square-unifi-protect");
                let server_binary = [sibling_binary, Some(release_binary)]
                    .into_iter()
                    .flatten()
                    .find(|candidate| candidate.is_file())
                    .unwrap_or_else(|| manifest_root.join("square-unifi-protect"));
                (manifest_root, server_binary)
            };
            Self {
                static_dir: root.join("app/static"),
                root,
                server_binary,
            }
        }

        fn validate(&self) -> anyhow::Result<()> {
            ensure!(
                self.server_binary.is_file(),
                "Rust server binary is missing: {}",
                self.server_binary.display()
            );
            ensure!(
                self.server_binary.metadata()?.permissions().mode() & 0o111 != 0,
                "Rust server binary is not executable: {}",
                self.server_binary.display()
            );
            ensure!(
                self.static_dir.join("index.html").is_file(),
                "browser assets are missing: {}",
                self.static_dir.display()
            );
            Ok(())
        }
    }

    struct ServerProcess {
        child: Child,
    }

    impl ServerProcess {
        fn try_status(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
            self.child.try_wait()
        }

        fn stop(&mut self) {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            let process_id = self.child.id();
            // SAFETY: kill receives the child PID returned by std::process and
            // sends only SIGTERM. Failure is harmless because the fallback
            // Child::kill below targets the same owned child handle.
            unsafe {
                libc::kill(process_id as libc::pid_t, libc::SIGTERM);
            }
            let deadline = Instant::now() + SHUTDOWN_GRACE;
            while Instant::now() < deadline {
                if self.child.try_wait().ok().flatten().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for ServerProcess {
        fn drop(&mut self) {
            self.stop();
        }
    }

    struct TemporaryDataDir(PathBuf);

    impl TemporaryDataDir {
        fn create() -> anyhow::Result<Self> {
            let directory = env::temp_dir().join(format!(
                "square-protect-menubar-smoke-{}-{}",
                std::process::id(),
                random_token()
            ));
            fs::create_dir(&directory)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
            Ok(Self(directory))
        }
    }

    impl Drop for TemporaryDataDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Debug)]
    enum UserEvent {
        Menu(MenuEvent),
    }

    struct MenuItems {
        open_dashboard: MenuItem,
        open_data_folder: MenuItem,
        setup_secret: MenuItem,
        status: MenuItem,
        quit: MenuItem,
    }

    impl MenuItems {
        fn new(port: u16, has_setup_secret: bool) -> anyhow::Result<(Self, Menu)> {
            let menu = Menu::new();
            let open_dashboard = MenuItem::new("Open Dashboard", true, None);
            let open_data_folder = MenuItem::new("Open Data Folder", true, None);
            let setup_secret = MenuItem::new(
                if has_setup_secret {
                    "Show One-Time Setup Secret"
                } else {
                    "First-Run Setup Complete"
                },
                has_setup_secret,
                None,
            );
            let status = MenuItem::new(format!("Running on port {port}"), false, None);
            let quit = MenuItem::new("Quit", true, None);
            let first_separator = PredefinedMenuItem::separator();
            let second_separator = PredefinedMenuItem::separator();
            menu.append_items(&[
                &open_dashboard,
                &open_data_folder,
                &setup_secret,
                &first_separator,
                &status,
                &second_separator,
                &quit,
            ])?;
            Ok((
                Self {
                    open_dashboard,
                    open_data_folder,
                    setup_secret,
                    status,
                    quit,
                },
                menu,
            ))
        }
    }

    struct MenubarApplication {
        resources: Resources,
        data_dir: PathBuf,
        port: u16,
        tls_enabled: bool,
        bootstrap_secret: Option<Zeroizing<String>>,
        server: Option<ServerProcess>,
        menu: Menu,
        items: MenuItems,
        tray_icon: Option<TrayIcon>,
        next_probe: Instant,
        reported_server_exit: bool,
    }

    impl MenubarApplication {
        fn new() -> anyhow::Result<Self> {
            let executable = env::current_exe().context("could not locate menu-bar executable")?;
            let resources = Resources::discover(&executable);
            resources.validate()?;
            let data_dir = data_dir()?;
            fs::create_dir_all(&data_dir)
                .with_context(|| format!("could not create data folder {}", data_dir.display()))?;
            let preferred_port = configured_port()?;
            let port = pick_port(preferred_port)?;
            let tls_enabled = env::var("SPI_TLS").as_deref() == Ok("1");
            let bootstrap_secret = prepare_bootstrap_secret(&resources.server_binary, &data_dir);
            let (items, menu) = MenuItems::new(port, bootstrap_secret.is_some())?;
            let server = spawn_server(
                &resources,
                &data_dir,
                port,
                tls_enabled,
                bootstrap_secret.as_deref().map(String::as_str),
            )?;
            Ok(Self {
                resources,
                data_dir,
                port,
                tls_enabled,
                bootstrap_secret,
                server: Some(server),
                menu,
                items,
                tray_icon: None,
                next_probe: Instant::now() + SETUP_PROBE_INTERVAL,
                reported_server_exit: false,
            })
        }

        fn create_tray_icon(&mut self) -> anyhow::Result<()> {
            if self.tray_icon.is_some() {
                return Ok(());
            }
            self.tray_icon = Some(
                TrayIconBuilder::new()
                    .with_menu(Box::new(self.menu.clone()))
                    .with_tooltip(APP_NAME)
                    .with_title("◉")
                    .build()?,
            );
            // Winit has no window to redraw, so explicitly wake the main run
            // loop after installing the NSStatusItem.
            if let Some(run_loop) = CFRunLoop::main() {
                run_loop.wake_up();
            }
            Ok(())
        }

        fn dashboard_url(&self) -> String {
            let scheme = if self.tls_enabled { "https" } else { "http" };
            format!("{scheme}://{LOOPBACK_HOST}:{}", self.port)
        }

        fn handle_menu(&mut self, event_loop: &ActiveEventLoop, event: MenuEvent) {
            if event.id == *self.items.open_dashboard.id() {
                if let Err(error) = open_target(self.dashboard_url()) {
                    show_error(&format!("Could not open the dashboard: {error:#}"));
                }
            } else if event.id == *self.items.open_data_folder.id() {
                if let Err(error) = open_target(&self.data_dir) {
                    show_error(&format!("Could not open the data folder: {error:#}"));
                }
            } else if event.id == *self.items.setup_secret.id() {
                if let Some(secret) = self.bootstrap_secret.as_deref() {
                    show_setup_secret(secret);
                }
            } else if event.id == *self.items.quit.id() {
                self.server.take();
                event_loop.exit();
            }
        }

        fn refresh_state(&mut self) {
            if let Some(server) = &mut self.server {
                match server.try_status() {
                    Ok(Some(status)) => {
                        self.items
                            .status
                            .set_text(format!("Server stopped ({status})"));
                        self.items.open_dashboard.set_enabled(false);
                        if !self.reported_server_exit {
                            self.reported_server_exit = true;
                            show_error(&format!(
                                "The Rust server stopped unexpectedly ({status}). Check {}.",
                                self.data_dir.join("service.log").display()
                            ));
                        }
                    }
                    Ok(None) => {}
                    Err(error) if !self.reported_server_exit => {
                        self.reported_server_exit = true;
                        show_error(&format!("Could not inspect the Rust server: {error}"));
                    }
                    Err(_) => {}
                }
            }
            if self.bootstrap_secret.is_some()
                && setup_complete(&self.resources.server_binary, &self.data_dir)
            {
                self.bootstrap_secret.take();
                self.items.setup_secret.set_text("First-Run Setup Complete");
                self.items.setup_secret.set_enabled(false);
            }
        }
    }

    impl ApplicationHandler<UserEvent> for MenubarApplication {
        fn new_events(&mut self, event_loop: &ActiveEventLoop, cause: StartCause) {
            if cause == StartCause::Init
                && let Err(error) = self.create_tray_icon()
            {
                show_error(&format!("Could not create the menu-bar icon: {error:#}"));
                event_loop.exit();
            }
            if Instant::now() >= self.next_probe {
                self.refresh_state();
                self.next_probe = Instant::now() + SETUP_PROBE_INTERVAL;
            }
        }

        fn resumed(&mut self, _event_loop: &ActiveEventLoop) {}

        fn window_event(
            &mut self,
            _event_loop: &ActiveEventLoop,
            _window_id: WindowId,
            _event: WindowEvent,
        ) {
        }

        fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
            match event {
                UserEvent::Menu(event) => self.handle_menu(event_loop, event),
            }
        }

        fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
            event_loop.set_control_flow(ControlFlow::WaitUntil(self.next_probe));
        }

        fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
            self.server.take();
        }
    }

    pub fn run() -> anyhow::Result<()> {
        match env::args_os().nth(1).as_deref() {
            Some(argument) if argument == std::ffi::OsStr::new("--validate-bundle") => {
                let resources = Resources::discover(&env::current_exe()?);
                resources.validate()?;
                println!("Square Protect app bundle is valid");
                return Ok(());
            }
            Some(argument) if argument == std::ffi::OsStr::new("--smoke-test") => {
                let resources = Resources::discover(&env::current_exe()?);
                resources.validate()?;
                smoke_test(&resources)?;
                println!("Square Protect app bundle smoke test passed");
                return Ok(());
            }
            _ => {}
        }

        let mut builder = EventLoop::<UserEvent>::with_user_event();
        builder
            .with_activation_policy(ActivationPolicy::Accessory)
            .with_default_menu(false)
            .with_activate_ignoring_other_apps(false);
        let event_loop = builder.build()?;
        let proxy = event_loop.create_proxy();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = proxy.send_event(UserEvent::Menu(event));
        }));
        let mut application = MenubarApplication::new().inspect_err(|error| {
            show_error(&format!("Square Protect could not start: {error:#}"));
        })?;
        event_loop.run_app(&mut application)?;
        Ok(())
    }

    fn configured_port() -> anyhow::Result<u16> {
        match env::var("SPI_PORT") {
            Ok(value) if value.is_empty() || value == "0" => Ok(DEFAULT_PORT),
            Ok(value) => value
                .parse::<u16>()
                .with_context(|| "SPI_PORT must be a whole number from 1 to 65535".to_owned()),
            Err(env::VarError::NotPresent) => Ok(DEFAULT_PORT),
            Err(error) => Err(error).context("SPI_PORT is not valid UTF-8"),
        }
    }

    fn pick_port(preferred: u16) -> anyhow::Result<u16> {
        ensure!(
            preferred > 0,
            "SPI_PORT must be a whole number from 1 to 65535"
        );
        let final_port = preferred.saturating_add(PORT_SEARCH_WIDTH);
        for port in preferred..=final_port {
            if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
                return Ok(port);
            }
        }
        anyhow::bail!("no free port found between {preferred} and {final_port}")
    }

    fn data_dir() -> anyhow::Result<PathBuf> {
        if let Some(path) = env::var_os("SPI_DATA_DIR") {
            let path = PathBuf::from(path);
            return if path.is_absolute() {
                Ok(path)
            } else {
                Ok(env::current_dir()?.join(path))
            };
        }
        let home = env::var_os("HOME").context("HOME is not configured")?;
        Ok(PathBuf::from(home)
            .join("Library/Application Support")
            .join("SquareProtect"))
    }

    fn setup_probe_command(binary: &Path, data_dir: &Path) -> Command {
        let mut command = Command::new(binary);
        command
            .arg("--setup-complete")
            .env("SPI_DATA_DIR", data_dir)
            .env_remove("SPI_BOOTSTRAP_SECRET")
            .current_dir(binary.parent().unwrap_or_else(|| Path::new(".")))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn setup_complete(binary: &Path, data_dir: &Path) -> bool {
        setup_probe_command(binary, data_dir)
            .status()
            .is_ok_and(|status| status.success())
    }

    fn prepare_bootstrap_secret(binary: &Path, data_dir: &Path) -> Option<Zeroizing<String>> {
        if setup_complete(binary, data_dir) {
            // SAFETY: menu-bar initialization is single-threaded and occurs
            // before the event loop or any application worker is started.
            unsafe { env::remove_var("SPI_BOOTSTRAP_SECRET") };
            return None;
        }
        let supplied = env::var("SPI_BOOTSTRAP_SECRET").ok();
        // SAFETY: menu-bar initialization is single-threaded and occurs
        // before the event loop or any application worker is started.
        unsafe { env::remove_var("SPI_BOOTSTRAP_SECRET") };
        Some(Zeroizing::new(select_bootstrap_secret(supplied)))
    }

    fn select_bootstrap_secret(supplied: Option<String>) -> String {
        supplied
            .filter(|secret| {
                (BOOTSTRAP_SECRET_MIN_LENGTH..=BOOTSTRAP_SECRET_MAX_LENGTH).contains(&secret.len())
            })
            .unwrap_or_else(random_token)
    }

    fn spawn_server(
        resources: &Resources,
        data_dir: &Path,
        port: u16,
        tls_enabled: bool,
        bootstrap_secret: Option<&str>,
    ) -> anyhow::Result<ServerProcess> {
        let log_path = data_dir.join("service.log");
        let stdout = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("could not open {}", log_path.display()))?;
        let stderr = stdout.try_clone()?;
        let mut command = Command::new(&resources.server_binary);
        command
            .current_dir(&resources.root)
            .env("SPI_DATA_DIR", data_dir)
            .env("SPI_STATIC_DIR", &resources.static_dir)
            .env("SPI_HOST", LOOPBACK_HOST)
            .env("SPI_PORT", port.to_string())
            .env("SPI_TLS", if tls_enabled { "1" } else { "0" })
            .env_remove("SPI_BOOTSTRAP_SECRET")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        if let Some(secret) = bootstrap_secret {
            command.env("SPI_BOOTSTRAP_SECRET", secret);
        }
        let child = command.spawn().with_context(|| {
            format!(
                "could not start Rust server {}",
                resources.server_binary.display()
            )
        })?;
        Ok(ServerProcess { child })
    }

    fn smoke_test(resources: &Resources) -> anyhow::Result<()> {
        let data_dir = TemporaryDataDir::create()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let secret = Zeroizing::new(random_token());
        let mut server = spawn_server(resources, &data_dir.0, port, false, Some(secret.as_str()))?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut status_passed = false;
        let mut index_passed = false;
        while Instant::now() < deadline {
            if let Some(status) = server.try_status()? {
                anyhow::bail!("embedded Rust server stopped during smoke test ({status})");
            }
            status_passed |= http_response(port, "/api/status")
                .is_ok_and(|response| response.contains("\"backend\":\"rust\""));
            index_passed |= http_response(port, "/")
                .is_ok_and(|response| response.contains("Square") && response.contains("Protect"));
            if status_passed && index_passed {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        anyhow::bail!(
            "embedded Rust server smoke test timed out (status={status_passed}, index={index_passed})"
        )
    }

    fn http_response(port: u16, path: &str) -> anyhow::Result<String> {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(200))?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        ensure!(
            response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200"),
            "smoke-test HTTP request failed"
        );
        Ok(response)
    }

    fn open_target(target: impl AsRef<std::ffi::OsStr>) -> anyhow::Result<()> {
        let status = Command::new("/usr/bin/open")
            .arg(target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        ensure!(status.success(), "macOS open command returned {status}");
        Ok(())
    }

    fn show_setup_secret(secret: &str) {
        let literal = applescript_literal(secret);
        let script = Zeroizing::new(format!(
            "display dialog \"Copy this into the dashboard's first-run setup form. It disappears after setup succeeds.\" with title \"One-Time Setup Secret\" default answer {} buttons {{\"Close\"}} default button \"Close\"\n",
            literal.as_str()
        ));
        let _ = run_applescript(script.as_bytes());
    }

    fn show_error(message: &str) {
        let literal = applescript_literal(message);
        let script = format!(
            "display alert \"Square Protect\" message {} as critical buttons {{\"Close\"}} default button \"Close\"\n",
            literal.as_str()
        );
        let _ = run_applescript(script.as_bytes());
    }

    fn run_applescript(script: &[u8]) -> anyhow::Result<()> {
        let mut child = Command::new("/usr/bin/osascript")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        child
            .stdin
            .take()
            .context("could not open AppleScript input")?
            .write_all(script)?;
        let status = child.wait()?;
        ensure!(status.success(), "AppleScript dialog returned {status}");
        Ok(())
    }

    fn applescript_literal(value: &str) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "\"{}\"",
            value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\r', "\\r")
                .replace('\n', "\\n")
        ))
    }

    fn random_token() -> String {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(bytes.as_mut());
        URL_SAFE_NO_PAD.encode(bytes.as_ref())
    }

    #[cfg(test)]
    mod tests {
        use std::{ffi::OsStr, fs::File};

        use tempfile::tempdir;

        use super::*;

        #[test]
        fn bundled_resources_are_resolved_from_contents_directory() {
            let temporary = tempdir().unwrap();
            let contents = temporary.path().join("Square Protect.app/Contents");
            let executable = contents.join("MacOS/Square Protect");
            let resources = contents.join("Resources");
            fs::create_dir_all(executable.parent().unwrap()).unwrap();
            fs::create_dir_all(resources.join("app/static")).unwrap();
            File::create(&executable).unwrap();
            let server = resources.join("square-unifi-protect");
            File::create(&server).unwrap();
            fs::set_permissions(&server, fs::Permissions::from_mode(0o755)).unwrap();
            File::create(resources.join("app/static/index.html")).unwrap();

            let discovered = Resources::discover(&executable);

            assert_eq!(discovered.root, resources);
            assert_eq!(discovered.server_binary, server);
            discovered.validate().unwrap();
        }

        #[test]
        fn bundle_validation_never_falls_back_to_build_machine_paths() {
            let temporary = tempdir().unwrap();
            let contents = temporary.path().join("Square Protect.app/Contents");
            let executable = contents.join("MacOS/Square Protect");
            fs::create_dir_all(executable.parent().unwrap()).unwrap();
            File::create(&executable).unwrap();

            let discovered = Resources::discover(&executable);

            assert_eq!(
                discovered.server_binary,
                contents.join("Resources/square-unifi-protect")
            );
            assert!(discovered.validate().is_err());
        }

        #[test]
        fn port_picker_skips_an_occupied_preferred_port() {
            let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let preferred = occupied.local_addr().unwrap().port();
            if preferred == u16::MAX {
                return;
            }

            assert_ne!(pick_port(preferred).unwrap(), preferred);
        }

        #[test]
        fn bootstrap_secret_accepts_only_bounded_supplied_values() {
            let supplied = "x".repeat(BOOTSTRAP_SECRET_MIN_LENGTH);
            assert_eq!(select_bootstrap_secret(Some(supplied.clone())), supplied);
            assert_ne!(
                select_bootstrap_secret(Some("short".into())),
                "short".to_owned()
            );
            assert_eq!(select_bootstrap_secret(None).len(), 43);
        }

        #[test]
        fn setup_probe_never_inherits_bootstrap_secret() {
            let command = setup_probe_command(Path::new("server"), Path::new("data"));
            let environment = command.get_envs().collect::<Vec<_>>();

            assert!(environment.iter().any(|(name, value)| {
                *name == OsStr::new("SPI_DATA_DIR") && *value == Some(OsStr::new("data"))
            }));
            assert!(environment.iter().any(|(name, value)| {
                *name == OsStr::new("SPI_BOOTSTRAP_SECRET") && value.is_none()
            }));
        }

        #[test]
        fn applescript_literals_escape_control_characters() {
            assert_eq!(
                applescript_literal("quote\" slash\\\nline\r").as_str(),
                "\"quote\\\" slash\\\\\\nline\\r\""
            );
        }
    }
}
