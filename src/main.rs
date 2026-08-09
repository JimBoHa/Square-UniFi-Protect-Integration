use anyhow::Context as _;
use square_unifi_protect::{AppState, Config, Store, build_router, tls};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args_os().nth(1).as_deref() {
        Some(argument) if argument == std::ffi::OsStr::new("--healthcheck") => {
            return healthcheck().await;
        }
        Some(argument) if argument == std::ffi::OsStr::new("--setup-complete") => {
            return setup_complete();
        }
        _ => {}
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env().map_err(anyhow::Error::from)?;
    if !config.bind_host.is_loopback() && !config.tls_enabled {
        anyhow::bail!(
            "A non-loopback SPI_HOST requires SPI_TLS=1; refusing to expose credentials over HTTP"
        );
    }
    let store = Store::open(&config.data_dir).map_err(anyhow::Error::from)?;
    let state = AppState::new(store, config.clone());
    state.start_background_work();
    let router = build_router(state);
    let address = config.socket_addr();

    if let Some(tls_config) = tls::rustls_config(&config)
        .await
        .map_err(anyhow::Error::from)?
    {
        tracing::info!(%address, "Square Protect Rust server listening with TLS");
        axum_server::bind_rustls(address, tls_config)
            .serve(router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .context("TLS server stopped unexpectedly")?;
    } else {
        tracing::info!(%address, "Square Protect Rust server listening");
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| format!("could not bind {address}"))?;
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .context("server stopped unexpectedly")?;
    }
    Ok(())
}

fn setup_complete() -> anyhow::Result<()> {
    let data_dir = std::env::var_os("SPI_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("./data"));
    let store = Store::open(data_dir).map_err(anyhow::Error::from)?;
    anyhow::ensure!(
        store.setup_complete().map_err(anyhow::Error::from)?,
        "setup is incomplete"
    );
    Ok(())
}

async fn healthcheck() -> anyhow::Result<()> {
    let port = std::env::var("SPI_PORT").unwrap_or_else(|_| "8000".into());
    let port = port.parse::<u16>().context("SPI_PORT is invalid")?;
    let scheme = if std::env::var("SPI_TLS").as_deref() == Ok("1") {
        "https"
    } else {
        "http"
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .tls_danger_accept_invalid_certs(true)
        .build()?;
    let response = client
        .get(format!("{scheme}://127.0.0.1:{port}/api/status"))
        .send()
        .await?;
    anyhow::ensure!(response.status().is_success(), "health endpoint failed");
    Ok(())
}
