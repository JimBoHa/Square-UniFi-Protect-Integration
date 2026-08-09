use anyhow::Context as _;
use square_unifi_protect::{AppState, Config, DEFAULT_PORT, Store, build_router, tls};
use std::net::{SocketAddr, TcpListener};
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
    let tls_config = tls::rustls_config(&config)
        .await
        .map_err(anyhow::Error::from)?;
    let listener = bind_listener(address)?;

    if let Some(tls_config) = tls_config {
        tracing::info!(%address, "Square Protect Rust server listening with TLS");
        axum_server::from_tcp_rustls(listener, tls_config)
            .context("could not adopt the reserved TCP listener")?
            .serve(router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .context("TLS server stopped unexpectedly")?;
    } else {
        tracing::info!(%address, "Square Protect Rust server listening");
        let listener = tokio::net::TcpListener::from_std(listener)
            .context("could not adopt the reserved TCP listener")?;
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .context("server stopped unexpectedly")?;
    }
    Ok(())
}

fn bind_listener(address: SocketAddr) -> anyhow::Result<TcpListener> {
    let listener = TcpListener::bind(address).with_context(|| {
        format!(
            "fixed TCP port {} is unavailable at {address}; stop the service using it or set SPI_PORT explicitly",
            address.port()
        )
    })?;
    listener
        .set_nonblocking(true)
        .context("could not configure the reserved TCP listener")?;
    Ok(listener)
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
    let port = std::env::var("SPI_PORT").unwrap_or_else(|_| DEFAULT_PORT.to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_port_bind_reports_an_occupied_port() {
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = occupied.local_addr().unwrap();

        let error = bind_listener(address).unwrap_err().to_string();
        assert!(error.contains(&address.port().to_string()));
        assert!(error.contains("fixed TCP port"));
    }
}
