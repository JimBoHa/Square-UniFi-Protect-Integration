use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use crate::{AppError, AppResult};

pub const MIN_POLL_INTERVAL_SECONDS: f64 = 1.0;

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub static_dir: PathBuf,
    pub bind_host: IpAddr,
    pub port: u16,
    pub tls_enabled: bool,
    pub tls_certfile: Option<PathBuf>,
    pub tls_keyfile: Option<PathBuf>,
    pub cookie_secure: bool,
    pub poll_interval: Option<std::time::Duration>,
    pub bootstrap_secret: Option<String>,
}

impl Config {
    pub fn from_env() -> AppResult<Self> {
        let data_dir = PathBuf::from(env::var("SPI_DATA_DIR").unwrap_or_else(|_| "./data".into()));
        let static_dir = env::var_os("SPI_STATIC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("app/static"));
        let host_text = env::var("SPI_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let bind_host = host_text.parse::<IpAddr>().map_err(|_| {
            AppError::BadRequest("SPI_HOST must be a literal IPv4 or IPv6 address".into())
        })?;
        let port_text = env::var("SPI_PORT").unwrap_or_else(|_| "8000".into());
        let port = port_text.parse::<u16>().map_err(|_| {
            AppError::BadRequest("SPI_PORT must be a whole number from 1 to 65535".into())
        })?;
        if port == 0 {
            return Err(AppError::BadRequest(
                "SPI_PORT must be a whole number from 1 to 65535".into(),
            ));
        }

        let tls_enabled = env_flag("SPI_TLS");
        let tls_certfile = env::var_os("SPI_TLS_CERTFILE").map(PathBuf::from);
        let tls_keyfile = env::var_os("SPI_TLS_KEYFILE").map(PathBuf::from);
        if tls_certfile.is_some() != tls_keyfile.is_some() {
            return Err(AppError::BadRequest(
                "SPI_TLS_CERTFILE and SPI_TLS_KEYFILE must be configured together".into(),
            ));
        }
        if tls_certfile.is_some() && !tls_enabled {
            return Err(AppError::BadRequest(
                "Administrator-supplied certificates require SPI_TLS=1".into(),
            ));
        }

        let poll_interval = if env_flag("SPI_DISABLE_POLLER") {
            None
        } else {
            let value = env::var("SPI_POLL_INTERVAL").unwrap_or_else(|_| "60".into());
            let seconds = value.parse::<f64>().map_err(|_| invalid_poll_interval())?;
            if !seconds.is_finite() || seconds < MIN_POLL_INTERVAL_SECONDS {
                return Err(invalid_poll_interval());
            }
            Some(std::time::Duration::from_secs_f64(seconds))
        };

        let bootstrap_secret = env::var("SPI_BOOTSTRAP_SECRET").ok();
        // Rust cannot portably remove an inherited environment string from the
        // parent service manager, but it does remove it from this process.
        unsafe { env::remove_var("SPI_BOOTSTRAP_SECRET") };

        Ok(Self {
            data_dir,
            static_dir,
            bind_host,
            port,
            tls_enabled,
            tls_certfile,
            tls_keyfile,
            cookie_secure: tls_enabled || env_flag("SPI_COOKIE_SECURE"),
            poll_interval,
            bootstrap_secret,
        })
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind_host, self.port)
    }

    pub fn is_loopback_bind(&self) -> bool {
        self.bind_host.is_loopback()
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name).is_ok_and(|value| value == "1")
}

fn invalid_poll_interval() -> AppError {
    AppError::BadRequest("SPI_POLL_INTERVAL must be a finite number of at least 1 second".into())
}
