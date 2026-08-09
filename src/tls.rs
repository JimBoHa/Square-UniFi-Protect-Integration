use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, UdpSocket},
    path::{Path, PathBuf},
};

use axum_server::tls_rustls::RustlsConfig;
use fs2::FileExt;
use rcgen::{CertifiedKey, KeyPair, PublicKeyData, generate_simple_self_signed};
use x509_parser::{extensions::GeneralName, parse_x509_certificate, time::ASN1Time};

use crate::{
    AppError, AppResult,
    config::Config,
    security::{secure_dir, secure_file},
};

const CERT_FILENAME: &str = "tls-cert.pem";
const KEY_FILENAME: &str = "tls-key.pem";

pub async fn rustls_config(config: &Config) -> AppResult<Option<RustlsConfig>> {
    if !config.tls_enabled {
        return Ok(None);
    }
    let (cert, key) = match (&config.tls_certfile, &config.tls_keyfile) {
        (Some(cert), Some(key)) => {
            validate_custom_pair(cert, key)?;
            (cert.clone(), key.clone())
        }
        (None, None) => ensure_self_signed_pair(&config.data_dir, config.bind_host)?,
        _ => unreachable!("configuration validates paired custom TLS paths"),
    };
    RustlsConfig::from_pem_file(&cert, &key)
        .await
        .map(Some)
        .map_err(|error| {
            AppError::BadRequest(format!(
                "TLS certificate and private key could not be loaded as a pair: {error}"
            ))
        })
}

fn validate_custom_pair(cert: &Path, key: &Path) -> AppResult<()> {
    if !cert.is_absolute() || !key.is_absolute() {
        return Err(AppError::BadRequest(
            "Custom TLS certificate and key paths must be absolute".into(),
        ));
    }
    if !cert.is_file() {
        return Err(AppError::BadRequest(format!(
            "Custom TLS certificate is not a file: {}",
            cert.display()
        )));
    }
    if !key.is_file() {
        return Err(AppError::BadRequest(format!(
            "Custom TLS private key is not a file: {}",
            key.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if key.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(AppError::BadRequest(
                "Custom TLS private key must not be accessible to group or other users".into(),
            ));
        }
    }
    let pem = fs::read(cert)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem)
        .map_err(|_| AppError::BadRequest("Custom TLS certificate is not valid PEM".into()))?;
    let (_, certificate) = parse_x509_certificate(&pem.contents)
        .map_err(|_| AppError::BadRequest("Custom TLS certificate is not valid PEM".into()))?;
    let now = ASN1Time::now();
    if certificate.validity().not_before > now {
        return Err(AppError::BadRequest(
            "Custom TLS certificate is not valid yet".into(),
        ));
    }
    if certificate.validity().not_after <= now {
        return Err(AppError::BadRequest(
            "Custom TLS certificate has expired".into(),
        ));
    }
    Ok(())
}

fn ensure_self_signed_pair(data_dir: &Path, bind_host: IpAddr) -> AppResult<(PathBuf, PathBuf)> {
    fs::create_dir_all(data_dir)?;
    secure_dir(data_dir)?;
    let lock_path = data_dir.join(".tls-generation.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    secure_file(&lock_path)?;
    FileExt::lock_exclusive(&lock)?;

    let names = local_certificate_names(bind_host);
    if let Some(pair) = legacy_generation_pair(data_dir)
        && generated_pair_is_valid(&pair.0, &pair.1, &names)
    {
        // Reuse a currently deployed generation-based pair. It is already
        // atomically published and contains this machine's LAN addresses.
        FileExt::unlock(&lock)?;
        return Ok(pair);
    }
    let cert_path = data_dir.join(CERT_FILENAME);
    let key_path = data_dir.join(KEY_FILENAME);
    if cert_path.is_file()
        && key_path.is_file()
        && generated_pair_is_valid(&cert_path, &key_path, &names)
    {
        secure_file(&cert_path)?;
        secure_file(&key_path)?;
        FileExt::unlock(&lock)?;
        return Ok((cert_path, key_path));
    }

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(names).map_err(AppError::internal)?;
    // Publish the key first. If the process stops between the two replaces,
    // the old certificate either lacks a required address or no longer matches
    // the new key, so the next startup regenerates before opening a socket.
    publish_private(&key_path, signing_key.serialize_pem().as_bytes())?;
    publish_private(&cert_path, cert.pem().as_bytes())?;
    FileExt::unlock(&lock)?;
    Ok((cert_path, key_path))
}

fn local_certificate_names(bind_host: IpAddr) -> Vec<String> {
    let mut names = vec![
        "localhost".to_owned(),
        "square-unifi-protect.local".to_owned(),
        "127.0.0.1".to_owned(),
    ];
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            let address = interface.ip();
            if address.is_unspecified() || address.is_multicast() {
                continue;
            }
            let address = address.to_string();
            if !names.contains(&address) {
                names.push(address);
            }
        }
    }
    if !bind_host.is_unspecified() {
        let address = bind_host.to_string();
        if !names.contains(&address) {
            names.push(address);
        }
    }
    if let Some(address) = routed_local_ip() {
        let address = address.to_string();
        if !names.contains(&address) {
            names.push(address);
        }
    }
    names
}

fn certificate_covers_names(path: &Path, required: &[String]) -> bool {
    let Ok(pem) = fs::read(path) else {
        return false;
    };
    let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(&pem) else {
        return false;
    };
    let Ok((_, certificate)) = parse_x509_certificate(&pem.contents) else {
        return false;
    };
    let now = ASN1Time::now();
    if certificate.validity().not_before > now || certificate.validity().not_after <= now {
        return false;
    }
    let Ok(Some(san)) = certificate.subject_alternative_name() else {
        return false;
    };
    let mut names = Vec::new();
    for name in &san.value.general_names {
        match name {
            GeneralName::DNSName(value) => names.push((*value).to_owned()),
            GeneralName::IPAddress(bytes) if bytes.len() == 4 => {
                if let Ok(bytes) = <[u8; 4]>::try_from(*bytes) {
                    names.push(std::net::Ipv4Addr::from(bytes).to_string());
                }
            }
            GeneralName::IPAddress(bytes) if bytes.len() == 16 => {
                if let Ok(bytes) = <[u8; 16]>::try_from(*bytes) {
                    names.push(std::net::Ipv6Addr::from(bytes).to_string());
                }
            }
            _ => {}
        }
    }
    required.iter().all(|required| names.contains(required))
}

fn generated_pair_is_valid(cert_path: &Path, key_path: &Path, required: &[String]) -> bool {
    if !certificate_covers_names(cert_path, required) {
        return false;
    }
    let Ok(cert_pem) = fs::read(cert_path) else {
        return false;
    };
    let Ok((_, cert_pem)) = x509_parser::pem::parse_x509_pem(&cert_pem) else {
        return false;
    };
    let Ok((_, certificate)) = parse_x509_certificate(&cert_pem.contents) else {
        return false;
    };
    let Ok(key_pem) = fs::read_to_string(key_path) else {
        return false;
    };
    let Ok(key_pair) = KeyPair::from_pem(&key_pem) else {
        return false;
    };
    certificate.public_key().raw == key_pair.subject_public_key_info()
}

fn legacy_generation_pair(data_dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let generation = fs::read_to_string(data_dir.join(".tls-current")).ok()?;
    let generation = generation.trim();
    if generation.len() != 32 || !generation.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let directory = data_dir.join(".tls-material").join(generation);
    let cert = directory.join(CERT_FILENAME);
    let key = directory.join(KEY_FILENAME);
    (cert.is_file() && key.is_file()).then_some((cert, key))
}

fn publish_private(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    match fs::rename(&temporary, path) {
        Ok(()) => {}
        Err(error) if path.exists() => {
            fs::remove_file(&temporary)?;
            tracing::debug!(%error, "another process published TLS material first");
        }
        Err(error) => return Err(error.into()),
    }
    secure_file(path)?;
    Ok(())
}

fn routed_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:53").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn config(data_dir: PathBuf, bind_host: IpAddr) -> Config {
        Config {
            data_dir,
            static_dir: PathBuf::from("static"),
            bind_host,
            port: 8000,
            tls_enabled: true,
            tls_certfile: None,
            tls_keyfile: None,
            cookie_secure: true,
            poll_interval: None,
            bootstrap_secret: None,
        }
    }

    #[test]
    fn creates_private_tls_pair() {
        let temp = tempfile::tempdir().unwrap();
        let (cert, key) =
            ensure_self_signed_pair(temp.path(), "127.0.0.1".parse().unwrap()).unwrap();
        assert!(cert.is_file());
        assert!(key.is_file());
        assert!(certificate_covers_names(
            &cert,
            &local_certificate_names("127.0.0.1".parse().unwrap())
        ));
        assert!(generated_pair_is_valid(
            &cert,
            &key,
            &local_certificate_names("127.0.0.1".parse().unwrap())
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(key.metadata().unwrap().permissions().mode() & 0o077, 0);
        }
    }

    #[tokio::test]
    async fn disabled_tls_returns_no_server_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = config(temp.path().to_owned(), "127.0.0.1".parse().unwrap());
        config.tls_enabled = false;
        assert!(rustls_config(&config).await.unwrap().is_none());
        assert!(!temp.path().join(CERT_FILENAME).exists());
        assert!(!temp.path().join(KEY_FILENAME).exists());
    }

    #[test]
    fn generated_pair_is_reused_when_names_are_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let host = "192.0.2.10".parse().unwrap();
        let (cert, key) = ensure_self_signed_pair(temp.path(), host).unwrap();
        let first_cert = fs::read(&cert).unwrap();
        let first_key = fs::read(&key).unwrap();
        let (same_cert, same_key) = ensure_self_signed_pair(temp.path(), host).unwrap();
        assert_eq!(cert, same_cert);
        assert_eq!(key, same_key);
        assert_eq!(fs::read(cert).unwrap(), first_cert);
        assert_eq!(fs::read(key).unwrap(), first_key);
    }

    #[test]
    fn explicit_bind_ip_is_covered_and_new_bind_ip_rotates_pair() {
        let temp = tempfile::tempdir().unwrap();
        let first_host: IpAddr = "192.0.2.10".parse().unwrap();
        let second_host: IpAddr = "192.0.2.11".parse().unwrap();
        let (cert, key) = ensure_self_signed_pair(temp.path(), first_host).unwrap();
        let first_cert = fs::read(&cert).unwrap();
        let first_key = fs::read(&key).unwrap();
        assert!(certificate_covers_names(&cert, &[first_host.to_string()]));
        ensure_self_signed_pair(temp.path(), second_host).unwrap();
        assert!(certificate_covers_names(&cert, &[second_host.to_string()]));
        assert!(fs::read(cert).unwrap() != first_cert || fs::read(key).unwrap() != first_key);
    }

    #[test]
    fn corrupt_certificate_or_key_is_repaired_before_reuse() {
        for corrupt in [CERT_FILENAME, KEY_FILENAME] {
            let temp = tempfile::tempdir().unwrap();
            let host = "192.0.2.20".parse().unwrap();
            let (cert, key) = ensure_self_signed_pair(temp.path(), host).unwrap();
            fs::write(temp.path().join(corrupt), b"corrupt").unwrap();
            let repaired = ensure_self_signed_pair(temp.path(), host).unwrap();
            assert!(generated_pair_is_valid(
                &repaired.0,
                &repaired.1,
                &[host.to_string()]
            ));
            assert_eq!(repaired, (cert, key));
        }
    }

    #[test]
    fn mismatched_generated_key_is_rotated_with_certificate() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let host = "192.0.2.21".parse().unwrap();
        let (cert, key) = ensure_self_signed_pair(first.path(), host).unwrap();
        let first_cert = fs::read(&cert).unwrap();
        let (_, other_key) = ensure_self_signed_pair(second.path(), host).unwrap();
        fs::write(&key, fs::read(other_key).unwrap()).unwrap();
        assert!(!generated_pair_is_valid(&cert, &key, &[host.to_string()]));
        let repaired = ensure_self_signed_pair(first.path(), host).unwrap();
        assert!(generated_pair_is_valid(
            &repaired.0,
            &repaired.1,
            &[host.to_string()]
        ));
        assert_ne!(fs::read(repaired.0).unwrap(), first_cert);
    }

    #[test]
    fn custom_tls_paths_must_be_absolute_regular_and_private() {
        assert!(matches!(
            validate_custom_pair(Path::new("cert.pem"), Path::new("key.pem")),
            Err(AppError::BadRequest(_))
        ));
        let temp = tempfile::tempdir().unwrap();
        let cert = temp.path().join("missing-cert.pem");
        let key = temp.path().join("missing-key.pem");
        assert!(matches!(
            validate_custom_pair(&cert, &key),
            Err(AppError::BadRequest(_))
        ));
        fs::write(&cert, b"invalid").unwrap();
        fs::write(&key, b"invalid").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
            let error = validate_custom_pair(&cert, &key).unwrap_err().to_string();
            assert!(error.contains("group or other users"));
        }
    }

    #[tokio::test]
    async fn valid_custom_pair_loads_and_mismatched_pair_fails() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let (cert, key) =
            ensure_self_signed_pair(first.path(), "192.0.2.30".parse().unwrap()).unwrap();
        let (_, other_key) =
            ensure_self_signed_pair(second.path(), "192.0.2.31".parse().unwrap()).unwrap();
        let mut custom = config(first.path().to_owned(), "0.0.0.0".parse().unwrap());
        custom.tls_certfile = Some(cert.clone());
        custom.tls_keyfile = Some(key);
        assert!(rustls_config(&custom).await.unwrap().is_some());
        custom.tls_keyfile = Some(other_key);
        assert!(matches!(
            rustls_config(&custom).await,
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn concurrent_generation_publishes_one_matched_reusable_pair() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_owned();
        let barrier = Arc::new(Barrier::new(6));
        let handles: Vec<_> = (0..6)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    ensure_self_signed_pair(&path, "192.0.2.40".parse().unwrap()).unwrap()
                })
            })
            .collect();
        let pairs: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(pairs.iter().all(|pair| pair == &pairs[0]));
        assert!(certificate_covers_names(
            &pairs[0].0,
            &["192.0.2.40".into()]
        ));
        assert!(
            fs::read_to_string(&pairs[0].1)
                .unwrap()
                .contains("PRIVATE KEY")
        );
    }

    #[test]
    fn legacy_generation_pointer_is_strict_and_never_traverses() {
        let temp = tempfile::tempdir().unwrap();
        for invalid in ["", "../outside", &"f".repeat(31), &"g".repeat(32)] {
            fs::write(temp.path().join(".tls-current"), invalid).unwrap();
            assert!(legacy_generation_pair(temp.path()).is_none());
        }
    }
}
