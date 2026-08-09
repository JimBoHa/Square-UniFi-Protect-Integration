use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fernet::Fernet;
use hmac::{Hmac, Mac};
use rand::RngCore;
use scrypt::{Params, scrypt};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{AppError, AppResult};

const KEY_FILENAME: &str = "secret.key";
const HMAC_SALT_FILENAME: &str = "hmac.salt";
const HMAC_DOMAIN: &[u8] = b"square-unifi-protect:credential-cipher:keyed-hmac:v2";
const BOOTSTRAP_SECRET_MIN_LENGTH: usize = 32;
const BOOTSTRAP_SECRET_MAX_LENGTH: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct CredentialCipher {
    fernet: Arc<Fernet>,
    keyed_hmac_key: [u8; 32],
}

impl CredentialCipher {
    pub fn open(data_dir: &Path) -> AppResult<Self> {
        fs::create_dir_all(data_dir)?;
        secure_dir(data_dir)?;
        let key = match std::env::var("SPI_ENCRYPTION_KEY") {
            Ok(value) => value,
            Err(_) => {
                load_or_create_text_secret(&data_dir.join(KEY_FILENAME), Fernet::generate_key)?
            }
        };
        let fernet = Fernet::new(&key)
            .ok_or_else(|| AppError::BadRequest("Invalid Fernet encryption key".into()))?;
        let raw_key = base64::engine::general_purpose::URL_SAFE
            .decode(key.as_bytes())
            .map_err(AppError::internal)?;
        let installation_salt =
            load_or_create_binary_secret(&data_dir.join(HMAC_SALT_FILENAME), 32)?;
        let mut mac = HmacSha256::new_from_slice(&raw_key).map_err(AppError::internal)?;
        mac.update(HMAC_DOMAIN);
        mac.update(&[0]);
        mac.update(&installation_salt);
        let keyed_hmac_key: [u8; 32] = mac.finalize().into_bytes().into();
        Ok(Self {
            fernet: Arc::new(fernet),
            keyed_hmac_key,
        })
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        self.fernet.encrypt(plaintext.as_bytes())
    }

    pub fn decrypt(&self, ciphertext: &str) -> AppResult<String> {
        let plaintext = self.fernet.decrypt(ciphertext).map_err(|_| {
            AppError::internal(anyhow::anyhow!("Could not decrypt stored credential"))
        })?;
        String::from_utf8(plaintext).map_err(AppError::internal)
    }

    pub fn keyed_hmac_hex(&self, domain: &[u8], payload: &[u8]) -> AppResult<String> {
        if domain.is_empty() || domain.contains(&0) {
            return Err(AppError::BadRequest(
                "HMAC domain must be non-empty and contain no NUL bytes".into(),
            ));
        }
        let mut mac =
            HmacSha256::new_from_slice(&self.keyed_hmac_key).map_err(AppError::internal)?;
        mac.update(domain);
        mac.update(&[0]);
        mac.update(payload);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

pub struct BootstrapSecretVerifier {
    digest: Mutex<Option<[u8; 32]>>,
}

impl BootstrapSecretVerifier {
    pub fn new(configured: Option<String>, generate_if_missing: bool) -> Self {
        let valid = configured.filter(|value| {
            (BOOTSTRAP_SECRET_MIN_LENGTH..=BOOTSTRAP_SECRET_MAX_LENGTH).contains(&value.len())
        });
        let generated = valid.is_none() && generate_if_missing;
        let secret = valid.or_else(|| generated.then(new_session_token));
        if generated && let Some(value) = secret.as_deref() {
            tracing::warn!(
                "Generated one-time first-run bootstrap secret: {value}\n\
                 Enter it in the setup form. It will not be shown over HTTP."
            );
        }
        let digest = secret.map(|value| Sha256::digest(value.as_bytes()).into());
        Self {
            digest: Mutex::new(digest),
        }
    }

    pub fn configured(&self) -> bool {
        self.digest
            .lock()
            .expect("bootstrap mutex poisoned")
            .is_some()
    }

    pub fn verify(&self, candidate: &str) -> bool {
        let candidate: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        self.digest
            .lock()
            .expect("bootstrap mutex poisoned")
            .as_ref()
            .is_some_and(|expected| bool::from(expected.ct_eq(&candidate)))
    }

    pub fn clear(&self) {
        if let Some(mut digest) = self.digest.lock().expect("bootstrap mutex poisoned").take() {
            digest.fill(0);
        }
    }
}

pub fn hash_password(password: &str) -> AppResult<String> {
    let mut salt = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let mut digest = [0_u8; 64];
    let params = Params::new(14, 8, 1).map_err(AppError::internal)?;
    scrypt(password.as_bytes(), &salt, &params, &mut digest).map_err(AppError::internal)?;
    Ok(format!(
        "scrypt${}${}",
        hex::encode(salt),
        hex::encode(digest)
    ))
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let mut fields = stored.split('$');
    let Some("scrypt") = fields.next() else {
        return false;
    };
    let (Some(salt_hex), Some(expected_hex), None) = (fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    let (Ok(salt), Ok(expected)) = (hex::decode(salt_hex), hex::decode(expected_hex)) else {
        return false;
    };
    if expected.len() != 64 {
        return false;
    }
    let Ok(params) = Params::new(14, 8, 1) else {
        return false;
    };
    let mut digest = vec![0_u8; expected.len()];
    if scrypt(password.as_bytes(), &salt, &params, &mut digest).is_err() {
        return false;
    }
    bool::from(digest.ct_eq(&expected))
}

pub fn new_session_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash_session_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn load_or_create_text_secret(path: &Path, generate: impl FnOnce() -> String) -> AppResult<String> {
    match fs::read_to_string(path) {
        Ok(value) => return Ok(value.trim().to_owned()),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        Err(_) => {}
    }
    let value = generate();
    publish_private_file(path, value.as_bytes())?;
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn load_or_create_binary_secret(path: &Path, length: usize) -> AppResult<Vec<u8>> {
    match fs::read(path) {
        Ok(value) if value.len() == length => return Ok(value),
        Ok(_) => {
            return Err(AppError::BadRequest(
                "Invalid installation HMAC salt".into(),
            ));
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        Err(_) => {}
    }
    let mut value = vec![0_u8; length];
    rand::rng().fill_bytes(&mut value);
    publish_private_file(path, &value)?;
    let stored = fs::read(path)?;
    if stored.len() != length {
        return Err(AppError::BadRequest(
            "Invalid installation HMAC salt".into(),
        ));
    }
    Ok(stored)
}

fn publish_private_file(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let temporary = private_temp_path(path);
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
    match fs::hard_link(&temporary, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
    }
    let _ = fs::remove_file(&temporary);
    secure_file(path)?;
    Ok(())
}

fn private_temp_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("secret"),
        uuid::Uuid::new_v4()
    ))
}

pub fn secure_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn secure_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn password_hash_matches_python_storage_contract() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.starts_with("scrypt$"));
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn password_hashes_are_salted_and_malformed_values_fail_closed() {
        let first = hash_password("same-password").unwrap();
        let second = hash_password("same-password").unwrap();
        assert_ne!(first, second);
        for malformed in [
            "",
            "scrypt",
            "scrypt$00",
            "scrypt$zz$00",
            "scrypt$00$zz",
            "scrypt$00$00$extra",
            "pbkdf2$00$00",
        ] {
            assert!(!verify_password("same-password", malformed), "{malformed}");
        }
    }

    #[test]
    fn verifies_known_python_scrypt_hash() {
        let stored = "scrypt$000102030405060708090a0b0c0d0e0f$ad4581319c08c6bbdbb62fa8457e83836b6555280b79ad595daefb21e4f4b17a3c99f5572e842911d148f662c76ad8b0531ea8f27bac7f8c4a69c27d1ee72076";
        assert!(verify_password("compatibility-test", stored));
    }

    #[test]
    fn fernet_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let cipher = CredentialCipher::open(temp.path()).unwrap();
        let encrypted = cipher.encrypt("secret");
        assert_eq!(cipher.decrypt(&encrypted).unwrap(), "secret");
    }

    #[test]
    fn credential_cipher_rejects_tampering_and_separates_hmac_domains() {
        let temp = tempfile::tempdir().unwrap();
        let cipher = CredentialCipher::open(temp.path()).unwrap();
        let mut encrypted = cipher.encrypt("private credential").into_bytes();
        let last = encrypted.len() - 1;
        encrypted[last] = if encrypted[last] == b'A' { b'B' } else { b'A' };
        assert!(
            cipher
                .decrypt(std::str::from_utf8(&encrypted).unwrap())
                .is_err()
        );

        let payload = b"same-payload";
        let first = cipher.keyed_hmac_hex(b"domain-one", payload).unwrap();
        let second = cipher.keyed_hmac_hex(b"domain-two", payload).unwrap();
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        assert!(matches!(
            cipher.keyed_hmac_hex(b"", payload),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            cipher.keyed_hmac_hex(b"bad\0domain", payload),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn credential_material_is_private_and_reused() {
        let temp = tempfile::tempdir().unwrap();
        let first = CredentialCipher::open(temp.path()).unwrap();
        let token = first.encrypt("persisted");
        let second = CredentialCipher::open(temp.path()).unwrap();
        assert_eq!(second.decrypt(&token).unwrap(), "persisted");
        assert_eq!(
            fs::read(temp.path().join(HMAC_SALT_FILENAME))
                .unwrap()
                .len(),
            32
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(temp.path().join(KEY_FILENAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
            assert_eq!(
                fs::metadata(temp.path().join(HMAC_SALT_FILENAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
    }

    #[test]
    fn concurrent_cipher_opens_publish_one_compatible_keypair() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_owned();
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    CredentialCipher::open(&path).unwrap()
                })
            })
            .collect();
        let ciphers: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let token = ciphers[0].encrypt("shared");
        assert!(
            ciphers
                .iter()
                .all(|cipher| cipher.decrypt(&token).unwrap() == "shared")
        );
        assert_eq!(
            fs::read_dir(&path)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
    }

    #[test]
    fn bootstrap_secret_is_bounded_one_time_and_constant_shape() {
        let secret = "b".repeat(32);
        let verifier = BootstrapSecretVerifier::new(Some(secret.clone()), false);
        assert!(verifier.configured());
        assert!(verifier.verify(&secret));
        assert!(!verifier.verify(&format!("{}x", &secret[..31])));
        verifier.clear();
        assert!(!verifier.configured());
        assert!(!verifier.verify(&secret));
    }

    #[test]
    fn invalid_configured_bootstrap_secret_is_not_accepted() {
        let verifier = BootstrapSecretVerifier::new(Some("too-short".into()), false);
        assert!(!verifier.configured());
        assert!(!verifier.verify("too-short"));
        let oversized = "x".repeat(4097);
        let verifier = BootstrapSecretVerifier::new(Some(oversized.clone()), false);
        assert!(!verifier.configured());
        assert!(!verifier.verify(&oversized));
    }

    #[test]
    fn session_tokens_are_random_urlsafe_and_hash_deterministically() {
        let first = new_session_token();
        let second = new_session_token();
        assert_ne!(first, second);
        assert_eq!(first.len(), 43);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        assert_eq!(hash_session_token(&first), hash_session_token(&first));
        assert_ne!(hash_session_token(&first), hash_session_token(&second));
        assert_eq!(hash_session_token(&first).len(), 64);
    }

    #[test]
    fn secure_helpers_repair_existing_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("private");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("value");
        fs::write(&file, b"secret").unwrap();
        secure_dir(&directory).unwrap();
        secure_file(&file).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o077,
                0
            );
            assert_eq!(fs::metadata(file).unwrap().permissions().mode() & 0o077, 0);
        }
    }

    #[test]
    fn pure_rust_fernet_decrypts_python_cryptography_token() {
        let fernet = Fernet::new("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap();
        let plaintext = fernet
            .decrypt("gAAAAABlU_EAlBsofvIBHhtZlk-rrUgknfrH-wbyxLmFm5-cIrDRFL3HXZ8yzY4B4dXQtJ0XCEs_An68xr78u4L5RtJ9YNZGb449DfFao8tl0L9m6PQFDiA=")
            .unwrap();

        assert_eq!(plaintext, b"python-fernet-compatibility");
    }
}
