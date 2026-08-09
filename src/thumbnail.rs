use std::{
    fs::{self, OpenOptions},
    io::{Cursor, Read, Write},
    path::Path,
};

use image::{
    DynamicImage, ImageDecoder, ImageEncoder, ImageFormat, ImageReader, Limits,
    codecs::jpeg::JpegEncoder, imageops::FilterType,
};

use crate::{AppError, AppResult, security::secure_file, store::Store};

pub const MAX_THUMBNAIL_FILE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThumbnailPolicy {
    pub compression_enabled: bool,
    pub jpeg_quality: i64,
    pub max_dimension: i64,
    pub retention_days: i64,
    pub max_storage_mib: i64,
    pub revision: i64,
}

#[derive(Clone, Debug)]
pub struct PreparedThumbnail {
    pub data: Vec<u8>,
    pub policy_revision: i64,
    pub changed: bool,
    pub error: Option<String>,
}

pub fn load_policy(store: &Store) -> AppResult<ThumbnailPolicy> {
    let settings = store.get_settings([
        "thumbnail.compression_enabled",
        "thumbnail.jpeg_quality",
        "thumbnail.max_dimension",
        "thumbnail.retention_days",
        "thumbnail.max_storage_mib",
        "thumbnail.policy_revision",
    ])?;
    let bounded = |key: &str, default: i64, low: i64, high: i64| {
        settings
            .get(key)
            .and_then(|value| value.as_deref())
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(default)
            .clamp(low, high)
    };
    Ok(ThumbnailPolicy {
        compression_enabled: settings["thumbnail.compression_enabled"].as_deref() == Some("1"),
        jpeg_quality: bounded("thumbnail.jpeg_quality", 72, 30, 95),
        max_dimension: bounded("thumbnail.max_dimension", 960, 320, 3840),
        retention_days: bounded("thumbnail.retention_days", 0, 0, 3650),
        max_storage_mib: bounded("thumbnail.max_storage_mib", 0, 0, 1_048_576),
        revision: bounded("thumbnail.policy_revision", 0, 0, i64::MAX),
    })
}

pub fn prepare_thumbnail(original: &[u8], policy: &ThumbnailPolicy) -> PreparedThumbnail {
    if !policy.compression_enabled {
        return PreparedThumbnail {
            data: original.to_vec(),
            policy_revision: 0,
            changed: false,
            error: None,
        };
    }
    match compress_jpeg(original, policy) {
        Ok(compressed) if compressed.len() < original.len() => PreparedThumbnail {
            data: compressed,
            policy_revision: policy.revision,
            changed: true,
            error: None,
        },
        Ok(_) => PreparedThumbnail {
            data: original.to_vec(),
            policy_revision: policy.revision,
            changed: false,
            error: None,
        },
        Err(error) => PreparedThumbnail {
            data: original.to_vec(),
            policy_revision: policy.revision,
            changed: false,
            error: Some(error.to_string()),
        },
    }
}

fn compress_jpeg(original: &[u8], policy: &ThumbnailPolicy) -> AppResult<Vec<u8>> {
    if original.len() as u64 > MAX_THUMBNAIL_FILE_BYTES {
        return Err(AppError::PayloadTooLarge(
            "Thumbnail exceeds the compression size limit".into(),
        ));
    }
    let cursor = Cursor::new(original);
    let mut reader = ImageReader::with_format(cursor, ImageFormat::Jpeg);
    let mut limits = Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(256 * 1024 * 1024);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().map_err(AppError::internal)?;
    let orientation = decoder.orientation().map_err(AppError::internal)?;
    let mut decoded = DynamicImage::from_decoder(decoder).map_err(AppError::internal)?;
    decoded.apply_orientation(orientation);
    let maximum = policy.max_dimension as u32;
    let resized = if decoded.width() <= maximum && decoded.height() <= maximum {
        decoded
    } else {
        decoded.resize(maximum, maximum, FilterType::Lanczos3)
    };
    let rgb = resized.to_rgb8();
    let mut compressed = Vec::new();
    JpegEncoder::new_with_quality(&mut compressed, policy.jpeg_quality as u8)
        .write_image(
            rgb.as_raw(),
            rgb.width(),
            rgb.height(),
            image::ExtendedColorType::Rgb8,
        )
        .map_err(AppError::internal)?;
    Ok(compressed)
}

pub fn read_thumbnail(path: &Path) -> AppResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_THUMBNAIL_FILE_BYTES {
        return Err(AppError::BadRequest(
            "Thumbnail is not a bounded regular file".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > MAX_THUMBNAIL_FILE_BYTES {
        return Err(AppError::BadRequest(
            "Thumbnail is not a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_THUMBNAIL_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_THUMBNAIL_FILE_BYTES {
        return Err(AppError::PayloadTooLarge(
            "Thumbnail exceeds the maintenance size limit".into(),
        ));
    }
    Ok(bytes)
}

pub fn write_thumbnail(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("thumbnail"),
        uuid::Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    if let Err(error) = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        secure_file(path)
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};
    use std::sync::{Arc, Barrier};

    fn noisy_jpeg(width: u32, height: u32) -> Vec<u8> {
        let image = ImageBuffer::from_fn(width, height, |x, y| {
            Rgb([
                ((x * 31 + y * 17) % 255) as u8,
                ((x * 13 + y * 29) % 255) as u8,
                ((x * 7 + y * 37) % 255) as u8,
            ])
        });
        let mut bytes = Vec::new();
        JpegEncoder::new_with_quality(&mut bytes, 95)
            .write_image(
                image.as_raw(),
                width,
                height,
                image::ExtendedColorType::Rgb8,
            )
            .unwrap();
        bytes
    }

    #[test]
    fn compression_reduces_and_resizes_a_large_jpeg() {
        let original = noisy_jpeg(1600, 900);
        let policy = ThumbnailPolicy {
            compression_enabled: true,
            jpeg_quality: 40,
            max_dimension: 320,
            retention_days: 0,
            max_storage_mib: 0,
            revision: 7,
        };
        let prepared = prepare_thumbnail(&original, &policy);
        assert!(prepared.error.is_none());
        assert!(prepared.changed);
        assert!(prepared.data.len() < original.len());
        assert_eq!(prepared.policy_revision, 7);
        let resized =
            image::load_from_memory_with_format(&prepared.data, ImageFormat::Jpeg).unwrap();
        assert!(resized.width().max(resized.height()) <= 320);
    }

    #[test]
    fn failed_compression_preserves_original() {
        let original = b"not-a-camera-jpeg";
        let policy = ThumbnailPolicy {
            compression_enabled: true,
            jpeg_quality: 72,
            max_dimension: 960,
            retention_days: 0,
            max_storage_mib: 0,
            revision: 4,
        };
        let prepared = prepare_thumbnail(original, &policy);
        assert_eq!(prepared.data, original);
        assert!(!prepared.changed);
        assert_eq!(prepared.policy_revision, 4);
        assert!(prepared.error.is_some());
    }

    #[test]
    fn disabled_compression_never_decodes_or_changes_input() {
        let original = b"not-even-a-jpeg";
        let policy = ThumbnailPolicy {
            compression_enabled: false,
            jpeg_quality: 1,
            max_dimension: 1,
            retention_days: 45,
            max_storage_mib: 100,
            revision: 99,
        };
        let prepared = prepare_thumbnail(original, &policy);
        assert_eq!(prepared.data, original);
        assert_eq!(prepared.policy_revision, 0);
        assert!(!prepared.changed);
        assert!(prepared.error.is_none());
    }

    #[test]
    fn policy_loader_defaults_and_clamps_corrupt_stored_values() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        assert_eq!(
            load_policy(&store).unwrap(),
            ThumbnailPolicy {
                compression_enabled: false,
                jpeg_quality: 72,
                max_dimension: 960,
                retention_days: 0,
                max_storage_mib: 0,
                revision: 0,
            }
        );
        for (key, value) in [
            ("thumbnail.compression_enabled", "1"),
            ("thumbnail.jpeg_quality", "999"),
            ("thumbnail.max_dimension", "2"),
            ("thumbnail.retention_days", "-5"),
            ("thumbnail.max_storage_mib", "999999999"),
            ("thumbnail.policy_revision", "not-a-number"),
        ] {
            store.set_setting(key, value, false).unwrap();
        }
        let policy = load_policy(&store).unwrap();
        assert!(policy.compression_enabled);
        assert_eq!(policy.jpeg_quality, 95);
        assert_eq!(policy.max_dimension, 320);
        assert_eq!(policy.retention_days, 0);
        assert_eq!(policy.max_storage_mib, 1_048_576);
        assert_eq!(policy.revision, 0);
    }

    #[test]
    fn thumbnail_write_is_atomic_private_and_readable() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("thumbnail.jpg");
        write_thumbnail(&path, b"first-published-image").unwrap();
        assert_eq!(read_thumbnail(&path).unwrap(), b"first-published-image");
        write_thumbnail(&path, b"replacement-image").unwrap();
        assert_eq!(read_thumbnail(&path).unwrap(), b"replacement-image");
        assert_eq!(
            fs::read_dir(temp.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o077, 0);
        }
    }

    #[test]
    fn concurrent_thumbnail_writes_never_publish_mixed_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("race.jpg");
        let first = vec![b'A'; 256 * 1024];
        let second = vec![b'B'; 256 * 1024];
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [first.clone(), second.clone()]
            .into_iter()
            .map(|bytes| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    write_thumbnail(&path, &bytes).unwrap();
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let published = read_thumbnail(&path).unwrap();
        assert!(published == first || published == second);
    }

    #[test]
    fn thumbnail_reader_rejects_directories_and_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_thumbnail(temp.path()),
            Err(AppError::BadRequest(_))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = temp.path().join("target.jpg");
            let link = temp.path().join("link.jpg");
            fs::write(&target, b"image").unwrap();
            symlink(&target, &link).unwrap();
            assert!(matches!(
                read_thumbnail(&link),
                Err(AppError::BadRequest(_))
            ));
        }
    }
}
