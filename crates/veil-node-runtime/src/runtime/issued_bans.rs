//! Small durable records for locally issued P-Net bans. The DHT snapshot
//! remains a cache of both locally published and received records.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use veil_dht::NetworkAuthGate as _;
use veil_identity::network_access::NetworkAccessGate;
use veil_identity::network_ban::{MAX_BAN_BLOB_SIZE, decode_ban_blob};
use veil_proto::budget::MAX_BAN_LIST_SIZE;
use veil_util::lock;

// Serialize rare administrative writes and capacity accounting, including
// when a config reload overlaps an admin request that already started.
static STORAGE: Mutex<()> = Mutex::new(());

pub(super) fn storage_dir(config: &veil_cfg::Config) -> Option<PathBuf> {
    sibling_storage_dir(config, ".pnet-bans")
}

pub(super) fn sibling_storage_dir(config: &veil_cfg::Config, suffix: &str) -> Option<PathBuf> {
    if !config.persist_enabled {
        return None;
    }
    let snapshot = Path::new(config.dht.values_persist_path.as_deref()?);
    let mut name = snapshot.file_name()?.to_os_string();
    name.push(suffix);
    Some(snapshot.with_file_name(name))
}

pub(super) fn directory_exists(dir: &Path) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir() {
        return Err(io::Error::other("P-Net ban storage must be a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::other("P-Net ban storage must be owner-only"));
        }
    }
    Ok(true)
}

pub(super) fn entry_key(path: &Path) -> Option<[u8; 32]> {
    if path.extension()?.to_str()? != "pban" {
        return None;
    }
    veil_util::hex_to_array::<32>(path.file_stem()?.to_str()?).ok()
}

pub(super) fn open_record(path: &Path) -> io::Result<Option<fs::File>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Ok(None);
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    Ok(file.metadata()?.is_file().then_some(file))
}

pub(super) fn read_record_bytes(path: &Path, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let Some(file) = open_record(path)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    Ok((bytes.len() <= limit).then_some(bytes))
}

fn owned_record(
    path: &Path,
    key: &[u8; 32],
    gate: &NetworkAccessGate,
    issuer: &[u8; 32],
) -> io::Result<Option<(u64, Vec<u8>)>> {
    let Some(bytes) = read_record_bytes(path, MAX_BAN_BLOB_SIZE)? else {
        return Ok(None);
    };
    let Ok(record) = decode_ban_blob(&bytes) else {
        return Ok(None);
    };
    Ok(
        (record.admin_node_id == *issuer && gate.verify_ban_record(key, &bytes))
            .then_some((record.issued_at_unix, bytes)),
    )
}

pub(super) fn ensure_directory(dir: &Path) -> io::Result<()> {
    if !directory_exists(dir)? {
        veil_util::create_dir_owner_only(dir)?;
        if !directory_exists(dir)? {
            return Err(io::Error::other("P-Net ban storage could not be created"));
        }
    }
    Ok(())
}

pub(super) fn save(
    dir: &Path,
    key: [u8; 32],
    bytes: &[u8],
    issued_at: u64,
    gate: &NetworkAccessGate,
    issuer: &[u8; 32],
) -> io::Result<()> {
    let _storage = lock!(STORAGE);
    ensure_directory(dir)?;
    let path = dir.join(format!("{}.pban", veil_util::bytes_to_hex(&key)));
    match owned_record(&path, &key, gate, issuer) {
        Ok(Some((previous, _))) if previous > issued_at => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut count = 0;
            for entry in fs::read_dir(dir)? {
                if entry_key(&entry?.path()).is_some() {
                    count += 1;
                }
            }
            if count >= MAX_BAN_LIST_SIZE {
                // Retire one unavailable or no longer authorized record
                // before adding a new file. Never evict an authorized ban.
                let victim = fs::read_dir(dir)?.find_map(|entry| {
                    let path = entry.ok()?.path();
                    let key = entry_key(&path)?;
                    matches!(owned_record(&path, &key, gate, issuer), Ok(None)).then_some(path)
                });
                if count == MAX_BAN_LIST_SIZE
                    && let Some(path) = victim
                {
                    fs::remove_file(path)?;
                } else {
                    return Err(io::Error::other("P-Net ban storage is full"));
                }
            }
        }
        Err(error) => return Err(error),
    }
    veil_util::atomic_write_owner_only(&path, bytes)
}

pub(super) fn load(
    dir: &Path,
    gate: &NetworkAccessGate,
    issuer: &[u8; 32],
    logger: &veil_observability::NodeLogger,
) -> io::Result<Vec<([u8; 32], Vec<u8>)>> {
    let _storage = lock!(STORAGE);
    if !directory_exists(dir)? {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    let mut skipped = 0;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(key) = entry_key(&path) else {
            continue;
        };
        if records.len() == MAX_BAN_LIST_SIZE {
            logger.warn(
                "network.ban.storage.limit",
                "restored the maximum number of records",
            );
            break;
        }
        match owned_record(&path, &key, gate, issuer) {
            Ok(Some((_, bytes))) => records.push((key, bytes)),
            _ => skipped += 1,
        }
    }
    if skipped > 0 {
        logger.warn("network.ban.storage.skipped", format!("records={skipped}"));
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_storage_requires_both_persistence_settings() {
        let mut config = veil_cfg::Config::default();
        assert!(storage_dir(&config).is_none());
        config.dht.values_persist_path = Some("data/dht-values.json".into());
        assert_eq!(
            storage_dir(&config).as_deref(),
            Some(Path::new("data/dht-values.json.pnet-bans")),
        );
        config.persist_enabled = false;
        assert!(storage_dir(&config).is_none());
    }
}
