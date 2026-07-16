//! Local `instance_id` state.
//!
//! On first start an veil node generates a random 16-byte
//! `instance_id`, persists it to `~/.config/veil/instance_id`, and
//! reads it back on subsequent starts. The id is stable for the
//! device's lifetime — it survives identity rotation, name changes
//! even master_seed compromise recovery: it's purely local routing
//! state, not cryptographic material.
//!
//! The id is published inside the
//! [`InstanceRegistry`](super::super::proto::instance_registry::InstanceRegistry)
//! and used by peers to target `Recipient::Specific(instance_id)`
//! deliveries.
//!
//! # Persistence format
//!
//! ```text
//! [0..2] magic = "II" (Instance Id) u16
//! [2] version = 1 u8
//! [3..19] instance_id [u8; 16]
//! [19..51] label_len + label 1 B + up to MAX_LABEL_BYTES
//! ```
//!
//! A short, human-readable label (e.g. `laptop`, `home-server`) is
//! stored alongside — it surfaces in the published InstanceRegistry
//! so the user can tell their own devices apart in tooling output.
//!
//! Unlike [`identity_master_file`](super::master_file) this
//! file carries no secrets; file mode is the user-configurable
//! default.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};

// ── Constants ────────────────────────────────────────────────────────────────

/// Magic bytes identifying the instance-id file.
pub const INSTANCE_FILE_MAGIC: [u8; 2] = *b"II";
/// Wire-format version.
pub const INSTANCE_FILE_V1: u8 = 1;

/// Length of the instance id.
pub const INSTANCE_ID_LEN: usize = 16;

/// Maximum label length (UTF-8 bytes) matching the registry cap.
pub const MAX_LABEL_BYTES: usize = 64;

/// Default filename under `runtime_veil_dir` or caller-supplied path.
pub const DEFAULT_INSTANCE_FILE: &str = "instance_id";

// ── Types ────────────────────────────────────────────────────────────────────

/// Local instance identity: the 16-byte id plus the operator label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInstance {
    pub instance_id: [u8; INSTANCE_ID_LEN],
    pub label: String,
}

/// Errors emitted while loading or persisting the instance file.
#[derive(Debug, thiserror::Error)]
pub enum InstanceFileError {
    #[error("instance file io: {0}")]
    Io(#[from] io::Error),
    #[error("instance file malformed: {0}")]
    Malformed(String),
}

// ── Public API ───────────────────────────────────────────────────────────────

impl LocalInstance {
    /// Generate a fresh instance with a random 16-byte id and the
    /// given label. The caller typically persists the result with
    /// [`Self::save`] immediately.
    pub fn generate(label: impl Into<String>) -> Self {
        let mut id = [0u8; INSTANCE_ID_LEN];
        OsRng.fill_bytes(&mut id);
        let mut label = label.into();
        truncate_utf8_to_bytes(&mut label, MAX_LABEL_BYTES);
        Self {
            instance_id: id,
            label,
        }
    }

    /// Load a `LocalInstance` from `path` if it exists, otherwise
    /// generate a fresh one, persist it, and return that.
    ///
    /// The default label is used only when generating a new instance.
    pub fn load_or_init(path: &Path, default_label: &str) -> Result<Self, InstanceFileError> {
        match Self::load(path) {
            Ok(inst) => Ok(inst),
            Err(InstanceFileError::Io(ref e)) if e.kind() == io::ErrorKind::NotFound => {
                let inst = Self::generate(default_label);
                inst.save(path)?;
                Ok(inst)
            }
            Err(other) => Err(other),
        }
    }

    /// Load from `path`. Returns a NotFound io error if the file is
    /// missing, so the caller can distinguish "first start" from
    /// "corrupt file".
    pub fn load(path: &Path) -> Result<Self, InstanceFileError> {
        // Retry on transient EACCES (WSL2 ext4 quirk under heavy parallel
        // FS load). Real permission misconfigs surface after the retries.
        let bytes = veil_util::with_eacces_retry(|| fs::read(path))?;
        Self::decode(&bytes)
    }

    /// Persist to `path` atomically (tmp + fsync + rename). Creates
    /// the parent directory if missing.
    pub fn save(&self, path: &Path) -> Result<(), InstanceFileError> {
        if self.label.len() > MAX_LABEL_BYTES {
            return Err(InstanceFileError::Malformed(format!(
                "label {} exceeds cap {MAX_LABEL_BYTES}",
                self.label.len()
            )));
        }
        let encoded = self.encode();
        // Hardened atomic write: unpredictable getrandom tmp suffix + O_EXCL +
        // O_NOFOLLOW + mode 0o600 + parent fsync (symlink/TOCTOU-resistant,
        // owner-only). Replaces a weaker local copy that used a predictable
        // `.tmp` name with no O_EXCL/O_NOFOLLOW/mode hardening.
        veil_util::atomic_write(path, &encoded)?;
        Ok(())
    }

    /// Change only the label; id stays fixed.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        let mut label = label.into();
        truncate_utf8_to_bytes(&mut label, MAX_LABEL_BYTES);
        self.label = label;
        self
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + INSTANCE_ID_LEN + 1 + self.label.len());
        out.extend_from_slice(&INSTANCE_FILE_MAGIC);
        out.push(INSTANCE_FILE_V1);
        out.extend_from_slice(&self.instance_id);
        out.push(self.label.len() as u8);
        out.extend_from_slice(self.label.as_bytes());
        out
    }

    fn decode(buf: &[u8]) -> Result<Self, InstanceFileError> {
        if buf.len() < 3 + INSTANCE_ID_LEN + 1 {
            return Err(InstanceFileError::Malformed(format!(
                "truncated (got {} bytes)",
                buf.len()
            )));
        }
        if buf[0..2] != INSTANCE_FILE_MAGIC {
            return Err(InstanceFileError::Malformed("bad magic".into()));
        }
        if buf[2] != INSTANCE_FILE_V1 {
            return Err(InstanceFileError::Malformed(format!(
                "unsupported version {}",
                buf[2]
            )));
        }
        let mut instance_id = [0u8; INSTANCE_ID_LEN];
        instance_id.copy_from_slice(&buf[3..3 + INSTANCE_ID_LEN]);
        let label_len = buf[3 + INSTANCE_ID_LEN] as usize;
        if label_len > MAX_LABEL_BYTES {
            return Err(InstanceFileError::Malformed(format!(
                "label_len {label_len} exceeds cap {MAX_LABEL_BYTES}"
            )));
        }
        let label_start = 3 + INSTANCE_ID_LEN + 1;
        let label_end = label_start + label_len;
        if buf.len() != label_end {
            return Err(InstanceFileError::Malformed(format!(
                "size {} != expected {label_end}",
                buf.len()
            )));
        }
        let label = std::str::from_utf8(&buf[label_start..label_end])
            .map_err(|e| InstanceFileError::Malformed(format!("label utf8: {e}")))?
            .to_string();
        Ok(Self { instance_id, label })
    }
}

/// Build the conventional path for a given veil state directory.
///
/// The `state_dir` is typically
/// [`cfg::runtime_veil_dir`](super::runtime_veil_dir), which
/// already handles Linux/macOS XDG conventions.
pub fn default_instance_path(state_dir: &Path) -> PathBuf {
    state_dir.join(DEFAULT_INSTANCE_FILE)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Truncate `s` so that its UTF-8 byte length is ≤ `limit`, at a char
/// boundary (so we never slice a multi-byte codepoint in half).
fn truncate_utf8_to_bytes(s: &mut String, limit: usize) {
    if s.len() <= limit {
        return;
    }
    let mut end = limit;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    fn tempdir() -> PathBuf {
        crate::test_support::scratch_dir("veil-instance-test")
    }

    #[test]
    fn generate_is_random() {
        let a = LocalInstance::generate("a");
        let b = LocalInstance::generate("b");
        assert_ne!(a.instance_id, b.instance_id);
    }

    #[test]
    fn roundtrip_basic() {
        let dir = tempdir();
        let path = dir.join("instance_id");
        let inst = LocalInstance::generate("laptop");
        inst.save(&path).unwrap();
        let loaded = LocalInstance::load(&path).unwrap();
        assert_eq!(loaded, inst);
    }

    #[test]
    fn load_or_init_creates_when_missing() {
        let dir = tempdir();
        let path = dir.join("instance_id");
        assert!(!path.exists());
        let inst = LocalInstance::load_or_init(&path, "fresh").unwrap();
        assert_eq!(inst.label, "fresh");
        assert!(path.exists());
        // Second call must return the same id.
        let again = LocalInstance::load_or_init(&path, "different-label-ignored").unwrap();
        assert_eq!(again, inst);
    }

    #[test]
    fn load_on_nonexistent_file_returns_io_not_found() {
        let dir = tempdir();
        let path = dir.join("does-not-exist");
        let err = LocalInstance::load(&path).unwrap_err();
        match err {
            InstanceFileError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let dir = tempdir();
        let path = dir.join("bad");
        let inst = LocalInstance::generate("x");
        inst.save(&path).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] = b'X';
        fs::write(&path, &bytes).unwrap();
        let err = LocalInstance::load(&path).unwrap_err();
        assert!(matches!(err, InstanceFileError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_unknown_version() {
        let dir = tempdir();
        let path = dir.join("v99");
        let inst = LocalInstance::generate("x");
        inst.save(&path).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[2] = 99;
        fs::write(&path, &bytes).unwrap();
        let err = LocalInstance::load(&path).unwrap_err();
        assert!(matches!(err, InstanceFileError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_truncated_file() {
        let dir = tempdir();
        let path = dir.join("trunc");
        let inst = LocalInstance::generate("x");
        inst.save(&path).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes.truncate(5);
        fs::write(&path, &bytes).unwrap();
        let err = LocalInstance::load(&path).unwrap_err();
        assert!(matches!(err, InstanceFileError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_size_mismatch() {
        let dir = tempdir();
        let path = dir.join("extra");
        let inst = LocalInstance::generate("x");
        inst.save(&path).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(0xFF);
        fs::write(&path, &bytes).unwrap();
        let err = LocalInstance::load(&path).unwrap_err();
        assert!(matches!(err, InstanceFileError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn generate_truncates_oversized_label_at_char_boundary() {
        let long = "a".repeat(MAX_LABEL_BYTES + 10);
        let inst = LocalInstance::generate(long);
        assert_eq!(inst.label.len(), MAX_LABEL_BYTES);
        assert!(inst.label.is_char_boundary(inst.label.len()));
    }

    #[test]
    fn generate_preserves_utf8_char_boundaries_on_truncate() {
        // Fill with 3-byte codepoints; after truncation to
        // MAX_LABEL_BYTES bytes we must still be on a char boundary.
        let three_byte = "中"; // 3 bytes in UTF-8
        let long = three_byte.repeat(MAX_LABEL_BYTES);
        let inst = LocalInstance::generate(long);
        assert!(inst.label.len() <= MAX_LABEL_BYTES);
        assert!(inst.label.chars().all(|c| c == '中'));
    }

    #[test]
    fn with_label_preserves_id() {
        let a = LocalInstance::generate("first");
        let b = a.clone().with_label("renamed");
        assert_eq!(a.instance_id, b.instance_id);
        assert_eq!(b.label, "renamed");
    }

    #[test]
    fn save_rejects_label_above_cap_in_memory() {
        // If a caller bypasses generate/with_label and pushes
        // label > MAX_LABEL_BYTES directly, save surfaces the error.
        let mut inst = LocalInstance::generate("x");
        inst.label = "a".repeat(MAX_LABEL_BYTES + 1);
        let dir = tempdir();
        let err = inst.save(&dir.join("f")).unwrap_err();
        assert!(matches!(err, InstanceFileError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn creates_parent_directory() {
        let dir = tempdir();
        let path = dir.join("nested").join("sub").join("instance_id");
        let inst = LocalInstance::generate("x");
        inst.save(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn empty_label_roundtrips() {
        let dir = tempdir();
        let path = dir.join("empty");
        let inst = LocalInstance::generate("");
        inst.save(&path).unwrap();
        let loaded = LocalInstance::load(&path).unwrap();
        assert_eq!(loaded, inst);
        assert!(loaded.label.is_empty());
    }

    #[test]
    fn default_instance_path_uses_conventional_filename() {
        let dir = PathBuf::from("/tmp/veil-state");
        let path = default_instance_path(&dir);
        assert_eq!(path, dir.join("instance_id"));
    }

    #[test]
    fn stable_across_process_restart_simulation() {
        // The contract: load_or_init is idempotent across callers.
        let dir = tempdir();
        let path = dir.join("instance_id");
        let first = LocalInstance::load_or_init(&path, "one").unwrap();
        // Different caller with a different default label — id must
        // not change.
        let second = LocalInstance::load_or_init(&path, "two").unwrap();
        assert_eq!(first, second);
        assert_eq!(second.label, "one");
    }
}
