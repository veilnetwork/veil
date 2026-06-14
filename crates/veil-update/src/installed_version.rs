//! Persistent record of the currently-installed binary's
//! `release_unix`.
//!
//! Used by the update mechanism in two places:
//! * `check_for_update` — compare against operator's currently-
//!   published manifest to decide UpToDate vs Available.
//! * apply path — pass to `verify_manifest` to enforce
//!   anti-downgrade.
//!
//! # Why a separate state file (not a config field)
//!
//! Operators edit config; the runtime should NEVER write to the
//! operator's config file (would lose comments, formatting
//! re-order keys). Installed-version is machine-set, not operator-
//! set, so it lives in its own JSON file under a runtime-state
//! directory chosen by the operator (e.g. `/var/lib/veil/`).
//!
//! # Wire format
//!
//! Single-line JSON: `{"release_unix":1700000000}`. Plain enough
//! that operators can `cat` + `jq` it for diagnostics; rich enough
//! that future fields (installed_sha256, installed_version_str
//! manifest_blob) can be added without breaking older readers.
//! Unknown JSON fields are ignored on read; missing required field
//! reports a clean parse error.
//!
//! # Atomicity
//!
//! Writes go through [`veil_util::atomic_write`] (write-to-tmp +
//! fsync + rename) so a crash mid-install never leaves the file
//! truncated or half-written. After a power loss the next read
//! either sees the old release_unix or the new one — never garbage.

use std::path::{Path, PathBuf};

use veil_util::atomic_write;

/// split error variants so callers
/// can react differently to a malformed file vs a missing required
/// field vs a HMAC failure. Previously everything non-I/O was a
/// `Parse(String)` blob — operators couldn't distinguish "file is
/// garbage" from "file's mac doesn't verify" at a glance, and the
/// upper-layer apply path couldn't decide whether to back-off or
/// fail-fast.
#[derive(Debug, thiserror::Error)]
pub enum InstalledVersionError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON decode failed — file is corrupt, partial-write garbage
    /// or schema-drift between binaries.
    #[error("malformed installed-version file: {0}")]
    Malformed(String),
    /// File's `mac` field is missing or doesn't verify (keyed
    /// load). Distinct from `Malformed` so the apply path can
    /// fail-fast (refuse to dial-down the floor) vs continue
    /// bootstrapping in unauthenticated mode.
    #[error("installed-version file failed HMAC verification (corrupt or tampered)")]
    MacFailure,
    /// Backwards-compat variant for callers that match against the
    /// old `Parse(String)` shape. New code should use
    /// [`Self::Malformed`] or [`Self::MacFailure`].
    #[error("parse installed-version file: {0}")]
    Parse(String),
}

/// JSON shape on disk. Public for callers that want to read a
/// pre-decoded record without going through the store API (e.g.
/// debug tools).
///
/// when the store is configured with an HMAC
/// key (production path), the on-disk JSON carries an additional
/// `mac` field — a BLAKE3 keyed-hash over the canonical body
/// `{"release_unix": N}`. A local FS-write attacker can no longer
/// silently rewrite `release_unix` to bypass anti-downgrade because
/// the MAC won't verify. Legacy (no-key) stores still read the
/// unauthenticated form for backwards compatibility.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstalledVersionRecord {
    /// release_unix of the manifest that produced the installed binary.
    pub release_unix: u64,
    /// BLAKE3 keyed-hash over `serde_json::to_vec(SignedBody { release_unix })`.
    /// Hex-encoded. Absence = legacy / unauthenticated record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

/// Inner body that the MAC commits (excludes the MAC field itself).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SignedBody {
    release_unix: u64,
}

/// Domain-tag prefixed to the BLAKE3 keyed-hash input so the same
/// per-device key cannot be cross-protocol-misused as a MAC for any
/// other JSON file format.
const INSTALLED_VERSION_MAC_DOMAIN: &[u8] = b"veil-installed-version-mac-v1\0";

/// File-backed persistence for `installed_release_unix`.
#[derive(Debug, Clone)]
pub struct InstalledVersionStore {
    path: PathBuf,
    hmac_key: Option<[u8; 32]>,
}

impl InstalledVersionStore {
    /// Legacy unauthenticated store. Kept for tests and tools that
    /// haven't been updated to thread an HMAC key. Production callers
    /// should use [`Self::with_hmac_key`] instead.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            hmac_key: None,
        }
    }

    /// HMAC-aware constructor. All writes embed a MAC; all reads
    /// verify it and refuse silently-tampered files.
    pub fn with_hmac_key(path: PathBuf, hmac_key: [u8; 32]) -> Self {
        Self {
            path,
            hmac_key: Some(hmac_key),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the installed_release_unix from disk.
    ///
    /// Returns `Ok(None)` if the file does not exist (fresh install
    /// or operator hasn't run an update yet). Returns `Err` only on
    /// real I/O errors or parse failures — file-not-found is NOT an
    /// error because every node's first run starts in this state.
    ///
    /// when the store has an HMAC key, the
    /// on-disk MAC is verified and a mismatch surfaces as a parse
    /// error so the apply path fail-safes — better to refuse the
    /// install than to silently dial-down the anti-downgrade floor.
    pub fn read(&self) -> Result<Option<InstalledVersionRecord>, InstalledVersionError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                // distinguish malformed JSON
                // (Malformed) from MAC failure (MacFailure) so callers
                // can react differently — see the variant docs.
                let rec: InstalledVersionRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| InstalledVersionError::Malformed(e.to_string()))?;
                if let Some(key) = self.hmac_key {
                    // Authenticated mode — file MUST have a valid MAC.
                    if !verify_record_mac(&rec, &key) {
                        return Err(InstalledVersionError::MacFailure);
                    }
                }
                Ok(Some(rec))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(InstalledVersionError::Io(e)),
        }
    }

    /// Write a fresh `installed_release_unix` atomically. Replaces
    /// any existing record — the apply path calls this AFTER a
    /// successful binary swap.
    pub fn write(&self, release_unix: u64) -> Result<(), InstalledVersionError> {
        let mac = self.hmac_key.map(|key| {
            let body = SignedBody { release_unix };
            let body_bytes =
                serde_json::to_vec(&body).expect("SignedBody serialization is infallible");
            compute_record_mac(&body_bytes, &key)
        });
        let rec = InstalledVersionRecord { release_unix, mac };
        let mut bytes =
            serde_json::to_vec(&rec).map_err(|e| InstalledVersionError::Parse(e.to_string()))?;
        // Trailing newline so `cat` output is operator-friendly.
        bytes.push(b'\n');
        atomic_write(&self.path, &bytes)?;
        Ok(())
    }

    /// Convenience: read just the `release_unix` value, mapping
    /// "file does not exist" to `None`. Used by `check_for_update`
    /// callers that don't care about the wrapper struct.
    pub fn read_release_unix(&self) -> Result<Option<u64>, InstalledVersionError> {
        Ok(self.read()?.map(|r| r.release_unix))
    }

    /// Anti-downgrade read for the apply path, tolerant of a one-time
    /// migration from a legacy (unauthenticated) state file.
    ///
    /// Returns `(release_unix, was_legacy)`:
    /// * unkeyed store, OR keyed store with a VALID mac → `(Some(v), false)`.
    /// * keyed store, record carries NO mac (written before C-08 enabled
    ///   authentication) → `(Some(v), true)`: the caller adopts the value once
    ///   (trust-on-first-use) and the subsequent [`Self::write`] re-writes it
    ///   authenticated, so later reads are `Ok` or `MacFailure`.
    /// * keyed store, record carries a PRESENT-but-INVALID mac →
    ///   `Err(MacFailure)`: tampering with an already-authenticated record is
    ///   never silently accepted (fail-closed).
    /// * no file → `(None, false)`.
    ///
    /// **SECURITY (C-08):** the legacy (no-mac) branch is trust-on-first-use.
    /// An attacker who rewrites the still-unauthenticated file before the first
    /// authenticated write can seed a lowered floor — no worse than the pre-C-08
    /// fully-unauthenticated state, and only in that one migration window. After
    /// the first authenticated write, any change to the recorded value is
    /// detected. Because a no-mac file is always treated as legacy, a writer who
    /// can also strip the mac can re-enter the migration window; the apply path
    /// therefore surfaces the migration to the operator (see
    /// `ApplyOutcome::migrated_legacy_state`) so a repeated no-mac downgrade is
    /// visible rather than silent.
    pub fn read_release_unix_for_apply(
        &self,
    ) -> Result<(Option<u64>, bool), InstalledVersionError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let rec: InstalledVersionRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| InstalledVersionError::Malformed(e.to_string()))?;
                match self.hmac_key {
                    // Unauthenticated store: behaves exactly as before.
                    None => Ok((Some(rec.release_unix), false)),
                    Some(key) => {
                        if rec.mac.is_none() {
                            // Legacy record predating authentication → migrate.
                            Ok((Some(rec.release_unix), true))
                        } else if verify_record_mac(&rec, &key) {
                            Ok((Some(rec.release_unix), false))
                        } else {
                            // mac present but wrong → active tampering.
                            Err(InstalledVersionError::MacFailure)
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((None, false)),
            Err(e) => Err(InstalledVersionError::Io(e)),
        }
    }
}

/// Derive the anti-downgrade state-file MAC key from a node's 32-byte Ed25519
/// identity seed. Both the apply path AND the update checker (diff-audit M16)
/// MUST derive the key this way so the file one writes is verifiable by the
/// other — otherwise the checker would either trust an unauthenticated file or
/// reject a correctly-authenticated one.
pub fn mac_key_from_ed25519_seed(seed: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("veil.update.installed-version.mac.v1", seed)
}

fn compute_record_mac(body_bytes: &[u8], key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(INSTALLED_VERSION_MAC_DOMAIN);
    hasher.update(body_bytes);
    let h = hasher.finalize();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(h.as_bytes())
}

fn verify_record_mac(rec: &InstalledVersionRecord, key: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq as _;
    let Some(claimed_b64) = rec.mac.as_deref() else {
        return false;
    };
    use base64::Engine as _;
    let Ok(claimed_bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(claimed_b64)
    else {
        return false;
    };
    let body = SignedBody {
        release_unix: rec.release_unix,
    };
    let body_bytes = match serde_json::to_vec(&body) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(INSTALLED_VERSION_MAC_DOMAIN);
    hasher.update(&body_bytes);
    let expected = hasher.finalize();
    expected.as_bytes().ct_eq(claimed_bytes.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn unique_path(label: &str) -> PathBuf {
        // Use the same kind of unique-name scheme the rest of the
        // tree uses for tmpfile tests — millisecond timestamp +
        // a per-test label keeps parallel runs isolated even when
        // the same test fixture function is reused.
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("veil-installed-version-{label}-{pid}-{nanos}.json"))
    }

    #[test]
    fn epic484_3_read_returns_none_when_file_missing() {
        let path = unique_path("read-missing");
        let store = InstalledVersionStore::new(path.clone());
        assert!(matches!(store.read(), Ok(None)));
        // Cleanup is unnecessary — file never existed.
    }

    #[test]
    fn epic484_3_write_then_read_round_trip() {
        let path = unique_path("write-then-read");
        let store = InstalledVersionStore::new(path.clone());
        store.write(1_700_000_000).unwrap();
        let r = store.read().unwrap().expect("file must exist after write");
        assert_eq!(r.release_unix, 1_700_000_000);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epic484_3_write_replaces_existing_record() {
        // Apply path writes the NEW release_unix after a successful
        // binary swap, replacing the old one. Verify atomic-replace
        // semantics: subsequent read sees the new value.
        let path = unique_path("write-replace");
        let store = InstalledVersionStore::new(path.clone());
        store.write(1_700_000_000).unwrap();
        store.write(1_800_000_000).unwrap();
        let r = store.read_release_unix().unwrap();
        assert_eq!(r, Some(1_800_000_000));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epic484_3_read_release_unix_short_circuit_for_missing_file() {
        let path = unique_path("short-circuit");
        let store = InstalledVersionStore::new(path);
        assert_eq!(store.read_release_unix().unwrap(), None);
    }

    #[test]
    fn epic484_3_malformed_file_surfaces_parse_error() {
        // An operator (or a bug, or a corrupted disk) leaves garbage
        // in the state file. Read must NOT panic; must surface a
        // clean Parse error so the caller can decide whether to
        // fall back to "treat as fresh install" or surface to the
        // operator.
        let path = unique_path("malformed");
        std::fs::write(&path, b"this is not json").unwrap();
        let store = InstalledVersionStore::new(path.clone());
        let err = store.read().unwrap_err();
        assert!(matches!(err, InstalledVersionError::Malformed(_)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epic484_3_unknown_json_fields_are_ignored_for_forward_compat() {
        // Future binaries may add fields (installed_sha256
        // installed_version_str, manifest_blob). Older binaries
        // reading those files must NOT fail — serde drops unknowns
        // by default, but make this an explicit invariant test
        // because regressions here break rollback compatibility.
        let path = unique_path("forward-compat");
        std::fs::write(
            &path,
            br#"{"release_unix":1700000000,"future_field":"hello","another":42}"#,
        )
        .unwrap();
        let store = InstalledVersionStore::new(path.clone());
        let r = store
            .read()
            .unwrap()
            .expect("must parse despite unknown fields");
        assert_eq!(r.release_unix, 1_700_000_000);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epic484_3_missing_required_field_is_parse_error() {
        // Inverse of the forward-compat test: a record missing the
        // REQUIRED release_unix field must NOT silently default.
        let path = unique_path("missing-required");
        std::fs::write(&path, br#"{"unrelated":42}"#).unwrap();
        let store = InstalledVersionStore::new(path.clone());
        let err = store.read().unwrap_err();
        assert!(matches!(err, InstalledVersionError::Malformed(_)));
        let _ = std::fs::remove_file(&path);
    }

    /// HMAC mode → write+read round-trip
    /// recovers the original release_unix and the embedded MAC field
    /// is non-empty.
    #[test]
    fn phase647_h15_hmac_round_trip_preserves_release_unix() {
        let path = unique_path("h15-roundtrip");
        let key = [0x33u8; 32];
        let store = InstalledVersionStore::with_hmac_key(path.clone(), key);
        store.write(1_750_000_000).unwrap();
        let r = store.read().unwrap().expect("file must exist");
        assert_eq!(r.release_unix, 1_750_000_000);
        assert!(
            r.mac.is_some(),
            "MAC field must be present in authenticated mode"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// attacker rewrites release_unix in place to bypass
    /// anti-downgrade. MAC verification surfaces a parse error.
    #[test]
    fn phase647_h15_tampered_release_unix_fails_verification() {
        let path = unique_path("h15-tampered");
        let key = [0x66u8; 32];
        let store = InstalledVersionStore::with_hmac_key(path.clone(), key);
        store.write(1_750_000_000).unwrap();
        // Attacker rewrites just the release_unix field.
        let raw = std::fs::read_to_string(&path).unwrap();
        let tampered = raw.replace("1750000000", "1600000000");
        std::fs::write(&path, tampered).unwrap();
        let err = store.read().unwrap_err();
        assert!(
            matches!(err, InstalledVersionError::MacFailure),
            "tampered file must surface as MacFailure"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// HMAC-aware read of a legacy file (no `mac` field) must
    /// also be rejected — the apply path should fail-safe rather than
    /// dial-down the floor based on an unauthenticated input.
    #[test]
    fn phase647_h15_keyed_read_rejects_legacy_unsigned_record() {
        let path = unique_path("h15-legacy-rejected");
        // Write a plain (unsigned) record manually.
        std::fs::write(&path, br#"{"release_unix":1700000000}"#).unwrap();
        let store = InstalledVersionStore::with_hmac_key(path.clone(), [0u8; 32]);
        let err = store.read().unwrap_err();
        assert!(matches!(err, InstalledVersionError::MacFailure));
        let _ = std::fs::remove_file(&path);
    }

    /// legacy `new` constructor stays unauthenticated and
    /// reads/writes the no-mac form (backwards compat path).
    #[test]
    fn phase647_h15_legacy_constructor_writes_no_mac_field() {
        let path = unique_path("h15-legacy-write");
        let store = InstalledVersionStore::new(path.clone());
        store.write(1_700_000_000).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("\"mac\""),
            "legacy unauthenticated write must NOT emit a mac field: {raw}"
        );
        let r = store.read().unwrap().unwrap();
        assert_eq!(r.release_unix, 1_700_000_000);
        let _ = std::fs::remove_file(&path);
    }

    // ── C-08: read_release_unix_for_apply migration semantics ──────────────

    /// Unkeyed store behaves exactly as the plain read: value, never "legacy".
    #[test]
    fn c08_apply_read_unkeyed_is_never_legacy() {
        let path = unique_path("c08-unkeyed");
        let store = InstalledVersionStore::new(path.clone());
        store.write(1_700_000_000).unwrap();
        assert_eq!(
            store.read_release_unix_for_apply().unwrap(),
            (Some(1_700_000_000), false)
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Keyed store reading its own authenticated record: value, not legacy.
    #[test]
    fn c08_apply_read_keyed_valid_mac_is_not_legacy() {
        let path = unique_path("c08-keyed-valid");
        let store = InstalledVersionStore::with_hmac_key(path.clone(), [0x5Au8; 32]);
        store.write(1_750_000_000).unwrap();
        assert_eq!(
            store.read_release_unix_for_apply().unwrap(),
            (Some(1_750_000_000), false)
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Keyed store reading a LEGACY (no-mac) file written before C-08: accepted
    /// once, flagged `was_legacy = true` so the caller migrates; the subsequent
    /// authenticated write clears the flag.
    #[test]
    fn c08_apply_read_keyed_legacy_no_mac_is_migration() {
        let path = unique_path("c08-legacy-migrate");
        // File as written by a pre-C-08 (unkeyed) apply.
        InstalledVersionStore::new(path.clone())
            .write(1_700_000_000)
            .unwrap();
        let keyed = InstalledVersionStore::with_hmac_key(path.clone(), [0x5Au8; 32]);
        assert_eq!(
            keyed.read_release_unix_for_apply().unwrap(),
            (Some(1_700_000_000), true),
            "legacy no-mac file must be accepted once as a migration"
        );
        // After the apply re-writes it, the next read is authenticated, not legacy.
        keyed.write(1_800_000_000).unwrap();
        assert_eq!(
            keyed.read_release_unix_for_apply().unwrap(),
            (Some(1_800_000_000), false),
            "re-written record is authenticated, no longer a migration"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Keyed store reading a record whose mac is PRESENT but wrong (active
    /// tampering of an already-authenticated file): fail-closed, never adopted
    /// as a migration.
    #[test]
    fn c08_apply_read_keyed_bad_mac_is_rejected_not_migrated() {
        let path = unique_path("c08-bad-mac");
        let store = InstalledVersionStore::with_hmac_key(path.clone(), [0x66u8; 32]);
        store.write(1_750_000_000).unwrap();
        // Attacker lowers release_unix in place; the mac no longer matches.
        let raw = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, raw.replace("1750000000", "1600000000")).unwrap();
        assert!(
            matches!(
                store.read_release_unix_for_apply(),
                Err(InstalledVersionError::MacFailure)
            ),
            "a present-but-invalid mac must fail closed, not migrate"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// No state file → fresh install: (None, not-legacy).
    #[test]
    fn c08_apply_read_missing_file_is_fresh() {
        let path = unique_path("c08-missing");
        let store = InstalledVersionStore::with_hmac_key(path, [0u8; 32]);
        assert_eq!(store.read_release_unix_for_apply().unwrap(), (None, false));
    }
}
