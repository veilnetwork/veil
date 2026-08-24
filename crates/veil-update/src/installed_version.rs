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
/// the MAC won't verify. An unkeyed store still reads the plain form,
/// which is what the read-only inspect and check paths use.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstalledVersionRecord {
    /// release_unix of the manifest that produced the installed binary.
    pub release_unix: u64,
    /// BLAKE3 keyed-hash over `serde_json::to_vec(SignedBody { release_unix })`.
    /// Hex-encoded. Absent only for an unkeyed store's own writes.
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

/// `release_unix` of the build this binary came from, baked in at compile time
/// from `$VEIL_RELEASE_UNIX`.
///
/// `scripts/build-release.sh` exports it from the same `--source-date-epoch`
/// variable it hands to `update sign-manifest --release-unix`, so a release
/// binary and the manifest that publishes it carry the identical number. A
/// developer `cargo build` leaves the variable unset and gets `0`, which
/// contributes no floor — exactly today's behaviour.
///
/// ⚠️ TWO release paths, not one. `release.yml` builds the Windows targets by
/// calling cargo directly (the repo-global clang `[env]` breaks on
/// `*-windows-msvc`), so it does NOT go through that script. It had no
/// equivalent export, which meant every published Windows binary carried a
/// floor of `0` — a missing variable degrades in silence, since the const
/// parser below only rejects a malformed one. That leg now sets the variable
/// and refuses to build without it; any third build path must do the same.
///
/// A DEDICATED variable rather than `SOURCE_DATE_EPOCH`: distro build systems
/// (Debian, Nix, Guix) set `SOURCE_DATE_EPOCH` to their own changelog date, and
/// a downstream rebuild stamped later than the upstream manifest would refuse
/// upstream's updates forever. This name is ours.
pub const EMBEDDED_RELEASE_UNIX: u64 = parse_embedded_release_unix();

/// Decimal parse in const context. A malformed `VEIL_RELEASE_UNIX` fails the
/// BUILD rather than silently degrading to `0` — a release binary that quietly
/// shipped without its floor is the failure this whole constant exists to
/// prevent, and it would be invisible until someone tried the downgrade.
const fn parse_embedded_release_unix() -> u64 {
    match option_env!("VEIL_RELEASE_UNIX") {
        None => 0,
        Some(text) => {
            let bytes = text.as_bytes();
            if bytes.is_empty() {
                panic!("VEIL_RELEASE_UNIX is set but empty");
            }
            let mut value: u64 = 0;
            let mut i = 0;
            while i < bytes.len() {
                let digit = bytes[i];
                if digit < b'0' || digit > b'9' {
                    panic!("VEIL_RELEASE_UNIX must be decimal digits only");
                }
                // Overflow is a const-eval error, so an absurd value is a build
                // failure too.
                value = value * 10 + (digit - b'0') as u64;
                i += 1;
            }
            value
        }
    }
}

/// The monotonic release floor an apply (or an availability decision) must
/// clear, given the authenticated on-disk record.
///
/// Missing state used to mean floor `0` — "fresh install, anything signed is
/// newer". That is true of a fresh install and false of an installed node whose
/// state file was deleted, and deleting one file is not a privilege. The gap
/// was wide enough for an OLD but still-validly-signed and still-unexpired
/// manifest to replace a newer running binary, reintroducing whatever that
/// release fixed.
///
/// The running binary's own release timestamp closes it: a process cannot be
/// executing a build that had not been published yet, so
/// [`EMBEDDED_RELEASE_UNIX`] is a floor an attacker cannot lower without first
/// replacing the binary — which is the thing they were trying to do. A genuine
/// fresh install is unaffected, because its binary was published before the
/// update it is fetching; and an authenticated record NEWER than the embedded
/// value still wins, so a node that has already updated is not dragged back to
/// its original release.
pub fn anti_downgrade_floor(recorded: Option<u64>) -> u64 {
    anti_downgrade_floor_from(recorded, embedded_release_unix())
}

/// [`anti_downgrade_floor`] with the embedded value passed in, so the policy
/// can be stated once and checked without rebuilding the crate.
pub(crate) fn anti_downgrade_floor_from(recorded: Option<u64>, embedded: u64) -> u64 {
    recorded.unwrap_or(0).max(embedded)
}

#[cfg(not(test))]
fn embedded_release_unix() -> u64 {
    EMBEDDED_RELEASE_UNIX
}

/// Test builds read the embedded floor through a thread-local so the REAL
/// decision — the one `apply_update` makes at its own call site — can be
/// exercised against a non-zero floor. A test suite compiled without
/// `VEIL_RELEASE_UNIX` has an embedded value of `0`, and a fix whose only
/// coverage was a helper function returning `0` would pass just as happily
/// with the fix removed.
#[cfg(test)]
fn embedded_release_unix() -> u64 {
    EMBEDDED_RELEASE_UNIX_OVERRIDE.with(|slot| slot.get().unwrap_or(EMBEDDED_RELEASE_UNIX))
}

#[cfg(test)]
thread_local! {
    static EMBEDDED_RELEASE_UNIX_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Pretend, for the current thread, that this binary was published at
/// `release_unix`. Restores the previous value on drop so tests running in
/// parallel on other threads are untouched.
#[cfg(test)]
pub(crate) struct EmbeddedReleaseGuard(Option<u64>);

#[cfg(test)]
impl EmbeddedReleaseGuard {
    pub(crate) fn set(release_unix: u64) -> Self {
        let previous = EMBEDDED_RELEASE_UNIX_OVERRIDE.with(|slot| slot.replace(Some(release_unix)));
        Self(previous)
    }
}

#[cfg(test)]
impl Drop for EmbeddedReleaseGuard {
    fn drop(&mut self) {
        EMBEDDED_RELEASE_UNIX_OVERRIDE.with(|slot| slot.set(self.0));
    }
}

/// File-backed persistence for `installed_release_unix`.
#[derive(Debug, Clone)]
pub struct InstalledVersionStore {
    path: PathBuf,
    hmac_key: Option<[u8; 32]>,
}

impl InstalledVersionStore {
    /// Unauthenticated store, for read-only callers (inspect, the update
    /// checker) and tests. Anything that gates anti-downgrade must use
    /// [`Self::with_hmac_key`] instead.
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

    /// Anti-downgrade read for the apply path.
    ///
    /// * unkeyed store → `Some(v)` (the value is simply not authenticated).
    /// * keyed store with a VALID mac → `Some(v)`.
    /// * keyed store, record carries NO mac, or a PRESENT-but-INVALID one →
    ///   `Err(MacFailure)`. Both are fail-closed: an unauthenticated record
    ///   under a keyed store means someone stripped the mac, and adopting it
    ///   would re-open the anti-downgrade window.
    /// * no file → `None` (fresh install).
    pub fn read_release_unix_for_apply(&self) -> Result<Option<u64>, InstalledVersionError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let rec: InstalledVersionRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| InstalledVersionError::Malformed(e.to_string()))?;
                match self.hmac_key {
                    None => Ok(Some(rec.release_unix)),
                    Some(key) if verify_record_mac(&rec, &key) => Ok(Some(rec.release_unix)),
                    Some(_) => Err(InstalledVersionError::MacFailure),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
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

    // ── V13-H4: the floor must not collapse when the state file goes away ──

    /// The defect. `read_release_unix_for_apply` reports `None` for a deleted
    /// state file exactly as it does for a fresh install, and `unwrap_or(0)`
    /// turned that into "any signed manifest is newer". Deleting one JSON file
    /// is not a privilege; it must not buy an attacker a downgrade.
    #[test]
    fn missing_state_falls_back_to_the_embedded_release() {
        let embedded = 1_800_000_000;
        assert_eq!(anti_downgrade_floor_from(None, embedded), embedded);
    }

    /// A genuine fresh install still installs: the binary was published before
    /// the update it is fetching, so the manifest clears its own binary's floor.
    #[test]
    fn a_fresh_install_still_clears_its_own_embedded_floor() {
        let embedded = 1_800_000_000;
        let newer_manifest = embedded + 1;
        assert!(newer_manifest > anti_downgrade_floor_from(None, embedded));
    }

    /// A node that has already updated must not be dragged back to the release
    /// its binary shipped with: the authenticated record wins when it is higher.
    #[test]
    fn an_authenticated_state_newer_than_embedded_wins() {
        let embedded = 1_800_000_000;
        let recorded = 1_900_000_000;
        assert_eq!(
            anti_downgrade_floor_from(Some(recorded), embedded),
            recorded
        );
    }

    /// And the reverse: a hand-replaced binary newer than the record is floored
    /// by the binary, not by the stale record.
    #[test]
    fn an_embedded_release_newer_than_the_state_wins() {
        let embedded = 1_900_000_000;
        let recorded = 1_800_000_000;
        assert_eq!(
            anti_downgrade_floor_from(Some(recorded), embedded),
            embedded
        );
    }

    /// A developer build leaves `VEIL_RELEASE_UNIX` unset, contributes no floor,
    /// and behaves exactly as before.
    #[test]
    fn an_unstamped_build_contributes_no_floor() {
        assert_eq!(anti_downgrade_floor_from(Some(42), 0), 42);
        assert_eq!(anti_downgrade_floor_from(None, 0), 0);
    }

    /// The public entry point must consult the embedded value, not just the
    /// record — this is what `apply_update` and the checker actually call.
    #[test]
    fn the_public_floor_consults_the_embedded_release() {
        let _guard = EmbeddedReleaseGuard::set(1_800_000_000);
        assert_eq!(anti_downgrade_floor(None), 1_800_000_000);
        assert_eq!(anti_downgrade_floor(Some(1_700_000_000)), 1_800_000_000);
        assert_eq!(anti_downgrade_floor(Some(1_900_000_000)), 1_900_000_000);
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

    /// HMAC-aware read of a file with no `mac` field must
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

    /// the unkeyed `new` constructor stays unauthenticated and
    /// reads/writes the no-mac form (backwards compat path).
    #[test]
    fn phase647_h15_legacy_constructor_writes_no_mac_field() {
        let path = unique_path("h15-legacy-write");
        let store = InstalledVersionStore::new(path.clone());
        store.write(1_700_000_000).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("\"mac\""),
            "an unkeyed write must NOT emit a mac field: {raw}"
        );
        let r = store.read().unwrap().unwrap();
        assert_eq!(r.release_unix, 1_700_000_000);
        let _ = std::fs::remove_file(&path);
    }

    // ── C-08: read_release_unix_for_apply semantics ────────────────────────

    /// Unkeyed store behaves exactly as the plain read.
    #[test]
    fn c08_apply_read_unkeyed_returns_the_value() {
        let path = unique_path("c08-unkeyed");
        let store = InstalledVersionStore::new(path.clone());
        store.write(1_700_000_000).unwrap();
        assert_eq!(
            store.read_release_unix_for_apply().unwrap(),
            Some(1_700_000_000)
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Keyed store reading its own authenticated record.
    #[test]
    fn c08_apply_read_keyed_valid_mac_returns_the_value() {
        let path = unique_path("c08-keyed-valid");
        let store = InstalledVersionStore::with_hmac_key(path.clone(), [0x5Au8; 32]);
        store.write(1_750_000_000).unwrap();
        assert_eq!(
            store.read_release_unix_for_apply().unwrap(),
            Some(1_750_000_000)
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Keyed store reading a record with NO mac: fail-closed. There is no
    /// migration path any more, so a stripped mac cannot re-open the
    /// anti-downgrade window even once.
    #[test]
    fn c08_apply_read_keyed_no_mac_is_rejected() {
        let path = unique_path("c08-no-mac-rejected");
        InstalledVersionStore::new(path.clone())
            .write(1_700_000_000)
            .unwrap();
        let keyed = InstalledVersionStore::with_hmac_key(path.clone(), [0x5Au8; 32]);
        assert!(
            matches!(
                keyed.read_release_unix_for_apply(),
                Err(InstalledVersionError::MacFailure)
            ),
            "an unauthenticated record under a keyed store must fail closed"
        );
        // A properly authenticated write is readable again.
        keyed.write(1_800_000_000).unwrap();
        assert_eq!(
            keyed.read_release_unix_for_apply().unwrap(),
            Some(1_800_000_000)
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
            "a present-but-invalid mac must fail closed"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// No state file → fresh install.
    #[test]
    fn c08_apply_read_missing_file_is_fresh() {
        let path = unique_path("c08-missing");
        let store = InstalledVersionStore::with_hmac_key(path, [0u8; 32]);
        assert_eq!(store.read_release_unix_for_apply().unwrap(), None);
    }
}
