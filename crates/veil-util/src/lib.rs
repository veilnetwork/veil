//! Crate-wide micro utilities shared across layers.
//!
//! Only truly cross-cutting helpers live here (hex encoding that both `cfg`
//! and `node` need, clock sources, atomic-write retry). Layer-specific
//! helpers belong in that layer's own `util.rs`.

/// Cross-platform mlocked-bytes primitive for secret-key allocations.
/// See [`mlock::MlockedBytes`].
pub mod mlock;

/// Sensitive-bytes container с automatic mlock-or-fallback selection.
/// See [`sensitive_bytes::SensitiveBytes`].
pub mod sensitive_bytes;

/// Run `op` with up to 5 attempts when it returns
/// [`std::io::ErrorKind::PermissionDenied`]. Exponential backoff
/// 25 / 50 / 100 / 200 ms before retries 2-5; any other error is
/// propagated immediately.
///
/// Motivation: WSL2 ext4 sporadically returns `EACCES` on `openat`/`mkdirat`
/// when many threads contend on `/tmp` directory-entry cache. This retry
/// papers over the kernel race without hiding real permission misconfigs
/// — a permanent `EACCES` (wrong owner, immutable bit) still surfaces after
/// the retries (worst-case ~375 ms accumulated delay before final error).
pub fn with_eacces_retry<F, T>(mut op: F) -> std::io::Result<T>
where
    F: FnMut() -> std::io::Result<T>,
{
    const ATTEMPTS: u32 = 5;
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..ATTEMPTS {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                if attempt + 1 < ATTEMPTS {
                    let delay_ms = 25u64 << attempt; // 25, 50, 100, 200
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
                last_err = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.expect("loop body sets last_err on every PermissionDenied iteration"))
}

/// Wrapper around [`std::fs::create_dir_all`] with
/// [`with_eacces_retry`] semantics.
pub fn create_dir_all_with_eacces_retry(path: &std::path::Path) -> std::io::Result<()> {
    with_eacces_retry(|| std::fs::create_dir_all(path))
}

/// Arm `command` to call `setsid` in the child between `fork` and `exec`
/// so daemon-mode spawns detach from the controlling terminal.
///
/// No-op on non-Unix platforms — Windows uses different process-group
/// primitives handled separately in the daemon path.
#[cfg(unix)]
pub fn setsid_on_spawn(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure only calls `setsid` and constructs an
    // `io::Error` on failure. Both are async-signal-safe operations
    // permitted between `fork` and `exec`.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Non-Unix no-op; see [`setsid_on_spawn`] above.
#[cfg(not(unix))]
pub fn setsid_on_spawn(_command: &mut std::process::Command) {}

/// scrub а spawning `Command`'s environment к а
/// minimal allow-list before spawn. Carries through only:
///
/// * `PATH` — pinned к а minimal `/usr/bin:/bin` if the parent did not
///   set it. Stdlib requires а PATH for any future
///   `Command::new("name")` (vs. absolute path) calls в the child.
/// * `HOME`, `USER`, `LOGNAME` — needed by tilde-expansion и user-
///   relative config paths.
/// * `TZ` — timestamp formatting.
/// * `LANG`, `LC_ALL` — UTF-8 stderr formatting (when set).
/// * `RUST_BACKTRACE` — preserve debug-friendliness on operator opt-in.
///
/// **Notably dropped**: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`
/// `RUST_LOG` (custom targets can divert logs), `PYTHONPATH`
/// `VEIL_*` (only the explicit `--config` arg should drive veil
/// behaviour). The pattern matches systemd's `EnvironmentFile=` discipline.
///
/// Use это для long-lived daemon spawns (`spawn_restart_child`
/// `spawn_background_node_process`) where the child runs unattended и
/// the parent's env могла прийти от an exec'd-into context (sudo, su
/// CI runner) с unwanted variables в scope.
pub fn scrub_command_env(command: &mut std::process::Command) {
    const ALLOW: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TZ",
        "LANG",
        "LC_ALL",
        "RUST_BACKTRACE",
    ];
    command.env_clear();
    for &key in ALLOW {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    // Make sure PATH is always set — child needs it to resolve any
    // sub-spawn target by name. Falls к the POSIX-standard minimum.
    if std::env::var_os("PATH").is_none() {
        command.env("PATH", "/usr/bin:/bin");
    }
}

/// Count the number of leading zero bits in `bytes` (big-endian).
///
/// Scans from the most-significant byte; stops as soon as a non-zero
/// byte is found. For a 32-byte BLAKE3 hash the maximum is 256.
///
/// previously duplicated in 8 modules (`node/util.rs`
/// `node/identity/verify.rs/publish.rs/resolver.rs`, `node/pex/initiator.rs`
/// `node/routing/pow.rs`, `crypto/pow/score.rs`, `cfg/sovereign_flow.rs`)
/// with varying return types (u8 / u16 / u32). One canonical `u32`
/// version lives here; call sites that want a narrower type cast down.
pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total = 0u32;
    for byte in bytes {
        let zeros = byte.leading_zeros();
        total += zeros;
        if zeros != 8 {
            break;
        }
    }
    total
}

/// Atomically replace `path` with `bytes`.
///
/// Sequence: write → `<path>.tmp` (mode 0o600 on Unix), `fsync`
/// `rename(tmp, path)`. A crash mid-write leaves only the sidecar tmp
/// file; the target is either the previous version or the new version
/// never truncated garbage.
///
/// The tmp write and the mkdir-of-parent are wrapped in
/// [`with_eacces_retry`] to paper over WSL2 kernel-level `EACCES` flakes
/// on shared `/tmp` directory-entry cache.
///
/// previously the tmp file inherited the
/// process umask (typically `0o644` on Linux → world-readable), which
/// leaked the peer-graph in every snapshot consumer (RouteCache
/// RTT table, Vivaldi coords, GatewayList, peer-pubkeys, autodiscover
/// cache). On Unix we now hard-set mode `0o600` at create time so the
/// snapshot is owner-readable only. On non-Unix targets (Windows) the
/// default ACL inherits from the parent directory; deployments are
/// expected to keep `~/.veil/` (or equivalent) under the user's own
/// profile, where the directory ACL already excludes other users.
pub fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let parent = path.parent();
    if let Some(p) = parent {
        create_dir_all_with_eacces_retry(p)?;
    }
    // The tmp path uses an UNPREDICTABLE getrandom suffix (NOT the old
    // time-XOR-pid mix, which an attacker who knows the approximate time and
    // pid could guess) AND is opened with `create_new` (O_EXCL). Together, a
    // pre-existing file at the tmp path — a symlink an attacker placed to
    // redirect the write, OR a plain regular file / hardlink they pre-created
    // in an attacker-writable parent to capture the secret — FAILS the open
    // instead of being followed or truncated. On the astronomically unlikely
    // name collision (or a transient Windows EACCES) we regenerate the suffix
    // and retry. Mode `0o600` + `O_NOFOLLOW` (Unix) are kept as belt-and-braces.
    const MAX_TMP_ATTEMPTS: usize = 8;
    let mut tmp_path: Option<std::path::PathBuf> = None;
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..MAX_TMP_ATTEMPTS {
        let mut rand_bytes = [0u8; 8];
        getrandom::getrandom(&mut rand_bytes)
            .map_err(|e| std::io::Error::other(format!("atomic_write: getrandom failed: {e}")))?;
        let tmp = path.with_extension(format!("tmp.{}", bytes_to_hex(&rand_bytes)));
        match open_owner_only_create_new(&tmp) {
            Ok(mut f) => {
                // Freshly-created exclusive file — write + fsync, then keep it
                // for the rename. A write/sync error is real (not a name race):
                // clean up the partial tmp and propagate without retrying.
                if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
                tmp_path = Some(tmp);
                break;
            }
            // AlreadyExists (collision / attacker pre-creation) or a transient
            // PermissionDenied (Windows AV) — retry with a fresh suffix.
            Err(e)
                if e.kind() == std::io::ErrorKind::AlreadyExists
                    || e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    let tmp = tmp_path.ok_or_else(|| {
        last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "atomic_write: could not create a unique tmp file after retries",
            )
        })
    })?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => {
            // fsync the parent
            // directory after the rename so the rename itself is
            // durably persisted. Without this, a power loss in the
            // narrow window between rename(2) returning and the dirent
            // hitting disk could leave the directory referencing
            // either the old name (file gone), the new name (good)
            // or a half-allocated inode — depending on the FS's
            // behaviour for unflushed dirent entries. Most ext4 /
            // xfs / btrfs configs already journal directory updates
            // but explicitly fsync'ing the parent is the only way to
            // make this guarantee portable. Best-effort: error here
            // does NOT roll back the rename (the file IS at its
            // target name, just not yet flushed) — a sync error on
            // the parent is recoverable on next boot.
            if let Some(p) = parent {
                let _ = fsync_dir(p);
            }
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// best-effort fsync of a directory
/// so a recently-completed `rename(2)` is durably persisted across
/// power loss. No-op on Windows where directory fsync semantics are
/// not exposed by the public std API.
#[cfg(unix)]
fn fsync_dir(dir: &std::path::Path) -> std::io::Result<()> {
    let f = std::fs::File::open(dir)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Owner-only (`0o600`) EXCLUSIVE create on Unix (`O_CREAT|O_EXCL` via
/// `create_new`); exclusive create on non-Unix too. `create_new` fails if the
/// path already exists — a plain regular file/hardlink OR a symlink — and
/// `O_NOFOLLOW` (Unix) additionally refuses a symlink, together closing BOTH
/// the symlink-redirect AND the pre-created-regular-file capture vectors where
/// an attacker pre-places a file at our tmp path to redirect or capture the
/// write. See [`atomic_write`] for the rationale.
#[cfg(unix)]
fn open_owner_only_create_new(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_owner_only_create_new(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Encode a byte slice as a lowercase hex string. Uses a pre-allocated
/// buffer and `write!` so the per-byte `format!` allocation is avoided.
///
/// Replaces the 7 previous ad-hoc copies scattered across `node/util.rs`
/// `cmd/handlers.rs`, `cmd/peers_cmd.rs`, `cfg/model.rs`
/// `node/admin_transport.rs`, `node/local_transport.rs`, `node/admin.rs`.
/// X3: capacity-bounded `HashMap` with random eviction.
///
/// Wraps `std::collections::HashMap` with a hard cap on entry count.
/// Once at capacity, subsequent `insert` evicts one arbitrary existing
/// entry to make room. This matches-C2 pattern that
/// was hand-rolled for `peer_sovereign_identities` /
/// `per_session_mlkem_dk` and replaces the ad-hoc "manually check
/// `len` before insert" code that led to the unbounded-growth audit
/// findings.
///
/// Random eviction is intentional and security-correct: the worst case
/// is forcing one extra full handshake / cache miss, which the caller
/// already handles. An attacker who churns the map can only cause
/// extra work bounded by `CAPACITY` per attack-cycle, not memory blow-up.
///
/// For LRU semantics use a different type (e.g. the `lru` crate); for
/// "drop-oldest insertion" use `VecDeque` + `HashMap` keyed by index.
/// `BoundedMap` is the right choice when:
/// * the entries are roughly equal-cost to recompute
/// * cache misses are bounded recovery (handshake, lookup), AND
/// * insertion-order tracking would cost more than re-doing the work.
#[derive(Debug, Clone)]
pub struct BoundedMap<K, V> {
    inner: std::collections::HashMap<K, V>,
    capacity: usize,
}

impl<K: std::hash::Hash + Eq + Clone, V> BoundedMap<K, V> {
    /// Create a `BoundedMap` with the given hard cap on entry count.
    /// `capacity = 0` is treated as "unbounded" — the map never evicts;
    /// callers who need uncapped behaviour should still wrap so all
    /// access goes through one type.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: std::collections::HashMap::new(),
            capacity,
        }
    }

    /// Insert a key-value pair. If at capacity AND the key is not
    /// already present, evicts one arbitrary existing entry first.
    /// Returns the previous value for `key`, if any (matching
    /// `HashMap::insert` semantics).
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if self.capacity > 0
            && self.inner.len() >= self.capacity
            && !self.inner.contains_key(&key)
            && let Some(victim) = self.inner.keys().next().cloned()
        {
            self.inner.remove(&victim);
        }
        self.inner.insert(key, value)
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key)
    }
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.get_mut(key)
    }
    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key)
    }
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, K, V> {
        self.inner.iter()
    }
    pub fn iter_mut(&mut self) -> std::collections::hash_map::IterMut<'_, K, V> {
        self.inner.iter_mut()
    }
    pub fn entry(&mut self, key: K) -> std::collections::hash_map::Entry<'_, K, V> {
        // Capacity-aware Entry is non-trivial (Vacant gets exclusive
        // borrow before we can evict). For now, callers that need
        // Entry semantics under cap should use `insert` + `get`.
        // This raw access is provided for read-modify-write paths
        // where the caller has already validated `len < capacity`
        // OR where `key` is known to exist.
        self.inner.entry(key)
    }
    pub fn retain<F: FnMut(&K, &mut V) -> bool>(&mut self, f: F) {
        self.inner.retain(f);
    }
}

impl<K: std::hash::Hash + Eq + Clone, V> Default for BoundedMap<K, V> {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod bounded_map_tests {
    use super::BoundedMap;

    #[test]
    fn insert_under_cap_keeps_all_entries() {
        let mut m: BoundedMap<u32, &'static str> = BoundedMap::new(3);
        m.insert(1, "a");
        m.insert(2, "b");
        m.insert(3, "c");
        assert_eq!(m.len(), 3);
        assert!(m.contains_key(&1));
        assert!(m.contains_key(&2));
        assert!(m.contains_key(&3));
    }

    #[test]
    fn insert_at_cap_evicts_one_on_new_key() {
        let mut m: BoundedMap<u32, &'static str> = BoundedMap::new(2);
        m.insert(1, "a");
        m.insert(2, "b");
        m.insert(3, "c"); // forces eviction
        assert_eq!(m.len(), 2);
        assert!(m.contains_key(&3));
    }

    #[test]
    fn insert_at_cap_does_not_evict_on_update() {
        let mut m: BoundedMap<u32, &'static str> = BoundedMap::new(2);
        m.insert(1, "a");
        m.insert(2, "b");
        m.insert(1, "a-updated"); // same key — no eviction
        assert_eq!(m.len(), 2);
        assert_eq!(m.get(&1), Some(&"a-updated"));
        assert!(m.contains_key(&2));
    }

    #[test]
    fn capacity_zero_is_unbounded() {
        let mut m: BoundedMap<u32, u32> = BoundedMap::new(0);
        for i in 0..1000 {
            m.insert(i, i);
        }
        assert_eq!(m.len(), 1000);
    }
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // write! to &mut String is infallible; ignoring the result is OK.
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Format the first 4 bytes of a node/peer ID as a lowercase hex string.
///
/// Used in log messages where the full 32-byte ID would be too verbose.
pub fn hex_short(b: &[u8; 32]) -> String {
    bytes_to_hex(&b[..4])
}

/// Format а byte slice as а lowercase hex string.  Identical к
/// [`bytes_to_hex`]; preserved для call-site continuity с veilcore
/// code що использовало the legacy alias.
pub fn hex_str(bytes: &[u8]) -> String {
    bytes_to_hex(bytes)
}

/// Error from the canonical hex decoders ([`hex_to_array`] / [`hex_to_bytes`]).
///
/// Carries enough detail that call sites which previously produced custom
/// `String` diagnostics can preserve them via a `match` on the variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// Input length was not the expected number of hex chars (`2 * N` for
    /// [`hex_to_array`], or odd for [`hex_to_bytes`]).
    WrongLength { expected: usize, got: usize },
    /// A 2-char chunk did not parse as a hex byte.
    InvalidByte,
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HexError::WrongLength { expected, got } => {
                write!(f, "expected {expected} hex chars, got {got}")
            }
            HexError::InvalidByte => write!(f, "non-hex character"),
        }
    }
}

impl std::error::Error for HexError {}

/// Decode a fixed-length lowercase/uppercase hex string into `[u8; N]`.
///
/// Strict: the input MUST be exactly `2 * N` chars. Each 2-char chunk is
/// parsed with [`u8::from_str_radix`] (radix 16) — identical to the dozen-odd
/// hand-rolled decoders this replaces, so migrations are behaviour-preserving.
///
/// Returns [`HexError::WrongLength`] on a length mismatch and
/// [`HexError::InvalidByte`] on the first non-hex chunk.
pub fn hex_to_array<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    if s.len() != 2 * N {
        return Err(HexError::WrongLength {
            expected: 2 * N,
            got: s.len(),
        });
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        // `chunk` is exactly 2 bytes of an ASCII-range &str slice.
        let pair = std::str::from_utf8(chunk).map_err(|_| HexError::InvalidByte)?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| HexError::InvalidByte)?;
    }
    Ok(out)
}

/// Decode an even-length hex string into a `Vec<u8>`.
///
/// Strict: the input length MUST be even. Per-chunk semantics match
/// [`hex_to_array`].
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, HexError> {
    if !s.len().is_multiple_of(2) {
        return Err(HexError::WrongLength {
            expected: s.len() + 1,
            got: s.len(),
        });
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let pair = std::str::from_utf8(chunk).map_err(|_| HexError::InvalidByte)?;
            u8::from_str_radix(pair, 16).map_err(|_| HexError::InvalidByte)
        })
        .collect()
}

/// Current UNIX timestamp truncated к `u32` seconds.
///
/// Clamps к `u32::MAX` rather than wrapping — timestamps after year 2106
/// saturate instead of rolling over к zero и breaking TTL comparisons.
///
/// Returns `0` if the system clock is before the UNIX epoch.
pub fn unix_secs_now_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(u32::MAX as u64) as u32
}

/// Current UNIX timestamp as а full `u64` seconds value.
///
/// Prefer this over inline `SystemTime::now.duration_since(UNIX_EPOCH)`
/// к keep timestamp acquisition в one place.  Returns `0` if the system
/// clock is before the UNIX epoch.
pub fn unix_secs_now_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Strip the host portion от а transport URI for log output.
///
/// Replaces the host:port pair с `[redacted]:port`, preserving the
/// scheme prefix (`tcp://`, `quic://`, `ws://`, …) и the port number.
/// Operators correlate sessions by `node_id` (always logged adjacent
/// в the same INFO line); routine logs no longer announce who is
/// talking к whom at the IP level.  Local schemes (`unix://`, `ipc://`)
/// pass through unchanged because они ара not PII.
pub fn redact_addr_for_log(transport: &str) -> std::borrow::Cow<'_, str> {
    let scheme_end = match transport.find("://") {
        Some(i) => i + 3,
        None => return std::borrow::Cow::Borrowed(transport),
    };
    let scheme = &transport[..scheme_end];
    let rest = &transport[scheme_end..];

    if scheme == "unix://" || scheme == "ipc://" {
        return std::borrow::Cow::Borrowed(transport);
    }

    let port_part = if rest.starts_with('[') {
        rest.split(']').nth(1).and_then(|s| s.strip_prefix(':'))
    } else {
        rest.rsplit_once(':').map(|(_, p)| p)
    };
    match port_part {
        Some(port) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            std::borrow::Cow::Owned(format!("{scheme}[redacted]:{port}"))
        }
        _ => std::borrow::Cow::Owned(format!("{scheme}[redacted]")),
    }
}

/// Probe the device's battery level (0-100 percent).
///
/// Returns 100 (assume full / no battery) on:
/// * Non-Linux platforms.
/// * Linux hosts без а `BAT*` entry в `/sys/class/power_supply`.
/// * Read errors (mount-point absent, kernel rebuild rare-case, etc.).
///
/// The 100-sentinel was chosen so battery-thresholded paths default к
/// the "no power-saving" branch when the level is unknown — better к
/// drain а desktop's wall power than over-aggressively slow а device
/// що happens к not expose battery info.
///
/// Phase 2 session 2 prep (veilcore extraction): canonicalized here
/// so session crate can read battery state без а dep on veilcore
/// (formerly lived в `veilcore/src/node/battery.rs`).
pub fn local_battery_level() -> u8 {
    #[cfg(target_os = "linux")]
    {
        // Walk all BAT* entries and return the first readable capacity value.
        if let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("BAT") {
                    let cap_path = entry.path().join("capacity");
                    if let Ok(s) = std::fs::read_to_string(&cap_path)
                        && let Ok(v) = s.trim().parse::<u8>()
                    {
                        return v;
                    }
                }
            }
        }
    }
    100 // default: assume full battery / no battery
}

// ── Poison-recovering lock macros ─────────────────────────────────────────────
//
// moved from `veilcore::lib` so downstream crates
// (veil-mesh etc.) can use the same recovery helpers without
// reverse-importing veilcore. Macros stay `#[macro_export]` so
// `use veil_util::lock;` works at every call site.

/// Acquire a `Mutex`, recovering from a poisoned state by consuming the guard.
///
/// If the mutex is poisoned (i.e. a previous holder panicked while holding it)
/// the error is logged at `error` level and the guard is returned anyway.
/// Callers must ensure that the data behind the mutex remains logically
/// consistent — poisoning means some invariant may have been violated.
#[macro_export]
macro_rules! lock {
    ($m:expr) => {
        $m.lock().unwrap_or_else(|p| {
            eprintln!(
                "WARN mutex poisoned at {}:{} — recovering from panic in prior holder",
                file!(),
                line!(),
            );
            p.into_inner()
        })
    };
}

/// Acquire an `RwLock` for reading, recovering from poisoning.
#[macro_export]
macro_rules! rlock {
    ($m:expr) => {
        $m.read().unwrap_or_else(|p| {
            eprintln!(
                "WARN rwlock poisoned (read) at {}:{} — recovering from panic in prior holder",
                file!(),
                line!(),
            );
            p.into_inner()
        })
    };
}

/// Acquire an `RwLock` for writing, recovering from poisoning.
#[macro_export]
macro_rules! wlock {
    ($m:expr) => {
        $m.write().unwrap_or_else(|p| {
            eprintln!(
                "WARN rwlock poisoned (write) at {}:{} — recovering from panic in prior holder",
                file!(),
                line!(),
            );
            p.into_inner()
        })
    };
}

// ── Ttl: typed wrapper for time-to-live durations ────────────
//
// cleanup: ~50 `*_TTL_SECS: u64` constants spread across crates
// freely mixed с `Duration` values, occasionally compared against `_TTL_MS`
// constants of different unit. Easy к accidentally pass а seconds value where
// milliseconds expected (or vice-versa) — `60u64` doesn't tell the compiler
// whether it's seconds or millis.
//
// `Ttl` makes the unit explicit at the type level: `Ttl::from_secs(60)` and
// `Ttl::from_millis(60)` are the same TYPE but the construction site documents
// which unit the literal is in. Callers pass `Ttl` and can no longer confuse
// units; the wrapped `Duration` is recovered via `as_duration` for arithmetic
// and comparison without dropping the type information.

/// Time-to-live duration. Newtype wrapper over `Duration` к
/// make TTL semantics explicit at function/struct boundaries и prevent
/// accidental seconds-vs-millis mix-ups at constant-declaration sites.
///
/// # Why this exists
///
/// ~50 `*_TTL_SECS: u64` constants spread across veil crates. Operator
/// who adds а new `_TTL_MS: u64` next to existing seconds constants creates
/// а footgun: the type system silently accepts the wrong-unit value. Wrapping
/// в `Ttl` makes the unit explicit at construction (`from_secs` / `from_millis`)
/// и opaque at boundaries — callers can't accidentally pass а raw integer
/// without going through one of the named constructors.
///
/// # Construction
///
/// Always go through one [`Ttl::from_secs`], [`Ttl::from_millis`], or
/// [`Ttl::from_duration`]. No `From<u64>` impl на purpose — would re-introduce
/// the unit-confusion footgun the type exists к prevent.
///
/// # Use
///
/// `as_duration` exposes the wrapped `Duration` for use в comparison
/// arithmetic, and `tokio::time::sleep`/etc. without unwrapping. `as_secs` /
/// `as_millis` для the rare cases where а raw integer is needed (typically
/// для serialization on the wire).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ttl(std::time::Duration);

impl Ttl {
    /// Zero-duration TTL, useful as а sentinel.
    pub const ZERO: Ttl = Ttl(std::time::Duration::ZERO);

    /// Construct из а seconds count.
    pub const fn from_secs(secs: u64) -> Self {
        Self(std::time::Duration::from_secs(secs))
    }

    /// Construct из а milliseconds count.
    pub const fn from_millis(millis: u64) -> Self {
        Self(std::time::Duration::from_millis(millis))
    }

    /// Construct из an explicit `Duration` (preserves any sub-second
    /// precision). Used when wrapping а pre-existing duration calculated
    /// dynamically (e.g. configurable interval scaled by а multiplier).
    pub const fn from_duration(d: std::time::Duration) -> Self {
        Self(d)
    }

    /// Underlying `Duration`. Use for comparison, arithmetic, и sleep
    /// calls без dropping the `Ttl` annotation prematurely.
    pub const fn as_duration(&self) -> std::time::Duration {
        self.0
    }

    /// Whole seconds (truncating fractional). Use only когда serializing
    /// over the wire или к а human-readable format.
    pub const fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }

    /// Whole milliseconds (preserves sub-second precision).
    pub const fn as_millis(&self) -> u128 {
        self.0.as_millis()
    }

    /// Whether the TTL is zero (sentinel for "disabled" в some configs).
    pub const fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Saturating addition. Returns `Ttl::MAX` (u64::MAX seconds) on overflow
    /// rather than panicking — defends against operator-supplied arithmetic
    /// that might compose long TTLs.
    pub fn saturating_add(self, other: Ttl) -> Ttl {
        Ttl(self.0.saturating_add(other.0))
    }

    /// Checked subtraction. Returns `None` если result would be negative —
    /// callers MUST handle the absent value explicitly rather than silently
    /// clamping к zero (which is а common bug source в TTL math).
    pub fn checked_sub(self, other: Ttl) -> Option<Ttl> {
        self.0.checked_sub(other.0).map(Ttl)
    }
}

impl std::fmt::Display for Ttl {
    /// Human-readable formatting: picks the largest whole-unit representation
    /// (e.g. 86400s prints as `1d`, 3600s as `1h`, 60s as `1m`, sub-second as
    /// `Nms`). Used в operator-facing log/IPC output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secs = self.0.as_secs();
        let nanos = self.0.subsec_nanos();
        if nanos == 0 {
            if secs == 0 {
                return write!(f, "0s");
            }
            if secs.is_multiple_of(86400) {
                return write!(f, "{}d", secs / 86400);
            }
            if secs.is_multiple_of(3600) {
                return write!(f, "{}h", secs / 3600);
            }
            if secs.is_multiple_of(60) {
                return write!(f, "{}m", secs / 60);
            }
            return write!(f, "{secs}s");
        }
        // Sub-second precision: format as ms.
        write!(f, "{}ms", self.0.as_millis())
    }
}

impl From<Ttl> for std::time::Duration {
    fn from(ttl: Ttl) -> Self {
        ttl.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_empty_string() {
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn single_byte_is_two_chars() {
        assert_eq!(bytes_to_hex(&[0x00]), "00");
        assert_eq!(bytes_to_hex(&[0xff]), "ff");
        assert_eq!(bytes_to_hex(&[0xab]), "ab");
    }

    #[test]
    fn multi_byte_lowercase() {
        assert_eq!(bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn hex_to_array_roundtrips_encode() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        let s = bytes_to_hex(&bytes);
        assert_eq!(hex_to_array::<4>(&s), Ok(bytes));
        // uppercase accepted too (from_str_radix is case-insensitive).
        assert_eq!(hex_to_array::<4>("DEADBEEF"), Ok(bytes));
    }

    #[test]
    fn hex_to_array_rejects_wrong_length_and_non_hex() {
        assert_eq!(
            hex_to_array::<4>("dead"),
            Err(HexError::WrongLength {
                expected: 8,
                got: 4
            })
        );
        assert_eq!(hex_to_array::<2>("zzzz"), Err(HexError::InvalidByte));
    }

    #[test]
    fn hex_to_bytes_strict_even_length() {
        assert_eq!(hex_to_bytes("00ffab"), Ok(vec![0x00, 0xff, 0xab]));
        assert_eq!(hex_to_bytes(""), Ok(vec![]));
        assert_eq!(
            hex_to_bytes("abc"),
            Err(HexError::WrongLength {
                expected: 4,
                got: 3
            })
        );
        assert_eq!(hex_to_bytes("0g"), Err(HexError::InvalidByte));
    }

    #[test]
    fn thirty_two_bytes_expected_length() {
        let bytes = [0u8; 32];
        assert_eq!(bytes_to_hex(&bytes).len(), 64);
    }

    /// snapshots written via `atomic_write`
    /// must end up with mode `0o600` on Unix (owner-only). Regression
    /// guard against accidental return to umask-default `0o644`.
    #[cfg(unix)]
    #[test]
    fn phase647_h25_atomic_write_uses_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.bin");
        atomic_write(&path, b"secret peer graph").expect("atomic_write succeeds");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        // Mask off type bits — only the low 9 bits are the rwx triple.
        assert_eq!(
            mode & 0o777,
            0o600,
            "atomic_write must produce owner-only files; got {:o}",
            mode & 0o777
        );
    }

    /// Round-trip sanity: contents survive write+rename intact.
    #[test]
    fn atomic_write_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        atomic_write(&path, b"hello world").expect("write");
        assert_eq!(std::fs::read(&path).unwrap(), b"hello world");
    }

    /// Replace existing file: second write overwrites first.
    #[test]
    fn atomic_write_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rotate.bin");
        atomic_write(&path, b"v1").unwrap();
        atomic_write(&path, b"v2-longer-payload").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"v2-longer-payload");
        // The.tmp sidecar is cleaned up on success.
        assert!(!path.with_extension("tmp").exists());
    }

    /// M-1 (audit 2026-06-03): the tmp open uses `create_new` (O_EXCL), so a
    /// pre-existing file at the tmp path is REFUSED (not followed/truncated) —
    /// the capture vector where an attacker pre-creates a file in an
    /// attacker-writable parent to grab a secret write. Pre-`create_new` this
    /// opened+truncated the attacker's file instead.
    #[test]
    fn open_owner_only_create_new_refuses_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("precreated");
        std::fs::write(&victim, b"attacker-content").unwrap();
        let err = open_owner_only_create_new(&victim)
            .expect_err("create_new must refuse a pre-existing path");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        // The pre-existing content must be intact (NOT truncated).
        assert_eq!(std::fs::read(&victim).unwrap(), b"attacker-content");
    }

    // ── R4: Ttl newtype ──────────────────────────────────────

    #[test]
    fn r4_ttl_secs_and_millis_construct_correctly() {
        assert_eq!(Ttl::from_secs(60).as_secs(), 60);
        assert_eq!(Ttl::from_secs(60).as_millis(), 60_000);
        assert_eq!(Ttl::from_millis(500).as_millis(), 500);
        assert_eq!(Ttl::from_millis(500).as_secs(), 0); // truncates
    }

    #[test]
    fn r4_ttl_zero_constant_and_predicate() {
        assert!(Ttl::ZERO.is_zero());
        assert_eq!(Ttl::ZERO.as_duration(), std::time::Duration::ZERO);
        assert!(!Ttl::from_secs(1).is_zero());
        assert!(!Ttl::from_millis(1).is_zero());
    }

    #[test]
    fn r4_ttl_as_duration_round_trips() {
        let d = std::time::Duration::from_millis(1234);
        let ttl = Ttl::from_duration(d);
        assert_eq!(ttl.as_duration(), d);
        // From impl works в the conversion direction too.
        let back: std::time::Duration = ttl.into();
        assert_eq!(back, d);
    }

    #[test]
    fn r4_ttl_saturating_add_does_not_panic() {
        let huge = Ttl::from_secs(u64::MAX);
        let sum = huge.saturating_add(Ttl::from_secs(1));
        // Saturated к Duration::MAX (which is u64::MAX seconds + max nanos).
        // Just check it didn't panic and result >= huge.
        assert!(sum >= huge);
    }

    #[test]
    fn r4_ttl_checked_sub_handles_underflow() {
        assert_eq!(
            Ttl::from_secs(10).checked_sub(Ttl::from_secs(3)),
            Some(Ttl::from_secs(7))
        );
        assert_eq!(
            Ttl::from_secs(3).checked_sub(Ttl::from_secs(10)),
            None,
            "subtracting larger TTL must return None, NOT silently wrap"
        );
    }

    #[test]
    fn r4_ttl_display_picks_largest_clean_unit() {
        assert_eq!(format!("{}", Ttl::from_secs(86_400)), "1d");
        assert_eq!(format!("{}", Ttl::from_secs(3 * 86_400)), "3d");
        assert_eq!(format!("{}", Ttl::from_secs(3600)), "1h");
        assert_eq!(format!("{}", Ttl::from_secs(7200)), "2h");
        assert_eq!(format!("{}", Ttl::from_secs(60)), "1m");
        assert_eq!(format!("{}", Ttl::from_secs(45)), "45s");
        assert_eq!(format!("{}", Ttl::from_millis(500)), "500ms");
        assert_eq!(format!("{}", Ttl::ZERO), "0s");
    }

    #[test]
    fn r4_ttl_display_breaks_ties_at_largest_unit_first() {
        // 90 seconds is NOT а whole minute — fall through к seconds.
        assert_eq!(format!("{}", Ttl::from_secs(90)), "90s");
        // 25h is NOT а whole day — fall through к hours.
        assert_eq!(format!("{}", Ttl::from_secs(25 * 3600)), "25h");
    }

    #[test]
    fn r4_ttl_compare_ord() {
        // Ord/PartialOrd derived from Duration — ensure intuitive ordering
        // without unwrapping. Critical for "is this TTL larger than that
        // threshold" branches.
        assert!(Ttl::from_secs(60) < Ttl::from_secs(120));
        assert!(Ttl::from_millis(999) < Ttl::from_secs(1));
        assert_eq!(Ttl::from_secs(60), Ttl::from_millis(60_000));
    }

    #[test]
    fn r4_ttl_const_constructors_compile_in_const_context() {
        // Lock в the const-fn property — necessary so call sites can use
        // Ttl::from_secs(60) directly в `pub const FOO_TTL: Ttl =...;`
        // declarations (the migration target for ~50 _TTL_SECS constants).
        const FOO: Ttl = Ttl::from_secs(60);
        const BAR: Ttl = Ttl::ZERO;
        assert_eq!(FOO.as_secs(), 60);
        assert!(BAR.is_zero());
    }

    // scrub_command_env tests. We can't easily
    // inspect а std::process::Command's env after configuration (no
    // public accessor), so we drive an actual `printenv` child and read
    // stdout. Skipped on non-Unix because /usr/bin/printenv is GNU.
    #[cfg(unix)]
    #[test]
    fn scrub_command_env_drops_unallowed_vars() {
        use std::process::Command;
        // SAFETY: unsetting an env var is documented to be safe in single-
        // threaded contexts; cargo test runs each #[test] on а fresh thread
        // but other tests in the same process could race. We use а unique
        // var name to avoid collisions.
        // SAFETY: see Rust 1.85+ deprecation notice on std::env::set_var —
        // this is only safe in single-threaded test scope. cargo nextest
        // gives each test its own process; the workspace standard runner
        // serializes scrub_command_env_* via single-threaded grouping is
        // not enforced, so we accept the small race risk for а unique
        // var name (env::set_var is locked behind the unsafe gate as of
        // 1.85 specifically to flag this).
        unsafe {
            std::env::set_var("VEIL_SCRUB_TEST_LEAK", "leaked");
            std::env::set_var("LD_PRELOAD", "/tmp/evil.so");
        }
        let mut cmd = Command::new("/usr/bin/printenv");
        scrub_command_env(&mut cmd);
        let out = cmd.output().expect("printenv");
        let env_text = String::from_utf8_lossy(&out.stdout);
        assert!(
            !env_text.contains("VEIL_SCRUB_TEST_LEAK"),
            "VEIL_SCRUB_TEST_LEAK should be scrubbed; saw:\n{env_text}"
        );
        assert!(
            !env_text.contains("LD_PRELOAD"),
            "LD_PRELOAD should be scrubbed; saw:\n{env_text}"
        );
        // PATH must always survive scrubbing (fallback applied if unset).
        assert!(
            env_text.lines().any(|l| l.starts_with("PATH=")),
            "PATH should survive scrub; saw:\n{env_text}"
        );
        unsafe {
            std::env::remove_var("VEIL_SCRUB_TEST_LEAK");
            std::env::remove_var("LD_PRELOAD");
        }
    }
}
