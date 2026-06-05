//! Discovered-peer cache.
//!
//! After a successful OVL1 handshake we know the peer is real
//! reachable, and signs as the claimed `node_id`. We snapshot
//! `(transport, public_key, nonce, algo)` to a persistent cache so
//! the next cold start has a 4th fallback layer in the bootstrap
//! cascade:
//!
//! 1. `config.bootstrap_peers` (operator-curated)
//! 2. compile-time `builtin_seeds`
//! 3. `_veil._bootstrap.<domain>` DNS TXT records
//! 4. **this cache** — peers we have personally proved reachable
//!    in a prior run.
//!
//! Why this matters for censorship-resistance: an authoritarian-state
//! censor that takes down all (1)-(3) — eg. blacklists known seed
//! IPs the operator has published, blacklists the DNS domain, ships
//! a binary update with poisoned `builtin_seeds` — still cannot
//! invalidate (4), because (4) is populated from peers the *user*
//! has previously talked to. The censor would need per-user state
//! (knowledge of every IP I've ever connected) plus the ability
//! to block all of them simultaneously, which is dramatically more
//! expensive than blocking a published seed list.
//!
//! Layout on disk: same JSON as
//! [`super::encode_bootstrap_bundle`] — re-uses the bootstrap
//! format so the cache file is interoperable with `config publish`
//! / `config fetch` and an operator can hand-edit it with `jq`.
//! Wrapped in a stable envelope so we can add the per-entry
//! `last_seen_unix` LRU timestamp without leaking it into the wire
//! format used by `publish`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use veil_types::BootstrapPeer;

/// Maximum entries kept in the cache. When full, the
/// least-recently-seen entry is evicted on the next `upsert`.
///
/// 32 is enough for "8 close-circle friends + 24 incidental peers
/// you've talked to in the last week"; small enough to bound disk
/// + memory cost (at ~250 B per entry → ~ 8 KB on disk).
pub const MAX_DISCOVERED_PEERS: usize = 32;

/// per-field caps so a single malformed peer
/// can't grow the on-disk cache to multi-MB by stuffing megabyte-long
/// transport URIs or TLS certificates. The transport URI cap follows
/// the same `MAX_TRANSPORT_STR_LEN` budget the proto layer enforces;
/// `MAX_TLS_CERT_BYTES` is sized for a typical 4 KiB PEM-encoded
/// X.509 + intermediate chain. Audit cycle-5: these caps are enforced at
/// `upsert` (per-entry storage) time. The load-from-disk path trusts the
/// HMAC-authenticated on-disk contents (a tampered file is rejected wholesale;
/// a legitimately-saved file can only contain already-capped entries), so it
/// does NOT re-filter per entry.
pub const MAX_TRANSPORT_STR_LEN: usize = 256;
pub const MAX_TLS_CERT_BYTES: usize = 8 * 1024;

/// One entry in the cache. The `peer` half is the
/// wire-compatible [`BootstrapPeer`] (drops directly into
/// `config.bootstrap_peers`); the `last_seen_unix` half is local
/// metadata for LRU eviction and freshness reasoning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    #[serde(flatten)]
    pub peer: BootstrapPeer,
    /// Unix-seconds when we last successfully completed an OVL1
    /// handshake with this peer. Used to LRU-evict cold entries.
    pub last_seen_unix: u64,
}

/// On-disk envelope. A separate top-level `version` field lets us
/// evolve the cache schema without breaking older binaries that
/// might still be reading the file.
///
/// we authenticate the inner payload with
/// a per-device HMAC key (BLAKE3 keyed-hash) — a local attacker who
/// rewrites the cache file to plant adversary-controlled candidate
/// peers can no longer make the daemon dial them, because the MAC
/// won't verify. `mac` is `None` for legacy cache files written
/// before this audit; loaders fall back to no-HMAC mode (with a
/// warning log) when the key is unavailable to preserve smooth
/// upgrades. Going forward, every save embeds a MAC.
#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheEnvelope {
    version: u32,
    peers: Vec<DiscoveredPeer>,
    /// BLAKE3 keyed-hash over `serde_json::to_vec(SignedBody { version, peers })`.
    /// Hex-encoded. Absence = legacy / unauthenticated cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
}

/// Inner body that [`CacheEnvelope::mac`] commits to. Excludes
/// the `mac` field itself so MAC-of-MAC is not a concern. Serialize-
/// only — the verifier re-serializes this from the parsed envelope's
/// peers, never deserializes.
#[derive(Debug, Serialize)]
struct SignedBody<'a> {
    version: u32,
    peers: &'a [DiscoveredPeer],
}

/// Domain-tag prefixed to the BLAKE3 keyed-hash input so the same
/// per-device key cannot be cross-protocol-misused as a MAC for any
/// other JSON file type that an operator might keep next to this one.
const CACHE_MAC_DOMAIN: &[u8] = b"veil-bootstrap-cache-mac-v1\0";

/// Discovered-peer cache backed by a single JSON file on disk.
///
/// Cheap clone of the in-memory state via `snapshot` for
/// bootstrap-task consumption; mutations go through `upsert` and
/// `save` to keep the disk file in sync.
#[derive(Debug)]
pub struct DiscoveredPeerCache {
    /// Indexed by `public_key` (base64) so a peer that re-connects
    /// from a different IP just refreshes the `transport` + timestamp
    /// of its existing entry rather than creating a duplicate.
    entries: HashMap<String, DiscoveredPeer>,
    path: PathBuf,
    /// Per-device key for the envelope HMAC. `None` = unauthenticated
    /// (in-memory tests, or a deployment that has not yet provisioned
    /// a key). See / in [`CacheEnvelope`] doc.
    hmac_key: Option<[u8; 32]>,
}

impl DiscoveredPeerCache {
    /// Load the cache from disk. Missing file = empty cache (no
    /// error — first-run case). Corrupt file = empty cache + warn
    /// log so a malformed cache doesn't block node start.
    ///
    /// this path-only loader cannot verify
    /// the envelope MAC — production callers should use
    /// [`Self::load_with_hmac_key`] instead. Kept as the legacy entry
    /// for tests and tools that already operate on unauthenticated
    /// cache files.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        Self::load_inner(path.into(), None)
    }

    /// HMAC-aware loader. Reads the cache file and verifies the
    /// envelope MAC against `hmac_key` (typically derived per-device
    /// from the daemon's veil_dir). On MAC mismatch the cache is
    /// dropped (returned empty) — better to fall through to the next
    /// bootstrap layer than to dial peers a local attacker chose.
    pub fn load_with_hmac_key(path: impl Into<PathBuf>, hmac_key: [u8; 32]) -> Self {
        Self::load_inner(path.into(), Some(hmac_key))
    }

    fn load_inner(path: PathBuf, hmac_key: Option<[u8; 32]>) -> Self {
        let entries = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<CacheEnvelope>(&bytes) {
                Ok(env) => {
                    if let Some(key) = hmac_key {
                        if !verify_envelope_mac(&env, &key) {
                            // MAC mismatch — local attacker
                            // probably rewrote the file, or we rotated
                            // the per-device key without re-saving.
                            // Either way the cache is no longer trusted.
                            eprintln!(
                                "[veil-bootstrap] discovered-peer cache at {} \
                                 failed HMAC verification — dropping; \
                                 will re-populate via successful handshakes",
                                path.display(),
                            );
                            HashMap::new()
                        } else {
                            env.peers
                                .into_iter()
                                .map(|e| (e.peer.public_key.clone(), e))
                                .collect()
                        }
                    } else {
                        // No key configured — fall back to unauthenticated
                        // load. Production callers should configure a key.
                        env.peers
                            .into_iter()
                            .map(|e| (e.peer.public_key.clone(), e))
                            .collect()
                    }
                }
                Err(e) => {
                    // surface parse
                    // errors via stderr. Previously the cache silently
                    // dropped to empty on any deserialization failure
                    // which masked operator-visible problems (truncated
                    // file from a crash, manual jq edit gone wrong
                    // schema-drift between binaries). An empty cache
                    // is recoverable, but the operator should know
                    // why so they can decide whether to investigate.
                    eprintln!(
                        "[veil-bootstrap] discovered-peer cache at {} \
                         failed to parse: {} — falling back to empty",
                        path.display(),
                        e
                    );
                    HashMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // First-run case — file simply doesn't exist yet.
                // No log noise; empty is the correct state.
                HashMap::new()
            }
            Err(e) => {
                // a real I/O error (permission
                // denied, ENOSPC during read, disk failure) is operator-
                // visible — log explicitly so it's not lost.
                eprintln!(
                    "[veil-bootstrap] discovered-peer cache at {} \
                     unreadable: {} — falling back to empty",
                    path.display(),
                    e
                );
                HashMap::new()
            }
        };
        Self {
            entries,
            path,
            hmac_key,
        }
    }

    /// In-memory only constructor — used by tests that don't want
    /// to touch the filesystem. Path is set to the empty path so
    /// `save` becomes a no-op.
    pub fn in_memory() -> Self {
        Self {
            entries: HashMap::new(),
            path: PathBuf::new(),
            hmac_key: None,
        }
    }

    /// Number of entries currently cached.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` iff no entries are cached.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add or refresh a peer's entry. Re-running with the same
    /// `public_key` replaces the entry — this handles the realistic
    /// case where a peer's IP / port changed between runs. When
    /// inserting (`MAX_DISCOVERED_PEERS + 1`)th distinct peer
    /// the entry with the smallest `last_seen_unix` is evicted.
    ///
    /// silently truncate or drop the entry if
    /// any per-field cap is exceeded. A malicious peer can no longer
    /// blow up our cache file by advertising a megabyte-long transport
    /// URI or TLS certificate.
    pub fn upsert(&mut self, peer: BootstrapPeer, now_unix: u64) {
        // Drop oversized entries entirely — better to lose a single
        // bootstrap candidate than to bloat the cache.
        if peer.transport.len() > MAX_TRANSPORT_STR_LEN {
            return;
        }
        if let Some(ref cert) = peer.tls_cert
            && cert.len() > MAX_TLS_CERT_BYTES
        {
            return;
        }
        if let Some(ref cacert) = peer.tls_ca_cert
            && cacert.len() > MAX_TLS_CERT_BYTES
        {
            return;
        }
        if let Some(existing) = self.entries.get_mut(&peer.public_key) {
            existing.peer = peer;
            existing.last_seen_unix = now_unix;
            return;
        }
        if self.entries.len() >= MAX_DISCOVERED_PEERS
            && let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.last_seen_unix)
                .map(|(k, _)| k.clone())
        {
            self.entries.remove(&oldest_key);
        }
        let key = peer.public_key.clone();
        self.entries.insert(
            key,
            DiscoveredPeer {
                peer,
                last_seen_unix: now_unix,
            },
        );
    }

    /// Snapshot of all cached peers as a `Vec<BootstrapPeer>` ready
    /// to feed into the bootstrap-task fallback chain. Sort order:
    /// most-recently-seen first, so the bootstrap-task tries the
    /// freshest entries before older ones.
    pub fn snapshot(&self) -> Vec<BootstrapPeer> {
        let mut sorted: Vec<&DiscoveredPeer> = self.entries.values().collect();
        sorted.sort_by_key(|e| std::cmp::Reverse(e.last_seen_unix));
        sorted.into_iter().map(|e| e.peer.clone()).collect()
    }

    /// `(oldest_unix, freshest_unix)` of all cached entries, or `None`
    /// when the cache is empty. Surfaced for diag: an
    /// operator looking at `node bootstrap-status` wants to know
    /// "is my cache layer current or full of dead seeds?". A cache
    /// whose freshest entry is months old is a hint that the node
    /// hasn't connected to anyone via the bootstrap chain in months
    /// — likely all higher layers (operator config, builtin, HTTPS
    /// DNS) are also failing.
    pub fn timestamp_range(&self) -> Option<(u64, u64)> {
        let mut iter = self.entries.values();
        let first = iter.next()?;
        let mut oldest = first.last_seen_unix;
        let mut freshest = first.last_seen_unix;
        for entry in iter {
            if entry.last_seen_unix < oldest {
                oldest = entry.last_seen_unix;
            }
            if entry.last_seen_unix > freshest {
                freshest = entry.last_seen_unix;
            }
        }
        Some((oldest, freshest))
    }

    /// Persist the in-memory state to the disk path provided to
    /// `load`. No-op when the cache was created via
    /// [`Self::in_memory`]. Errors propagate — caller decides
    /// whether to warn-and-continue or fail-hard.
    pub fn save(&self) -> std::io::Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        let peers: Vec<DiscoveredPeer> = self.entries.values().cloned().collect();
        let mac = self.hmac_key.map(|key| {
            let body = SignedBody {
                version: 1,
                peers: &peers,
            };
            let body_bytes =
                serde_json::to_vec(&body).expect("DiscoveredPeer serialization is infallible");
            compute_envelope_mac(&body_bytes, &key)
        });
        let env = CacheEnvelope {
            version: 1,
            peers,
            mac,
        };
        let bytes = serde_json::to_vec_pretty(&env)?;
        veil_util::atomic_write(&self.path, &bytes)
    }

    /// Path the cache reads from / writes to. Empty `Path` means
    /// the in-memory variant.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Compute the cache envelope MAC. BLAKE3 keyed-hash with a stable
/// domain prefix so the same per-device key is not abusable as a MAC
/// for any other JSON file format.
fn compute_envelope_mac(body_bytes: &[u8], key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(CACHE_MAC_DOMAIN);
    hasher.update(body_bytes);
    let h = hasher.finalize();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(h.as_bytes())
}

/// Verify an envelope's `mac` field. Returns `true` iff the envelope
/// has a MAC AND the MAC matches the recomputed value (constant-time
/// equality). Missing MAC = `false` (unauthenticated → reject in
/// keyed mode).
fn verify_envelope_mac(env: &CacheEnvelope, key: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq as _;
    let Some(claimed_b64) = env.mac.as_deref() else {
        return false;
    };
    use base64::Engine as _;
    let Ok(claimed_bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(claimed_b64)
    else {
        return false;
    };
    let body = SignedBody {
        version: env.version,
        peers: &env.peers,
    };
    let body_bytes = match serde_json::to_vec(&body) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(CACHE_MAC_DOMAIN);
    hasher.update(&body_bytes);
    let expected = hasher.finalize();
    expected.as_bytes().ct_eq(claimed_bytes.as_slice()).into()
}

/// Load (or generate) the per-device cache HMAC key in `veil_dir`.
///
/// Stored at `<veil_dir>/cache_hmac_key.bin` (32 random bytes
/// owner-only `0o600` on Unix). On first run the file is created with
/// fresh randomness; subsequent runs read the same key so cache files
/// written by a prior run still verify.
///
/// A key rotation is intentionally manual — operators who delete
/// `cache_hmac_key.bin` will get a fresh key on next start, and the
/// old cache file will fail verification on first read (then be
/// dropped and rebuilt as peers reconnect).
pub fn load_or_generate_cache_hmac_key(veil_dir: &Path) -> std::io::Result<[u8; 32]> {
    use rand_core::RngCore as _;
    let key_path = veil_dir.join("cache_hmac_key.bin");
    if let Ok(bytes) = std::fs::read(&key_path)
        && bytes.len() == 32
    {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }
    // Wrong length — fall through to regenerate.
    let mut key = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut key);
    veil_util::atomic_write(&key_path, &key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_types::SignatureAlgorithm;

    fn sample_peer(tag: u8) -> BootstrapPeer {
        BootstrapPeer {
            transport: format!("tcp://10.0.0.{tag}:9000"),
            public_key: format!("pk-{tag}"),
            nonce: format!("nc-{tag}"),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }
    }

    #[test]
    fn epic481_5_empty_load_from_missing_file() {
        let path = std::env::temp_dir().join("veil-481-5-missing.json");
        let _ = std::fs::remove_file(&path);
        let cache = DiscoveredPeerCache::load(&path);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn epic481_5_upsert_then_snapshot_returns_entry() {
        let mut cache = DiscoveredPeerCache::in_memory();
        cache.upsert(sample_peer(1), 1_700_000_000);
        let snap = cache.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].public_key, "pk-1");
    }

    #[test]
    fn epic481_5_upsert_same_pubkey_refreshes_in_place() {
        let mut cache = DiscoveredPeerCache::in_memory();
        cache.upsert(sample_peer(1), 1_700_000_000);
        // Same pubkey, different transport (peer moved IP).
        let mut p = sample_peer(1);
        p.transport = "tcp://10.0.0.99:9000".to_owned();
        cache.upsert(p, 1_700_000_500);
        assert_eq!(cache.len(), 1, "same pubkey must NOT create a duplicate");
        let snap = cache.snapshot();
        assert_eq!(snap[0].transport, "tcp://10.0.0.99:9000");
    }

    #[test]
    fn epic481_5_snapshot_orders_freshest_first() {
        let mut cache = DiscoveredPeerCache::in_memory();
        cache.upsert(sample_peer(1), 1_700_000_000);
        cache.upsert(sample_peer(2), 1_700_000_500); // newer
        cache.upsert(sample_peer(3), 1_700_000_100);
        let snap = cache.snapshot();
        assert_eq!(snap[0].public_key, "pk-2", "freshest must be first");
        assert_eq!(snap[1].public_key, "pk-3");
        assert_eq!(snap[2].public_key, "pk-1");
    }

    #[test]
    fn epic481_5_lru_evicts_oldest_when_at_cap() {
        let mut cache = DiscoveredPeerCache::in_memory();
        // Fill to cap with monotonically-increasing timestamps.
        for i in 0..MAX_DISCOVERED_PEERS as u8 {
            cache.upsert(sample_peer(i + 1), 1_700_000_000 + i as u64);
        }
        assert_eq!(cache.len(), MAX_DISCOVERED_PEERS);
        // The oldest entry has the smallest timestamp (= peer "1" at
        // `1_700_000_000`). Insert one more — that oldest must go.
        cache.upsert(sample_peer(99), 1_700_001_000);
        assert_eq!(
            cache.len(),
            MAX_DISCOVERED_PEERS,
            "LRU cap must hold steady at MAX_DISCOVERED_PEERS"
        );
        let snap = cache.snapshot();
        let pks: Vec<String> = snap.iter().map(|p| p.public_key.clone()).collect();
        assert!(
            !pks.contains(&"pk-1".to_owned()),
            "oldest entry pk-1 should have been evicted"
        );
        assert!(
            pks.contains(&"pk-99".to_owned()),
            "newest entry pk-99 must be present"
        );
    }

    #[test]
    fn epic481_5_save_load_round_trip() {
        let path =
            std::env::temp_dir().join(format!("veil-481-5-roundtrip-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut cache = DiscoveredPeerCache::load(&path);
            cache.upsert(sample_peer(1), 1_700_000_000);
            cache.upsert(sample_peer(2), 1_700_000_100);
            cache.save().expect("save");
        }
        let cache2 = DiscoveredPeerCache::load(&path);
        assert_eq!(cache2.len(), 2);
        let snap = cache2.snapshot();
        assert_eq!(snap[0].public_key, "pk-2");
        assert_eq!(snap[1].public_key, "pk-1");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epic481_5_load_corrupt_file_returns_empty_cache() {
        let path =
            std::env::temp_dir().join(format!("veil-481-5-corrupt-{}.json", std::process::id()));
        std::fs::write(&path, b"not valid json {{{").expect("write");
        let cache = DiscoveredPeerCache::load(&path);
        assert!(
            cache.is_empty(),
            "corrupt cache must NOT panic — empty cache so node still boots"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epic481_5_save_in_memory_variant_is_noop() {
        let mut cache = DiscoveredPeerCache::in_memory();
        cache.upsert(sample_peer(1), 1_700_000_000);
        cache
            .save()
            .expect("in-memory save returns Ok without touching disk");
    }

    #[test]
    fn epic484_4_timestamp_range_returns_none_when_empty() {
        let cache = DiscoveredPeerCache::in_memory();
        assert_eq!(
            cache.timestamp_range(),
            None,
            "empty cache must report None for timestamp_range"
        );
    }

    #[test]
    fn epic484_4_timestamp_range_returns_oldest_and_freshest() {
        let mut cache = DiscoveredPeerCache::in_memory();
        cache.upsert(sample_peer(1), 1_700_000_500);
        cache.upsert(sample_peer(2), 1_700_000_100); // oldest
        cache.upsert(sample_peer(3), 1_700_000_900); // freshest
        cache.upsert(sample_peer(4), 1_700_000_300);
        assert_eq!(
            cache.timestamp_range(),
            Some((1_700_000_100, 1_700_000_900)),
            "must return (min, max) across all entries",
        );
    }

    #[test]
    fn epic484_4_timestamp_range_single_entry_returns_same_for_both() {
        let mut cache = DiscoveredPeerCache::in_memory();
        cache.upsert(sample_peer(1), 1_700_000_500);
        assert_eq!(
            cache.timestamp_range(),
            Some((1_700_000_500, 1_700_000_500)),
            "single entry: oldest == freshest",
        );
    }

    #[test]
    fn epic481_5_disk_format_uses_envelope_with_version() {
        let path =
            std::env::temp_dir().join(format!("veil-481-5-format-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut cache = DiscoveredPeerCache::load(&path);
        cache.upsert(sample_peer(1), 1_700_000_000);
        cache.save().expect("save");
        let raw = std::fs::read_to_string(&path).expect("read");
        assert!(
            raw.contains("\"version\""),
            "envelope must have version field"
        );
        assert!(raw.contains("\"peers\""), "envelope must have peers field");
        assert!(
            raw.contains("\"last_seen_unix\""),
            "per-entry timestamp must be persisted"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// with HMAC mode enabled, a save+load
    /// round-trip recovers the original entries (MAC verifies).
    #[test]
    fn phase647_h14_hmac_roundtrip_preserves_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let key = [0x42u8; 32];
        let mut cache = DiscoveredPeerCache::load_with_hmac_key(&path, key);
        cache.upsert(sample_peer(1), 1_700_000_000);
        cache.upsert(sample_peer(2), 1_700_000_500);
        cache.save().expect("save");
        let cache2 = DiscoveredPeerCache::load_with_hmac_key(&path, key);
        assert_eq!(cache2.len(), 2);
        let snap = cache2.snapshot();
        assert!(snap.iter().any(|p| p.public_key == "pk-1"));
        assert!(snap.iter().any(|p| p.public_key == "pk-2"));
    }

    /// file tampered after save → MAC fails → cache loaded empty.
    /// Simulates an attacker rewriting the JSON to plant a sybil peer.
    #[test]
    fn phase647_h14_tampered_cache_drops_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let key = [0x77u8; 32];
        let mut cache = DiscoveredPeerCache::load_with_hmac_key(&path, key);
        cache.upsert(sample_peer(1), 1_700_000_000);
        cache.save().expect("save");
        // Attacker rewrites the file: change peer's transport.
        let raw = std::fs::read_to_string(&path).unwrap();
        let tampered = raw.replace("10.0.0.1", "10.0.0.99");
        std::fs::write(&path, tampered).unwrap();
        // Loader detects MAC mismatch and drops the cache.
        let cache2 = DiscoveredPeerCache::load_with_hmac_key(&path, key);
        assert_eq!(
            cache2.len(),
            0,
            "tampered cache must NOT load — MAC mismatch dropped to empty"
        );
    }

    /// a different key (e.g. attacker doesn't know per-device key)
    /// also fails verification → empty cache.
    #[test]
    fn phase647_h14_wrong_key_drops_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let key1 = [0xAAu8; 32];
        let key2 = [0xBBu8; 32];
        let mut cache = DiscoveredPeerCache::load_with_hmac_key(&path, key1);
        cache.upsert(sample_peer(1), 1_700_000_000);
        cache.save().expect("save");
        let cache2 = DiscoveredPeerCache::load_with_hmac_key(&path, key2);
        assert_eq!(cache2.len(), 0);
    }

    /// legacy unauthenticated cache loads with the key-less
    /// `load` path (backwards compat). Production deployments
    /// should use `load_with_hmac_key` to gain authentication.
    #[test]
    fn phase647_h14_legacy_no_mac_path_loads_unauthenticated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        // Save without a key → no MAC field in envelope.
        let mut cache = DiscoveredPeerCache::load(&path);
        cache.upsert(sample_peer(1), 1_700_000_000);
        cache.save().expect("save");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("\"mac\""),
            "no key configured → MAC field absent: {raw}"
        );
        // Legacy load returns the entries.
        let cache2 = DiscoveredPeerCache::load(&path);
        assert_eq!(cache2.len(), 1);
    }

    /// helper auto-generates the per-device key and persists
    /// it; second call returns the same key (idempotent).
    #[test]
    fn phase647_h14_load_or_generate_key_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let k1 = load_or_generate_cache_hmac_key(dir.path()).expect("first");
        let k2 = load_or_generate_cache_hmac_key(dir.path()).expect("second");
        assert_eq!(k1, k2, "same veil_dir → same key on subsequent calls");
        // Sanity: not all-zero (would happen if RngCore fill was no-op).
        assert!(k1.iter().any(|&b| b != 0));
    }

    /// a peer that advertises a transport URI
    /// past the per-field cap is dropped — its bytes never reach the
    /// cache and so cannot bloat the on-disk file.
    #[test]
    fn phase647_h16_oversized_transport_uri_dropped() {
        let mut cache = DiscoveredPeerCache::in_memory();
        let mut p = sample_peer(1);
        p.transport = format!("tcp://{}:9000", "x".repeat(MAX_TRANSPORT_STR_LEN));
        cache.upsert(p, 1_700_000_000);
        assert_eq!(cache.len(), 0, "oversized transport URI must NOT be cached");
    }

    /// a peer whose `tls_cert` exceeds the per-field cap is
    /// dropped. Same risk class as transport URI but typically
    /// larger payloads (PEM-encoded chains) so a separate test path.
    #[test]
    fn phase647_h16_oversized_tls_cert_dropped() {
        let mut cache = DiscoveredPeerCache::in_memory();
        let mut p = sample_peer(2);
        p.tls_cert = Some("Z".repeat(MAX_TLS_CERT_BYTES + 1));
        cache.upsert(p, 1_700_000_000);
        assert_eq!(cache.len(), 0);
    }

    /// a peer with reasonable values still upserts cleanly.
    #[test]
    fn phase647_h16_normal_sized_peer_still_upserts() {
        let mut cache = DiscoveredPeerCache::in_memory();
        let mut p = sample_peer(3);
        p.tls_cert = Some("A".repeat(MAX_TLS_CERT_BYTES / 2));
        cache.upsert(p, 1_700_000_000);
        assert_eq!(cache.len(), 1);
    }
}
