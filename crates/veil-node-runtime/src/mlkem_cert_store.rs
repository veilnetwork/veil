//! Peer ML-KEM certificates that outlive the process.
//!
//! ## The record with exactly one writer
//!
//! `IdentityDocument` and `InstanceRegistry` are republished to the DHT by
//! EVERY device of an identity (`runtime/identity_publish.rs` publishes the
//! full registry), so one live device keeps both answerable on behalf of the
//! whole family. `MlKemKeyCert` is not: its slot is
//! `MlKemKeyCert::dht_key(node_id, instance_id)` and the only writer that ever
//! exists for it is the device that owns that instance. A device that stops
//! republishing stops being resolvable, and nothing else can stand in for it.
//!
//! Measured on a real phone: an Android device of a family force-stopped, a
//! sibling posting a device-sync event for it and retrying for ~45 minutes.
//! Every deposit failed at
//! `mailbox_seal failed: protocol error: mailbox_seal failed: PeerUnresolved`.
//! The blocker is the SEAL, not the relay lookup — `offline_seal::seal_for`
//! cannot encrypt for a recipient whose certificate it cannot fetch, so the
//! deposit never reaches a relay at all, and the relay-target cache the app
//! layer keeps for the same recipient never gets a chance to run.
//!
//! Before this store the only thing that had ever held a peer's certificate was
//! [`CERT_CACHE_TTL`](crate::mlkem_resolver::PeerMlKemCertCache) — 30 minutes,
//! in RAM, gone on restart. A device off for longer than that had nothing
//! cached and nothing resolvable, and there was no third place to look.
//!
//! ## The bound is the certificate's own validity, not a cache TTL
//!
//! A cache TTL is a freshness/bandwidth trade someone chose. The certificate
//! carries a window it was SIGNED for — `valid_from_unix ..= valid_until_unix`,
//! issued as `now ..= now + 30 days` at startup and rolled forward on every
//! 6-hourly republish (`runtime/identity_publish.rs`,
//! `runtime/sovereign_republish.rs`) — and
//! [`verify_mlkem_cert`](veil_identity::mlkem_fanout::verify_mlkem_cert)
//! refuses it outside that window. That signed window, not a cache TTL, is the
//! honest bound on how long a remembered certificate may be used.
//!
//! So rows here are the SIGNED WIRE BYTES, never a parsed
//! [`VerifiedMlkemCert`], and [`MlKemCertStore::recall`] re-runs the identical
//! `verify_mlkem_cert` against the document in hand. A remembered certificate
//! is therefore accepted on exactly the terms a freshly-walked one would be:
//! same signature check against the same current document, same validity
//! window, same node-id binding. The file is untrusted input — someone who
//! rewrites it gains nothing, because a row that is unsigned, expired, foreign,
//! or signed by a subkey the document no longer carries fails the same check
//! the network copy would.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::{Engine as _, engine::general_purpose::STANDARD};

use veil_identity::mlkem_fanout::{MlkemFanoutError, VerifiedMlkemCert, verify_mlkem_cert};
use veil_proto::identity_document::IdentityDocument;
use veil_proto::mlkem_cert::MlKemKeyCert;
use veil_util::lock;

use crate::runtime::persistence::{read_snapshot, write_snapshot};

/// `(node_id, instance_id)` — the ONE device a certificate belongs to.
///
/// Keyed by the pair and not by `node_id` alone because a multi-device identity
/// publishes one certificate per device, each bound to its own `instance_id`
/// and `cert_version`; a node-keyed row could only ever hold one of them and
/// would answer "the certificate of the device I am sealing for" with whichever
/// row it happened to hold.
pub type CertKey = ([u8; 32], [u8; 16]);

/// Cap on remembered certificates.
///
/// One ML-KEM-768 certificate is ~1.3 KB of wire bytes (~1.8 KB base64), and a
/// single identity can publish up to `MAX_FANOUT_CERTS` (16) of them, so this
/// bounds the file at roughly 450 KB — small enough to rewrite whole on each
/// new certificate, which is what keeps the writer a single atomic snapshot
/// rather than an append log needing its own compaction.
///
/// Deliberately below the in-RAM
/// [`MAX_PEER_MLKEM_CACHE`](veil_proto::budget::MAX_PEER_MLKEM_CACHE) of 512:
/// the RAM cache absorbs transient third-party traffic, while this file only
/// has to answer for people actually corresponded with.
pub const MAX_REMEMBERED_CERTS: usize = 256;

/// What the store held for one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertRecall {
    /// A remembered certificate that verifies against the current document at
    /// `now` — usable on exactly the terms a freshly-walked one would be.
    Verified(Box<VerifiedMlkemCert>),
    /// Material WAS remembered and its own signed validity window has closed.
    ///
    /// Distinct from [`Self::Absent`] because the two mean opposite things to
    /// whoever is retrying: expired material says the peer was known and its
    /// certificate needs re-publishing before anything can be sealed for it,
    /// while absent says the peer was never resolved at all.
    Expired {
        /// The end of the window the certificate was signed for.
        valid_until_unix: u64,
    },
    /// Nothing is remembered for this device.
    Absent,
}

/// One remembered certificate: the signed bytes, plus the three fields decoded
/// once so ordering and eviction do not re-parse the whole file.
#[derive(Debug, Clone)]
struct Row {
    bytes: Vec<u8>,
    cert_version: u64,
    valid_from_unix: u64,
    valid_until_unix: u64,
}

impl Row {
    /// Supersede order, identical to the one the DHT walks use when several
    /// replicas answer: `cert_version` is the documented monotonic rotation
    /// counter, `valid_from_unix` breaks ties between republications of the
    /// same version.
    fn supersede_key(&self) -> (u64, u64) {
        (self.cert_version, self.valid_from_unix)
    }

    fn from_cert(cert: &MlKemKeyCert) -> Self {
        Self {
            bytes: cert.encode(),
            cert_version: cert.cert_version,
            valid_from_unix: cert.valid_from_unix,
            valid_until_unix: cert.valid_until_unix,
        }
    }
}

/// On-disk shape — one object per remembered certificate, in the same
/// hex-ids-and-strings style as the `peers_discovered.json` / `bans.json`
/// snapshots this store shares its writer with.
#[derive(serde::Serialize, serde::Deserialize)]
struct CertSnapshot {
    node_id: String,
    instance_id: String,
    /// The signed `MlKemKeyCert`, base64. Base64 rather than hex only because
    /// the certificate is ~1.3 KB and there are up to
    /// [`MAX_REMEMBERED_CERTS`] of them.
    cert: String,
}

/// `(node_id, instance_id) → signed MlKemKeyCert`, atomically snapshotted next
/// to `config.toml`.
pub struct MlKemCertStore {
    /// `None` for a store with nowhere to write — tests, and any runtime built
    /// without a config path. Everything else behaves identically, so a caller
    /// never has to ask whether persistence is on.
    path: Option<PathBuf>,
    rows: Mutex<BTreeMap<CertKey, Row>>,
    /// Snapshot generation, taken WHILE the `rows` lock is held so its order is
    /// the order the mutations happened in.
    next_gen: AtomicU64,
    /// Highest generation actually on disk. Guarded rather than atomic because
    /// the guard also serializes the writes themselves — see [`Self::flush`].
    published_gen: Mutex<u64>,
}

/// Snapshot path for `config_path`: `…/config.toml` → `…/peer_mlkem_certs.json`.
/// Same derivation as [`bans_path`](crate::runtime::persistence::bans_path).
#[must_use]
pub fn peer_mlkem_certs_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("peer_mlkem_certs.json")
}

impl MlKemCertStore {
    /// Read the snapshot beside `config_path`, dropping anything already past
    /// its signed validity window.
    ///
    /// An unreadable or malformed file yields an empty store: this is
    /// disposable material — every row is re-obtainable from the DHT the moment
    /// its owner is online — and refusing to boot over it would hand anyone
    /// with write access to the directory a denial of service. `read_snapshot`
    /// has already said which of the two it was.
    #[must_use]
    pub fn load(config_path: &Path, now_unix: u64) -> Self {
        let path = peer_mlkem_certs_path(config_path);
        let snapshots: Vec<CertSnapshot> = match read_snapshot(&path, "peer ML-KEM certs") {
            Ok(Some(v)) => v,
            Ok(None) | Err(_) => Vec::new(),
        };
        let mut rows = BTreeMap::new();
        for snap in snapshots {
            let Some(key) = decode_key(&snap) else {
                continue;
            };
            let Ok(bytes) = STANDARD.decode(&snap.cert) else {
                continue;
            };
            // Decoded, not trusted: the row must at minimum be a well-formed
            // certificate for the device it is filed under. The signature is
            // NOT checked here — that needs the peer's document, which this
            // runtime does not hold at load time and which `recall` has.
            let Ok(cert) = MlKemKeyCert::decode(&bytes) else {
                continue;
            };
            if (cert.node_id, cert.instance_id) != key {
                continue;
            }
            rows.insert(key, Row::from_cert(&cert));
        }
        prune(&mut rows, now_unix);
        Self {
            path: Some(path),
            rows: Mutex::new(rows),
            next_gen: AtomicU64::new(0),
            published_gen: Mutex::new(0),
        }
    }

    /// A store that remembers for the life of the process and writes nothing.
    #[must_use]
    pub fn ephemeral() -> Self {
        Self {
            path: None,
            rows: Mutex::new(BTreeMap::new()),
            next_gen: AtomicU64::new(0),
            published_gen: Mutex::new(0),
        }
    }

    /// How many certificates are held. Bound is [`MAX_REMEMBERED_CERTS`].
    #[must_use]
    pub fn len(&self) -> usize {
        lock!(self.rows).len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remember a certificate the caller has just verified against the peer's
    /// document.
    ///
    /// Returns whether the store now holds THIS certificate — `false` when it
    /// already held one that supersedes it, or when the certificate is already
    /// outside its own window (material that could never be served is not
    /// material worth a disk write).
    ///
    /// A write that fails leaves the row standing in memory and is logged by
    /// the shared snapshot writer; the row is then exactly as durable as the
    /// process, which is what the store had before it existed.
    pub fn remember(&self, cert: &MlKemKeyCert, now_unix: u64) -> bool {
        if !cert.is_valid_at(now_unix) {
            return false;
        }
        let key = (cert.node_id, cert.instance_id);
        let row = Row::from_cert(cert);
        let (generation, snapshot) = {
            let mut rows = lock!(self.rows);
            if let Some(held) = rows.get(&key)
                && held.supersede_key() >= row.supersede_key()
            {
                return false;
            }
            rows.insert(key, row);
            prune(&mut rows, now_unix);
            // A rotation the peer published while we were holding the old row
            // could have been evicted right back out by the cap; say so rather
            // than claim a row that is not there.
            if !rows.contains_key(&key) {
                return false;
            }
            (self.next_generation(), encode(&rows))
        };
        self.flush(generation, &snapshot);
        true
    }

    /// The remembered certificate for one device, put through the same
    /// verification a freshly-walked one faces.
    ///
    /// `doc` is the peer's already-verified `IdentityDocument`. Everything the
    /// DHT path checks is checked here against it — signature under the named
    /// subkey, node-id binding, algorithm, and the certificate's own validity
    /// window — so this can only return material the network copy would also
    /// have been accepted as.
    ///
    /// A row that fails for any reason OTHER than expiry is deleted: the
    /// signature no longer verifying under the current document is what a
    /// device whose subkey was REVOKED looks like, and keeping such a row would
    /// let a revoked device go on being sealed for out of a local file.
    pub fn recall(
        &self,
        node_id: &[u8; 32],
        instance_id: &[u8; 16],
        doc: &IdentityDocument,
        now_unix: u64,
    ) -> CertRecall {
        let key = (*node_id, *instance_id);
        let Some(row) = lock!(self.rows).get(&key).cloned() else {
            return CertRecall::Absent;
        };
        let verdict = MlKemKeyCert::decode(&row.bytes)
            .ok()
            .map(|cert| verify_mlkem_cert(&cert, doc, now_unix));
        match verdict {
            Some(Ok(verified)) => CertRecall::Verified(Box::new(verified)),
            Some(Err(MlkemFanoutError::CertNotValidNow { until, .. })) => CertRecall::Expired {
                valid_until_unix: until,
            },
            _ => {
                self.forget(&key);
                CertRecall::Absent
            }
        }
    }

    /// Drop every remembered certificate of one identity.
    ///
    /// Called from
    /// [`invalidate_peer`](crate::mlkem_resolver::DhtMlKemEkResolver::invalidate_peer),
    /// where the peer has just said it cannot open what we sealed. Dropping the
    /// RAM caches alone would leave this file re-serving the same refused
    /// material on the next seal — the persistent version of exactly the
    /// re-wedging loop that invalidation exists to break, and worse, because
    /// this one survives a restart.
    pub fn forget_node(&self, node_id: &[u8; 32]) {
        let (generation, snapshot) = {
            let mut rows = lock!(self.rows);
            let before = rows.len();
            rows.retain(|(held, _), _| held != node_id);
            if rows.len() == before {
                return;
            }
            (self.next_generation(), encode(&rows))
        };
        self.flush(generation, &snapshot);
    }

    fn forget(&self, key: &CertKey) {
        let (generation, snapshot) = {
            let mut rows = lock!(self.rows);
            if rows.remove(key).is_none() {
                return;
            }
            (self.next_generation(), encode(&rows))
        };
        self.flush(generation, &snapshot);
    }

    /// The next snapshot generation. Call it while the `rows` lock is held: the
    /// point is that generation order equals mutation order.
    fn next_generation(&self) -> u64 {
        self.next_gen.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn flush(&self, generation: u64, snapshot: &[CertSnapshot]) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        // The guard serializes the writes AND orders them.
        //
        // The snapshot is encoded under the `rows` lock and written after it is
        // released, so two threads could reach the file in either order —
        // whichever wrote last won. Each snapshot is the WHOLE map, so a late
        // OLDER one silently undoes the newer mutation: the row `forget_node`
        // had just dropped is back, and the file re-serves material the peer
        // has already said it cannot open. That is the persistent re-wedging
        // loop invalidation exists to break, and unlike the RAM caches it
        // survives a restart.
        //
        // A superseded snapshot is therefore skipped rather than written. It
        // needs no write of its own: every generation encodes the entire map,
        // so the newer one already contains whatever the older one carried.
        let mut published = lock!(self.published_gen);
        if generation <= *published {
            return;
        }
        // `write_snapshot` logs its own failure at the site that knows the
        // path, and the caller has already been told the row stands in memory.
        // A failed write does not advance the mark: the next mutation should
        // still try, rather than believe this generation is on disk.
        if write_snapshot(path, &snapshot, "peer ML-KEM certs").is_durable() {
            *published = generation;
        }
    }
}

/// Drop what is past its window, then evict down to the cap.
///
/// Eviction takes the SOONEST-EXPIRING row first, because that is the row
/// closest to being worthless anyway — an LRU here would instead throw away the
/// certificate of the peer that is quiet, which is precisely the peer this
/// store exists to keep sealable.
fn prune(rows: &mut BTreeMap<CertKey, Row>, now_unix: u64) {
    rows.retain(|_, row| row.valid_until_unix >= now_unix);
    while rows.len() > MAX_REMEMBERED_CERTS {
        let Some(victim) = rows
            .iter()
            .min_by_key(|(_, row)| row.valid_until_unix)
            .map(|(key, _)| *key)
        else {
            break;
        };
        rows.remove(&victim);
    }
}

fn encode(rows: &BTreeMap<CertKey, Row>) -> Vec<CertSnapshot> {
    rows.iter()
        .map(|((node_id, instance_id), row)| CertSnapshot {
            node_id: veil_util::bytes_to_hex(node_id),
            instance_id: veil_util::bytes_to_hex(instance_id),
            cert: STANDARD.encode(&row.bytes),
        })
        .collect()
}

fn decode_key(snap: &CertSnapshot) -> Option<CertKey> {
    let node_id: [u8; 32] = veil_util::hex_to_bytes(&snap.node_id)
        .ok()?
        .try_into()
        .ok()?;
    let instance_id: [u8; 16] = veil_util::hex_to_bytes(&snap.instance_id)
        .ok()?
        .try_into()
        .ok()?;
    Some((node_id, instance_id))
}

/// A document and the subkey that signs certificates under it.
///
/// Lives outside `mod tests` because the resolver's tests exercise the same
/// certificates through the DHT walk, and two hand-rolled fixtures for one
/// certificate format is two chances for the test to agree with itself and
/// disagree with `verify_mlkem_cert`.
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;

    use ed25519_dalek::{Signer as _, SigningKey};
    use veil_crypto::identity::{certify_message, compute_node_id};
    use veil_proto::identity_document::{ALGO_ED25519, DOC_SIG_CONTEXT, IdentityKey};
    use veil_proto::prekey_bundle::ALGO_ML_KEM_768;

    pub(crate) const NOW: u64 = 1_700_000_000;

    pub(crate) struct Signer {
        sub_sk: SigningKey,
        pub(crate) doc: IdentityDocument,
        ek: Vec<u8>,
    }

    pub(crate) fn signer(seed: u8) -> Signer {
        let master_sk = SigningKey::from_bytes(&[seed; 32]);
        let master_pk = master_sk.verifying_key();
        let node_id = compute_node_id(master_pk.as_bytes());

        let sub_sk = SigningKey::from_bytes(&[seed ^ 0xFF; 32]);
        let sub_pk = sub_sk.verifying_key();
        let device_id = compute_node_id(sub_pk.as_bytes());
        let valid_from = NOW - 60;
        let valid_until = NOW + 3650 * 86_400;

        let cert_msg = certify_message(
            &node_id,
            ALGO_ED25519,
            sub_pk.as_bytes(),
            &device_id,
            valid_from,
            valid_until,
        );
        let identity_key = IdentityKey {
            algo: ALGO_ED25519,
            pubkey: sub_pk.as_bytes().to_vec(),
            device_id,
            valid_from_unix: valid_from,
            valid_until_unix: valid_until,
            master_sig: master_sk.sign(&cert_msg).to_bytes().to_vec(),
        };
        let mut doc = IdentityDocument {
            node_id,
            master_algo: ALGO_ED25519,
            master_pubkey: master_pk.as_bytes().to_vec(),
            issued_at_unix: NOW,
            valid_until_unix: valid_until,
            sig_key_idx: 0,
            identity_keys: vec![identity_key],
            revoked_devices: Vec::new(),
            document_sig: Vec::new(),
        };
        let mut msg = Vec::new();
        msg.extend_from_slice(DOC_SIG_CONTEXT);
        msg.extend_from_slice(&doc.canonical_signing_bytes());
        doc.document_sig = sub_sk.sign(&msg).to_bytes().to_vec();

        let (ek, _dk_seed) = veil_crypto::x3dh::generate_prekey();
        Signer { sub_sk, doc, ek }
    }

    impl Signer {
        pub(crate) fn cert(
            &self,
            instance_id: [u8; 16],
            valid_from: u64,
            valid_until: u64,
            cert_version: u64,
        ) -> MlKemKeyCert {
            let mut cert = MlKemKeyCert {
                node_id: self.doc.node_id,
                instance_id,
                mlkem_algo: ALGO_ML_KEM_768,
                mlkem_pubkey: self.ek.clone(),
                ratchet_x25519_pubkey: [0x5A; 32],
                valid_from_unix: valid_from,
                valid_until_unix: valid_until,
                cert_version,
                signing_identity_key_idx: 0,
                sig: Vec::new(),
            };
            let msg = cert.signing_message();
            cert.sig = self.sub_sk.sign(&msg).to_bytes().to_vec();
            cert
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{NOW, signer};
    use super::*;

    /// The measured case: nothing on the DHT for a device that is off, and a
    /// certificate remembered from when it was on. What decides is the
    /// certificate's OWN 30-day window, so a device off for a day is still
    /// sealable — a full day past the 30-minute RAM TTL that used to be the
    /// only thing holding it.
    #[test]
    fn a_remembered_cert_still_verifies_a_day_after_it_was_stored() {
        let s = signer(0x11);
        let store = MlKemCertStore::ephemeral();
        assert!(store.remember(&s.cert([0xab; 16], NOW, NOW + 30 * 86_400, 1), NOW));
        assert!(
            matches!(
                store.recall(&s.doc.node_id, &[0xab; 16], &s.doc, NOW + 86_400),
                CertRecall::Verified(_)
            ),
            "a day off is far inside the 30-day window the cert was signed for",
        );
    }

    /// Past `valid_until` the answer is not "no key" but "the key I have is out
    /// of its window" — a different situation for whoever is retrying, and the
    /// reason [`CertRecall::Expired`] exists apart from `Absent`.
    #[test]
    fn a_cert_past_its_signed_window_is_expired_not_absent() {
        let s = signer(0x12);
        let store = MlKemCertStore::ephemeral();
        assert!(store.remember(&s.cert([0xab; 16], NOW, NOW + 3600, 1), NOW));
        assert_eq!(
            store.recall(&s.doc.node_id, &[0xab; 16], &s.doc, NOW + 7200),
            CertRecall::Expired {
                valid_until_unix: NOW + 3600
            },
        );
    }

    /// A device never heard from has no key and cannot be sealed for — the
    /// honest answer, and the one the seal path already returns.
    #[test]
    fn an_unknown_device_is_absent() {
        let s = signer(0x13);
        let store = MlKemCertStore::ephemeral();
        assert_eq!(
            store.recall(&s.doc.node_id, &[0x11; 16], &s.doc, NOW),
            CertRecall::Absent,
        );
    }

    /// The file is untrusted input. A row whose signature does not verify under
    /// the document in force — what a REVOKED device's row becomes — is not
    /// served, and is deleted rather than re-tried forever.
    #[test]
    fn a_row_whose_signature_does_not_verify_is_dropped() {
        let mine = signer(0x14);
        let other = signer(0x15);
        let store = MlKemCertStore::ephemeral();
        // Signed by a different identity entirely: same shape, wrong signer.
        assert!(store.remember(&other.cert([0xab; 16], NOW, NOW + 30 * 86_400, 1), NOW));
        assert_eq!(
            store.recall(&other.doc.node_id, &[0xab; 16], &mine.doc, NOW),
            CertRecall::Absent,
            "verified against the WRONG document it must not be served",
        );
        assert!(store.is_empty(), "and must not be kept");
    }

    /// The cap holds, and what goes is the row closest to being useless.
    #[test]
    fn the_store_is_bounded_and_evicts_the_soonest_to_expire() {
        let s = signer(0x16);
        let store = MlKemCertStore::ephemeral();
        // This row expires first, so it is the one the cap must take.
        let doomed = [0u8; 16];
        assert!(store.remember(&s.cert(doomed, NOW, NOW + 86_400, 1), NOW));
        for i in 0..MAX_REMEMBERED_CERTS {
            let mut instance = [0u8; 16];
            instance[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            assert!(store.remember(&s.cert(instance, NOW, NOW + 30 * 86_400, 1), NOW));
        }
        assert_eq!(store.len(), MAX_REMEMBERED_CERTS);
        assert_eq!(
            store.recall(&s.doc.node_id, &doomed, &s.doc, NOW),
            CertRecall::Absent,
            "the soonest-expiring row is the one the cap takes",
        );
    }

    /// The whole point of a file: the certificate is still there after the
    /// process that fetched it is gone.
    /// Two writers, one file, and the OLDER snapshot arriving last.
    ///
    /// Every mutator encodes the whole map under the `rows` lock and writes it
    /// after releasing it, so the order the file sees is not the order the
    /// mutations happened in. A late older snapshot silently undoes the newer
    /// one — and because each snapshot is the entire map, "undoes" means the
    /// row `forget_node` just dropped is back on disk. That is the file
    /// re-serving material the peer has already said it cannot open, which is
    /// the persistent form of the re-wedging loop invalidation exists to break,
    /// and unlike the RAM caches it survives a restart.
    #[test]
    fn a_late_older_snapshot_does_not_resurrect_a_forgotten_row() {
        let s = signer(0x21);
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.toml");
        let store = MlKemCertStore::load(&config, NOW);
        assert!(store.remember(&s.cert([0xab; 16], NOW, NOW + 30 * 86_400, 1), NOW));

        // What a writer that got as far as encoding, then stalled, is holding.
        let stale_generation = store.next_generation();
        let stale_snapshot = encode(&lock!(store.rows).clone());
        assert_eq!(
            stale_snapshot.len(),
            1,
            "the stalled writer still has the row"
        );

        // Meanwhile the peer says it cannot open what we sealed.
        store.forget_node(&s.doc.node_id);
        assert_eq!(store.len(), 0);

        // The stalled writer finally lands.
        store.flush(stale_generation, &stale_snapshot);

        let reborn = MlKemCertStore::load(&config, NOW);
        assert_eq!(
            reborn.len(),
            0,
            "a superseded snapshot must not put the forgotten row back on disk",
        );
    }

    /// The ordering must not turn into "only the first write ever lands": a
    /// newer generation still replaces an older one, which is the ordinary case.
    #[test]
    fn a_newer_snapshot_still_replaces_an_older_one() {
        let s = signer(0x22);
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.toml");
        let store = MlKemCertStore::load(&config, NOW);
        assert!(store.remember(&s.cert([0xab; 16], NOW, NOW + 30 * 86_400, 1), NOW));
        assert_eq!(MlKemCertStore::load(&config, NOW).len(), 1);

        store.forget_node(&s.doc.node_id);
        assert_eq!(
            MlKemCertStore::load(&config, NOW).len(),
            0,
            "the newer snapshot is written, not skipped",
        );
    }

    #[test]
    fn a_restart_keeps_the_remembered_certs() {
        let s = signer(0x17);
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.toml");
        {
            let store = MlKemCertStore::load(&config, NOW);
            assert!(store.remember(&s.cert([0xab; 16], NOW, NOW + 30 * 86_400, 1), NOW));
        }
        let reborn = MlKemCertStore::load(&config, NOW + 86_400);
        assert!(
            matches!(
                reborn.recall(&s.doc.node_id, &[0xab; 16], &s.doc, NOW + 86_400),
                CertRecall::Verified(_)
            ),
            "a fresh process must find what the previous one resolved",
        );
    }

    /// Load drops what it could never serve, so a long-dead file does not come
    /// back as a pile of rows that fail one by one.
    #[test]
    fn load_drops_rows_already_past_their_window() {
        let s = signer(0x18);
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.toml");
        {
            let store = MlKemCertStore::load(&config, NOW);
            assert!(store.remember(&s.cert([0xab; 16], NOW, NOW + 3600, 1), NOW));
        }
        assert!(
            MlKemCertStore::load(&config, NOW + 7200).is_empty(),
            "expired material must not be reloaded",
        );
    }

    /// A peer that just refused what we sealed must not be re-sealed for out of
    /// this file on the next attempt, nor after a restart.
    #[test]
    fn forgetting_a_peer_removes_it_from_disk_too() {
        let s = signer(0x19);
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.toml");
        let store = MlKemCertStore::load(&config, NOW);
        assert!(store.remember(&s.cert([0xab; 16], NOW, NOW + 30 * 86_400, 1), NOW));
        store.forget_node(&s.doc.node_id);
        assert!(store.is_empty());
        assert!(
            MlKemCertStore::load(&config, NOW).is_empty(),
            "the removal must have reached the file, not just the map",
        );
    }

    /// An older republication must not displace the rotation that superseded
    /// it — the same supersede order the DHT walks apply when replicas differ.
    #[test]
    fn an_older_cert_does_not_displace_a_newer_one() {
        let s = signer(0x1a);
        let store = MlKemCertStore::ephemeral();
        assert!(store.remember(&s.cert([0xab; 16], NOW, NOW + 30 * 86_400, 9), NOW));
        assert!(
            !store.remember(&s.cert([0xab; 16], NOW - 86_400, NOW + 29 * 86_400, 8), NOW),
            "version 8 does not beat 9",
        );
        match store.recall(&s.doc.node_id, &[0xab; 16], &s.doc, NOW) {
            CertRecall::Verified(cert) => assert_eq!(cert.cert_version, 9),
            other => panic!("expected the newer cert, got {other:?}"),
        }
    }

    /// Material already outside its window is not worth a disk write.
    #[test]
    fn an_already_expired_cert_is_never_remembered() {
        let s = signer(0x1b);
        let store = MlKemCertStore::ephemeral();
        assert!(!store.remember(&s.cert([0xab; 16], NOW - 7200, NOW - 3600, 1), NOW));
        assert!(store.is_empty());
    }
}
