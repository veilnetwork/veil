//! Offline (store-and-forward mailbox) delivery: seal a message into a mailbox
//! blob, and open one fetched for us.
//!
//! The seal/open logic lives on [`RuntimeMailboxCrypto`], a handle holding the
//! cloned `Arc` components it needs. It implements [`veil_ipc::MailboxCryptoSink`]
//! and `service_tasks` installs it on the IPC server, which is how the app layer
//! reaches it — `NodeRuntime` itself can't be `Arc`-wrapped (circular reference)
//! and the IPC server only gets `Arc<dyn>` sinks, so the logic is parameterised
//! over the components rather than over `&NodeRuntime`.
//!
//! This header used to open with "DORMANT" and "NOTHING wires this into a
//! send/receive path yet". Both stopped being true once the sink was installed;
//! two thin `NodeRuntime::{seal,open}_offline_blob` wrappers stayed genuinely
//! uncalled and have been removed rather than kept as evidence for a claim
//! about the whole module. The DHT resolution still cannot be exercised
//! in-process, so that part of the path is covered by live testing, not by the
//! unit tests below.
//!
//! Key-handling invariant: the ML-KEM seeds and the sovereign signing key never
//! leave the runtime — `open` lifts candidates out of the seed ring into a
//! `Zeroizing` buffer that is wiped when the call returns, and the recovered
//! inner plaintext is zeroized inside `open_mailbox_blob`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};

use rand_core::RngCore;
use veil_dht::KademliaService;
use veil_dispatcher::PendingRecursive;
use veil_e2e::PeerMlKemCache;
use veil_identity::mailbox_seal::{self, MailboxSealError};
use veil_identity::mlkem_fanout::VerifiedMlkemCert;
use veil_identity::verify::verify_identity_document;
use veil_observability::NodeLogger;
use veil_proto::ipc::AuthAppDeliver;
use veil_session::SessionTxRegistry;

use crate::mlkem_resolver::{DhtMlKemEkResolver, PeerMlKemCertCache};

/// Auth-deliver freshness window for the OFFLINE (mailbox) open path. Unlike the
/// 300s live-onion window, a stored-and-forwarded message is delivered whenever
/// the recipient next comes online — days later is normal — so the window must
/// span realistic offline gaps. The real staleness bound is the relay's blob
/// retention (an aged-out blob is simply gone); anti-replay is the per-
/// (sender,nonce) replay cache + receiver-side content_id dedup, not freshness.
const MAILBOX_OPEN_FRESHNESS_SECS: u64 = 7 * 86_400;
const LOCAL_MLKEM_CERT_VERSION: u64 = 1;

fn local_verified_cert(
    node_id: [u8; 32],
    instance_id: [u8; 16],
    dk_seed: &[u8; veil_e2e::DK_SEED_BYTES],
) -> Result<VerifiedMlkemCert, OfflineSealError> {
    let (ek, _) = veil_e2e::keypair_from_dk_seed(dk_seed)
        .map_err(|error| OfflineSealError::LocalKey(error.to_string()))?;
    // Our own certificate, rebuilt locally rather than fetched. The ratchet
    // key comes from the same seed by the same derivation the ring publishes,
    // so a self-addressed seal and a peer-addressed one agree.
    let ratchet_sk = veil_crypto::identity::derive_ratchet_x25519_sk(dk_seed);
    let ratchet_x25519_pubkey =
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*ratchet_sk)).as_bytes();
    Ok(VerifiedMlkemCert {
        node_id,
        instance_id,
        mlkem_algo: veil_proto::prekey_bundle::ALGO_ML_KEM_768,
        mlkem_pubkey: ek.to_vec(),
        ratchet_x25519_pubkey,
        cert_version: LOCAL_MLKEM_CERT_VERSION,
    })
}

/// Who a mailbox blob is sealed for.
///
/// Named rather than passed as a bool because the two are not "the same thing
/// with a flag": one addresses somebody else, the other addresses the rest of
/// ourselves, and the second could not be expressed at all until now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxAudience {
    /// The recipient identity's devices. Addressed to our OWN id this means
    /// our own instance -- a normal first-document operation.
    Recipient,
    /// Every OTHER device of our identity, the active one excluded.
    ///
    /// What "carry this to my other device" means, and what had no spelling
    /// before: sealing to our own id produced a copy for ourselves and for
    /// nobody else, so a device group could never deliver anything to the
    /// device it had just linked.
    MyOtherDevices,
}

/// Which of our instances are NOT the one asking.
///
/// Pure, so the rule that decides who a sync reaches is testable without a
/// runtime, a DHT or a second device.
pub(crate) fn other_instances(
    all: Vec<veil_proto::instance_registry::InstanceEntry>,
    active: [u8; 16],
) -> Vec<veil_proto::instance_registry::InstanceEntry> {
    all.into_iter()
        .filter(|entry| entry.instance_id != active)
        .collect()
}

/// Failure of a runtime offline seal/open.
#[derive(Debug, thiserror::Error)]
pub enum OfflineSealError {
    #[error("no sovereign identity loaded")]
    NoIdentity,
    #[error("could not resolve + verify the recipient's ML-KEM cert from the DHT")]
    RecipientCertUnresolved,
    #[error("could not resolve + verify the sender's identity document from the DHT")]
    SenderDocUnresolved,
    #[error("could not derive the local ML-KEM recipient key: {0}")]
    LocalKey(String),
    #[error("seal: {0}")]
    Seal(#[source] MailboxSealError),
    #[error("open: {0}")]
    Open(#[source] MailboxSealError),
}

/// Component handle that owns the seal/open logic. Built from a `NodeRuntime`
/// (which holds all of these) but standalone so it can be the `Arc<dyn>` IPC
/// sink — `NodeRuntime` can't be `Arc`-wrapped (circular reference).
pub struct RuntimeMailboxCrypto {
    dht: Arc<KademliaService>,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    pending_recursive: Arc<Mutex<HashMap<[u8; 16], PendingRecursive>>>,
    local_node_id: [u8; 32],
    peer_mlkem_keys: Arc<RwLock<PeerMlKemCache>>,
    peer_ratchet_keys: Arc<RwLock<veil_e2e::PeerRatchetKeyCache>>,
    peer_mlkem_certs: Arc<RwLock<PeerMlKemCertCache>>,
    /// The CELL, not what it held when this handle was built.
    ///
    /// This sink is installed on the IPC server once and lives as long as the
    /// server does, so a snapshot here freezes whichever document was in force
    /// at that moment. That is exactly the defect the cell exists to prevent —
    /// its own doc comment records the 2026-07-17 production case where a frozen
    /// `Option<Arc<..>>` kept presenting an expired delegation — and it bit
    /// again, differently: a second device merged into the document, the cell
    /// was updated, and every deposit went on being sealed from the pre-merge
    /// copy that named one device. Nothing short of restarting the whole runtime
    /// made a merge visible, and restarting it dropped every client connection.
    sovereign: super::identity_state::SovereignIdentityCell,
    mlkem_keys: Arc<veil_e2e::MlKemSeedRing>,
    logger: Arc<NodeLogger>,
}

impl RuntimeMailboxCrypto {
    /// A one-shot DHT ML-KEM resolver over our shared components (mirrors the
    /// IPC-server resolver wiring in `service_tasks`).
    fn mlkem_resolver(&self) -> DhtMlKemEkResolver {
        DhtMlKemEkResolver::new(
            Arc::clone(&self.dht),
            Arc::clone(&self.session_tx_registry),
            Arc::clone(&self.pending_recursive),
            self.local_node_id,
            Arc::clone(&self.peer_mlkem_keys),
            Arc::clone(&self.peer_ratchet_keys),
            Arc::clone(&self.peer_mlkem_certs),
            Arc::clone(&self.logger),
        )
    }

    /// Seal `data` for `recipient_node_id`'s `(app_id, endpoint_id)` into a
    /// mailbox blob (the caller owns the binding — same fields the live onion
    /// `APP_DELIVER_AUTH` path binds).
    pub async fn seal(
        &self,
        recipient_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, OfflineSealError> {
        self.seal_for(
            MailboxAudience::Recipient,
            recipient_node_id,
            app_id,
            endpoint_id,
            data,
        )
        .await
    }

    /// [`seal`], with the audience said out loud. See [`MailboxAudience`].
    pub async fn seal_for(
        &self,
        audience: MailboxAudience,
        recipient_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, OfflineSealError> {
        // Read per call: a document merged since this handle was built is what
        // decides who "my other devices" are.
        let sovereign = self.sovereign.get().ok_or(OfflineSealError::NoIdentity)?;
        let now = now_unix();
        let nonce = rand_core::OsRng.next_u64();
        let auth = sovereign.sign_auth_deliver(
            recipient_node_id,
            app_id,
            endpoint_id,
            now,
            nonce,
            data.to_vec(),
            Vec::new(),
        );
        // Sealing to ourselves is a normal first-document operation. Never
        // depend on a DHT round-trip for our own certificate: the runtime owns
        // the exact DK seed and sovereign instance binding already.
        let certs: Vec<_> = if audience == MailboxAudience::MyOtherDevices {
            // OUR devices come from the document this runtime already holds,
            // not from a DHT walk about ourselves. Measured on a two-device
            // stand: the registry said instances=2 and resolving our own id
            // through the network still returned nothing, so every deposit was
            // addressed to no one. We know our devices; only their CERTS are
            // theirs to publish.
            let mine = sovereign.active_instance_id();
            let others = other_instances(sovereign.all_instance_entries(), mine);
            if others.is_empty() {
                Vec::new()
            } else {
                self.mlkem_resolver()
                    .certs_for_instances(
                        self.local_node_id,
                        &sovereign.document,
                        &others,
                        now,
                    )
                    .await
            }
        } else if recipient_node_id == self.local_node_id {
            vec![local_verified_cert(
                self.local_node_id,
                sovereign.active_instance_id(),
                &self.mlkem_keys.current_seed(),
            )?]
        } else {
            // EVERY device of the recipient. Sealing to one delivered to
            // whichever instance the registry listed first and silently not to
            // the rest — they stayed online, correctly published, and simply
            // never saw the mail.
            self.mlkem_resolver()
                .fetch_verified_certs(recipient_node_id)
                .await
        };
        if certs.is_empty() {
            return Err(OfflineSealError::RecipientCertUnresolved);
        }
        // Embed our own signed document so an offline recipient can verify us
        // without a DHT resolve (see `open` + `seal_mailbox_blob`).
        //
        // THE SENDER IS THE IDENTITY, NOT THE TRANSPORT KEY. The inner auth
        // already says so (`sign_auth_deliver` writes `document.node_id`), and
        // everything the recipient does with the sidecar's value assumes it:
        // the embedded document is accepted only when `doc.node_id` equals it,
        // the DHT fallback resolves it, and `verify_auth_deliver` compares it
        // against the document again. On a master device the two ids are the
        // same 32 bytes and every check passes by coincidence; on a sibling
        // they differ, the honest embedded document was discarded as forged,
        // the DHT resolve looked where nobody publishes, and every deposit the
        // sibling made failed open as `SenderDocUnresolved` — measured live as
        // the master receiving nothing at all.
        mailbox_seal::seal_mailbox_blob(
            &auth,
            &certs,
            &sovereign.document.node_id,
            &recipient_node_id,
            &sovereign.document,
        )
        .map_err(OfflineSealError::Seal)
    }

    /// Open + verify a mailbox blob fetched for us, decrypting under our
    /// instance's `dk_seed` (never leaves this handle) and verifying the
    /// auth-deliver against the sender's resolved document.
    pub async fn open(
        &self,
        blob: &[u8],
        our_cert_version: u64,
    ) -> Result<AuthAppDeliver, OfflineSealError> {
        let sovereign = self.sovereign.get().ok_or(OfflineSealError::NoIdentity)?;
        let our_instance = sovereign.active_instance_id();
        let now = now_unix();
        // Recover the sender from the blob's sidecar (the anonymous mailbox
        // deposit carries no usable wire sender), then resolve + verify against
        // its document. A forged sidecar yields a wrong id → the main-blob open
        // below fails closed.
        //
        // This is also where the blob's ERA is decided. A relay holds a mailbox
        // blob for a week (`veil_mailbox::DEFAULT_TTL_SECS`), so one deposited
        // before a key rotation is routinely fetched after it — the sidecar is
        // tried against each seed still inside its overlap window, and the seed
        // that opens it is the one the remaining two decrypts must use. Mixing
        // eras across the three would fail in a way that reads like a forged
        // blob rather than a stale key.
        let candidates = self.mlkem_keys.decrypt_seeds(now);
        let mut recovered = None;
        let mut last_err = None;
        for dk_seed in candidates.iter() {
            match mailbox_seal::recover_sender_node_id(
                blob,
                &our_instance,
                &self.local_node_id,
                dk_seed,
                our_cert_version,
            ) {
                Ok(id) => {
                    recovered = Some((id, *dk_seed));
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        // No candidate opened it. Report the LAST failure rather than a synthetic
        // one, so the "wrong EK era" class the module doc calls out stays
        // distinguishable in the log. `last_err` is empty only if the ring held
        // nothing at all, which cannot happen (it always yields the current
        // seed) — but saying so beats inventing a `MailboxSealError` that did
        // not occur.
        let (sender_node_id, dk_seed) = match recovered {
            Some(pair) => pair,
            None => {
                return Err(match last_err {
                    Some(e) => OfflineSealError::Open(e),
                    None => OfflineSealError::LocalKey("seed ring held no candidates".into()),
                });
            }
        };
        // Prefer the sender's OWN document embedded in the blob (v3): it is
        // self-authenticating, so we verify it locally and open with NO DHT
        // round-trip — the reachability proof that lets a NAT'd / cold-routing-
        // table recipient (e.g. a phone whose recursive walk finds 0 contacts)
        // open the message that previously failed `SenderDocUnresolved`. Fall back
        // to a DHT resolve only for a legacy v2 blob, or if the embed is
        // absent/forged (then it fails closed exactly like an unresolved lookup).
        let embedded = mailbox_seal::recover_embedded_sender_doc(
            blob,
            &our_instance,
            &self.local_node_id,
            &sender_node_id,
            &dk_seed,
            our_cert_version,
        )
        .filter(|doc| doc.node_id == sender_node_id && verify_identity_document(doc, now).is_ok());
        let sender_doc = match embedded {
            Some(doc) => doc,
            None => self
                .mlkem_resolver()
                // The blob's sender is an arbitrary third party, not necessarily a
                // connected peer — keep the XOR-closest recursive walk.
                .fetch_verified_document(sender_node_id, None)
                .await
                .ok_or(OfflineSealError::SenderDocUnresolved)?,
        };
        mailbox_seal::open_mailbox_blob(
            blob,
            &our_instance,
            &self.local_node_id,
            &sender_node_id,
            &dk_seed,
            our_cert_version,
            &sender_doc,
            now,
            // OFFLINE freshness: a mailbox message is delivered when the recipient
            // next comes online — possibly days later — so the 300s LIVE-delivery
            // window would reject every legitimate offline message as "stale".
            // Bound it instead by the relay's blob retention (a blob that aged out
            // can't be delivered at all); anti-replay is covered by the per-
            // (sender,nonce) replay cache + receiver-side content_id dedup.
            MAILBOX_OPEN_FRESHNESS_SECS,
        )
        .map_err(OfflineSealError::Open)
    }
}

impl veil_ipc::MailboxCryptoSink for RuntimeMailboxCrypto {
    fn seal_blob<'a>(
        &'a self,
        recipient_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = veil_ipc::MailboxSealOutcome> + Send + 'a>> {
        Box::pin(async move {
            use veil_ipc::MailboxSealOutcome as O;
            // A mailbox blob exists to reach ANOTHER MACHINE. Depositing one on
            // a relay for ourselves would be a round trip to a copy we already
            // hold -- the sender wrote it locally before asking for this. So at
            // this boundary "seal to my own identity" can only mean the rest of
            // my devices, and needs no flag from the caller to say so.
            //
            // The internal `seal` keeps addressing us alone; that path is the
            // first-document operation, which is genuinely about this device.
            let audience = if recipient_node_id == self.local_node_id {
                MailboxAudience::MyOtherDevices
            } else {
                MailboxAudience::Recipient
            };
            match self
                .seal_for(audience, recipient_node_id, app_id, endpoint_id, &data)
                .await
            {
                Ok(blob) => O::Ok(blob),
                Err(OfflineSealError::NoIdentity) => O::NoIdentity,
                Err(OfflineSealError::RecipientCertUnresolved) => O::PeerUnresolved,
                Err(_) => O::Failed,
            }
        })
    }

    fn open_blob<'a>(
        &'a self,
        blob: Vec<u8>,
        our_cert_version: u64,
    ) -> Pin<Box<dyn Future<Output = veil_ipc::MailboxOpenOutcome> + Send + 'a>> {
        Box::pin(async move {
            use veil_ipc::MailboxOpenOutcome as O;
            match self.open(&blob, our_cert_version).await {
                Ok(auth) => O::Ok {
                    sender_node_id: auth.sender_node_id,
                    app_id: auth.app_id,
                    endpoint_id: auth.endpoint_id,
                    data: auth.data,
                },
                Err(OfflineSealError::NoIdentity) => O::NoIdentity,
                Err(OfflineSealError::SenderDocUnresolved) => O::PeerUnresolved,
                Err(e) => {
                    // The IPC surface collapses every open failure into a
                    // generic `Failed`, which made the production loss class
                    // (fresh legitimate blobs failing open after receiver
                    // churn) undiagnosable: NoEnvelopeForInstance (sealed to a
                    // STALE instance/cert from an inconsistent DHT replica),
                    // AeadFailed (wrong EK era) and X3dh decap errors all look
                    // identical to the app. Keep the wire status unchanged,
                    // but log the full error chain — receiver-side, so one
                    // churn repro pins the exact class.
                    log::warn!("mailbox_open failed (detail): {e:?}");
                    O::Failed
                }
            }
        })
    }
}

impl super::NodeRuntime {
    /// Build a [`RuntimeMailboxCrypto`] handle from our shared components. Also
    /// the seam where the IPC server obtains its `Arc<dyn MailboxCryptoSink>`.
    pub(crate) fn mailbox_crypto(&self) -> RuntimeMailboxCrypto {
        RuntimeMailboxCrypto {
            dht: Arc::clone(&self.dht),
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            pending_recursive: Arc::clone(&self.dispatcher.pending_recursive),
            local_node_id: *self.identity.local_identity.node_id.as_bytes(),
            peer_mlkem_keys: Arc::clone(&self.identity.peer_mlkem_keys),
            peer_ratchet_keys: Arc::clone(&self.identity.peer_ratchet_keys),
            peer_mlkem_certs: Arc::clone(&self.identity.peer_mlkem_certs),
            sovereign: self.identity.sovereign_identity.clone(),
            mlkem_keys: Arc::clone(&self.identity.mlkem_keys),
            logger: Arc::clone(&self.logger),
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a `RuntimeMailboxCrypto` over a real standalone identity and an
    /// empty DHT. Every path this test takes is in-process: sealing to OURSELVES
    /// skips the recipient-cert resolve (`local_verified_cert`), and opening a
    /// v3 blob uses the sender document embedded in it. So the DHT is present to
    /// satisfy the type and is never consulted.
    fn crypto_over(
        dir: &std::path::Path,
        ring: Arc<veil_e2e::MlKemSeedRing>,
    ) -> RuntimeMailboxCrypto {
        let seed = veil_util::sensitive_bytes::SensitiveBytesN::<32>::from_bytes([0x5Au8; 32]);
        let now = now_unix();
        veil_identity::sovereign_flow::save_standalone_identity_to_dir(
            dir,
            &seed,
            now - 3600,
            now + 3 * 86_400,
        )
        .expect("persist standalone identity");
        let sov = Arc::new(
            veil_identity::sovereign::SovereignIdentity::load_from_dir(dir)
                .expect("load standalone identity"),
        );
        let local_node_id = *sov.node_id();
        RuntimeMailboxCrypto {
            dht: Arc::new(KademliaService::new(local_node_id)),
            session_tx_registry: Arc::new(RwLock::new(SessionTxRegistry::new())),
            pending_recursive: Arc::new(Mutex::new(HashMap::new())),
            local_node_id,
            peer_mlkem_keys: Arc::new(RwLock::new(PeerMlKemCache::new())),
            peer_ratchet_keys: Arc::new(RwLock::new(veil_e2e::PeerRatchetKeyCache::new())),
            peer_mlkem_certs: Arc::new(RwLock::new(PeerMlKemCertCache::new())),
            sovereign: crate::runtime::identity_state::SovereignIdentityCell::new(Some(sov)),
            mlkem_keys: ring,
            logger: Arc::new(NodeLogger::new_noop()),
        }
    }

    /// The handle follows the identity CELL, not whatever it held when built.
    ///
    /// This sink is installed on the IPC server once, at startup, and the app
    /// reaches every deposit through it. Holding a snapshot meant a document
    /// merged later — the whole of what linking a second device does — was
    /// invisible to sealing for the life of the process: the registry said two
    /// devices and every deposit kept being sealed from the copy that named one.
    ///
    /// Built here over an EMPTY cell so the difference is a plain error rather
    /// than a shape argument: a snapshot is `None` forever, and the same handle
    /// seals successfully the moment the cell is filled.
    #[tokio::test]
    async fn a_document_installed_after_the_handle_is_the_one_it_seals_from() {
        let tmp = tempfile::tempdir().unwrap();
        let (ek, dk) = veil_e2e::generate_keypair();
        let ring = Arc::new(veil_e2e::MlKemSeedRing::new(0, dk, ek));

        let seed = veil_util::sensitive_bytes::SensitiveBytesN::<32>::from_bytes([0x31u8; 32]);
        let now = now_unix();
        veil_identity::sovereign_flow::save_standalone_identity_to_dir(
            tmp.path(),
            &seed,
            now - 3600,
            now + 3 * 86_400,
        )
        .expect("persist standalone identity");
        let sov = Arc::new(
            veil_identity::sovereign::SovereignIdentity::load_from_dir(tmp.path())
                .expect("load standalone identity"),
        );
        let local_node_id = *sov.node_id();

        let cell = crate::runtime::identity_state::SovereignIdentityCell::new(None);
        let crypto = RuntimeMailboxCrypto {
            dht: Arc::new(KademliaService::new(local_node_id)),
            session_tx_registry: Arc::new(RwLock::new(SessionTxRegistry::new())),
            pending_recursive: Arc::new(Mutex::new(HashMap::new())),
            local_node_id,
            peer_mlkem_keys: Arc::new(RwLock::new(PeerMlKemCache::new())),
            peer_ratchet_keys: Arc::new(RwLock::new(veil_e2e::PeerRatchetKeyCache::new())),
            peer_mlkem_certs: Arc::new(RwLock::new(PeerMlKemCertCache::new())),
            sovereign: cell.clone(),
            mlkem_keys: ring,
            logger: Arc::new(NodeLogger::new_noop()),
        };

        assert!(
            matches!(
                crypto.seal(local_node_id, [0x77u8; 32], 9, b"before").await,
                Err(OfflineSealError::NoIdentity)
            ),
            "nothing is installed yet",
        );

        // What a merge does: install a document into the cell the runtime shares.
        cell.set(Arc::clone(&sov));

        crypto
            .seal(local_node_id, [0x77u8; 32], 9, b"after")
            .await
            .expect("the SAME handle must seal from the document now in force");
    }

    /// A mailbox blob sealed BEFORE a key rotation still opens after it.
    ///
    /// The blob's era has to be picked once and then used for all three
    /// decrypts — the sidecar that names the sender, the embedded sender
    /// document, and the main body. Nothing else covers that: using the current
    /// seed for any of them leaves every other test green while, in the field,
    /// a week of store-and-forward mail stops opening the moment a node rotates.
    #[tokio::test]
    async fn a_mailbox_blob_sealed_before_a_rotation_still_opens() {
        let tmp = tempfile::tempdir().unwrap();
        let (old_ek, old_dk) = veil_e2e::generate_keypair();
        let ring = Arc::new(veil_e2e::MlKemSeedRing::new(0, old_dk, old_ek));
        let crypto = crypto_over(tmp.path(), Arc::clone(&ring));

        let app_id = [0x77u8; 32];
        let payload = b"deposited before the rotation";
        let blob = crypto
            .seal(crypto.local_node_id, app_id, 9, payload)
            .await
            .expect("self-seal needs no DHT");

        // Rotate. The blob is now addressed to a key we no longer publish.
        let (new_ek, new_dk) = veil_e2e::generate_keypair();
        let now = now_unix();
        ring.rotate(
            now,
            1,
            new_dk,
            new_ek,
            veil_e2e::MLKEM_SEED_MIN_OVERLAP_SECS,
        )
        .expect("rotation with a full overlap");
        assert_ne!(ring.current_ek(), old_ek, "test premise: the key moved");

        let auth = crypto
            .open(&blob, LOCAL_MLKEM_CERT_VERSION)
            .await
            .expect("a blob sealed to the retired key must still open");
        assert_eq!(auth.data, payload);
        assert_eq!(auth.app_id, app_id);
        assert_eq!(auth.endpoint_id, 9);
    }

    /// A SIBLING's deposit must be openable, and a sibling is exactly a node
    /// whose transport id is NOT its document's node id.
    ///
    /// The seal used to write `local_node_id` into the sidecar while the inner
    /// auth said `document.node_id`. On a master device the two are the same
    /// 32 bytes and every check passes by coincidence. On a sibling they
    /// differ: the recipient recovered the transport id, threw away the
    /// honest embedded document (`doc.node_id` names the identity, not the
    /// transport), resolved the transport id in a DHT where nobody publishes a
    /// document, and failed `SenderDocUnresolved`. Measured live as a master
    /// device with zero inbound messages for a whole session while the
    /// sibling's client logged every deposit as stored.
    #[tokio::test]
    async fn a_blob_sealed_by_a_sibling_transport_key_still_opens() {
        let tmp = tempfile::tempdir().unwrap();
        let (ek, dk) = veil_e2e::generate_keypair();
        let ring = Arc::new(veil_e2e::MlKemSeedRing::new(0, dk, ek));
        let mut crypto = crypto_over(tmp.path(), Arc::clone(&ring));
        // The sibling condition, stated directly: the node runs on a mined
        // transport key, so its wire id is not the identity in its document.
        crypto.local_node_id = [0xD4u8; 32];

        let app_id = [0x42u8; 32];
        let payload = b"a sibling wrote this";
        let blob = crypto
            .seal(crypto.local_node_id, app_id, 3, payload)
            .await
            .expect("self-seal needs no DHT");

        let auth = crypto
            .open(&blob, LOCAL_MLKEM_CERT_VERSION)
            .await
            .expect("the recipient must verify the sender by its embedded document");
        assert_eq!(auth.data, payload);
        // And the author the app sees is the IDENTITY — the value the group
        // layer keys everything by — never the transport key.
        let doc_node_id = crypto.sovereign.get().unwrap().document.node_id;
        assert_eq!(auth.sender_node_id, doc_node_id);
        assert_ne!(auth.sender_node_id, crypto.local_node_id);
    }

    /// Past the overlap the retired seed is gone, and the blob fails CLOSED —
    /// an error, never a partially-verified message.
    #[tokio::test]
    async fn past_the_overlap_the_blob_no_longer_opens() {
        let tmp = tempfile::tempdir().unwrap();
        let (old_ek, old_dk) = veil_e2e::generate_keypair();
        let ring = Arc::new(veil_e2e::MlKemSeedRing::new(0, old_dk, old_ek));
        let crypto = crypto_over(tmp.path(), Arc::clone(&ring));

        let blob = crypto
            .seal(crypto.local_node_id, [0x77u8; 32], 9, b"too old")
            .await
            .expect("self-seal");

        // Rotate far enough in the PAST that the overlap has already lapsed.
        let long_ago = now_unix() - 2 * veil_e2e::MLKEM_SEED_MIN_OVERLAP_SECS;
        let (new_ek, new_dk) = veil_e2e::generate_keypair();
        ring.rotate(
            long_ago,
            1,
            new_dk,
            new_ek,
            veil_e2e::MLKEM_SEED_MIN_OVERLAP_SECS,
        )
        .expect("rotation");

        assert!(
            crypto.open(&blob, LOCAL_MLKEM_CERT_VERSION).await.is_err(),
            "an expired era must fail closed, not open under some other key"
        );
    }

    #[test]
    fn local_recipient_cert_is_derived_without_dht() {
        let node_id = [7; 32];
        let instance_id = [9; 16];
        let seed = [11; veil_e2e::DK_SEED_BYTES];
        let cert = local_verified_cert(node_id, instance_id, &seed).unwrap();

        assert_eq!(cert.node_id, node_id);
        assert_eq!(cert.instance_id, instance_id);
        assert_eq!(cert.cert_version, LOCAL_MLKEM_CERT_VERSION);
        assert_eq!(cert.mlkem_pubkey.len(), veil_e2e::EK_BYTES);
    }
}

#[cfg(test)]
mod audience_tests {
    use super::*;

    fn entry(instance_byte: u8) -> veil_proto::instance_registry::InstanceEntry {
        veil_proto::instance_registry::InstanceEntry {
            instance_id: [instance_byte; 16],
            bound_identity_key_idx: 0,
            label: String::new(),
            last_seen_unix_ms: 0,
        }
    }

    /// The point of the whole exercise: a sync addressed at "my devices"
    /// reaches the others and not the sender.
    #[test]
    fn the_sending_device_is_not_one_of_its_own_recipients() {
        let out = other_instances(vec![entry(0xAA), entry(0xBB), entry(0xCC)], [0xBB; 16]);
        let ids: Vec<_> = out.iter().map(|e| e.instance_id[0]).collect();
        assert_eq!(ids, vec![0xAA, 0xCC]);
    }

    /// A lone device syncing to "my other devices" has none. Empty is the
    /// honest answer -- the caller fails the send rather than depositing a
    /// blob addressed to nobody.
    #[test]
    fn a_lone_device_has_no_other_devices() {
        assert!(other_instances(vec![entry(0x11)], [0x11; 16]).is_empty());
    }

    /// Everyone kept when ours is not in the set: a document that has not
    /// caught up with this instance yet must not silently drop a recipient.
    #[test]
    fn an_unlisted_sender_removes_nobody() {
        assert_eq!(other_instances(vec![entry(1), entry(2)], [0xEE; 16]).len(), 2);
    }
}
