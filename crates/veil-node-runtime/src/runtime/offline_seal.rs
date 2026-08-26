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

use crate::mlkem_cert_store::MlKemCertStore;
use crate::mlkem_resolver::{DhtMlKemEkResolver, PeerMlKemCertCache, ResolveStage, ResolvedCerts};

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
        valid_until_unix: u64::MAX,
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

/// The ONE registry row a deposit addressed to `recipient_device_id` — one of
/// our OWN devices, named by its transport id — should be sealed for.
///
/// Sealing to every instance of the identity was the correct semantics when
/// the family shared one box: every device drained the same mailbox, each
/// opened its own envelope, the rest ignored it. The device box ended that —
/// the relay keys the box by the TARGET device id and only that device's
/// signed fetch drains it — so a deposit addressed to one device is opened by
/// exactly that device and the other N−1 envelopes are pure weight. Measured
/// live: an 1800-byte device-group chunk sealed to 30055 bytes with a
/// 5-device family (≈5 ML-KEM certs), which is what forced every family
/// mailbox delivery through the slice path — 6 onion round trips per blob,
/// hours of churn on a backlog.
///
/// The walk is registry row → `bound_identity_key_idx` →
/// `identity_keys[idx].device_id`, and it is entirely local: the recipient is
/// one of us, so both the registry and the document are already in hand.
/// `None` when no row maps (an older row whose key idx points nowhere useful,
/// or an out-of-range idx) and when more than one does (legacy rows all bound
/// to idx 0) — the caller keeps the full identity fan, failing open to
/// correctness rather than picking a device by guess.
///
/// Pure, so the rule that decides who a device-addressed deposit reaches is
/// testable without a runtime, a DHT or a second device.
pub(crate) fn select_own_device_instance(
    entries: &[veil_proto::instance_registry::InstanceEntry],
    identity_keys: &[veil_proto::identity_document::IdentityKey],
    recipient_device_id: &[u8; 32],
) -> Option<veil_proto::instance_registry::InstanceEntry> {
    let mut matches = entries.iter().filter(|entry| {
        identity_keys
            .get(entry.bound_identity_key_idx as usize)
            .is_some_and(|key| key.device_id == *recipient_device_id)
    });
    let first = matches.next()?;
    match matches.next() {
        // Two rows claiming the same device key is ambiguity, not a choice.
        Some(_) => None,
        None => Some(first.clone()),
    }
}

/// Why a seal could find no certificate to encrypt to.
///
/// One error variant used to carry both, and the two want opposite responses.
/// A recipient nobody has ever resolved has no key and will not have one until
/// it publishes; retrying is all that is left. A recipient whose remembered
/// certificates have all run past their SIGNED window was known — it needs only
/// to come online and republish, and the operator can be told which device and
/// how long ago. 45 minutes of live deposits produced the same
/// `mailbox_seal failed: ... PeerUnresolved` line for every attempt and said
/// neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertUnresolved {
    /// Nothing on the DHT and nothing remembered, for any device of the
    /// recipient. `devices` is how many were asked about — `0` means the
    /// recipient is known to have none we can address.
    NothingFound {
        /// How many devices were asked about and answered for by nobody.
        devices: usize,
    },
    /// Every device that could have been sealed for had only a remembered
    /// certificate whose own signed validity window has closed.
    OnlyExpired {
        /// How many devices were in that state.
        devices: usize,
    },
    /// The recipient's identity document never resolved, so its devices were
    /// never enumerated. NOT a statement about certificates: this recipient
    /// may be publishing perfectly and simply be unreachable from here — on
    /// another network, or behind a routing table that has not filled yet.
    DocumentUnresolved,
    /// The document resolved but the registry naming the recipient's devices
    /// did not. Same "we never learned who to ask" class as
    /// [`Self::DocumentUnresolved`], one step further in.
    RegistryUnresolved,
}

impl std::fmt::Display for CertUnresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NothingFound { devices } => write!(
                f,
                "{devices} device(s) of the recipient were asked about and none has a \
                 certificate on the network or one we had stored",
            ),
            Self::DocumentUnresolved => f.write_str(
                "the recipient's identity document did not resolve — its devices were never \
                 enumerated, so this says nothing about its certificates; the recipient may \
                 be unreachable from this node rather than unpublished",
            ),
            Self::RegistryUnresolved => f.write_str(
                "the recipient's identity document resolved but its instance registry did \
                 not — we never learned which devices to ask about",
            ),
            Self::OnlyExpired { devices } => write!(
                f,
                "{devices} device(s) had only a stored certificate past its own signed \
                 validity window — they must come online and republish",
            ),
        }
    }
}

impl ResolvedCerts {
    /// The reason a resolve produced nothing to seal to.
    fn unresolved(&self) -> CertUnresolved {
        // Stage first: a resolve that never enumerated the recipient's devices
        // has no standing to say anything about their certificates, however
        // many or few it counted.
        match self.stage {
            ResolveStage::DocumentUnresolved => return CertUnresolved::DocumentUnresolved,
            ResolveStage::RegistryUnresolved => return CertUnresolved::RegistryUnresolved,
            ResolveStage::Fanned => {}
        }
        if self.expired_devices > 0 {
            CertUnresolved::OnlyExpired {
                devices: self.expired_devices,
            }
        } else {
            CertUnresolved::NothingFound {
                devices: self.unknown_devices,
            }
        }
    }
}

/// Failure of a runtime offline seal/open.
#[derive(Debug, thiserror::Error)]
pub enum OfflineSealError {
    #[error("no sovereign identity loaded")]
    NoIdentity,
    #[error("no usable ML-KEM certificate for the recipient: {0}")]
    RecipientCertUnresolved(CertUnresolved),
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
    /// The same certificates on disk, bounded by each certificate's own signed
    /// validity window. What lets a deposit be sealed for a device that has
    /// been off longer than the RAM cache's TTL.
    peer_mlkem_cert_store: Arc<MlKemCertStore>,
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
            Arc::clone(&self.peer_mlkem_cert_store),
            Arc::clone(&self.logger),
        )
    }

    /// [`Self::seal_for`] with the audience left implicit.
    ///
    /// Test-only, and that is the whole story: once an identity could address
    /// its own devices, every production caller had an audience worth stating
    /// and moved to `seal_for`. Keeping the shorthand compiled into the
    /// library made it dead code the lint had to be told to ignore; keeping it
    /// behind `cfg(test)` says what it is instead.
    #[cfg(test)]
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

    /// Seal `data` for `recipient_node_id`'s `(app_id, endpoint_id)` into a
    /// mailbox blob — the caller owns the binding, the same fields the live
    /// onion `APP_DELIVER_AUTH` path binds — with the audience said out loud.
    /// See [`MailboxAudience`].
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
        // THE CRYPTOGRAPHIC RECIPIENT IS THE IDENTITY whenever the addressee is
        // any device of ours. Everything a recipient's crypto lives under — the
        // registry, the per-instance certs, the fan-out binding the certs are
        // checked against — is keyed by the identity, and the transport id is
        // only the relay's STORAGE key. Sealing with the transport id as the
        // binding failed `NodeIdMismatch` against every honest cert (measured,
        // once the seal error had a voice), and on the master it only ever
        // worked because its transport id IS the identity.
        //
        // The auth's dst uses the same value, because the opener reconstructs
        // dst as the id it opened under — the two must be one choice.
        let identity = sovereign.document.node_id;
        let addressed_to_us = audience == MailboxAudience::MyOtherDevices
            || recipient_node_id == self.local_node_id
            || sovereign
                .document
                .identity_keys
                .iter()
                .any(|key| key.device_id == recipient_node_id);
        let crypto_recipient = if addressed_to_us {
            identity
        } else {
            recipient_node_id
        };
        let auth = sovereign.sign_auth_deliver(
            crypto_recipient,
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
        let resolved: ResolvedCerts = if audience == MailboxAudience::MyOtherDevices {
            // OUR devices come from the document this runtime already holds,
            // not from a DHT walk about ourselves. Measured on a two-device
            // stand: the registry said instances=2 and resolving our own id
            // through the network still returned nothing, so every deposit was
            // addressed to no one. We know our devices; only their CERTS are
            // theirs to publish.
            let mine = sovereign.active_instance_id();
            let others = other_instances(sovereign.all_instance_entries(), mine);
            if others.is_empty() {
                ResolvedCerts::default()
            } else {
                self.mlkem_resolver()
                    .certs_for_instances(self.local_node_id, &sovereign.document, &others, now)
                    .await
            }
        } else if recipient_node_id == self.local_node_id {
            ResolvedCerts::just(local_verified_cert(
                // Under the identity, like the published copy: the fan-out
                // refuses any cert whose node id is not the recipient binding.
                identity,
                sovereign.active_instance_id(),
                &self.mlkem_keys.current_seed(),
            )?)
        } else if addressed_to_us {
            // The recipient is OUR OWN DEVICE, addressed by its transport id.
            // Everything it publishes — instance registry and per-instance
            // certs — lives under the IDENTITY, so a resolve under the
            // transport id walks keys nobody writes. Measured live: the
            // master's every deposit to its sibling failed `mailbox_seal`
            // while the sibling's deposits to the master (whose transport id
            // IS the identity) sailed through, and the asymmetry read as a
            // one-way network fault.
            //
            // Through the REGISTRY, not through instance ids derived from the
            // document: a device's published instance id is the random one its
            // config minted (`cfg::instance`), not `device_id[..16]`, and a
            // first version of this fix derived the latter and resolved
            // nothing.
            //
            // ONE envelope, not the family fan. The fan was the correct
            // semantics when the family shared one box — each device drained
            // it, opened its own envelope and ignored the rest. The device box
            // is drained by exactly the device it is keyed to, so the other
            // N−1 envelopes were pure weight: measured 1800 B → 30055 B at
            // 5 devices, which is what forced every family mailbox delivery
            // through the slice path. See `select_own_device_instance`; when
            // no registry row maps to the addressee, keep the fan — heavier
            // and correct beats lighter and lost.
            match select_own_device_instance(
                &sovereign.all_instance_entries(),
                &sovereign.document.identity_keys,
                &recipient_node_id,
            ) {
                Some(instance) => {
                    log::debug!(
                        "mailbox_seal: single-envelope for own device {} (instance {})",
                        veil_util::hex_short(&recipient_node_id),
                        veil_util::bytes_to_hex(&instance.instance_id[..4]),
                    );
                    self.mlkem_resolver()
                        .certs_for_instances(
                            self.local_node_id,
                            &sovereign.document,
                            std::slice::from_ref(&instance),
                            now,
                        )
                        .await
                }
                None => {
                    log::info!(
                        "mailbox_seal: full identity fan for own device {} (no unique registry row maps to it)",
                        veil_util::hex_short(&recipient_node_id),
                    );
                    self.mlkem_resolver().fetch_verified_certs(identity).await
                }
            }
        } else {
            // EVERY device of the recipient. Sealing to one delivered to
            // whichever instance the registry listed first and silently not to
            // the rest — they stayed online, correctly published, and simply
            // never saw the mail.
            self.mlkem_resolver()
                .fetch_verified_certs(recipient_node_id)
                .await
        };
        if resolved.is_empty() {
            return Err(OfflineSealError::RecipientCertUnresolved(
                resolved.unresolved(),
            ));
        }
        let certs = resolved.certs;
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
            &crypto_recipient,
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
        // Which id this blob was bound TO. Mail for us is bound to the
        // IDENTITY — that is where our certs live and what the seal side now
        // writes — so the identity goes first. The transport id stays as the
        // fallback for blobs sealed before the rule, on a master whose two ids
        // are the same 32 bytes; on a sibling it never matches anything new.
        let identity = sovereign.document.node_id;
        let our_ids: Vec<[u8; 32]> = if identity == self.local_node_id {
            vec![identity]
        } else {
            vec![identity, self.local_node_id]
        };
        let mut recovered = None;
        let mut last_err = None;
        'outer: for our_node_id in our_ids.iter() {
            for dk_seed in candidates.iter() {
                match mailbox_seal::recover_sender_node_id(
                    blob,
                    &our_instance,
                    our_node_id,
                    dk_seed,
                    our_cert_version,
                ) {
                    Ok(id) => {
                        recovered = Some((id, *dk_seed, *our_node_id));
                        break 'outer;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
        }
        // No candidate opened it. Report the LAST failure rather than a synthetic
        // one, so the "wrong EK era" class the module doc calls out stays
        // distinguishable in the log. `last_err` is empty only if the ring held
        // nothing at all, which cannot happen (it always yields the current
        // seed) — but saying so beats inventing a `MailboxSealError` that did
        // not occur.
        let (sender_node_id, dk_seed, our_node_id) = match recovered {
            Some(triple) => triple,
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
            &our_node_id,
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
            &our_node_id,
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
                // The wire status stays `PeerUnresolved` — it is a numbered
                // `MailboxCryptoStatus` the app decodes — but the class goes to
                // the log, because "no certificate at all" and "the stored
                // certificate is past its window" are answered by different
                // things and looked identical for 45 minutes of live retries.
                Err(OfflineSealError::RecipientCertUnresolved(reason)) => {
                    log::warn!(
                        "mailbox_seal: no recipient certificate (recipient={}): {reason}",
                        veil_util::hex_short(&recipient_node_id),
                    );
                    O::PeerUnresolved
                }
                Err(e) => {
                    // Same reasoning as the open path's detail log: the IPC
                    // surface collapses every remaining failure into `Failed`,
                    // and a seal that fails on the SENDER is even quieter than
                    // an open that fails on the receiver — the deposit simply
                    // never leaves, the outbox retries forever, and the log
                    // says a word with no class in it. Cost a live session:
                    // the master's deposits to its sibling failed for hours as
                    // "Failed" while every candidate cause needed this line to
                    // be told apart.
                    log::warn!(
                        "mailbox_seal failed (detail, recipient={}): {e:?}",
                        veil_util::hex_short(&recipient_node_id),
                    );
                    O::Failed
                }
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
            peer_mlkem_cert_store: Arc::clone(&self.identity.peer_mlkem_cert_store),
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

    /// The two failures a seal can have when it has no certificate, told apart.
    ///
    /// A recipient that has run its certificates past their signed window is
    /// waiting to republish; a recipient nothing was ever resolved for is not
    /// coming back on its own. Both used to arrive as one wordless
    /// `PeerUnresolved`, which is what 45 minutes of live retries produced.
    #[test]
    fn the_reason_separates_expired_material_from_none_at_all() {
        assert_eq!(
            ResolvedCerts::default().unresolved(),
            CertUnresolved::NothingFound { devices: 0 },
        );
        assert_eq!(
            ResolvedCerts {
                certs: Vec::new(),
                expired_devices: 2,
                unknown_devices: 1,
                stage: ResolveStage::Fanned,
            }
            .unresolved(),
            CertUnresolved::OnlyExpired { devices: 2 },
            "a device with expired material is the one the operator can act on",
        );
        assert!(
            OfflineSealError::RecipientCertUnresolved(CertUnresolved::OnlyExpired { devices: 2 })
                .to_string()
                .contains("republish"),
            "the error itself must say what has to happen next",
        );
    }

    /// A resolve that never learned who the recipient's devices are must not
    /// answer for them.
    ///
    /// The fan-out needs the identity document, then the instance registry,
    /// then one certificate per device — and only the third step is about
    /// certificates. Every one of the three used to end as the same sentence,
    /// "the recipient has never published a certificate we have seen", which
    /// is a claim about devices whose existence the first two steps never
    /// established. Two live-stand iterations were spent hunting a certificate
    /// problem while the real answer was that the peers in question were on a
    /// different network and their documents were never resolvable from here.
    #[test]
    fn a_resolve_that_never_enumerated_devices_says_so_instead_of_blaming_certificates() {
        for (stage, expected) in [
            (
                ResolveStage::DocumentUnresolved,
                CertUnresolved::DocumentUnresolved,
            ),
            (
                ResolveStage::RegistryUnresolved,
                CertUnresolved::RegistryUnresolved,
            ),
        ] {
            // Device counts deliberately non-zero AND expired-looking: the
            // stage must win, because those counts were never collected about
            // this recipient's real device set.
            let resolved = ResolvedCerts {
                certs: Vec::new(),
                expired_devices: 3,
                unknown_devices: 4,
                stage,
            };
            assert_eq!(
                resolved.unresolved(),
                expected,
                "{stage:?} must not be reported as a certificate verdict",
            );
            let said = OfflineSealError::RecipientCertUnresolved(resolved.unresolved()).to_string();
            assert!(
                !said.contains("never published"),
                "{stage:?} must not accuse the recipient of not publishing: {said}",
            );
        }

        // And the genuine certificate verdict still carries how many devices
        // were actually asked, so "nobody answered for 3 devices" is not the
        // same line as "this recipient has no devices we can address".
        assert_eq!(
            ResolvedCerts {
                certs: Vec::new(),
                expired_devices: 0,
                unknown_devices: 3,
                stage: ResolveStage::Fanned,
            }
            .unresolved(),
            CertUnresolved::NothingFound { devices: 3 },
        );
    }

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
            peer_mlkem_cert_store: Arc::new(MlKemCertStore::ephemeral()),
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
            peer_mlkem_cert_store: Arc::new(MlKemCertStore::ephemeral()),
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

    /// One envelope must be meaningfully lighter than the family fan — the
    /// whole point of `select_own_device_instance`.
    ///
    /// The live measurement behind it: an 1800-byte device-group chunk sealed
    /// to 30055 bytes with a 5-device family, which pushed every family
    /// mailbox delivery over the slice threshold. The bound asserted here is
    /// structural, not a ratio: each dropped device saves at least its
    /// ML-KEM-768 main-blob ciphertext (1088 bytes), so four dropped devices
    /// save at least four of those — however much lighter the rest of the
    /// format ever gets.
    #[test]
    fn one_envelope_is_meaningfully_lighter_than_the_family_fan() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = veil_util::sensitive_bytes::SensitiveBytesN::<32>::from_bytes([0x5Au8; 32]);
        let now = now_unix();
        veil_identity::sovereign_flow::save_standalone_identity_to_dir(
            tmp.path(),
            &seed,
            now - 3600,
            now + 3 * 86_400,
        )
        .expect("persist standalone identity");
        let sov = veil_identity::sovereign::SovereignIdentity::load_from_dir(tmp.path())
            .expect("load standalone identity");
        let identity = sov.document.node_id;

        // Five devices' certs, built locally the way `local_verified_cert`
        // always builds ours — the size comparison needs real envelopes, not
        // a DHT.
        let certs: Vec<_> = (0u8..5)
            .map(|i| {
                local_verified_cert(identity, [i + 1; 16], &[i + 13; veil_e2e::DK_SEED_BYTES])
                    .expect("local cert")
            })
            .collect();
        let auth = sov.sign_auth_deliver(
            identity,
            [0x77u8; 32],
            9,
            now,
            1,
            vec![0xABu8; 1800],
            Vec::new(),
        );
        let single = mailbox_seal::seal_mailbox_blob(
            &auth,
            &certs[..1],
            &identity,
            &identity,
            &sov.document,
        )
        .expect("single-envelope seal");
        let fan =
            mailbox_seal::seal_mailbox_blob(&auth, &certs, &identity, &identity, &sov.document)
                .expect("family-fan seal");
        assert!(
            fan.len() - single.len() >= 4 * 1088,
            "four dropped devices must save at least their four ML-KEM ciphertexts \
             (single={}, fan={})",
            single.len(),
            fan.len(),
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
        assert_eq!(
            other_instances(vec![entry(1), entry(2)], [0xEE; 16]).len(),
            2
        );
    }

    fn entry_bound(
        instance_byte: u8,
        key_idx: u16,
    ) -> veil_proto::instance_registry::InstanceEntry {
        veil_proto::instance_registry::InstanceEntry {
            instance_id: [instance_byte; 16],
            bound_identity_key_idx: key_idx,
            label: String::new(),
            last_seen_unix_ms: 0,
        }
    }

    fn key_for(device_byte: u8) -> veil_proto::identity_document::IdentityKey {
        veil_proto::identity_document::IdentityKey {
            algo: 0,
            pubkey: Vec::new(),
            device_id: [device_byte; 32],
            valid_from_unix: 0,
            valid_until_unix: 0,
            master_sig: Vec::new(),
        }
    }

    /// The point of the diet: a deposit addressed to ONE device seals for
    /// that device's instance alone, not for the family.
    #[test]
    fn a_device_addressed_deposit_picks_that_device_alone() {
        let keys = [key_for(0xA1), key_for(0xB2), key_for(0xC3)];
        let entries = [entry_bound(1, 0), entry_bound(2, 1), entry_bound(3, 2)];
        let picked = select_own_device_instance(&entries, &keys, &[0xB2; 32])
            .expect("the mapped row must be found");
        assert_eq!(picked.instance_id, [2u8; 16]);
    }

    /// A recipient no registry row maps to keeps the full fan — heavier and
    /// correct beats lighter and lost.
    #[test]
    fn a_recipient_no_row_maps_to_keeps_the_full_fan() {
        let keys = [key_for(0xA1)];
        let entries = [entry_bound(1, 0)];
        assert!(select_own_device_instance(&entries, &keys, &[0xEE; 32]).is_none());
    }

    /// An out-of-range key idx (an older row the document has moved past)
    /// maps to nothing rather than to whatever sits at a wrapped index.
    #[test]
    fn an_out_of_range_key_idx_keeps_the_full_fan() {
        let keys = [key_for(0xA1)];
        let entries = [entry_bound(1, 7)];
        assert!(select_own_device_instance(&entries, &keys, &[0xA1; 32]).is_none());
    }

    /// Two rows bound to the same key — the shape legacy registries have,
    /// every row at idx 0 — is ambiguity, and ambiguity keeps the fan.
    #[test]
    fn two_rows_claiming_one_key_keep_the_full_fan() {
        let keys = [key_for(0xA1)];
        let entries = [entry_bound(1, 0), entry_bound(2, 0)];
        assert!(select_own_device_instance(&entries, &keys, &[0xA1; 32]).is_none());
    }
}
