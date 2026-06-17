//! DORMANT runtime entry points for offline (store-and-forward mailbox)
//! delivery: seal a message into a mailbox blob, and open one fetched for us.
//!
//! The seal/open logic lives on [`RuntimeMailboxCrypto`], a handle holding the
//! cloned `Arc` components it needs. `NodeRuntime` exposes thin
//! [`seal_offline_blob`](super::NodeRuntime::seal_offline_blob) /
//! [`open_offline_blob`](super::NodeRuntime::open_offline_blob) wrappers, and
//! `RuntimeMailboxCrypto` ALSO implements [`veil_ipc::MailboxCryptoSink`] so the
//! IPC server can call it — `NodeRuntime` itself can't be `Arc`-wrapped (circular
//! reference) and the IPC server only gets `Arc<dyn>` sinks, so the logic is
//! parameterised over the components rather than over `&NodeRuntime`.
//!
//! NOTHING wires this into a send/receive path yet (the app-layer orchestration
//! and the IPC dispatch are still to build), and the DHT resolution can't be
//! exercised in an in-process unit test, so the live behaviour is UNVALIDATED —
//! needs an integration test on a real node + `/code-review ultra`.
//!
//! Key-handling invariant: `mlkem_dk_seed` and the sovereign signing key never
//! leave the runtime — `open` borrows the seed via `as_array()` and the
//! recovered inner plaintext is zeroized inside `open_mailbox_blob`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};

use rand_core::RngCore;
use veil_dht::KademliaService;
use veil_dispatcher::PendingRecursive;
use veil_e2e::PeerMlKemCache;
use veil_identity::auth_deliver::DEFAULT_AUTH_DELIVER_FRESHNESS_SECS;
use veil_identity::mailbox_seal::{self, MailboxSealError};
use veil_identity::sovereign::SovereignIdentity;
use veil_observability::NodeLogger;
use veil_proto::ipc::AuthAppDeliver;
use veil_session::SessionTxRegistry;

use crate::mlkem_resolver::DhtMlKemEkResolver;

/// Failure of a runtime offline seal/open.
#[derive(Debug, thiserror::Error)]
pub enum OfflineSealError {
    #[error("no sovereign identity loaded")]
    NoIdentity,
    #[error("could not resolve + verify the recipient's ML-KEM cert from the DHT")]
    RecipientCertUnresolved,
    #[error("could not resolve + verify the sender's identity document from the DHT")]
    SenderDocUnresolved,
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
    sovereign: Option<Arc<SovereignIdentity>>,
    mlkem_dk_seed: Arc<veil_util::sensitive_bytes::SensitiveBytesN<{ veil_e2e::DK_SEED_BYTES }>>,
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
        let sovereign = self.sovereign.as_ref().ok_or(OfflineSealError::NoIdentity)?;
        let now = now_unix();
        let nonce = rand_core::OsRng.next_u64();
        let auth = sovereign.sign_auth_deliver(
            recipient_node_id,
            app_id,
            endpoint_id,
            now,
            nonce,
            data.to_vec(),
            None,
        );
        let cert = self
            .mlkem_resolver()
            .fetch_verified_cert(recipient_node_id)
            .await
            .ok_or(OfflineSealError::RecipientCertUnresolved)?;
        mailbox_seal::seal_mailbox_blob(&auth, &cert, &self.local_node_id, &recipient_node_id)
            .map_err(OfflineSealError::Seal)
    }

    /// Open + verify a mailbox blob fetched for us, decrypting under our
    /// instance's `dk_seed` (never leaves this handle) and verifying the
    /// auth-deliver against the sender's resolved document.
    pub async fn open(
        &self,
        blob: &[u8],
        sender_node_id: [u8; 32],
        our_cert_version: u64,
    ) -> Result<AuthAppDeliver, OfflineSealError> {
        let sovereign = self.sovereign.as_ref().ok_or(OfflineSealError::NoIdentity)?;
        let our_instance = sovereign.active_instance_id();
        let now = now_unix();
        let sender_doc = self
            .mlkem_resolver()
            .fetch_verified_document(sender_node_id)
            .await
            .ok_or(OfflineSealError::SenderDocUnresolved)?;
        mailbox_seal::open_mailbox_blob(
            blob,
            &our_instance,
            &self.local_node_id,
            &sender_node_id,
            self.mlkem_dk_seed.as_array(),
            our_cert_version,
            &sender_doc,
            now,
            DEFAULT_AUTH_DELIVER_FRESHNESS_SECS,
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
            match self.seal(recipient_node_id, app_id, endpoint_id, &data).await {
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
        sender_node_id: [u8; 32],
        our_cert_version: u64,
    ) -> Pin<Box<dyn Future<Output = veil_ipc::MailboxOpenOutcome> + Send + 'a>> {
        Box::pin(async move {
            use veil_ipc::MailboxOpenOutcome as O;
            match self.open(&blob, sender_node_id, our_cert_version).await {
                Ok(auth) => O::Ok {
                    app_id: auth.app_id,
                    endpoint_id: auth.endpoint_id,
                    data: auth.data,
                },
                Err(OfflineSealError::NoIdentity) => O::NoIdentity,
                Err(OfflineSealError::SenderDocUnresolved) => O::PeerUnresolved,
                Err(_) => O::Failed,
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
            sovereign: self.identity.sovereign_identity.clone(),
            mlkem_dk_seed: Arc::clone(&self.mlkem_dk_seed),
            logger: Arc::clone(&self.logger),
        }
    }

    /// DORMANT. See [`RuntimeMailboxCrypto::seal`].
    pub async fn seal_offline_blob(
        &self,
        recipient_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, OfflineSealError> {
        self.mailbox_crypto()
            .seal(recipient_node_id, app_id, endpoint_id, data)
            .await
    }

    /// DORMANT. See [`RuntimeMailboxCrypto::open`].
    pub async fn open_offline_blob(
        &self,
        blob: &[u8],
        sender_node_id: [u8; 32],
        our_cert_version: u64,
    ) -> Result<AuthAppDeliver, OfflineSealError> {
        self.mailbox_crypto()
            .open(blob, sender_node_id, our_cert_version)
            .await
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
