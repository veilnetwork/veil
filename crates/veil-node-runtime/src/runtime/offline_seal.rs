//! DORMANT runtime entry points for offline (store-and-forward mailbox)
//! delivery: seal a message into a mailbox blob, and open one fetched for us.
//!
//! These compose the reviewed [`veil_identity::mailbox_seal`] core with the
//! runtime's DHT resolution ([`DhtMlKemEkResolver`]) and internal keys. NOTHING
//! wires them into a send or receive path yet — the app-layer orchestration
//! ("no delivery-ack after N + peer offline → put; on connect → fetch → open →
//! deliver → ack", dedup by contentId) is still to build, and these need LIVE
//! validation (the DHT resolution can't be exercised in an in-process unit test)
//! plus a `/code-review ultra` pass before they go live.
//!
//! Key-handling invariant: `mlkem_dk_seed` and the sovereign signing key never
//! leave the runtime — `open` borrows the seed via `as_array()` and the
//! recovered inner plaintext is zeroized inside `open_mailbox_blob`.

use std::sync::Arc;

use rand_core::RngCore;
use veil_identity::mailbox_seal::{self, MailboxSealError};
use veil_proto::ipc::AuthAppDeliver;

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

impl super::NodeRuntime {
    /// A one-shot DHT ML-KEM resolver over our shared runtime components
    /// (mirrors the IPC-server resolver wiring in `service_tasks`).
    fn mlkem_resolver(&self) -> DhtMlKemEkResolver {
        DhtMlKemEkResolver::new(
            Arc::clone(&self.dht),
            Arc::clone(&self.session_tx_registry),
            Arc::clone(&self.dispatcher.pending_recursive),
            *self.identity.local_identity.node_id.as_bytes(),
            Arc::clone(&self.identity.peer_mlkem_keys),
            Arc::clone(&self.logger),
        )
    }

    /// DORMANT. Seal `data` for `recipient_node_id`'s `(app_id, endpoint_id)`
    /// into a mailbox blob: sign an auth-deliver under our sovereign identity,
    /// resolve + verify the recipient's ML-KEM cert over the DHT, fan-out-encrypt
    /// to it, and return the serialized blob to drop at a mailbox relay.
    ///
    /// The caller owns the binding: this signs delivery of `data` to
    /// `(recipient, app_id, endpoint_id)` — the same fields the live onion
    /// `APP_DELIVER_AUTH` path binds.
    pub async fn seal_offline_blob(
        &self,
        recipient_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, OfflineSealError> {
        let sovereign = self
            .identity
            .sovereign_identity
            .as_ref()
            .ok_or(OfflineSealError::NoIdentity)?;
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
        let sender_node_id = *self.identity.local_identity.node_id.as_bytes();
        mailbox_seal::seal_mailbox_blob(&auth, &cert, &sender_node_id, &recipient_node_id)
            .map_err(OfflineSealError::Seal)
    }

    /// DORMANT. Open + verify a mailbox blob fetched for us. Decrypts under our
    /// instance's `dk_seed` (which never leaves the runtime), resolves + verifies
    /// the sender's document, checks the auth-deliver signature + freshness, and
    /// returns the verified [`AuthAppDeliver`] (the caller routes `data` to
    /// `(app_id, endpoint_id)`).
    ///
    /// `our_cert_version` is the version of our currently-published ML-KEM cert —
    /// it must match the published cert whose `dk_seed` we hold. TODO (supervised
    /// pass): source this from the runtime's own cert-publish state rather than
    /// taking it as a parameter.
    pub async fn open_offline_blob(
        &self,
        blob: &[u8],
        sender_node_id: [u8; 32],
        our_cert_version: u64,
    ) -> Result<AuthAppDeliver, OfflineSealError> {
        let sovereign = self
            .identity
            .sovereign_identity
            .as_ref()
            .ok_or(OfflineSealError::NoIdentity)?;
        let our_node_id = *self.identity.local_identity.node_id.as_bytes();
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
            &our_node_id,
            &sender_node_id,
            self.mlkem_dk_seed.as_array(),
            our_cert_version,
            &sender_doc,
            now,
            veil_identity::auth_deliver::DEFAULT_AUTH_DELIVER_FRESHNESS_SECS,
        )
        .map_err(OfflineSealError::Open)
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
