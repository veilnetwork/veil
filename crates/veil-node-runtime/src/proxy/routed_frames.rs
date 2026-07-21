//! E2E-protected relay fallback for proxy application streams.
//!
//! Proxy streams normally use a direct authenticated session. When the chosen
//! exit is not a direct neighbour, [`RoutedFrameBroadcaster`] wraps the raw APP
//! frame in the normal DHT-routed [`DeliveryEnvelope`]. The terminal node feeds
//! the decrypted frame back into the APP dispatcher with the envelope's
//! authenticated original sender, preserving the `(node_id, stream_id)` keys
//! used by APP_OPEN / APP_DATA / APP_RECEIPT / APP_CLOSE.

use std::sync::{Arc, RwLock};

use rand_core::RngCore;
use veil_app::AppMessage;
use veil_dispatcher::{DispatchResult, FrameDispatcher};
use veil_proto::{
    codec::{decode_header, encode_header},
    delivery::DeliveryEnvelope,
    family::{AppMsg, DeliveryMsg, FrameFamily},
    header::{FrameHeader, HEADER_SIZE},
};
use veil_session::{SessionTxRegistry, glue::SessionTxBroadcaster};
use veil_types::FrameBroadcaster;
use veil_util::{rlock, wlock};

/// Internal endpoint carrying an E2E-encrypted raw APP stream frame.
///
/// It is deliberately distinct from `EXIT_PROXY_APP_ID`: every node that may
/// initiate a proxy stream needs to receive routed receipts and return data,
/// even when that node is not itself configured as an exit.
pub const ROUTED_APP_FRAME_APP_ID: [u8; 32] = [0xEF; 32];
pub const ROUTED_APP_FRAME_ENDPOINT_ID: u32 = 0;

/// Maximum time a routed synchronous APP response waits for reverse-route/key
/// discovery. The originating connector has a longer APP_OPEN receipt timeout.
const RESPONSE_RETRY_ATTEMPTS: usize = 50;
const RESPONSE_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
const MAX_PENDING_RESPONSES: usize = 256;

fn build_routed_envelope(
    sender: [u8; 32],
    destination: [u8; 32],
    recipient_ek: &[u8],
    frame: &[u8],
) -> Option<DeliveryEnvelope> {
    let (ciphertext, _ack_key) =
        veil_e2e::encrypt_with_ack(recipient_ek, &sender, &destination, frame).ok()?;
    let encoded_ciphertext = ciphertext.encode();
    let mut payload = Vec::with_capacity(1 + encoded_ciphertext.len());
    payload.push(veil_proto::E2E_MARKER);
    payload.extend_from_slice(&encoded_ciphertext);

    let mut nonce = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let mut content_hash = blake3::Hasher::new();
    content_hash.update(b"veil/proxy-routed-frame/v1");
    content_hash.update(&nonce);
    content_hash.update(&sender);
    content_hash.update(&destination);
    content_hash.update(&payload);

    Some(DeliveryEnvelope {
        recipient: veil_proto::recipient::Recipient::any(destination),
        sender_node_id: sender,
        src_app_id: ROUTED_APP_FRAME_APP_ID,
        app_id: ROUTED_APP_FRAME_APP_ID,
        endpoint_id: ROUTED_APP_FRAME_ENDPOINT_ID,
        content_id: *content_hash.finalize().as_bytes(),
        created_at: veil_util::unix_secs_now_u64(),
        ttl_secs: 30,
        payload,
        trace_id: 0,
        require_ack: false,
    })
}

/// Direct-session broadcaster with an E2E DHT relay fallback.
pub struct RoutedFrameBroadcaster {
    direct: SessionTxBroadcaster,
    dispatcher: Arc<FrameDispatcher>,
}

impl RoutedFrameBroadcaster {
    pub fn new(
        session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
        dispatcher: Arc<FrameDispatcher>,
    ) -> Self {
        Self {
            direct: SessionTxBroadcaster::new(session_tx_registry),
            dispatcher,
        }
    }

    fn signal_route_discovery(&self, destination: [u8; 32], priority: u8) {
        let tx = self
            .dispatcher
            .route_miss_tx
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .as_ref()
            .cloned();
        if let Some(tx) = tx {
            let _ = tx.try_send((destination, priority));
        }
    }

    fn send_routed(&self, destination: &[u8; 32], priority: u8, frame: Vec<u8>) -> bool {
        // This internal transport is intentionally limited to the APP family;
        // it must never become a generic bypass around family-specific relay
        // admission and abuse controls.
        let Ok(header) = decode_header(&frame) else {
            return false;
        };
        if header.family != FrameFamily::App as u8
            || frame.len() != HEADER_SIZE.saturating_add(header.body_len as usize)
        {
            return false;
        }

        // A routed proxy frame is never allowed to fall back to plaintext.
        // Route discovery responses populate this cache with the recipient's
        // signed ML-KEM key; until then the caller retries the APP_OPEN.
        let recipient_ek = rlock!(self.dispatcher.crypto.peer_mlkem_keys)
            .get(destination)
            .map(|(key, _)| key.clone());
        let Some(recipient_ek) = recipient_ek else {
            self.signal_route_discovery(*destination, priority);
            return false;
        };
        let Some(envelope) = build_routed_envelope(
            self.dispatcher.local_node_id,
            *destination,
            &recipient_ek,
            &frame,
        ) else {
            return false;
        };
        let envelope_bytes = envelope.encode();

        let mut hops = rlock!(self.dispatcher.route_cache).lookup_all(destination);
        if hops.is_empty() {
            self.signal_route_discovery(*destination, priority);
            return false;
        }
        // RouteCache normally returns the best path first. Avoid retrying the
        // final peer immediately after the direct send above already failed;
        // cached relay alternatives remain eligible.
        hops.retain(|hop| hop != destination);
        hops.dedup();
        if hops.is_empty() {
            self.signal_route_discovery(*destination, priority);
            return false;
        }
        let suffix_len = 8 + 1; // trace_id + relay_hops
        let body_len = 32 + envelope_bytes.len() + suffix_len;
        let mut routed_header =
            FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
        routed_header.body_len = body_len as u32;

        for hop in hops {
            let mut routed = Vec::with_capacity(HEADER_SIZE + body_len);
            routed.extend_from_slice(&encode_header(&routed_header));
            routed.extend_from_slice(&hop);
            routed.extend_from_slice(&envelope_bytes);
            routed.extend_from_slice(&0u64.to_be_bytes());
            routed.push(0); // locally originated: no relay traversed yet
            if self.direct.send_to(&hop, priority, routed) {
                return true;
            }
            wlock!(self.dispatcher.route_cache).invalidate_hop(destination, &hop);
        }

        self.signal_route_discovery(*destination, priority);
        false
    }
}

impl FrameBroadcaster for RoutedFrameBroadcaster {
    fn send_to(&self, peer_id: &[u8; 32], priority: u8, bytes: Vec<u8>) -> bool {
        if self.direct.send_to(peer_id, priority, bytes.clone()) {
            return true;
        }
        self.send_routed(peer_id, priority, bytes)
    }

    fn send_to_all_with_priority(&self, priority: u8, bytes: Arc<[u8]>) {
        self.direct.send_to_all_with_priority(priority, bytes);
    }

    fn active_node_ids(&self) -> Vec<[u8; 32]> {
        self.direct.active_node_ids()
    }
}

/// Spawn the endpoint that unwraps routed raw APP frames on every node.
pub fn spawn_routed_app_frame_endpoint(
    dispatcher: Arc<FrameDispatcher>,
    app_registry: Arc<veil_app::AppEndpointRegistry>,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    logger: Arc<veil_observability::NodeLogger>,
) -> tokio::task::JoinHandle<()> {
    let (endpoint_handle, mut receiver) =
        app_registry.register(ROUTED_APP_FRAME_APP_ID, ROUTED_APP_FRAME_ENDPOINT_ID, 512);
    let broadcaster = Arc::new(RoutedFrameBroadcaster::new(
        session_tx_registry,
        Arc::clone(&dispatcher),
    ));
    let response_slots = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_RESPONSES));

    tokio::spawn(async move {
        let _endpoint_handle = endpoint_handle;
        while let Some(message) = receiver.recv().await {
            let AppMessage::Deliver {
                src_node_id,
                src_app_id,
                data,
                ..
            } = message
            else {
                continue;
            };
            if src_node_id == [0u8; 32] || src_app_id != ROUTED_APP_FRAME_APP_ID {
                continue;
            }
            let bytes: &[u8] = &data;
            let Ok(header) = decode_header(bytes) else {
                continue;
            };
            if header.family != FrameFamily::App as u8
                || bytes.len() != HEADER_SIZE.saturating_add(header.body_len as usize)
            {
                continue;
            }
            let Ok(message_type) = AppMsg::try_from(header.msg_type) else {
                continue;
            };
            if !matches!(
                message_type,
                AppMsg::AppOpen | AppMsg::AppData | AppMsg::AppClose | AppMsg::AppReceipt
            ) {
                continue;
            }

            let body = &bytes[HEADER_SIZE..];
            match dispatcher.dispatch_app(&header, body, src_node_id.into()) {
                DispatchResult::Response(response) => {
                    let Ok(slot) = Arc::clone(&response_slots).try_acquire_owned() else {
                        logger.warn(
                            "proxy.routed.response_overflow",
                            "too many pending routed APP responses",
                        );
                        continue;
                    };
                    let broadcaster = Arc::clone(&broadcaster);
                    tokio::spawn(async move {
                        let _slot = slot;
                        for _ in 0..RESPONSE_RETRY_ATTEMPTS {
                            if broadcaster.send_to(
                                &src_node_id,
                                veil_proto::header::priority::INTERACTIVE,
                                response.clone(),
                            ) {
                                return;
                            }
                            tokio::time::sleep(RESPONSE_RETRY_INTERVAL).await;
                        }
                    });
                }
                DispatchResult::Violation(reason) => logger.warn(
                    "proxy.routed.app_violation",
                    format!("peer={} {reason}", veil_util::hex_short(&src_node_id)),
                ),
                DispatchResult::RateLimited => logger.warn(
                    "proxy.routed.rate_limited",
                    format!("peer={}", veil_util::hex_short(&src_node_id)),
                ),
                _ => {}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_endpoint_is_distinct_from_exit_endpoint() {
        assert_ne!(ROUTED_APP_FRAME_APP_ID, veil_proxy::EXIT_PROXY_APP_ID);
        let payload = veil_proto::app::AppOpenPayload {
            app_id: veil_proxy::EXIT_PROXY_APP_ID,
            endpoint_id: veil_proxy::EXIT_PROXY_ENDPOINT_ID,
            flags: 0,
        };
        assert!(!payload.encode().is_empty());
    }

    #[test]
    fn routed_proxy_frame_is_e2e_encrypted_and_preserves_sender() {
        let sender = [0x11; 32];
        let destination = [0x22; 32];
        let (recipient_ek, recipient_dk) = veil_e2e::generate_keypair();
        let app_payload = veil_proto::app::AppOpenPayload {
            app_id: veil_proxy::EXIT_PROXY_APP_ID,
            endpoint_id: veil_proxy::EXIT_PROXY_ENDPOINT_ID,
            flags: 0,
        }
        .encode();
        let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppOpen as u16);
        header.body_len = app_payload.len() as u32;
        header.stream_id = 7;
        let mut raw_frame = encode_header(&header).to_vec();
        raw_frame.extend_from_slice(&app_payload);

        let envelope =
            build_routed_envelope(sender, destination, &recipient_ek, &raw_frame).unwrap();
        assert_eq!(envelope.sender_node_id, sender);
        assert_eq!(envelope.recipient_node_id(), destination);
        assert_eq!(envelope.app_id, ROUTED_APP_FRAME_APP_ID);
        assert_eq!(envelope.payload.first(), Some(&veil_proto::E2E_MARKER));
        assert!(
            !envelope
                .payload
                .windows(raw_frame.len())
                .any(|window| window == raw_frame),
            "raw proxy frame must not be visible in the relay envelope"
        );

        let encrypted = veil_proto::E2eEnvelope::decode(&envelope.payload[1..]).unwrap();
        let decrypted =
            veil_e2e::decrypt(&recipient_dk, &sender, &destination, &encrypted).unwrap();
        assert_eq!(decrypted, raw_frame);
    }
}
