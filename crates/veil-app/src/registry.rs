//! Application endpoint registry.
//!
//! The `AppEndpointRegistry` multiplexes incoming application-plane messages
//! to registered local endpoints. Each endpoint is identified by an
//! `(app_id, endpoint_id)` pair and backed by a `tokio::sync::mpsc` channel.
//!
//! # Registration
//!
//! ```ignore
//! let (handle, rx) = registry.register(app_id, endpoint_id);
//! // use rx to receive AppDataPayload / AppSendPayload
//! // drop `handle` to deregister automatically
//! ```
//!
//! # Routing
//!
//! The runtime calls `route_data` or `route_send` when a matching frame
//! arrives from the network. Frames for unknown endpoints are silently
//! dropped (the caller should respond with a `AppClose{reason: REFUSED}` or
//! `AppReceipt{status: NOT_FOUND}` if a reply is warranted).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::sync::mpsc;
use veil_util::lock;

use veil_discovery::{directory::AppEndpointEntry, service::DiscoveryService};
use veil_proto::app::{AppDataPayload, AppRtDataPayload, AppSendPayload};

use crate::AppMetrics;

// ── EndpointKey ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointKey {
    pub app_id: [u8; 32],
    pub endpoint_id: u32,
}

// ── EndpointSender ────────────────────────────────────────────────────────────

/// Messages that an endpoint can receive.
#[derive(Debug)]
pub enum AppMessage {
    Data(AppDataPayload),
    Send(AppSendPayload),
    /// IPC-layer delivery: veil datagram from `src_node_id` destined for
    /// this endpoint. Carries the fully-decoded data без re-encoding.
    /// d: pool-backed для chat_node-style high-throughput IPC.
    Deliver {
        src_node_id: [u8; 32],
        src_app_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: veil_bufpool::PooledShared,
    },
    /// Real-time media frame (loss-tolerant, no window check).
    RtData(AppRtDataPayload),
    /// Epidemic flood broadcast received from the veil.
    EpidemicBroadcast {
        /// Original sender of the broadcast.
        origin: [u8; 32],
        /// Application-level payload.
        payload: Vec<u8>,
    },
    /// Permanent delivery failure: all retransmit attempts for `content_id`
    /// were exhausted without receiving a `DeliveryStatus(DELIVERED)` ACK.
    /// Sent to all endpoints registered under the originating app.
    DeliveryFailed {
        content_id: [u8; 32],
    },
    /// E2E delivery stage notification.
    /// Fired for each confirmed stage of the 5-stage receipt FSM:
    /// Accepted(0), Stored(2), Fetched(6), Delivered(1), AppAcked(7).
    /// Maps directly to `delivery_status::*` constants.
    DeliveryStage {
        content_id: [u8; 32],
        stage: u8,
    },
    /// A stream was opened to this endpoint by a remote/local IPC client.
    StreamOpen {
        stream_id: u32,
        src_node_id: [u8; 32],
        initial_window: u32,
    },
    /// Incoming stream data segment.
    StreamData {
        stream_id: u32,
        data: Vec<u8>,
    },
    /// Stream was closed by the other side.
    StreamClose {
        stream_id: u32,
    },
}

// ── AutoPublisher ─────────────────────────────────────────────────────────────

/// Wires the registry to a `DiscoveryService` so that every `register` call
/// automatically announces the endpoint.
#[derive(Clone)]
struct AutoPublisher {
    local_node_id: [u8; 32],
    discovery: Arc<DiscoveryService>,
    /// Endpoint TTL in seconds from now.
    ttl_secs: u64,
}

impl AutoPublisher {
    fn publish(&self, app_id: [u8; 32], endpoint_id: u32) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let expires_at = now_secs.saturating_add(self.ttl_secs);
        let entry = AppEndpointEntry {
            node_id: self.local_node_id,
            app_id,
            endpoint_id,
            gateway_node_id: None,
            // audit U12: monotonic per (node_id, app_id, endpoint_id) so the
            // directory's anti-rollback guard is meaningful (was hardcoded 0,
            // leaving the guard latent). Wall-clock seconds advance across every
            // republish AND across restarts (a persisted counter would reset on
            // restart); same-second republishes share an epoch, which the
            // strict-`<` guard accepts as a TTL refresh. u32 holds unix-seconds
            // until 2106.
            epoch: now_secs as u32,
            expires_at,
            max_concurrent_streams: 0,
            protocol_version: 0,
            bandwidth_hint_kbps: 0,
        };
        // Best-effort — ignore errors (e.g., role NotAllowed on Leaf).
        let _ = self.discovery.announce_app_endpoint(entry);
    }
}

// ── AppEndpointRegistry ───────────────────────────────────────────────────────

/// In-process demultiplexer for application endpoints.
///
/// Clone-cheap: the inner map is behind an `Arc<Mutex<_>>`.
#[derive(Clone, Default)]
pub struct AppEndpointRegistry {
    inner: Arc<Mutex<RegistryInner>>,
    metrics: Option<std::sync::Arc<dyn AppMetrics>>,
    publisher: Option<Arc<AutoPublisher>>,
}

/// each endpoint registration is
/// stamped with a monotonically-increasing generation counter.
/// `EndpointHandle` records the generation it owns; on drop, the
/// handle removes its slot only if the current generation matches.
/// Without this, a re-register that overwrites the slot with a fresh
/// sender could be silently torn down by the original handle's
/// Drop, leaving the new owner's `register` call permanently orphaned.
type EndpointGen = u64;

#[derive(Debug)]
struct EndpointSlot {
    sender: mpsc::Sender<AppMessage>,
    generation: EndpointGen,
}

#[derive(Debug, Default)]
struct RegistryInner {
    endpoints: HashMap<EndpointKey, EndpointSlot>,
    next_generation: EndpointGen,
}

impl AppEndpointRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a `NodeMetrics` instance so that silent channel drops are counted.
    pub fn with_metrics(mut self, metrics: std::sync::Arc<dyn AppMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Wire in auto-publish so every `register` / `try_register` call
    /// announces the endpoint to the discovery service.
    ///
    /// * `local_node_id` — this node's 32-byte identifier.
    /// * `discovery` — the discovery service to announce to.
    /// * `ttl_secs` — lifetime of the announced record in seconds.
    pub fn with_auto_publish(
        mut self,
        local_node_id: [u8; 32],
        discovery: Arc<DiscoveryService>,
        ttl_secs: u64,
    ) -> Self {
        self.publisher = Some(Arc::new(AutoPublisher {
            local_node_id,
            discovery,
            ttl_secs,
        }));
        self
    }

    /// Register an endpoint, **overwriting** any existing registration.
    ///
    /// Returns an `EndpointHandle` (RAII guard that deregisters on drop) and a
    /// `Receiver` for incoming messages. The `capacity` argument sets the
    /// mpsc channel buffer depth.
    ///
    /// **Warning:** if the key is already occupied, the old sender is replaced.
    /// The old `EndpointHandle::drop` will then remove the *new* sender.
    /// Prefer [`try_register`] for conflict-safe registration.
    pub fn register(
        &self,
        app_id: [u8; 32],
        endpoint_id: u32,
        capacity: usize,
    ) -> (EndpointHandle, mpsc::Receiver<AppMessage>) {
        let (tx, rx) = mpsc::channel(capacity);
        let key = EndpointKey {
            app_id,
            endpoint_id,
        };
        let generation;
        {
            let mut inner = lock!(self.inner);
            // bump the generation
            // counter so this registration is unambiguously identified
            // for the matching `EndpointHandle::drop`. Old handles
            // racing with this re-register will see their generation
            // doesn't match the current slot and skip the removal —
            // closes the race where a delayed Drop tore down the new
            // owner's mailbox.
            inner.next_generation = inner.next_generation.saturating_add(1);
            generation = inner.next_generation;
            if inner.endpoints.contains_key(&key) {
                log::warn!(
                    "app_registry: overwriting existing endpoint app_id={} endpoint_id={} — \
                     prior handle's drop is now safely no-op (generation guard)",
                    veil_util::bytes_to_hex(&app_id[..4]),
                    endpoint_id,
                );
            }
            inner.endpoints.insert(
                key,
                EndpointSlot {
                    sender: tx,
                    generation,
                },
            );
        }
        if let Some(pub_) = &self.publisher {
            pub_.publish(app_id, endpoint_id);
        }
        let handle = EndpointHandle {
            key,
            generation,
            registry: Arc::clone(&self.inner),
        };
        (handle, rx)
    }

    /// Try to register an endpoint.
    ///
    /// Returns `Err` if the key is already occupied by another sender.
    /// Unlike `register`, this is conflict-safe: it never overwrites an
    /// existing live registration.
    #[allow(clippy::result_unit_err)]
    pub fn try_register(
        &self,
        app_id: [u8; 32],
        endpoint_id: u32,
        capacity: usize,
    ) -> Result<(EndpointHandle, mpsc::Receiver<AppMessage>), ()> {
        let key = EndpointKey {
            app_id,
            endpoint_id,
        };
        let generation;
        {
            let mut inner = lock!(self.inner);
            // Check if the slot is occupied and the sender is still alive.
            if let Some(existing) = inner.endpoints.get(&key)
                && !existing.sender.is_closed()
            {
                return Err(());
                // Sender is closed (holder was dropped) — reclaim the slot.
            }
            inner.next_generation = inner.next_generation.saturating_add(1);
            generation = inner.next_generation;
            let (tx, rx) = mpsc::channel(capacity);
            inner.endpoints.insert(
                key,
                EndpointSlot {
                    sender: tx,
                    generation,
                },
            );
            drop(inner);
            if let Some(pub_) = &self.publisher {
                pub_.publish(app_id, endpoint_id);
            }
            let handle = EndpointHandle {
                key,
                generation,
                registry: Arc::clone(&self.inner),
            };
            Ok((handle, rx))
        }
    }

    /// Route an `AppData` frame to the matching endpoint.
    ///
    /// Returns `true` if the endpoint was found and the message was queued.
    pub fn route_data(&self, payload: AppDataPayload) -> bool {
        let key = EndpointKey {
            app_id: payload.app_id,
            endpoint_id: payload.endpoint_id,
        };
        self.send_to(key, AppMessage::Data(payload))
    }

    /// Route an `AppRtData` real-time frame to the matching endpoint.
    ///
    /// Returns `true` if the endpoint was found and the message was queued.
    pub fn route_rt_data(&self, payload: AppRtDataPayload) -> bool {
        let key = EndpointKey {
            app_id: payload.app_id,
            endpoint_id: payload.endpoint_id,
        };
        self.send_to(key, AppMessage::RtData(payload))
    }

    /// Route an `AppSend` datagram to the matching endpoint.
    ///
    /// Returns `true` if the endpoint was found and the message was queued.
    pub fn route_send(&self, payload: AppSendPayload) -> bool {
        let key = EndpointKey {
            app_id: payload.app_id,
            endpoint_id: payload.endpoint_id,
        };
        self.send_to(key, AppMessage::Send(payload))
    }

    /// Route an IPC-layer deliver message to the matching endpoint.
    ///
    /// Used by the IPC data plane when a local or remote app sends a datagram
    /// to an endpoint registered by an IPC client.
    pub fn route_ipc_deliver(
        &self,
        src_node_id: [u8; 32],
        src_app_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: veil_bufpool::PooledShared,
    ) -> bool {
        let key = EndpointKey {
            app_id,
            endpoint_id,
        };
        self.send_to(
            key,
            AppMessage::Deliver {
                src_node_id,
                src_app_id,
                app_id,
                endpoint_id,
                data,
            },
        )
    }

    /// Get a clone of the sender for an endpoint, if it exists and is live.
    ///
    /// Used by `IpcStreamTable` to hold a reference to the acceptor's channel
    /// without going through `route_*` every time.
    pub fn get_sender(
        &self,
        app_id: [u8; 32],
        endpoint_id: u32,
    ) -> Option<mpsc::Sender<AppMessage>> {
        let key = EndpointKey {
            app_id,
            endpoint_id,
        };
        let inner = lock!(self.inner);
        inner
            .endpoints
            .get(&key)
            .filter(|slot| !slot.sender.is_closed())
            .map(|slot| slot.sender.clone())
    }

    fn send_to(&self, key: EndpointKey, msg: AppMessage) -> bool {
        let inner = lock!(self.inner);
        if let Some(slot) = inner.endpoints.get(&key) {
            let tx = &slot.sender;
            match tx.try_send(msg) {
                Ok(()) => true,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    let app_hex = veil_util::bytes_to_hex(&key.app_id);
                    log::warn!(
                        "app_endpoint: channel full — dropping message for app_id={app_hex} endpoint_id={}",
                        key.endpoint_id,
                    );
                    if let Some(m) = &self.metrics {
                        m.inc_app_msg_channel_full();
                    }
                    false
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    let app_hex = veil_util::bytes_to_hex(&key.app_id);
                    log::warn!(
                        "app_endpoint: channel closed — dropping message for app_id={app_hex} endpoint_id={}",
                        key.endpoint_id,
                    );
                    if let Some(m) = &self.metrics {
                        m.inc_app_msg_channel_closed();
                    }
                    false
                }
            }
        } else {
            false
        }
    }

    /// Route an `APP_OPEN` acceptance event to a registered endpoint as
    /// `AppMessage::StreamOpen`.
    ///
    /// Called by the frame dispatcher when a remote peer successfully opens a
    /// stream to this node's app endpoint. The endpoint can then allocate a
    /// bridge and start exchanging stream data.
    pub fn route_stream_open(
        &self,
        app_id: [u8; 32],
        endpoint_id: u32,
        stream_id: u32,
        src_node_id: [u8; 32],
        initial_window: u32,
    ) -> bool {
        let key = EndpointKey {
            app_id,
            endpoint_id,
        };
        self.send_to(
            key,
            AppMessage::StreamOpen {
                stream_id,
                src_node_id,
                initial_window,
            },
        )
    }

    /// Route an `APP_DATA` segment to a registered endpoint as
    /// `AppMessage::StreamData`, preserving the `stream_id` from the frame header.
    pub fn route_stream_data(
        &self,
        app_id: [u8; 32],
        endpoint_id: u32,
        stream_id: u32,
        data: Vec<u8>,
    ) -> bool {
        let key = EndpointKey {
            app_id,
            endpoint_id,
        };
        self.send_to(key, AppMessage::StreamData { stream_id, data })
    }

    /// Route an `APP_CLOSE` event to a registered endpoint as
    /// `AppMessage::StreamClose`.
    pub fn route_stream_close(&self, app_id: [u8; 32], endpoint_id: u32, stream_id: u32) -> bool {
        let key = EndpointKey {
            app_id,
            endpoint_id,
        };
        self.send_to(key, AppMessage::StreamClose { stream_id })
    }

    /// Deliver an epidemic broadcast to **all** registered endpoints.
    ///
    /// Each endpoint receives its own `AppMessage::EpidemicBroadcast` copy.
    /// Silently skips full or closed channels.
    pub fn broadcast_epidemic(&self, origin: [u8; 32], payload: Vec<u8>) {
        let inner = lock!(self.inner);
        for slot in inner.endpoints.values() {
            let _ = slot.sender.try_send(AppMessage::EpidemicBroadcast {
                origin,
                payload: payload.clone(),
            });
        }
    }

    /// Notify all endpoints registered under `src_app_id` that a message failed
    /// to deliver permanently.
    ///
    /// Silently skips full or closed channels — the sender application is
    /// responsible for correlating `content_id` values it owns.
    pub fn route_delivery_failed(&self, src_app_id: [u8; 32], content_id: [u8; 32]) {
        let inner = lock!(self.inner);
        for (key, slot) in &inner.endpoints {
            if key.app_id == src_app_id {
                let _ = slot
                    .sender
                    .try_send(AppMessage::DeliveryFailed { content_id });
            }
        }
    }

    /// Notify all endpoints registered under `src_app_id` of a delivery stage
    /// transition.
    ///
    /// `stage` is one of the `delivery_status::*` constants that participate
    /// in the E2E receipt FSM: ACCEPTED, QUEUED (Stored), FETCHED, DELIVERED
    /// APP_ACKED. Silently skips full or closed channels.
    pub fn route_delivery_stage(&self, src_app_id: [u8; 32], content_id: [u8; 32], stage: u8) {
        let inner = lock!(self.inner);
        for (key, slot) in &inner.endpoints {
            if key.app_id == src_app_id {
                let _ = slot
                    .sender
                    .try_send(AppMessage::DeliveryStage { content_id, stage });
            }
        }
    }

    /// Number of currently registered endpoints.
    pub fn len(&self) -> usize {
        lock!(self.inner).endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── EndpointHandle ────────────────────────────────────────────────────────────

/// RAII guard that deregisters an endpoint when dropped.
#[derive(Debug)]
pub struct EndpointHandle {
    key: EndpointKey,
    /// generation this handle owns.
    /// `Drop` only removes the slot if it's still on this generation —
    /// a re-register that bumped the gen is left untouched.
    generation: EndpointGen,
    registry: Arc<Mutex<RegistryInner>>,
}

impl EndpointHandle {
    /// Returns the key identifying this endpoint.
    pub fn key(&self) -> EndpointKey {
        self.key
    }
}

impl Drop for EndpointHandle {
    fn drop(&mut self) {
        let mut inner = lock!(self.registry);
        // remove only if our gen still matches.
        // If a `register` call has bumped the slot to a fresh gen, our Drop
        // would otherwise tear down an unrelated owner's mailbox.
        if let Some(slot) = inner.endpoints.get(&self.key)
            && slot.generation == self.generation
        {
            inner.endpoints.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::app::{AppDataPayload, AppSendPayload};

    fn sample_app_id() -> [u8; 32] {
        [0x55u8; 32]
    }

    #[test]
    fn register_and_route_data() {
        let registry = AppEndpointRegistry::new();
        let app_id = sample_app_id();
        let (_handle, mut rx) = registry.register(app_id, 1, 8);

        let payload = AppDataPayload {
            app_id,
            endpoint_id: 1,
            seq: 1,
            data: b"hello".to_vec(),
        };
        let routed = registry.route_data(payload.clone());
        assert!(routed);

        let msg = rx.try_recv().expect("message should be available");
        if let AppMessage::Data(received) = msg {
            assert_eq!(received, payload);
        } else {
            panic!("expected AppMessage::Data");
        }
    }

    #[test]
    fn route_to_unknown_endpoint_returns_false() {
        let registry = AppEndpointRegistry::new();
        let payload = AppDataPayload {
            app_id: sample_app_id(),
            endpoint_id: 99,
            seq: 0,
            data: vec![],
        };
        assert!(!registry.route_data(payload));
    }

    #[test]
    fn deregister_on_handle_drop() {
        let registry = AppEndpointRegistry::new();
        let (handle, _rx) = registry.register(sample_app_id(), 2, 4);
        assert_eq!(registry.len(), 1);
        drop(handle);
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn two_endpoints_receive_independently() {
        let registry = AppEndpointRegistry::new();
        let app_id = sample_app_id();
        let (_h1, mut rx1) = registry.register(app_id, 1, 4);
        let (_h2, mut rx2) = registry.register(app_id, 2, 4);

        registry.route_data(AppDataPayload {
            app_id,
            endpoint_id: 1,
            seq: 0,
            data: b"ep1".to_vec(),
        });
        registry.route_data(AppDataPayload {
            app_id,
            endpoint_id: 2,
            seq: 0,
            data: b"ep2".to_vec(),
        });

        if let AppMessage::Data(d) = rx1.try_recv().unwrap() {
            assert_eq!(d.data, b"ep1");
        } else {
            panic!();
        }

        if let AppMessage::Data(d) = rx2.try_recv().unwrap() {
            assert_eq!(d.data, b"ep2");
        } else {
            panic!();
        }
    }

    #[test]
    fn route_send_delivers_datagram() {
        let registry = AppEndpointRegistry::new();
        let app_id = sample_app_id();
        let (_h, mut rx) = registry.register(app_id, 3, 4);

        let payload = AppSendPayload {
            src_app_id: [0u8; 32],
            app_id,
            endpoint_id: 3,
            data: veil_bufpool::pooled_shared_from_vec(b"datagram".to_vec()),
        };
        assert!(registry.route_send(payload.clone()));

        if let AppMessage::Send(received) = rx.try_recv().unwrap() {
            assert_eq!(received, payload);
        } else {
            panic!("expected AppMessage::Send");
        }
    }

    #[test]
    fn no_messages_for_wrong_app_id() {
        let registry = AppEndpointRegistry::new();
        let (_h, mut rx) = registry.register([0xAAu8; 32], 1, 4);

        // Route to a different app_id
        registry.route_data(AppDataPayload {
            app_id: [0xBBu8; 32],
            endpoint_id: 1,
            seq: 0,
            data: vec![],
        });

        assert!(
            rx.try_recv().is_err(),
            "should not receive message for different app_id"
        );
    }
}
