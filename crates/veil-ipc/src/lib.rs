//! Veil IPC server.
//!
//! extraction: lifted out of `veilcore::node::ipc` into its
//! own Tier-3 crate. Two trait surfaces let the server stay free of
//! veilcore concretes:
//!
//! [`IpcMetrics`] — two metric counters used by the frame-delivery
//! path ([`IpcMetrics::inc_ipc_delivery_drops`] for backpressure-drop
//! accounting, [`IpcMetrics::inc_rt_frames_tx`] for the
//! `STREAM_RT_DATA` outbound counter). Production runtime supplies
//! the impl via `veil-observability::NodeMetrics`.
//!
//! [`IpcConfigErrorSink`] — collapses the `cfg::ConfigError` wrapping
//! that the production runtime expects into a plain `String` so the
//! IPC layer doesn't need to know about veilcore's error tree.
//! The runtime adapter wraps the strings in the canonical
//! `NodeError::Config(ConfigError::ValidationFailed(...))` envelope.
//!
//! All other previously-veilcore types come from already-extracted
//! Tier-3 crates: `RouteCache` (veil-routing), `PeerMlKemCache`
//! (veil-e2e), `AnycastService` (veil-anycast)
//! `TransportHintRegistry` (veil-transport), `PendingAckTracker`
//! (veil-pending-ack), `PendingRecursive` / `CaptureEvent`
//! (veil-dispatcher-state), `AppEndpointRegistry` / `AppMessage`
//! (veil-app), `RateLimiter` (veil-abuse), `FrameBroadcaster`
//! (veil-types).

pub mod bridge;
mod frame_io;
mod handlers;
pub mod path;
pub mod server;
pub mod streams;
pub mod transport;

pub use path::IpcEndpoint;
pub use server::IpcServer;
pub use streams::IpcStreamTable;

// ── Metrics surface ──────────────────────────────────────────────────────────

/// Subset of `NodeMetrics` that the IPC server actually calls. Production
/// runtime implements this for `Arc<NodeMetrics>` over in
/// `veil-observability`; tests use an in-process `NoopMetrics` shim.
pub trait IpcMetrics: Send + Sync {
    /// Bump the IPC-frame-delivery drop counter on backpressure.
    fn inc_ipc_delivery_drops(&self);
    /// Bump the realtime-frames-transmitted counter.
    fn inc_rt_frames_tx(&self);
}

/// Helper impl: `Arc<T>` proxies to `T` if `T` impls `IpcMetrics`. This
/// avoids an extra `Deref` call inside hot paths that already hold `Arc`s.
impl<T: IpcMetrics + ?Sized> IpcMetrics for std::sync::Arc<T> {
    fn inc_ipc_delivery_drops(&self) {
        (**self).inc_ipc_delivery_drops()
    }
    fn inc_rt_frames_tx(&self) {
        (**self).inc_rt_frames_tx()
    }
}

// ── Mobile event sink ──────────────────────────────────

/// Hook the IPC server calls when an app delivers a mobile-lifecycle
/// event (background-mode toggle, network-state change). Implemented by
/// the veil runtime over in `veilcore`; tests use a noop or recording
/// shim.
///
/// Both methods run on the IPC dispatch task, which is on the daemon's
/// tokio runtime. Implementations must avoid blocking — the typical
/// pattern is `&self` against shared atomics + a `Notify` to wake any
/// reactive subsystems (reconnect loop, session runners).
pub trait MobileEventSink: Send + Sync {
    /// App reports a background-mode tier change.
    /// Daemon scales keepalive cadence accordingly.
    fn set_mobile_background_mode(&self, mode: veil_proto::MobileBackgroundMode);

    /// App reports a network-state change.
    /// Daemon eagerly tears down stale sessions and reconnects via
    /// bootstrap so user-visible reconnect latency drops from
    /// keepalive-timeout (~30 s) to sub-second.
    fn network_changed(&self, payload: veil_proto::NetworkChangedPayload);
}

/// `Arc<T>` proxy [`MobileEventSink`].
impl<T: MobileEventSink + ?Sized> MobileEventSink for std::sync::Arc<T> {
    fn set_mobile_background_mode(&self, mode: veil_proto::MobileBackgroundMode) {
        (**self).set_mobile_background_mode(mode)
    }
    fn network_changed(&self, payload: veil_proto::NetworkChangedPayload) {
        (**self).network_changed(payload)
    }
}

// ── Push-envelope sink ──────────────────────

/// Hook the IPC server calls when an app sends `LocalAppMsg::SetPushEnvelope`.
/// Implemented by the veil runtime, routes to
/// `NodeRuntime::set_rendezvous_push_envelope` so the next maintenance tick
/// re-signs every active rendezvous-ad with the new envelope (or clears it
/// when `envelope.is_empty`).
///
/// Returns the matching-rendezvous outcome — the IPC handler maps it to the
/// `SetPushEnvelopeStatus` wire byte.
pub trait PushEnvelopeSink: Send + Sync {
    /// Update the sealed push envelope (FCM/APNs token sealed to
    /// the chosen push-relay) on a rendezvous-publisher entry matched
    /// by `(rendezvous_node_id, auth_cookie)`. Returns `true` if a
    /// matching entry was found and updated; `false` if no such entry.
    fn set_rendezvous_push_envelope(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        envelope: Vec<u8>,
    ) -> bool;

    /// Epic 489.10 slice 4.3.4 — update the sealed wake-HMAC envelope
    /// on the same rendezvous-publisher entry (matched the same way).
    /// Returns `true` if a matching entry was found and updated.
    ///
    /// Default-impl returns `false` so existing implementors compile
    /// without changes; the trait's name dates from when push was the only
    /// rendezvous-bound envelope.  Real impls (production
    /// `NodeRuntime`) override.
    fn set_rendezvous_wake_hmac_envelope(
        &self,
        _rendezvous_node_id: [u8; 32],
        _auth_cookie: [u8; 16],
        _envelope: Vec<u8>,
    ) -> bool {
        false
    }
}

impl<T: PushEnvelopeSink + ?Sized> PushEnvelopeSink for std::sync::Arc<T> {
    fn set_rendezvous_push_envelope(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        envelope: Vec<u8>,
    ) -> bool {
        (**self).set_rendezvous_push_envelope(rendezvous_node_id, auth_cookie, envelope)
    }

    fn set_rendezvous_wake_hmac_envelope(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        envelope: Vec<u8>,
    ) -> bool {
        (**self).set_rendezvous_wake_hmac_envelope(rendezvous_node_id, auth_cookie, envelope)
    }
}

// ── Mailbox backend ─────────────────────

/// One blob the mailbox returns to the IPC layer. Mirrors
/// `veil_mailbox::MailboxBlob` without forcing the IPC crate to
/// depend on `veil-mailbox`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxBlobOut {
    /// 32-byte sender node id (set by depositor at put-time).
    pub sender_id: [u8; 32],
    /// 32-byte content id.
    pub content_id: [u8; 32],
    /// Unix-seconds when the blob was deposited.
    pub deposited_at: u64,
    /// Encrypted blob bytes.
    pub blob: Vec<u8>,
}

/// Outcome of a mailbox put. Mirrors `veil_mailbox::PutOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxPutOutcome {
    /// Blob persisted; `evicted` is the count of older blobs evicted to fit.
    Stored {
        /// Number of older blobs evicted.
        evicted: u32,
    },
    /// Same `(receiver, content_id)` already present. Original preserved.
    Duplicate,
    /// Per-receiver quota would have been exceeded.
    QuotaPerReceiverExceeded,
    /// Blob alone exceeds the global cap.
    QuotaGlobalExceeded,
    /// Sender exceeded the per-receiver rate limit.
    RateLimited,
    /// relay configured with
    /// `require_capability_token = true` rejected a PUT that arrived
    /// without a capability token. IPC clients that surface this to the
    /// app layer should prompt the user to re-fetch the receiver's
    /// `RendezvousAd`.
    CapabilityRequired,
    /// capability token decode or verify
    /// failed (expired, wrong receiver, or bad signature).
    CapabilityInvalid,
    /// per-sender byte cap would be exceeded.
    /// Sender_id is the BLAKE3 of the sender's identity pubkey, so this
    /// gates abuse spread across many receiver targets.
    QuotaPerSenderExceeded,
}

/// Hook the IPC server calls for mailbox operations
/// ([`crate::server::IpcServer::with_mailbox_backend`]). Implemented
/// by the veil runtime, which routes to a wrapped
/// [`veil_mailbox::Mailbox`] after verifying that the caller's
/// `auth_cookie` (for `fetch`/`ack`) matches one of the receiver's
/// registered rendezvous-publisher entries.
///
/// Methods run synchronously on the IPC dispatch task — implementations
/// must avoid blocking. The redb backend in `veil-mailbox` does
/// brief disk I/O per call (~1 ms typical); higher latency would require
/// an internal queue + tokio task.
pub trait MailboxBackend: Send + Sync {
    /// Deposit `blob` for `receiver_id` from `sender_id`. No
    /// authentication — the per-receiver quota and rate limit gate
    /// the call. Returns `None` if the daemon does not have a
    /// mailbox configured (operator did not opt).
    ///
    /// `push_envelope` is the sealed FCM/APNs token (sender obtained
    /// it from receiver's `RendezvousAd` in DHT). When present and
    /// the put resulted in `Stored`, the runtime fires a wake-push
    /// to the receiver after this call returns (fire-and-forget; the
    /// outcome here reports only the storage status). `None` (or
    /// empty) skips the push trigger — useful for receivers without
    /// a registered push token (e.g. desktop clients).
    ///
    /// `capability_token` (audit U14) carries the optional receiver-issued
    /// mailbox capability token from `MailboxPutPayload`. The implementation
    /// MUST route it to `put_with_capability` so the relay's
    /// `require_capability_token` policy is honored on the IPC path; previously
    /// this field was dropped at the backend boundary, so an IPC client could
    /// neither satisfy nor was gated by that policy.
    ///
    /// `wake_hmac_envelope` (Epic 489.10 slice 4.4) is the sealed `WakeHmacKey`
    /// envelope the sender copied from the receiver's `RendezvousAd`. When the
    /// put results in `Stored` and a push fires, the runtime unseals it with the
    /// relay's X25519 sk and mints an authenticated wake payload bound to
    /// `content_id` + `receiver_id`; `None`/empty falls back to the legacy
    /// wake-only push.
    // The 7 data args mirror the wire `MailboxPutPayload` 1:1 (identity +
    // blob + the three sealed trailers); a params struct would just shuffle
    // the same fields, so allow the arity here.
    #[allow(clippy::too_many_arguments)]
    fn put(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        sender_id: [u8; 32],
        blob: Vec<u8>,
        push_envelope: Option<Vec<u8>>,
        capability_token: Option<Vec<u8>>,
        wake_hmac_envelope: Option<Vec<u8>>,
    ) -> Option<MailboxPutOutcome>;

    /// Fetch all currently-stored blobs for `receiver_id`, oldest
    /// first. `auth_cookie` must match one of the receiver's
    /// registered rendezvous-publisher entries; mismatch returns an
    /// empty list (no distinction from "no blobs", to avoid being a
    /// probing oracle). Returns `None` if no mailbox configured.
    fn fetch(&self, receiver_id: [u8; 32], auth_cookie: [u8; 16]) -> Option<Vec<MailboxBlobOut>>;

    /// Acknowledge receipt of one blob, deleting it from the mailbox.
    /// Idempotent (repeat ack returns `Some(false)`). `auth_cookie`
    /// is verified the same way as [`Self::fetch`]. Returns
    /// `None` if no mailbox configured.
    fn ack(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        auth_cookie: [u8; 16],
    ) -> Option<bool>;
}

impl<T: MailboxBackend + ?Sized> MailboxBackend for std::sync::Arc<T> {
    #[allow(clippy::too_many_arguments)]
    fn put(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        sender_id: [u8; 32],
        blob: Vec<u8>,
        push_envelope: Option<Vec<u8>>,
        capability_token: Option<Vec<u8>>,
        wake_hmac_envelope: Option<Vec<u8>>,
    ) -> Option<MailboxPutOutcome> {
        (**self).put(
            receiver_id,
            content_id,
            sender_id,
            blob,
            push_envelope,
            capability_token,
            wake_hmac_envelope,
        )
    }
    fn fetch(&self, receiver_id: [u8; 32], auth_cookie: [u8; 16]) -> Option<Vec<MailboxBlobOut>> {
        (**self).fetch(receiver_id, auth_cookie)
    }
    fn ack(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        auth_cookie: [u8; 16],
    ) -> Option<bool> {
        (**self).ack(receiver_id, content_id, auth_cookie)
    }
}

// ── Outbox backend ──────────────────────

/// One outbox entry the IPC layer ferries between app and runtime.
/// Mirrors `veil_mailbox::OutboxEntry` minus the receiver_id (the
/// IPC message already carries it explicitly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntryOut {
    /// Content id (caller-chosen).
    pub content_id: [u8; 32],
    /// Unix-seconds deposit timestamp.
    pub deposited_at: u64,
    /// Encrypted payload bytes.
    pub blob: Vec<u8>,
}

/// Hook the IPC server calls for sender-side outbox operations.
/// Implemented by the veil runtime, which routes to a wrapped
/// `veil_mailbox::Outbox`.
///
/// All methods run synchronously on the IPC dispatch task —
/// implementations must avoid blocking. redb writes are ~1 ms
/// typical.
pub trait OutboxBackend: Send + Sync {
    /// Record a freshly-sent message. `Ok(true)` means stored;
    /// `Ok(false)` means the runtime has no outbox configured
    /// (`mailbox.enabled` off).
    fn put(&self, receiver_id: [u8; 32], content_id: [u8; 32], blob: Vec<u8>) -> bool;

    /// Find entries for `receiver_id` deposited at-or-after `since`
    /// not in `bloom_bytes` (encoded `BloomFilter`). Returns `None`
    /// if no outbox or if the bloom failed to decode (caller can't
    /// tell — same as "no missing entries").
    fn find_missing(
        &self,
        receiver_id: [u8; 32],
        since: u64,
        bloom_bytes: Vec<u8>,
    ) -> Option<Vec<OutboxEntryOut>>;

    /// Drop one entry after end-to-end ack. `true` = removed
    /// `false` = not present (or no outbox).
    fn ack(&self, receiver_id: [u8; 32], content_id: [u8; 32]) -> bool;
}

impl<T: OutboxBackend + ?Sized> OutboxBackend for std::sync::Arc<T> {
    fn put(&self, receiver_id: [u8; 32], content_id: [u8; 32], blob: Vec<u8>) -> bool {
        (**self).put(receiver_id, content_id, blob)
    }
    fn find_missing(
        &self,
        receiver_id: [u8; 32],
        since: u64,
        bloom_bytes: Vec<u8>,
    ) -> Option<Vec<OutboxEntryOut>> {
        (**self).find_missing(receiver_id, since, bloom_bytes)
    }
    fn ack(&self, receiver_id: [u8; 32], content_id: [u8; 32]) -> bool {
        (**self).ack(receiver_id, content_id)
    }
}

// ── Rendezvous replica resolver ────────

/// One verified replica candidate returned by [`RendezvousReplicaResolver`].
/// Mirrors `veil_proto::ReplicaWire` minus the wire encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedReplica {
    /// Relay's `node_id` — sender targets this for `MailboxPut`.
    pub relay_node_id: [u8; 32],
    /// Unix-seconds when the rendezvous publication expires.
    pub valid_until_unix: u64,
    /// Sealed FCM/APNs envelope to attach to the put (may be empty).
    pub push_envelope: Vec<u8>,
    /// receiver-signed mailbox capability
    /// token bytes pulled from the resolved RendezvousAd. Senders include
    /// these in `MailboxPutPayload.capability_token` if the relay
    /// enforces `require_capability_token = true`. Empty when the
    /// receiver did not mint a token (legacy receivers / hybrid identities).
    pub capability_token: Vec<u8>,
    /// Sealed `WakeHmacKey` envelope (Epic 489.10 slice 4.4) copied verbatim
    /// from the resolved `RendezvousAd.wake_hmac_envelope`. Senders forward it
    /// in `MailboxPutPayload.wake_hmac_envelope` so the relay can mint an
    /// authenticated wake payload. Empty when the receiver did not register for
    /// wake-HMAC (defaults to empty for backward compat).
    pub wake_hmac_envelope: Vec<u8>,
    /// KEM algorithm tag for [`Self::rendezvous_kem_pk`] (v5 ad). `0` = X25519.
    pub rendezvous_kem_algo: u8,
    /// The relay's KEM public key from the resolved v5 `RendezvousAd` — the
    /// seal target a sender uses to anonymously deliver a `MailboxPut` to this
    /// relay (`send_anonymous` to `(relay_node_id, MAILBOX_APP_ID, PUT)`).
    /// Empty when the ad is pre-v5 or the receiver advertised no relay key
    /// (sender then falls back to the live rendezvous path).
    pub rendezvous_kem_pk: Vec<u8>,
}

/// Hook the IPC server calls when an app issues
/// `LocalAppMsg::LookupRendezvousReplicas`. Implemented by the
/// veil runtime: looks up the receiver's RendezvousAd in the DHT
/// (local cache + recursive query), verifies signature + freshness
/// and returns up to `max_replicas` candidate relays the sender can
/// fan-out mailbox puts to.
///
/// Today the resolver returns at most 1 entry (single-key
/// publication). When K=3 multi-key publication ships, the same
/// trait fills `Vec` with all K entries — no API break.
///
/// Methods are async because DHT lookup may need a network round-trip;
/// trait uses a boxed future to keep the abstraction object-safe.
pub trait RendezvousReplicaResolver: Send + Sync {
    /// Resolve up to `max_replicas` verified replicas for `receiver_id`.
    /// Returns an empty Vec on DHT miss / no fresh ad / verification
    /// failure — caller cannot distinguish (these are all "no usable
    /// replica" from the sender's perspective).
    fn resolve_replicas<'a>(
        &'a self,
        receiver_id: [u8; 32],
        max_replicas: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<ResolvedReplica>> + Send + 'a>>;
}

impl<T: RendezvousReplicaResolver + ?Sized> RendezvousReplicaResolver for std::sync::Arc<T> {
    fn resolve_replicas<'a>(
        &'a self,
        receiver_id: [u8; 32],
        max_replicas: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<ResolvedReplica>> + Send + 'a>>
    {
        (**self).resolve_replicas(receiver_id, max_replicas)
    }
}

// ── Offline-mailbox seal/open sink ─────────────────────────────

/// Outcome of [`MailboxCryptoSink::seal_blob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxSealOutcome {
    /// Sealed — carries the mailbox blob to `MailboxPut` at a relay.
    Ok(Vec<u8>),
    /// No sovereign identity is loaded on the node.
    NoIdentity,
    /// The recipient's ML-KEM cert could not be resolved + verified from DHT.
    PeerUnresolved,
    /// The seal operation itself failed (oversized / encrypt error).
    Failed,
}

/// Outcome of [`MailboxCryptoSink::open_blob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxOpenOutcome {
    /// Opened + verified — carries the verified sender, routing target + plaintext.
    Ok {
        /// Verified sender node_id (recovered from the blob's sidecar and
        /// confirmed by the auth-deliver signature — NOT a wire hint).
        sender_node_id: [u8; 32],
        /// Verified destination app id.
        app_id: [u8; 32],
        /// Verified destination endpoint id.
        endpoint_id: u32,
        /// Verified plaintext.
        data: Vec<u8>,
    },
    /// No sovereign identity is loaded on the node.
    NoIdentity,
    /// The sender's identity document could not be resolved + verified from DHT.
    PeerUnresolved,
    /// The open/verify failed (decode / AEAD / signature / freshness).
    Failed,
}

/// Hook the IPC server calls for `LocalAppMsg::MailboxSeal` / `MailboxOpen` —
/// the node-side E2E crypto for offline (store-and-forward) delivery.
/// Implemented by the runtime (the only place holding the sovereign signing key
/// plus the ML-KEM decapsulation seed). Async because both walk the DHT (recipient
/// cert / sender document resolution); a boxed future keeps the trait
/// object-safe (same pattern as [`RendezvousReplicaResolver`]).
pub trait MailboxCryptoSink: Send + Sync {
    /// Seal `data` for `recipient_node_id`'s `(app_id, endpoint_id)`.
    fn seal_blob<'a>(
        &'a self,
        recipient_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = MailboxSealOutcome> + Send + 'a>>;

    /// Open + verify `blob`, decrypting under our cert version `our_cert_version`.
    /// The sender is RECOVERED from the blob's sidecar (not supplied by the
    /// caller — on the anonymous mailbox path the wire sender is 0) and returned,
    /// crypto-verified, in [`MailboxOpenOutcome::Ok`].
    fn open_blob<'a>(
        &'a self,
        blob: Vec<u8>,
        our_cert_version: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = MailboxOpenOutcome> + Send + 'a>>;
}

impl<T: MailboxCryptoSink + ?Sized> MailboxCryptoSink for std::sync::Arc<T> {
    fn seal_blob<'a>(
        &'a self,
        recipient_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = MailboxSealOutcome> + Send + 'a>> {
        (**self).seal_blob(recipient_node_id, app_id, endpoint_id, data)
    }

    fn open_blob<'a>(
        &'a self,
        blob: Vec<u8>,
        our_cert_version: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = MailboxOpenOutcome> + Send + 'a>> {
        (**self).open_blob(blob, our_cert_version)
    }
}

// ── Peer-list provider ─────────────────────────────────────────

/// Hook the IPC server calls when an app issues `LocalAppMsg::GetPeers`.
/// Implemented by the veil runtime to snapshot its current
/// `live_sessions` map and surface it as a typed `PeersListPayload`.
///
/// Runs synchronously on the IPC dispatch task — implementations must
/// avoid blocking; the typical pattern is a brief `&self` lock against
/// a `Mutex<BTreeMap<…>>` and a quick clone.
pub trait PeerListProvider: Send + Sync {
    /// Snapshot the daemon's currently-active peer sessions. Server
    /// trims [`veil_proto::MAX_PEERS_LIST_ENTRIES`] before
    /// encoding — providers don't need to paginate, but should not
    /// return entries beyond the cap (excess is silently dropped).
    fn list_peers(&self) -> veil_proto::PeersListPayload;
}

/// `Arc<T>` proxy [`PeerListProvider`].
impl<T: PeerListProvider + ?Sized> PeerListProvider for std::sync::Arc<T> {
    fn list_peers(&self) -> veil_proto::PeersListPayload {
        (**self).list_peers()
    }
}

// ── PnetStatusProvider ────────────────────────────────────────────────

/// Hook the IPC server calls when an app issues
/// [`veil_proto::family::LocalAppMsg::PnetStatusQuery`].
///
/// Implemented by the veil runtime which has access to the
/// `NetworkAccessGate` cache populated at OVL1 handshake-time.  Apps
/// (ogate / oproxy / SDK consumers) use this to gate their app-layer
/// admission on the daemon's already-performed cert verification
/// instead of maintaining their own static `allowed_node_ids` list.
///
/// Runs synchronously on the IPC dispatch task — implementations must
/// avoid blocking; the typical pattern is a brief lock against the
/// per-session cert map.
pub trait PnetStatusProvider: Send + Sync {
    /// Look up the P-Net admission status for a given peer.
    /// Implementation contract:
    /// * Echo `peer_node_id` back in the result for IPC pipeline-safety.
    /// * Set `admitted=true` only if there's an active veil session.
    /// * Set `has_cert=true` only if a MembershipCert was verified for
    ///   this peer (i.e. daemon's P-Net is enabled and handshake passed).
    /// * When `has_cert=true`, populate `admin`, `valid_until_unix`,
    ///   `network_id` from the cached cert.
    /// * `valid_until_unix == 0` is the "no expiry" sentinel and MUST be
    ///   propagated verbatim (not rewritten to far-future).
    fn peer_status(&self, peer_node_id: &[u8; 32]) -> veil_proto::PnetStatusResultPayload;
}

/// `Arc<T>` proxy [`PnetStatusProvider`].
impl<T: PnetStatusProvider + ?Sized> PnetStatusProvider for std::sync::Arc<T> {
    fn peer_status(&self, peer_node_id: &[u8; 32]) -> veil_proto::PnetStatusResultPayload {
        (**self).peer_status(peer_node_id)
    }
}

// ── Bootstrap-URI join sink ────────────────────────────────────

/// Outcome of a bootstrap-URI join request, returned by
/// [`BootstrapJoinSink::join_uri`]. Wire-byte status codes mirror
/// `veil_proto::join_status` constants so the IPC handler can
/// pass the result through without mapping table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapJoinOutcome {
    /// URI decoded, verified, peer registered for outbound dial.
    Ok {
        peer_node_id: [u8; 32],
        detail: String,
    },
    /// URI parse failed (bad scheme, malformed base64, truncated body).
    InvalidUri(String),
    /// URI is encrypted (`veil:pair?…`) but no password was provided.
    PasswordRequired,
    /// URI is encrypted and the provided password was wrong.
    PasswordWrong,
    /// URI is signed and signature did not verify against expected_issuer_pk.
    SignatureInvalid(String),
    /// Same `pubkey` is already registered — no-op success.
    AlreadyRegistered { peer_node_id: [u8; 32] },
    /// Daemon-side error (out of memory, runtime in shutdown, etc.).
    InternalError(String),
}

/// Hook the IPC server calls when an app sends `LocalAppMsg::JoinBootstrapUri`
///. Implementations decode the URI through the standard
/// bootstrap-invite paths (plain / encrypted / signed) and register the
/// resulting peer with the runtime.
///
/// Receives raw URI + optional password + optional expected-issuer-pk
/// bytes verbatim; the IPC crate intentionally doesn't depend on
/// veil-bootstrap so the decode + crypto verification stays in
/// veilcore where the runtime can also drive the registration.
pub trait BootstrapJoinSink: Send + Sync {
    /// Decode the URI, verify it (if signed / encrypted), and register
    /// the resulting peer for outbound dial. Synchronous from the IPC
    /// handler's POV — implementations should keep CPU work bounded
    /// (Argon2id decrypt + signature verify in worst case ≈ 200 ms on
    /// budget Android).
    fn join_uri(
        &self,
        uri: &str,
        password: Option<&str>,
        expected_issuer_pk: Option<&str>,
    ) -> BootstrapJoinOutcome;
}

/// `Arc<T>` proxy [`BootstrapJoinSink`].
impl<T: BootstrapJoinSink + ?Sized> BootstrapJoinSink for std::sync::Arc<T> {
    fn join_uri(
        &self,
        uri: &str,
        password: Option<&str>,
        expected_issuer_pk: Option<&str>,
    ) -> BootstrapJoinOutcome {
        (**self).join_uri(uri, password, expected_issuer_pk)
    }
}

// ── Create-bootstrap-invite sink (Epic 489.7 generator side) ───

/// Outcome of [`BootstrapInviteCreateSink::create_invite`].  Mirrors
/// `veil_proto::create_invite_status` byte codes so the IPC handler
/// can pass the result through without a mapping table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapInviteCreateOutcome {
    /// Invite assembled and encoded.  Carries the canonical URI.
    Ok { uri: String },
    /// Daemon's config has no `[identity]` or no `[[listen]]` entry —
    /// runtime cannot assemble an invite that points anywhere.
    NotConfigured(String),
    /// Caller-supplied password failed validation (empty / oversized).
    BadPassword(String),
    /// Daemon-internal failure (encode error, hybrid identity on
    /// encrypted path, runtime in shutdown, …).
    InternalError(String),
}

/// Hook the IPC server calls when an app sends
/// `LocalAppMsg::CreateBootstrapInvite`.  Implementations assemble
/// the daemon's own [`veil_types::BootstrapPeer`] from `[identity]` +
/// the first `[[listen]]` entry, then encode the canonical URI (plain
/// or encrypted depending on `password`).  Same Arc<dyn> pattern as
/// other IPC sinks — kept in veil-ipc so the crate doesn't pull
/// in veil-bootstrap.
pub trait BootstrapInviteCreateSink: Send + Sync {
    /// Build a bootstrap invite URI.  Synchronous from the IPC handler's
    /// POV — implementations should keep CPU work bounded (encoding is
    /// allocation + base64; encryption variant adds Argon2id derive
    /// + ChaCha20-Poly1305 encrypt, ~100-200 ms on budget Android).
    fn create_invite(&self, password: Option<&str>) -> BootstrapInviteCreateOutcome;
}

impl<T: BootstrapInviteCreateSink + ?Sized> BootstrapInviteCreateSink for std::sync::Arc<T> {
    fn create_invite(&self, password: Option<&str>) -> BootstrapInviteCreateOutcome {
        (**self).create_invite(password)
    }
}

// ── Multi-device pairing sinks (Epic 489.8) ────────────────────

/// Outcome of [`PairSourceSink::create_invite`].  Mirrors
/// `veil_proto::pair_source_status` byte codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairSourceCreateOutcome {
    /// Invite assembled.  URI is ready to QR-render.
    Ok {
        uri: String,
    },
    NotConfigured(String),
    AlreadyInProgress(String),
    InternalError(String),
}

/// Outcome of [`PairSourceSink::handle_hello`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairSourceHandleHelloOutcome {
    Ok {
        cert_bytes: Vec<u8>,
        oob_code: [u8; 6],
    },
    WrongState(String),
    BadHello(String),
    InternalError(String),
}

/// Outcome of [`PairSourceSink::handle_confirm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairSourceHandleConfirmOutcome {
    /// Ceremony complete; daemon finalized + persisted new IdentityDocument.
    Ok,
    UserAborted(String),
    BadConfirm(String),
    WrongState(String),
    InternalError(String),
}

/// Outcome of [`PairTargetSink::consume_uri`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairTargetConsumeOutcome {
    /// URI parsed, ceremony state initialised.  Hello bytes ready
    /// for transport to Source.
    Ok {
        hello_bytes: Vec<u8>,
    },
    BadUri(String),
    Expired(String),
    AlreadyInProgress(String),
    InternalError(String),
}

/// Outcome of [`PairTargetSink::handle_cert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairTargetHandleCertOutcome {
    /// Cert decoded and verified.  OOB code ready for visual compare with
    /// Source's screen.
    Ok {
        oob_code: [u8; 6],
    },
    BadCert(String),
    WrongState(String),
    InternalError(String),
}

/// Outcome of [`PairTargetSink::build_confirm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairTargetBuildConfirmOutcome {
    /// Confirm bytes ready for transport to Source.  Daemon also
    /// persisted the new IdentityDocument + identity_sk on disk if
    /// `confirmed = true`.
    Ok {
        confirm_bytes: Vec<u8>,
    },
    WrongState(String),
    InternalError(String),
}

/// Hook the IPC server calls for Source-side ceremony ops.
/// Implementations hold ephemeral ceremony state in memory (one-at-a-
/// time semantics — a fresh CreateInvite drops any in-flight ceremony).
pub trait PairSourceSink: Send + Sync {
    /// Generate a fresh pair_secret + URI, stash ceremony state.
    /// `master_password` is needed if the sovereign identity's
    /// master_sk is encrypted at rest (Argon2id master.enc).
    fn create_invite(&self, master_password: Option<&str>) -> PairSourceCreateOutcome;
    /// Process Hello bytes from Target — verifies MAC, master-
    /// certifies Target's subkey, returns Cert bytes + OOB code.
    fn handle_hello(&self, hello_bytes: &[u8]) -> PairSourceHandleHelloOutcome;
    /// Process Confirm bytes from Target — verifies proof, finalizes
    /// (writes new IdentityDocument to disk + publishes via runtime
    /// republish task), drops ceremony state.  On user-aborted Confirm
    /// the appended IdentityKey is rolled back.
    fn handle_confirm(&self, confirm_bytes: &[u8]) -> PairSourceHandleConfirmOutcome;
}

impl<T: PairSourceSink + ?Sized> PairSourceSink for std::sync::Arc<T> {
    fn create_invite(&self, master_password: Option<&str>) -> PairSourceCreateOutcome {
        (**self).create_invite(master_password)
    }
    fn handle_hello(&self, hello_bytes: &[u8]) -> PairSourceHandleHelloOutcome {
        (**self).handle_hello(hello_bytes)
    }
    fn handle_confirm(&self, confirm_bytes: &[u8]) -> PairSourceHandleConfirmOutcome {
        (**self).handle_confirm(confirm_bytes)
    }
}

/// Hook the IPC server calls for Target-side ceremony ops.
pub trait PairTargetSink: Send + Sync {
    /// Parse scanned URI, generate own keypair + ephemeral, build Hello.
    fn consume_uri(&self, uri: &str, instance_label: Option<&str>) -> PairTargetConsumeOutcome;
    /// Process Cert from Source — verify sig chain, derive session key,
    /// compute OOB code for visual compare.
    fn handle_cert(&self, cert_bytes: &[u8]) -> PairTargetHandleCertOutcome;
    /// Emit Confirm bytes based on user's OOB-compare decision.
    /// `confirmed = true` triggers identity persistence to disk.
    fn build_confirm(&self, confirmed: bool) -> PairTargetBuildConfirmOutcome;
}

impl<T: PairTargetSink + ?Sized> PairTargetSink for std::sync::Arc<T> {
    fn consume_uri(&self, uri: &str, instance_label: Option<&str>) -> PairTargetConsumeOutcome {
        (**self).consume_uri(uri, instance_label)
    }
    fn handle_cert(&self, cert_bytes: &[u8]) -> PairTargetHandleCertOutcome {
        (**self).handle_cert(cert_bytes)
    }
    fn build_confirm(&self, confirmed: bool) -> PairTargetBuildConfirmOutcome {
        (**self).build_confirm(confirmed)
    }
}

// ── Mobile-status provider ─────────────────────────────────────

/// Hook the IPC server calls when an app sends `LocalAppMsg::GetMobileStatus`
///. Implemented by the veil runtime over its existing
/// `mobile_status` helper; tests use a fixed stub. Same Arc<dyn>
/// pattern as [`PeerListProvider`] / [`MobileEventSink`].
///
/// Returns a typed wire payload directly so the IPC handler can encode
/// without a translation table.
pub trait MobileStatusProvider: Send + Sync {
    /// Snapshot the daemon's current mobile / battery / keepalive state.
    /// Synchronous from the IPC dispatch task — implementations should
    /// keep work bounded (single config-reload + atomic loads).
    fn mobile_status(&self) -> veil_proto::MobileStatusPayload;
}

/// `Arc<T>` proxy [`MobileStatusProvider`].
impl<T: MobileStatusProvider + ?Sized> MobileStatusProvider for std::sync::Arc<T> {
    fn mobile_status(&self) -> veil_proto::MobileStatusPayload {
        (**self).mobile_status()
    }
}

// ── Push event bus ─────────────

/// Default capacity of the broadcast channel inside [`EventBus`]. Sized for a
/// few seconds of event burst on a slow consumer (Flutter UI in the middle of
/// a frame paint) before the broadcast channel starts dropping the oldest
/// items per-receiver. Lagged receivers see `RecvError::Lagged(n)` and we
/// surface that as a single dropped event in the IPC client task — the SDK
/// just misses an intermediate state, not a fatal error.
pub const EVENT_BUS_DEFAULT_CAPACITY: usize = 256;

/// Push-event fan-out for the IPC server.
///
/// The runtime publishes events (session-count changes, mobile-tier
/// transitions, identity rotations) into the bus; every connected IPC
/// client subscribes once at handshake-finish time and receives a copy
/// of every published event as a `LocalAppMsg::Event` frame. Without
/// this, a Flutter UI would have to poll `GetMobileStatus` / `GetPeers`
/// at a fixed cadence — wasted battery on budget Android.
///
/// Wraps `tokio::sync::broadcast::Sender` so the runtime can clone it
/// across publishers and the IPC server can call `subscribe` once
/// per connection. Bounded capacity (see [`EVENT_BUS_DEFAULT_CAPACITY`])
/// — slow subscribers just drop intermediate events, they do not
/// backpressure the publisher.
#[derive(Clone)]
pub struct EventBus {
    tx: tokio::sync::broadcast::Sender<veil_proto::EventPayload>,
}

impl EventBus {
    /// Create a new bus with the default capacity ([`EVENT_BUS_DEFAULT_CAPACITY`]).
    pub fn new() -> Self {
        Self::with_capacity(EVENT_BUS_DEFAULT_CAPACITY)
    }

    /// Create a new bus with a custom broadcast-channel capacity.
    pub fn with_capacity(cap: usize) -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(cap.max(1));
        Self { tx }
    }

    /// Publish an event to all currently-subscribed IPC clients. Returns
    /// the number of receivers that observed the event; zero is normal
    /// (no app connected yet). Dropped events on lagged receivers do not
    /// fail this call.
    pub fn publish(&self, event: veil_proto::EventPayload) -> usize {
        // Defensive: payload exceeding the wire cap would only fail on
        // encode anyway, but slipping it through the bus would spam
        // every subscriber with a frame the server then refuses to send.
        // Drop at the source to keep the contract one-sided.
        if event.payload.len() > veil_proto::MAX_EVENT_PAYLOAD_LEN {
            return 0;
        }
        self.tx.send(event).unwrap_or(0)
    }

    /// Subscribe a fresh receiver — typically called once per IPC client.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<veil_proto::EventPayload> {
        self.tx.subscribe()
    }

    /// Number of currently-active subscribers. Useful for tests + metrics.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("receiver_count", &self.tx.receiver_count())
            .finish()
    }
}
