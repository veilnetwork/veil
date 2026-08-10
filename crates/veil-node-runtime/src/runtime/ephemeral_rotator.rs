//! Glue between [`veil_transport::rotation`] and the live runtime —
//! Phase 5f Step 2.
//!
//! Builds the [`veil_transport::rotation::BindFn`] +
//! [`veil_transport::rotation::BroadcastFn`] closures with real
//! production wiring (the standard ephemeral binder + signed
//! `TransportMigrationNotify` broadcasts over the live session-tx
//! registry) and hands them to the generic
//! [`veil_transport::rotation::run_rotation_loop`] driver.
//!
//! ## Scope (Step 2)
//!
//! - [`spawn_ephemeral_rotator`]: spawns the rotation loop with production
//!   closures wired up. Caller passes the listener's
//!   `EphemeralConfig`, the local node-id + Ed25519 signing key, a URI
//!   template that turns the picked port into the full transport URI
//!   broadcast to peers, and an `Arc<RwLock<SessionTxRegistry>>` for
//!   the actual frame broadcast.  Returns the events receiver and a
//!   shutdown watch handle.
//! - Unit tests exercise the broadcast plumbing with a registered fake
//!   peer and verify the wire bytes round-trip through `decode_header` +
//!   `TransportMigrationNotifyPayload::decode` +
//!   `verify_transport_migration_notify`.
//!
//! ## Production wiring (Step 3 — shipped)
//!
//! - **Listener swap**: [`wire_ephemeral_rotator`] returns
//!   [`EphemeralRotatorHandles`] containing a consumer task that, on
//!   each `RotationEvent::Rotated`, rebinds the listener and pushes the
//!   fresh `TransportListener` through the accept-loop's swap channel.
//! - **Lifecycle invocation**: `services::spawn_listeners` calls
//!   [`wire_ephemeral_rotator_for_listen`] (services.rs) which builds
//!   the swap channel and invokes [`wire_ephemeral_rotator`] for each
//!   listen entry whose `[listen.ephemeral]` block is populated.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use veil_transport::rotation::{
    AdoptFn, BindFn, BroadcastFn, DefaultBinder, RotationEvent, RotationSpec, run_rotation_loop,
};

use veil_cfg::EphemeralConfig;
use veil_observability::NodeLogger;
use veil_proto::{
    codec::encode_header,
    family::{FrameFamily, SessionMsg},
    header::{FrameHeader, HEADER_SIZE},
    session::sign_transport_migration_notify,
};
use veil_session::SessionTxRegistry;
use veil_transport::{TransportContext, TransportListener, TransportRegistry, TransportUri};

/// Function that turns the freshly bound port into the canonical
/// transport URI advertised to peers.  Typical bodies:
///
/// ```ignore
/// |port: u16| format!("obfs4-tcp://example.com:{port}")
/// ```
///
/// Kept as a type alias rather than a concrete closure trait so call
/// sites can pass either a plain `fn(u16) -> String` or a closure that
/// captures `host` / `advertise_template` from the config.
pub type UriTemplate = Box<dyn Fn(u16) -> String + Send + Sync + 'static>;

/// Production broadcaster: signs a `TransportMigrationNotify` payload
/// under the local identity key and pushes the wire-encoded frame to every
/// active session through [`SessionTxRegistry::send_to_all_with_priority`].
///
/// `new_expiry_offset` is added to `now_unix()` to compute the NEW URI's
/// expiry — peers will treat the cached entry as valid up to that point
/// and fall back to a fresh `ResolveTransport` lookup beyond.
pub struct SessionTxBroadcaster {
    local_node_id: [u8; 32],
    signing_key: Arc<SigningKey>,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    uri_template: Arc<UriTemplate>,
    new_expiry_offset: Duration,
}

impl BroadcastFn for SessionTxBroadcaster {
    fn broadcast(
        &self,
        new_port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
        let local_node_id = self.local_node_id;
        let signing_key = Arc::clone(&self.signing_key);
        let registry = Arc::clone(&self.session_tx_registry);
        let uri_template = Arc::clone(&self.uri_template);
        let expiry_offset = self.new_expiry_offset;
        Box::pin(async move {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let new_expiry = now.saturating_add(expiry_offset.as_secs());
            let new_uri = (uri_template)(new_port);
            let payload = sign_transport_migration_notify(
                local_node_id,
                new_expiry,
                now,
                new_uri,
                &signing_key,
            );
            let body = payload.encode();
            let mut hdr = FrameHeader::new(
                FrameFamily::Session as u8,
                SessionMsg::TransportMigrationNotify as u16,
            );
            hdr.body_len = body.len() as u32;
            let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
            frame.extend_from_slice(&encode_header(&hdr));
            frame.extend_from_slice(&body);
            let pooled = veil_bufpool::pooled_shared_from_vec(frame);
            // Use INTERACTIVE priority (matches DetachPayload broadcast in
            // shutdown — migration is operationally urgent but not
            // realtime-critical).  Sync RwLock read here — `send_to_all`
            // returns immediately after enqueuing, so the guard lifetime
            // is microseconds, not held across .await.
            veil_util::rlock!(registry).send_to_all(pooled);
        })
    }
}

/// Spawn the rotation lifecycle for one ephemeral listener.
///
/// Returns:
///   - `JoinHandle<()>` for the rotation-loop task.
///   - `mpsc::Receiver<RotationEvent>` through which the caller can
///     observe rotation outcomes (e.g. invoke listener-swap mechanics
///     on `RotationEvent::Rotated`).
///   - `watch::Sender<bool>` for clean shutdown — flip to `true` to stop.
///
/// Caller is responsible for draining `events_rx`. If the receiver
/// fills, the loop's `events_tx.send(...).await` will park, blocking
/// subsequent rotations.  64-deep channel matches the bind-retry cap
/// and is more than sufficient for any realistic rotation cadence.
/// What the rotator's consumer sends to a listener's accept loop.
///
/// Two messages rather than one listener, because a rotation is two events
/// separated by the grace period. `Activate` starts the new port WITHOUT
/// touching the one in service; `RetireOld` closes the previous one once the
/// grace period says peers have had time to learn the new URI. Collapsing
/// them into "here is your new listener" is what made the grace period a
/// promise the code did not keep.
pub enum ListenerSwap {
    /// Accept on this listener from now on, keeping the previous one.
    Activate(Box<dyn TransportListener>),
    /// The grace period is over: close the listener `Activate` replaced.
    RetireOld,
}

// Hand-written: `TransportListener` is a trait object with no `Debug`
// bound, and adding one to the trait for a log line is the wrong trade.
impl std::fmt::Debug for ListenerSwap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Activate(l) => f.debug_tuple("Activate").field(&l.local_addr()).finish(),
            Self::RetireOld => f.write_str("RetireOld"),
        }
    }
}

/// What to BIND and what to ADVERTISE, which are different questions.
///
/// They were answered with one value, and that is the whole of report9 V-06:
/// the operator's `advertise` address — a public IP or a DNS name this machine
/// need not own — was handed to `bind`. Every rotation then failed to rebind
/// and the listener never moved, in exactly the configuration `advertise`
/// exists for. Absent an `advertise` URI the two coincide, which is why it went
/// unnoticed: the default configuration is the one where the bug cannot show.
///
/// Returns `(bind_uri, bind_host, advertise_uri, advertise_host)`.
fn rotation_targets(
    listen_uri: &TransportUri,
    advertise_uri: Option<&TransportUri>,
) -> (TransportUri, String, TransportUri, String) {
    let bind_host = listen_uri.plaintext_host().unwrap_or("0.0.0.0").to_owned();
    let advertise = advertise_uri.cloned().unwrap_or_else(|| listen_uri.clone());
    let advertise_host = advertise
        .plaintext_host()
        .map(str::to_owned)
        .unwrap_or_else(|| bind_host.clone());
    (listen_uri.clone(), bind_host, advertise, advertise_host)
}

/// Binds a port the rotator has probed free and puts it into service
/// alongside the listener already accepting.
///
/// This runs BEFORE the migration notify goes out, and its answer decides
/// whether the notify goes out at all — see `run_rotation_loop`. A probe
/// bind only proves the port was free a moment ago; between the probe's
/// drop and this bind anything on the host can take it, and a notify sent
/// on the strength of the probe advertises whatever won that race.
struct ListenerAdopter {
    template: TransportUri,
    host: String,
    registry: Arc<TransportRegistry>,
    listen_ctx: Arc<TransportContext>,
    swap_tx: mpsc::Sender<ListenerSwap>,
    logger: Arc<NodeLogger>,
    listen_id: String,
}

impl AdoptFn for ListenerAdopter {
    fn adopt(
        &self,
        new_port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'static>> {
        let template = self.template.clone();
        let host = self.host.clone();
        let registry = Arc::clone(&self.registry);
        let listen_ctx = Arc::clone(&self.listen_ctx);
        let swap_tx = self.swap_tx.clone();
        let logger = Arc::clone(&self.logger);
        let listen_id = self.listen_id.clone();
        Box::pin(async move {
            let Some(new_uri) = template.with_host_port(host, new_port) else {
                logger.warn(
                    "listen.rotation.uri_compose_failed",
                    format!("listen_id={listen_id} could not compose new URI for port {new_port}"),
                );
                return false;
            };
            let new_listener = match registry.bind(&new_uri, listen_ctx).await {
                Ok(l) => l,
                Err(e) => {
                    logger.warn(
                        "listen.rotation.rebind_failed",
                        format!(
                            "listen_id={listen_id} bind({new_uri:?}) failed: {e} \
                             — old listener kept in service, nothing advertised",
                        ),
                    );
                    return false;
                }
            };
            let local_addr = new_listener.local_addr();
            if let Err(e) = swap_tx.send(ListenerSwap::Activate(new_listener)).await {
                logger.warn(
                    "listen.rotation.swap_send_failed",
                    format!("listen_id={listen_id} accept loop swap channel closed: {e}"),
                );
                return false;
            }
            logger.info(
                "listen.rotation.swap_sent",
                format!("listen_id={listen_id} new_port={new_port} new_addr={local_addr}"),
            );
            true
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_ephemeral_rotator<A: AdoptFn>(
    spec: RotationSpec,
    local_node_id: [u8; 32],
    signing_key: SigningKey,
    uri_template: UriTemplate,
    new_expiry_offset: Duration,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    adopter: A,
) -> (
    JoinHandle<()>,
    mpsc::Receiver<RotationEvent>,
    watch::Sender<bool>,
) {
    spawn_ephemeral_rotator_with_binder(
        spec,
        local_node_id,
        signing_key,
        uri_template,
        new_expiry_offset,
        session_tx_registry,
        DefaultBinder,
        adopter,
    )
}

/// Test-hook variant of the same helper — accepts a custom binder so unit
/// tests can drive the loop with mocked random-port outcomes without
/// touching real sockets.
#[allow(clippy::too_many_arguments)]
pub fn spawn_ephemeral_rotator_with_binder<B: BindFn, A: AdoptFn>(
    spec: RotationSpec,
    local_node_id: [u8; 32],
    signing_key: SigningKey,
    uri_template: UriTemplate,
    new_expiry_offset: Duration,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    binder: B,
    adopter: A,
) -> (
    JoinHandle<()>,
    mpsc::Receiver<RotationEvent>,
    watch::Sender<bool>,
) {
    let (events_tx, events_rx) = mpsc::channel(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let broadcaster = SessionTxBroadcaster {
        local_node_id,
        signing_key: Arc::new(signing_key),
        session_tx_registry,
        uri_template: Arc::new(uri_template),
        new_expiry_offset,
    };
    let handle = tokio::spawn(async move {
        run_rotation_loop(spec, binder, adopter, broadcaster, events_tx, shutdown_rx).await;
    });
    (handle, events_rx, shutdown_tx)
}

// ── Phase 5f Step 3 — full listener wiring ──────────────────────────

/// Bundle of handles returned by [`wire_ephemeral_rotator`].  Caller
/// owns these handles; dropping the shutdown sender or the swap_tx
/// triggers the rotator + consumer tasks to exit cleanly.
#[derive(Debug)]
pub struct EphemeralRotatorHandles {
    /// Join handle for the rotation-loop task.
    pub rotator: JoinHandle<()>,
    /// Join handle for the consumer task that rebinds the listener
    /// after each `RotationEvent::Rotated` and pushes it to the accept
    /// loop through the swap channel.
    pub consumer: JoinHandle<()>,
    /// Watch sender to signal shutdown.  Both tasks observe this
    /// indirectly through the rotator's internal channel.
    pub shutdown: watch::Sender<bool>,
}

/// Build + spawn the rotator AND the listener-rebind consumer for
/// one ephemeral listen entry.  Caller has already bound the initial
/// listener separately; this helper drives subsequent rotations.
///
/// Returns `Err` if the operator's config is malformed (invalid
/// duration spec, inverted port range, zero rotation interval) —
/// caught up-front so spawn_listeners fails clearly during startup rather
/// than silently dying on the first rotation tick.
///
/// Accepts the listener swap channel (`listener_swap_tx`) that the
/// accept-loop owns the receiver of.  On each rotation, the consumer
/// task: parses the new URI, calls `registry.bind(new_uri)`, and pushes
/// the freshly-bound listener through swap_tx.  The accept loop drains
/// and swaps to the new listener between accepts.
#[allow(clippy::too_many_arguments)]
pub fn wire_ephemeral_rotator(
    eph: &EphemeralConfig,
    listen_uri: &TransportUri,
    advertise_uri: Option<&TransportUri>,
    local_node_id: [u8; 32],
    signing_key: SigningKey,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    registry: Arc<TransportRegistry>,
    listen_ctx: Arc<TransportContext>,
    listener_swap_tx: mpsc::Sender<ListenerSwap>,
    logger: Arc<NodeLogger>,
    listen_id_for_log: String,
) -> Result<EphemeralRotatorHandles, String> {
    use veil_transport::rotation::parse_duration_spec;

    // ── parse config ────────────────────────────────────────────────
    let rotation =
        parse_duration_spec(&eph.rotation).map_err(|e| format!("rotation parse failed: {e}"))?;
    let grace = parse_duration_spec(&eph.grace_period)
        .map_err(|e| format!("grace_period parse failed: {e}"))?;
    let (port_lo, port_hi) = eph.range;
    let (bind_uri, host, template_source, template_host) =
        rotation_targets(listen_uri, advertise_uri);

    let spec = RotationSpec::new(
        host.clone(),
        port_lo..=port_hi,
        eph.bind_retries,
        rotation,
        grace,
    )
    .map_err(|e| format!("spec invalid: {e}"))?;

    // ── URI template for the broadcast payload ────────────────────
    // The operator's `advertise` URI when set, so peers learn the
    // externally-reachable address rather than the bind host; the bind URI
    // otherwise. See `rotation_targets` for why these are kept apart.
    let template_for_broadcast = template_source.clone();
    let host_for_broadcast = template_host.clone();
    let uri_template: UriTemplate = Box::new(move |port: u16| {
        template_for_broadcast
            .with_host_port(host_for_broadcast.clone(), port)
            .map(|u| u.to_string())
            .unwrap_or_else(|| format!("ephemeral-port-{port}"))
    });

    // ── rotator + broadcast pipeline ───────────────────────────────
    // Bundle expiry matches the rotation interval × 4 — peers' caches
    // stay valid past 4 full rotation cycles, so a receiver that misses
    // (say) 3 consecutive migration notifies still has a usable URI
    // until the operator's next rotation.
    let new_expiry_offset = rotation.saturating_mul(4);
    let listen_id = listen_id_for_log;
    // The adopter is what makes the port real. It runs inside the rotation
    // loop ahead of the broadcast, so a port nothing came up on is never
    // advertised — see `run_rotation_loop`.
    let adopter = ListenerAdopter {
        // The BIND side of `rotation_targets`. The adopter's only job is to
        // make the port real; what peers are told is the broadcast template's
        // business, and conflating the two is report9 V-06.
        template: bind_uri,
        host: host.clone(),
        registry,
        listen_ctx,
        swap_tx: listener_swap_tx.clone(),
        logger: Arc::clone(&logger),
        listen_id: listen_id.clone(),
    };
    let (rotator_handle, mut events_rx, shutdown_tx) = spawn_ephemeral_rotator(
        spec,
        local_node_id,
        signing_key,
        uri_template,
        new_expiry_offset,
        session_tx_registry,
        adopter,
    );

    // ── consumer task: log the lifecycle, retire the old listener ──
    // The rebind moved into the adopter above, because it has to happen
    // BEFORE the broadcast. What is left here is the other end of the grace
    // period: closing the listener the rotation replaced, and not a moment
    // earlier — peers cache the old URI for several rotation intervals, and
    // the ones that missed the notify are exactly who the grace is for.
    let consumer = tokio::spawn(async move {
        while let Some(ev) = events_rx.recv().await {
            match ev {
                RotationEvent::Rotated { new_port } => {
                    logger.info(
                        "listen.rotation.rotated",
                        format!(
                            "listen_id={listen_id} new_port={new_port} — both listeners \
                             accepting until the grace period ends",
                        ),
                    );
                }
                RotationEvent::RetireOld => {
                    if listener_swap_tx
                        .send(ListenerSwap::RetireOld)
                        .await
                        .is_err()
                    {
                        logger.warn(
                            "listen.rotation.retire_send_failed",
                            format!("listen_id={listen_id} accept loop swap channel closed"),
                        );
                        break;
                    }
                }
                RotationEvent::AdoptFailed { reason } => {
                    logger.warn(
                        "listen.rotation.adopt_failed",
                        format!("listen_id={listen_id} reason={reason}"),
                    );
                }
                RotationEvent::BindFailed { reason } => {
                    logger.warn(
                        "listen.rotation.bind_failed",
                        format!("listen_id={listen_id} reason={reason}"),
                    );
                }
                RotationEvent::Shutdown => break,
            }
        }
    });

    Ok(EphemeralRotatorHandles {
        rotator: rotator_handle,
        consumer,
        shutdown: shutdown_tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicU32, Ordering};
    use veil_proto::{
        codec::decode_header,
        session::{TransportMigrationNotifyPayload, verify_transport_migration_notify},
    };
    use veil_session::SessionTxRegistry;
    use veil_transport::error::TransportError;

    /// Scripted binder used by the wire-level test below — returns one
    /// port in order then errors thereafter.
    /// Adopter for tests that are about the rotator, not the listener: it
    /// answers "yes, I came up" without binding anything. Tests that care
    /// whether the port is really taken drive `run_rotation_loop` directly
    /// (see `veil_transport::rotation`).
    struct AlwaysAdopts;

    impl AdoptFn for AlwaysAdopts {
        fn adopt(
            &self,
            _new_port: u16,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'static>> {
            Box::pin(async { true })
        }
    }

    struct ScriptedBinder {
        ports: Arc<StdMutex<Vec<u16>>>,
        calls: Arc<AtomicU32>,
    }
    impl BindFn for ScriptedBinder {
        fn bind(
            &self,
            _host: String,
            _port_range: std::ops::RangeInclusive<u16>,
            _bind_retries: u32,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = veil_transport::error::Result<(tokio::net::TcpListener, u16)>,
                    > + Send
                    + 'static,
            >,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let next = self.ports.lock().unwrap().pop();
            Box::pin(async move {
                match next {
                    Some(port) => {
                        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
                        Ok((listener, port))
                    }
                    None => Err(TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "scripted: out of ports",
                    ))),
                }
            })
        }
    }

    #[tokio::test]
    async fn broadcaster_writes_signed_migration_notify_to_registered_peer() {
        // Identity setup — caller passes ownership of the SigningKey,
        // but we keep a duplicate-via-from_bytes so the test can verify
        // the sig against the matching pubkey.
        let sk_bytes = [0xA5u8; 32];
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_pk = signing_key.verifying_key().to_bytes();
        let local_node_id = *blake3::hash(&verifying_pk).as_bytes();

        // Build a live SessionTxRegistry + register one fake peer so we
        // can observe the broadcast.
        let registry: Arc<RwLock<SessionTxRegistry>> =
            Arc::new(RwLock::new(SessionTxRegistry::with_capacity(4)));
        let fake_peer_id = [0xBBu8; 32];
        let mut peer_rx = {
            let mut reg = veil_util::wlock!(registry);
            reg.register(fake_peer_id)
        };

        // Rotation spec — tiny interval, zero grace so the test
        // observes the broadcast directly after the bind tick.
        let spec = RotationSpec::new(
            "127.0.0.1",
            10000..=60000,
            8,
            Duration::from_millis(50),
            Duration::ZERO,
        )
        .unwrap();
        let scripted_port = 51234;
        let binder = ScriptedBinder {
            ports: Arc::new(StdMutex::new(vec![scripted_port])),
            calls: Arc::new(AtomicU32::new(0)),
        };

        let template: UriTemplate =
            Box::new(|port: u16| format!("obfs4-tcp://example.test:{port}"));
        let (handle, mut events_rx, shutdown_tx) = spawn_ephemeral_rotator_with_binder(
            spec,
            local_node_id,
            signing_key,
            template,
            Duration::from_secs(3600),
            Arc::clone(&registry),
            binder,
            AlwaysAdopts,
        );

        // Wait for `Rotated` on the real clock — interval is 50ms.
        let ev = tokio::time::timeout(Duration::from_secs(5), events_rx.recv())
            .await
            .expect("events_rx timeout")
            .expect("events stream ended");
        match ev {
            RotationEvent::Rotated { new_port } => assert_eq!(new_port, scripted_port),
            other => panic!("expected Rotated, got {other:?}"),
        }

        // The broadcaster ran inside the same tick — the peer's
        // outbox must already carry a PriorityFrame.
        let frame = tokio::time::timeout(Duration::from_secs(2), peer_rx.recv())
            .await
            .expect("peer_rx timeout")
            .expect("peer queue closed");
        let bytes: &[u8] = frame.1.as_ref();

        // Decode the frame header + payload.
        assert!(bytes.len() >= HEADER_SIZE);
        let hdr = decode_header(&bytes[..HEADER_SIZE]).expect("decode_header");
        assert_eq!(hdr.family, FrameFamily::Session as u8);
        assert_eq!(hdr.msg_type, SessionMsg::TransportMigrationNotify as u16);
        let body = &bytes[HEADER_SIZE..HEADER_SIZE + hdr.body_len as usize];
        let payload = TransportMigrationNotifyPayload::decode(body).expect("decode payload");
        assert_eq!(payload.node_id, local_node_id);
        assert_eq!(
            payload.new_transport,
            format!("obfs4-tcp://example.test:{scripted_port}"),
        );

        // Sig must verify under the matching pubkey.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        verify_transport_migration_notify(&payload, &verifying_pk, now)
            .expect("sig must verify under the identity pubkey");

        // Cleanup.
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn bind_failure_does_not_broadcast() {
        let sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let local_node_id = *blake3::hash(&sk.verifying_key().to_bytes()).as_bytes();

        let registry: Arc<RwLock<SessionTxRegistry>> =
            Arc::new(RwLock::new(SessionTxRegistry::with_capacity(4)));
        let fake_peer_id = [0xCCu8; 32];
        let mut peer_rx = {
            let mut reg = veil_util::wlock!(registry);
            reg.register(fake_peer_id)
        };

        let spec = RotationSpec::new(
            "127.0.0.1",
            10000..=60000,
            0,
            Duration::from_millis(50),
            Duration::ZERO,
        )
        .unwrap();
        let binder = ScriptedBinder {
            ports: Arc::new(StdMutex::new(vec![])), // empty → bind fails
            calls: Arc::new(AtomicU32::new(0)),
        };
        let template: UriTemplate = Box::new(|p: u16| format!("test://{p}"));

        let (handle, mut events_rx, shutdown_tx) = spawn_ephemeral_rotator_with_binder(
            spec,
            local_node_id,
            sk,
            template,
            Duration::from_secs(3600),
            Arc::clone(&registry),
            binder,
            AlwaysAdopts,
        );

        let ev = tokio::time::timeout(Duration::from_secs(5), events_rx.recv())
            .await
            .expect("events_rx timeout")
            .expect("events stream ended");
        match ev {
            RotationEvent::BindFailed { .. } => {}
            other => panic!("expected BindFailed, got {other:?}"),
        }

        // Peer must NOT have received any frame — the broadcaster is
        // only invoked after a successful bind.
        assert!(
            peer_rx.try_recv().is_err(),
            "broadcast must not fire when bind fails",
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    // ── wire_ephemeral_rotator error paths ──────────────────────────

    /// Helper: build a listen URI and EphemeralConfig for the validation
    /// tests.  Uses obfs4-tcp which supports `with_host_port` (per
    /// `crates/veil-transport/src/uri.rs::with_host_port`).
    #[allow(clippy::type_complexity)] // test-fixture tuple
    fn mock_inputs(
        eph_rotation: &str,
        eph_grace: &str,
        port_range: (u16, u16),
    ) -> (
        veil_cfg::EphemeralConfig,
        TransportUri,
        Arc<RwLock<SessionTxRegistry>>,
        Arc<TransportRegistry>,
        Arc<TransportContext>,
        Arc<NodeLogger>,
    ) {
        let eph = veil_cfg::EphemeralConfig {
            range: port_range,
            rotation: eph_rotation.to_owned(),
            bind_retries: 8,
            grace_period: eph_grace.to_owned(),
        };
        let uri = TransportUri::parse("obfs4-tcp://127.0.0.1:5556").unwrap();
        let registry = Arc::new(RwLock::new(SessionTxRegistry::with_capacity(4)));
        let transport_registry = Arc::new(TransportRegistry::with_defaults());
        let transport_ctx = Arc::new(TransportContext::for_debug().expect("debug ctx"));
        let logger = Arc::new(NodeLogger::new_noop());
        (
            eph,
            uri,
            registry,
            transport_registry,
            transport_ctx,
            logger,
        )
    }

    /// Binding and advertising must not be the same address.
    ///
    /// The rotator hands its adopter a URI to BIND and the broadcaster a URI to
    /// ADVERTISE, and both came from the advertise template. So with `advertise`
    /// set to a public address — which is what the option is for — every
    /// rotation asked the kernel to bind an address this machine does not own,
    /// the rebind failed, and the listener never moved (report9 V-06).
    ///
    /// Asserted on the decision rather than through a bind, because the bind is
    /// what a machine with that address would refuse and this one cannot
    /// reproduce: the wrong VALUE is the defect.
    #[test]
    fn bind_target_is_the_listen_address_not_the_advertised_one() {
        // A scheme that shows its host: `plaintext_host` is None for obfs4 and
        // every TLS scheme, and both sides then fall back to the same
        // "0.0.0.0" — which is why the default deployment never saw this.
        let listen = TransportUri::parse("tcp://127.0.0.1:5556").unwrap();
        let advertise = TransportUri::parse("tcp://203.0.113.7:5556").unwrap();

        let (bind_uri, bind_host, adv_uri, adv_host) = rotation_targets(&listen, Some(&advertise));
        assert_eq!(
            bind_host, "127.0.0.1",
            "the rotator would bind an address this host does not own"
        );
        assert_eq!(bind_uri.to_string(), listen.to_string());
        assert_eq!(
            adv_host, "203.0.113.7",
            "peers must still learn the externally reachable address"
        );
        assert_eq!(adv_uri.to_string(), advertise.to_string());
    }

    /// Without `advertise` the two coincide — which is why the swap above went
    /// unnoticed, and why a test that only covers the default proves nothing.
    #[test]
    fn without_an_advertise_uri_both_targets_are_the_listen_address() {
        let listen = TransportUri::parse("tcp://127.0.0.1:5556").unwrap();
        let (bind_uri, bind_host, adv_uri, adv_host) = rotation_targets(&listen, None);
        assert_eq!(bind_host, adv_host);
        assert_eq!(bind_uri.to_string(), adv_uri.to_string());
        assert_eq!(bind_host, "127.0.0.1");
    }

    /// What an encrypted listen URI actually resolves to, written down because
    /// it surprised this pass.
    ///
    /// `plaintext_host` exists to warn operators about DPI-readable endpoints,
    /// not to name a bind address — it is None for obfs4 and for every TLS
    /// scheme. Using it here means an obfs4 listener rebinds on 0.0.0.0 no
    /// matter which host the operator configured. That is pre-existing and
    /// separate from V-06; it is asserted so the behaviour is a decision on
    /// record rather than a surprise, and so a change to it fails loudly.
    #[test]
    fn an_encrypted_listen_uri_falls_back_to_all_interfaces() {
        let listen = TransportUri::parse("obfs4-tcp://127.0.0.1:5556").unwrap();
        let (_, bind_host, _, adv_host) = rotation_targets(&listen, None);
        assert_eq!(bind_host, "0.0.0.0");
        assert_eq!(adv_host, "0.0.0.0");
    }

    #[test]
    fn wire_rejects_unparseable_rotation_spec() {
        let sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let (eph, uri, registry, transport_registry, transport_ctx, logger) =
            mock_inputs("not-a-duration", "30s", (10000, 60000));
        let (swap_tx, _swap_rx) = mpsc::channel(2);
        let err = wire_ephemeral_rotator(
            &eph,
            &uri,
            None,
            [0u8; 32],
            sk,
            registry,
            transport_registry,
            transport_ctx,
            swap_tx,
            logger,
            "test-listen-1".to_owned(),
        )
        .unwrap_err();
        assert!(err.contains("rotation parse failed"), "got: {err}");
    }

    #[test]
    fn wire_rejects_unparseable_grace_period() {
        let sk = SigningKey::from_bytes(&[0x22u8; 32]);
        let (eph, uri, registry, transport_registry, transport_ctx, logger) =
            mock_inputs("60s", "garbage", (10000, 60000));
        let (swap_tx, _swap_rx) = mpsc::channel(2);
        let err = wire_ephemeral_rotator(
            &eph,
            &uri,
            None,
            [0u8; 32],
            sk,
            registry,
            transport_registry,
            transport_ctx,
            swap_tx,
            logger,
            "test-listen-2".to_owned(),
        )
        .unwrap_err();
        assert!(err.contains("grace_period parse failed"), "got: {err}");
    }

    #[test]
    fn wire_rejects_inverted_port_range() {
        let sk = SigningKey::from_bytes(&[0x33u8; 32]);
        let (eph, uri, registry, transport_registry, transport_ctx, logger) =
            mock_inputs("60s", "30s", (60000, 10000));
        let (swap_tx, _swap_rx) = mpsc::channel(2);
        let err = wire_ephemeral_rotator(
            &eph,
            &uri,
            None,
            [0u8; 32],
            sk,
            registry,
            transport_registry,
            transport_ctx,
            swap_tx,
            logger,
            "test-listen-3".to_owned(),
        )
        .unwrap_err();
        assert!(err.contains("port range invalid"), "got: {err}");
    }

    #[test]
    fn wire_rejects_zero_rotation_interval() {
        let sk = SigningKey::from_bytes(&[0x44u8; 32]);
        let (eph, uri, registry, transport_registry, transport_ctx, logger) =
            mock_inputs("0s", "30s", (10000, 60000));
        let (swap_tx, _swap_rx) = mpsc::channel(2);
        let err = wire_ephemeral_rotator(
            &eph,
            &uri,
            None,
            [0u8; 32],
            sk,
            registry,
            transport_registry,
            transport_ctx,
            swap_tx,
            logger,
            "test-listen-4".to_owned(),
        )
        .unwrap_err();
        assert!(err.contains("rotation_interval must be > 0"), "got: {err}");
    }
}
