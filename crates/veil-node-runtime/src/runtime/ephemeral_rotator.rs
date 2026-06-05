//! Glue between [`veil_transport::rotation`] и the live runtime —
//! Phase 5f Step 2.
//!
//! Builds the [`veil_transport::rotation::BindFn`] +
//! [`veil_transport::rotation::BroadcastFn`] closures with real
//! production wiring (the standard ephemeral binder + signed
//! `TransportMigrationNotify` broadcasts over the live session-tx
//! registry) и hands them к the generic
//! [`veil_transport::rotation::run_rotation_loop`] driver.
//!
//! ## Scope (Step 2)
//!
//! - [`spawn_ephemeral_rotator`]: spawns the rotation loop с production
//!   closures wired up. Caller passes the listener's
//!   `EphemeralConfig`, the local node-id + Ed25519 signing key, а URI
//!   template что turns the picked port into the full transport URI
//!   broadcast к peers, and an `Arc<RwLock<SessionTxRegistry>>` для
//!   the actual frame broadcast.  Returns the events receiver и а
//!   shutdown watch handle.
//! - Unit tests exercise the broadcast plumbing с а registered fake
//!   peer и verify the wire bytes round-trip through `decode_header` +
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
    BindFn, BroadcastFn, DefaultBinder, RotationEvent, RotationSpec, run_rotation_loop,
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

/// Function что turns the freshly bound port into the canonical
/// transport URI advertised к peers.  Typical bodies:
///
/// ```ignore
/// |port: u16| format!("obfs4-tcp://example.com:{port}")
/// ```
///
/// Kept as а type alias rather than а concrete closure trait so call
/// sites can pass either а plain `fn(u16) -> String` или а closure что
/// captures `host` / `advertise_template` от the config.
pub type UriTemplate = Box<dyn Fn(u16) -> String + Send + Sync + 'static>;

/// Production broadcaster: signs а `TransportMigrationNotify` payload
/// под the local identity key и pushes the wire-encoded frame к every
/// active session через [`SessionTxRegistry::send_to_all_with_priority`].
///
/// `new_expiry_offset` is added к `now_unix()` к compute the NEW URI's
/// expiry — peers will treat the cached entry as valid up к that point
/// и fall back к а fresh `ResolveTransport` лookup beyond.
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
            // Use INTERACTIVE priority (matches DetachPayload broadcast в
            // shutdown — migration is operationally urgent but не
            // realtime-critical).  Sync RwLock read here — `send_to_all`
            // returns immediately after enqueuing, so the guard lifetime
            // is microseconds, не held across .await.
            veil_util::rlock!(registry).send_to_all(pooled);
        })
    }
}

/// Spawn the rotation lifecycle для one ephemeral listener.
///
/// Returns:
///   - `JoinHandle<()>` для the rotation-loop task.
///   - `mpsc::Receiver<RotationEvent>` через which the caller can
///     observe rotation outcomes (e.g. invoke listener-swap mechanics
///     on `RotationEvent::Rotated`).
///   - `watch::Sender<bool>` для clean shutdown — flip к `true` к stop.
///
/// Caller is responsible для draining `events_rx`. Если the receiver
/// fills, the loop's `events_tx.send(...).await` will park, blocking
/// subsequent rotations.  64-deep channel matches the bind-retry cap
/// и is more than sufficient for any realistic rotation cadence.
pub fn spawn_ephemeral_rotator(
    spec: RotationSpec,
    local_node_id: [u8; 32],
    signing_key: SigningKey,
    uri_template: UriTemplate,
    new_expiry_offset: Duration,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
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
    )
}

/// Test-hook variant того же helper — accepts а custom binder so unit
/// tests can drive the loop с mocked random-port outcomes без
/// touching real sockets.
pub fn spawn_ephemeral_rotator_with_binder<B: BindFn>(
    spec: RotationSpec,
    local_node_id: [u8; 32],
    signing_key: SigningKey,
    uri_template: UriTemplate,
    new_expiry_offset: Duration,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    binder: B,
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
        run_rotation_loop(spec, binder, broadcaster, events_tx, shutdown_rx).await;
    });
    (handle, events_rx, shutdown_tx)
}

// ── Phase 5f Step 3 — full listener wiring ──────────────────────────

/// Bundle of handles returned by [`wire_ephemeral_rotator`].  Caller
/// owns these handles; dropping the shutdown sender или the swap_tx
/// triggers the rotator + consumer tasks к exit cleanly.
#[derive(Debug)]
pub struct EphemeralRotatorHandles {
    /// Join handle for the rotation-loop task.
    pub rotator: JoinHandle<()>,
    /// Join handle for the consumer task что rebinds the listener
    /// after each `RotationEvent::Rotated` и pushes it to the accept
    /// loop через the swap channel.
    pub consumer: JoinHandle<()>,
    /// Watch sender to signal shutdown.  Both tasks observe это
    /// indirectly через the rotator's internal channel.
    pub shutdown: watch::Sender<bool>,
}

/// Build + spawn the rotator AND the listener-rebind consumer для
/// one ephemeral listen entry.  Caller has already bound the initial
/// listener separately; this helper drives subsequent rotations.
///
/// Returns `Err` если the operator's config is malformed (invalid
/// duration spec, inverted port range, zero rotation interval) —
/// caught up-front so spawn_listeners fails clearly при startup rather
/// than silently dying на the first rotation tick.
///
/// Accepts the listener swap channel (`listener_swap_tx`) что the
/// accept-loop owns the receiver of.  On each rotation, the consumer
/// task: parses the new URI, calls `registry.bind(new_uri)`, и pushes
/// the freshly-bound listener through swap_tx.  The accept loop drains
/// и swaps к the new listener между accepts.
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
    listener_swap_tx: mpsc::Sender<Box<dyn TransportListener>>,
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
    let host = listen_uri.plaintext_host().unwrap_or("0.0.0.0").to_owned();

    let spec = RotationSpec::new(
        host.clone(),
        port_lo..=port_hi,
        eph.bind_retries,
        rotation,
        grace,
    )
    .map_err(|e| format!("spec invalid: {e}"))?;

    // ── URI template для the broadcast payload ────────────────────
    // Prefer the operator's `advertise` URI as the template when set
    // (so peers learn the externally-reachable address rather than
    // the bind host).  When absent, fall back к the bind URI.
    let template_source = advertise_uri.cloned().unwrap_or_else(|| listen_uri.clone());
    let template_host = template_source
        .plaintext_host()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| host.clone());
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
    // stay valid past 4 full rotation cycles, so а receiver что misses
    // (say) 3 consecutive migration notifies still has а usable URI
    // until the operator's next rotation.
    let new_expiry_offset = rotation.saturating_mul(4);
    let (rotator_handle, mut events_rx, shutdown_tx) = spawn_ephemeral_rotator(
        spec,
        local_node_id,
        signing_key,
        uri_template,
        new_expiry_offset,
        session_tx_registry,
    );

    // ── consumer task: rebind + push к accept loop ────────────────
    let template_for_rebind = template_source;
    let host_for_rebind = template_host;
    let listen_id = listen_id_for_log;
    let consumer = tokio::spawn(async move {
        while let Some(ev) = events_rx.recv().await {
            match ev {
                RotationEvent::Rotated { new_port } => {
                    let Some(new_uri) =
                        template_for_rebind.with_host_port(host_for_rebind.clone(), new_port)
                    else {
                        logger.warn(
                            "listen.rotation.uri_compose_failed",
                            format!(
                                "listen_id={listen_id} could not compose new URI for port {new_port}",
                            ),
                        );
                        continue;
                    };
                    match registry.bind(&new_uri, Arc::clone(&listen_ctx)).await {
                        Ok(new_listener) => {
                            let local_addr = new_listener.local_addr();
                            if let Err(e) = listener_swap_tx.send(new_listener).await {
                                logger.warn(
                                    "listen.rotation.swap_send_failed",
                                    format!(
                                        "listen_id={listen_id} accept loop swap channel closed: {e}",
                                    ),
                                );
                                break;
                            }
                            logger.info(
                                "listen.rotation.swap_sent",
                                format!(
                                    "listen_id={listen_id} new_port={new_port} new_addr={local_addr}",
                                ),
                            );
                        }
                        Err(e) => {
                            logger.warn(
                                "listen.rotation.rebind_failed",
                                format!(
                                    "listen_id={listen_id} bind({new_uri:?}) failed: {e} \
                                     — old listener kept in service",
                                ),
                            );
                        }
                    }
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
    /// port в order then errors thereafter.
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
        // but we keep а duplicate-via-from_bytes so the test can verify
        // the sig against the matching pubkey.
        let sk_bytes = [0xA5u8; 32];
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_pk = signing_key.verifying_key().to_bytes();
        let local_node_id = *blake3::hash(&verifying_pk).as_bytes();

        // Build а live SessionTxRegistry + register one fake peer so we
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
        // outbox должно already carry а PriorityFrame.
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
        // only invoked после а successful bind.
        assert!(
            peer_rx.try_recv().is_err(),
            "broadcast must not fire when bind fails",
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    // ── wire_ephemeral_rotator error paths ──────────────────────────

    /// Helper: build а listen URI и EphemeralConfig for the validation
    /// tests.  Uses obfs4-tcp которое supports `with_host_port` (per
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
