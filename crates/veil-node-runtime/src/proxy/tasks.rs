//! SOCKS5 and exit-proxy spawn helpers —.
//!
//! Extracted from `NodeRuntime::spawn_socks5_task` and
//! `NodeRuntime::spawn_exit_proxy_task`. These previously sat among ~30
//! other `spawn_*_task` methods on `NodeRuntime`; moving them here keeps
//! proxy-specific imports and types grouped with the rest of the proxy
//! subsystem under `node/proxy/`.
//!
//! The functions still need several `NodeRuntime` references, so they take
//! a small context struct instead of `&mut NodeRuntime` — this makes the
//! coupling explicit rather than implicit.

use std::sync::{Arc, RwLock as StdRwLock};

use tokio::{sync::watch, task::JoinHandle};

use veil_app::AppEndpointRegistry;
use veil_cfg::{self as cfg, NodeId};
use veil_dispatcher::FrameDispatcher;
use veil_observability::NodeLogger;
use veil_session::SessionTxRegistry;

use veil_proxy::veil_connector::{PendingReceiptMap, VeilStreamRxMap};

use super::routed_frames::RoutedFrameBroadcaster;

/// References the SOCKS5 spawn needs from `NodeRuntime`. Grouping them
/// here keeps the caller site short.
pub(crate) struct Socks5SpawnCtx<'a> {
    pub config: &'a cfg::Config,
    pub shutdown_tx: &'a watch::Sender<bool>,
    pub logger: &'a Arc<NodeLogger>,
    pub session_tx_registry: Arc<StdRwLock<SessionTxRegistry>>,
    pub dispatcher: Arc<FrameDispatcher>,
    pub mlkem_ek_resolver: Arc<dyn veil_types::MlKemEkResolver>,
    pub local_node_id: NodeId,
    pub pending_stream_receipts: PendingReceiptMap,
    pub veil_stream_rx: VeilStreamRxMap,
    /// Shared wire stream-id allocator (see `NodeRuntime::wire_stream_counter`).
    pub wire_stream_counter: Arc<std::sync::atomic::AtomicU32>,
    /// optional metrics for throttle counter.
    pub metrics: Option<Arc<veil_observability::NodeMetrics>>,
}

/// Spawn the SOCKS5 listener task. Returns `None` when disabled in config
/// or when `exit_node_id` is not set (a warning is logged in that case).
pub(crate) fn spawn_socks5(ctx: Socks5SpawnCtx<'_>) -> Option<JoinHandle<()>> {
    if !ctx.config.proxy.socks5.enabled {
        return None;
    }

    let exit_node_id = match ctx.config.proxy.socks5.exit_node_id_bytes() {
        Some(id) => id,
        None => {
            ctx.logger.warn(
                "proxy.socks5.no_exit_node",
                "SOCKS5 proxy enabled but exit_node_id is not configured — not starting",
            );
            return None;
        }
    };

    // Prefer a direct authenticated session and transparently fall back to an
    // E2E-protected DHT-routed APP frame when the exit is not our neighbour.
    let broadcaster: Arc<dyn veil_types::FrameBroadcaster> = Arc::new(RoutedFrameBroadcaster::new(
        ctx.session_tx_registry,
        ctx.dispatcher,
        ctx.mlkem_ek_resolver,
    ));
    let connector = Arc::new(veil_proxy::VeilConnector::new(
        broadcaster,
        exit_node_id,
        *ctx.local_node_id.as_bytes(),
        ctx.pending_stream_receipts,
        ctx.veil_stream_rx,
        ctx.wire_stream_counter,
    ));
    let proxy_metrics: Option<Arc<dyn veil_proxy::ProxyMetrics>> = ctx
        .metrics
        .clone()
        .map(|m| m as Arc<dyn veil_proxy::ProxyMetrics>);
    let proxy = Arc::new(
        veil_proxy::Socks5Proxy::new(
            &ctx.config.proxy.socks5.listen,
            exit_node_id,
            connector as Arc<dyn veil_proxy::socks5::ProxyConnector>,
        )
        .with_metrics(proxy_metrics),
    );

    let listen = ctx.config.proxy.socks5.listen.clone();
    ctx.logger.info(
        "proxy.socks5.start",
        format!("SOCKS5 proxy listening on {listen}"),
    );

    Some(tokio::spawn(proxy.run(ctx.shutdown_tx.subscribe())))
}

/// References the exit proxy spawn needs.
pub(crate) struct ExitProxySpawnCtx<'a> {
    pub config: &'a cfg::Config,
    pub logger: &'a Arc<NodeLogger>,
    pub dispatcher: Arc<FrameDispatcher>,
    pub app_registry: Arc<AppEndpointRegistry>,
    pub session_tx_registry: Arc<StdRwLock<SessionTxRegistry>>,
    pub mlkem_ek_resolver: Arc<dyn veil_types::MlKemEkResolver>,
}

/// Spawn the exit-proxy accept loop. Registers the well-known
/// `EXIT_PROXY_APP_ID` endpoint and handles incoming proxy-connect streams.
/// Returns `None` when disabled in config.
pub(crate) fn spawn_exit_proxy(ctx: ExitProxySpawnCtx<'_>) -> Option<JoinHandle<()>> {
    use veil_app::AppMessage;
    use veil_proxy::veil_connector::run_server_bridge;
    use veil_proxy::{EXIT_PROXY_APP_ID, EXIT_PROXY_ENDPOINT_ID};

    if !ctx.config.proxy.exit.enabled {
        return None;
    }
    let role = ctx.dispatcher.role;

    // Channel capacity 256 absorbs bursts of StreamOpen + StreamData events
    // before back-pressure kicks in.
    let (ep_handle, mut rx) =
        ctx.app_registry
            .register(EXIT_PROXY_APP_ID, EXIT_PROXY_ENDPOINT_ID, 256);

    let broadcaster: Arc<dyn veil_types::FrameBroadcaster> = Arc::new(RoutedFrameBroadcaster::new(
        ctx.session_tx_registry,
        Arc::clone(&ctx.dispatcher),
        ctx.mlkem_ek_resolver,
    ));
    let exit_enabled = ctx.config.proxy.exit.enabled;
    let allow_private = ctx.config.proxy.exit.allow_private;
    let logger = Arc::clone(ctx.logger);
    // pass metrics into the exit handler so destination
    // denials are counted for ops visibility.
    let metrics: Option<Arc<dyn veil_proxy::ProxyMetrics>> = ctx
        .dispatcher
        .metrics
        .clone()
        .map(|m| m as Arc<dyn veil_proxy::ProxyMetrics>);

    ctx.logger
        .info("proxy.exit.start", "exit proxy accept loop started");

    Some(tokio::spawn(async move {
        // Keep the endpoint handle alive for the lifetime of the loop.
        let _ep_handle = ep_handle;
        // Per-stream data channels: stream_id → sender.
        let mut stream_data_txs: std::collections::HashMap<
            u32,
            tokio::sync::mpsc::Sender<Vec<u8>>,
        > = std::collections::HashMap::new();

        /// Maximum concurrent exit-proxy streams (prevents resource exhaustion).
        const MAX_EXIT_STREAMS: usize = 1024;

        while let Some(msg) = rx.recv().await {
            match msg {
                AppMessage::StreamOpen {
                    stream_id,
                    src_node_id,
                    ..
                } => {
                    // Prune stale entries (closed channels) before cap check.
                    stream_data_txs.retain(|_, tx| !tx.is_closed());
                    if stream_data_txs.len() >= MAX_EXIT_STREAMS {
                        logger.warn(
                            "proxy.exit.cap_reached",
                            format!(
                                "exit proxy stream cap {} reached; rejecting stream_id={}",
                                MAX_EXIT_STREAMS, stream_id
                            ),
                        );
                        continue;
                    }
                    let (data_tx, data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(
                        veil_proto::budget::PROXY_STREAM_CHANNEL_CAP,
                    );
                    stream_data_txs.insert(stream_id, data_tx);

                    // Inner duplex pipe: bridge task ↔ proxy handler.
                    let (client_half, server_half) = tokio::io::duplex(256 * 1024);

                    // Bridge: server_half ↔ veil. : handle is
                    // dropped intentionally — the proxy-bridge lifecycle
                    // follows the stream, and the detached task exits when
                    // the pipe closes.
                    let _bridge = tokio::spawn(run_server_bridge(
                        server_half,
                        data_rx,
                        src_node_id,
                        stream_id,
                        Arc::clone(&broadcaster),
                    ));

                    // Exit handler: client_half ↔ TCP. Same
                    // lifecycle rule as above.
                    let _connect =
                        tokio::spawn(veil_proxy::exit::handle_proxy_connect_stream_with_metrics(
                            role,
                            exit_enabled,
                            allow_private,
                            metrics.clone(),
                            client_half,
                        ));
                }
                AppMessage::StreamData { stream_id, data } => {
                    if let Some(tx) = stream_data_txs.get(&stream_id) {
                        match tx.try_send(data) {
                            Ok(()) => {}
                            // Channel full: SOCKS5 egress can't keep up.
                            // Drop the entry so the bridge task detects
                            // receiver closure and sends APP_CLOSE back.
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_))
                            | Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                stream_data_txs.remove(&stream_id);
                            }
                        }
                    }
                }
                AppMessage::StreamClose { stream_id } => {
                    stream_data_txs.remove(&stream_id);
                }
                _ => {}
            }
        }
        logger.info("proxy.exit.stop", "exit proxy accept loop ended");
    }))
}
