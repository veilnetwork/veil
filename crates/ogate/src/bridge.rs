//! TUN ↔ veil IPC bridge.
//!
//! Wires three components:
//!
//! * **TUN device** (one of the platform-specific `tun::*` impls).
//! * **VeilClient** IPC connection bound to a named endpoint
//!   `(namespace="ogate.<network>", name=<app>, endpoint=<cfg.endpoint_id>)`.
//! * **`SharedState`** (peer routing table + pre-computed peer app_ids),
//!   held in an `ArcSwap` so SIGHUP can hot-reload the peer table without
//!   restarting the bridge.
//!
//! Three background tasks:
//! * **Egress**: TUN read → parse dst IP → `state.load()` lookup → `AppSender::send`.
//! * **Ingress**: `AppReceiver::recv` → `state.load()` mode / anti-spoof → TUN write.
//! * **Routes**: recheck P-Net admission and apply SIGHUP configuration
//!   changes through an atomic routing snapshot.
//!
//! On `ctrl_c` / `SIGTERM` all tasks exit and the function returns.

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{Mutex, Notify, watch};
use veil_util::unix_secs_now_u64;
use veilclient::client::PnetStatus;
use veilclient::{APP_IPC_SEND_PREFIX_BYTES, AppHandle, VeilClient};

use crate::app_id::{derive_app_id, namespace_for};
use crate::batch::{BatchIter, EgressBatches, is_batch_envelope};
use crate::config::OgateConfig;
use crate::routing::{Decision, NodeId, RoutingTable, parse_ip_endpoints};
use crate::tun::{Device, Reader, Writer};

/// Egress flush threshold (bytes).  When a per-peer batch crosses this size,
/// or the NEXT push would push it over, we ship the batch immediately.
///
/// Phase E27 root cause (2026-05-22):  obfs4 transport hard-caps a single
/// frame ciphertext at `MAX_FRAME_CIPHERTEXT_BYTES = 16384`
/// ([crates/veil-obfs4/src/lib.rs](crates/veil-obfs4/src/lib.rs)).  Above
/// that, `wrap_frame` returns `OversizedFrame`, the writer task exits, and the
/// session closes.  Obfs4 also appends random 0-1024 bytes of padding per
/// frame, so the SAFE plaintext-payload ceiling is:
///   16384 − 1024 (worst-case pad) − 17 (obfs4 hdr + tag) − 16 (session AEAD
///   tag) − 24 (FrameHeader) − 72 (AppSendPayload header) ≈ 15 231 bytes.
///
/// Set to 14 000 for conservative headroom against jitter in padding/tag math.
/// Pre-flush logic below ensures the NEXT push checks BEFORE appending — so
/// a single TUN packet larger than this threshold ships solo (= effectively
/// pre-E27 behaviour for big packets), and multi-packet batching only happens
/// when individual packets are small enough to coalesce.
///
/// At MTU 1500 each batch fits ~9 packets; at MTU 4500 ~3 packets; at MTU
/// ≥ 14 000 each packet ships solo (no batching win — drop the testnet MTU
/// if you want batching benefit).
///
/// Overrideable via `OGATE_BATCH_BYTES` env var:  bench-only knob for local
/// stands where the daemon-to-daemon TCP is plain (no obfs4 cap), so larger
/// batches can be safely shipped.  Production / testnet (obfs4) must keep
/// the default to stay under `MAX_FRAME_CIPHERTEXT_BYTES` (16 KiB).
const EGRESS_FLUSH_BYTES_DEFAULT: usize = 14_000;

// Hard ceiling for a single solo-shipped packet's payload over obfs4
// (`MAX_OBFS4_SOLO_PAYLOAD_BYTES`, defined at crate root so `config::validate`
// reaches it on all platforms — a unix-only home broke the Windows release
// build). Derived from `MAX_FRAME_CIPHERTEXT_BYTES = 16384` minus the worst-case
// obfs4 padding (1024), obfs4 hdr+tag (17), session AEAD tag (16), `FrameHeader`
// (24) and `AppSendPayload` header (72) — same arithmetic as
// `EGRESS_FLUSH_BYTES_DEFAULT`'s rationale. Above it, `wrap_frame` would return
// `OversizedFrame` and tear down the session, so we drop just that packet.
use crate::MAX_OBFS4_SOLO_PAYLOAD_BYTES;

fn egress_flush_bytes() -> usize {
    std::env::var("OGATE_BATCH_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(EGRESS_FLUSH_BYTES_DEFAULT)
}

// Phase E27 kill-switch:  was a compile-time const, now config-driven
// via `[batch] enabled = bool` (default true; see `OgateConfig::batch`).
// Audit batch 2026-05-24 (M13): rolling upgrade safety — operators can
// flip off batching during mixed-version rollouts without re-compile.

/// Egress max-batch-age before forced flush.  Tradeoff: smaller = lower latency,
/// larger = better coalescing.  200 µs picks the same order-of-magnitude as the
/// tokio scheduling jitter we see in production traces, so coalescing aggregates
/// "what naturally arrives between schedules" without adding visible latency.
const EGRESS_FLUSH_AFTER: Duration = Duration::from_micros(200);

/// Hot-swappable state: peer routing decisions + peer app_id lookup.
///
/// Egress and ingress tasks `.load()` this on every packet. SIGHUP swaps
/// it in one atomic store.
#[derive(Clone)]
pub struct SharedState {
    pub table: RoutingTable,
    /// Same peer set as the table, materialized as `(node_id, app_id)`
    /// and sorted by node_id at build time for binary lookup on egress.
    pub peer_app_ids: Vec<(NodeId, [u8; 32])>,
    // Only finite deadlines need a wall-clock read on the packet path.
    pnet_expiries: HashMap<NodeId, u64>,
    // Admission sweeps keep this marker. Reloaded address allocations get a new one.
    routing_config: Arc<()>,
    /// Configured virtual-iface MTU. Used by the ingress task to drop
    /// oversize packets BEFORE writing to TUN — a compromised peer cannot
    /// inject larger-than-expected frames that would either fragment
    /// unexpectedly or trip kernel-side anomaly handling.
    pub mtu: u16,
}

impl SharedState {
    pub fn build(cfg: &OgateConfig) -> Result<Self, BridgeError> {
        let table = RoutingTable::from_config(cfg).map_err(|e| BridgeError::Routing(e.into()))?;
        let mut peer_app_ids: Vec<_> = table
            .peer_node_ids()
            .map(|nid| (*nid, derive_app_id(nid, &cfg.network, &cfg.app)))
            .collect();
        peer_app_ids.sort_unstable_by_key(|(node_id, _)| *node_id);
        Ok(Self {
            table,
            peer_app_ids,
            pnet_expiries: HashMap::new(),
            routing_config: Arc::new(()),
            mtu: cfg.mtu,
        })
    }

    fn with_pnet_admissions(&self, admissions: &HashMap<NodeId, u64>) -> Self {
        let mut state = self.clone();
        state
            .table
            .retain_peers(|peer| admissions.contains_key(peer));
        state
            .peer_app_ids
            .retain(|(peer, _)| admissions.contains_key(peer));
        state.pnet_expiries = state
            .peer_app_ids
            .iter()
            .filter_map(|(peer, _)| {
                let expires = admissions[peer];
                (expires != 0).then_some((*peer, expires))
            })
            .collect();
        state
    }

    fn app_id_for(&self, peer: &NodeId) -> Option<[u8; 32]> {
        if !self.cert_is_current(peer) {
            return None;
        }
        self.peer_app_ids
            .binary_search_by_key(peer, |(node_id, _)| *node_id)
            .ok()
            .map(|index| self.peer_app_ids[index].1)
    }

    fn permits_queued_egress(&self, config: &Arc<()>, peer: &NodeId, app_id: [u8; 32]) -> bool {
        Arc::ptr_eq(config, &self.routing_config) && self.app_id_for(peer) == Some(app_id)
    }

    fn cert_is_current(&self, peer: &NodeId) -> bool {
        self.pnet_expiries.get(peer).is_none_or(|expires| {
            let now = unix_secs_now_u64();
            now != 0 && now < *expires
        })
    }
}

const PNET_REFRESH_PERIOD: Duration = Duration::from_secs(5);
const PNET_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const PNET_LEGACY_QUERY_GROUP: usize = 16;
// Daemons admit 10 local queries per second per IPC client. Leave room for
// other local queries and avoid consuming the burst quota at startup.
const PNET_QUERY_SPACING: Duration = Duration::from_millis(125);

fn pnet_status_admits(peer: &NodeId, status: &PnetStatus, now: u64) -> bool {
    status.peer_node_id == *peer
        && status.admitted
        && status.has_cert
        && (status.valid_until_unix == 0 || (now != 0 && now < status.valid_until_unix))
}

async fn connect_pnet_status(
    socket: &Path,
    expected_node: NodeId,
    pace: &mut tokio::time::Interval,
) -> Option<Arc<VeilClient>> {
    pace.tick().await;
    let connect = async {
        let client = VeilClient::connect(socket)
            .await
            .map_err(BridgeError::client)?;
        let identity = client.node_identity().await.map_err(BridgeError::client)?;
        if identity.node_id != expected_node {
            return Err(BridgeError::IdentityChanged);
        }
        Ok(client)
    };
    match tokio::time::timeout(PNET_QUERY_TIMEOUT, connect).await {
        Ok(Ok(client)) => Some(Arc::new(client)),
        Ok(Err(error)) => {
            tracing::debug!(%error, "P-Net status connection failed");
            None
        }
        Err(_) => {
            tracing::debug!("P-Net status connection timed out");
            None
        }
    }
}

async fn query_pnet_batch(
    client: &VeilClient,
    peers: &[(NodeId, [u8; 32])],
    pace: &mut tokio::time::Interval,
) -> Option<HashMap<NodeId, u64>> {
    let ids: Vec<_> = peers.iter().map(|(node_id, _)| *node_id).collect();
    pace.tick().await;
    let reply = tokio::time::timeout(PNET_QUERY_TIMEOUT, client.peer_pnet_admissions(&ids)).await;
    match reply {
        Ok(Ok(entries)) => {
            let now = unix_secs_now_u64();
            Some(
                entries
                    .into_iter()
                    .filter_map(|entry| {
                        let expiry = entry.valid_until_unix?;
                        (expiry == 0 || (now != 0 && now < expiry))
                            .then_some((entry.peer_node_id, expiry))
                    })
                    .collect(),
            )
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "P-Net admission batch failed");
            None
        }
        Err(_) => {
            tracing::warn!("P-Net admission batch timed out");
            None
        }
    }
}

async fn query_pnet_legacy(
    client: &Arc<VeilClient>,
    peers: &[(NodeId, [u8; 32])],
    pace: &mut tokio::time::Interval,
) -> (HashMap<NodeId, u64>, bool) {
    let mut queries = tokio::task::JoinSet::new();
    for &(peer, _) in peers {
        pace.tick().await;
        let client = Arc::clone(client);
        queries.spawn(async move {
            let reply =
                tokio::time::timeout(PNET_QUERY_TIMEOUT, client.peer_pnet_status(&peer)).await;
            (peer, reply)
        });
    }

    let mut admitted = HashMap::new();
    let mut uncertain = false;
    while let Some(result) = queries.join_next().await {
        match result {
            Ok((peer, Ok(Ok(status)))) if status.peer_node_id != peer => {
                uncertain = true;
                tracing::warn!("P-Net status reply did not match the requested peer");
            }
            Ok((peer, Ok(Ok(status))))
                if pnet_status_admits(&peer, &status, unix_secs_now_u64()) =>
            {
                admitted.insert(peer, status.valid_until_unix);
            }
            Ok((peer, Ok(Ok(status)))) => {
                tracing::debug!(peer = %hex::encode(peer), admitted = status.admitted,
                    has_cert = status.has_cert, "peer has no current P-Net admission");
            }
            Ok((peer, Ok(Err(error)))) => {
                uncertain = true;
                tracing::debug!(peer = %hex::encode(peer), %error, "P-Net status query failed");
            }
            Ok((peer, Err(_))) => {
                uncertain = true;
                tracing::debug!(peer = %hex::encode(peer), "P-Net status query timed out");
            }
            Err(error) => {
                uncertain = true;
                tracing::warn!(%error, "P-Net status task failed");
            }
        }
    }
    // The caller resets this connection on failure. Some daemons send zero
    // IDs here, so an abandoned reply must never answer a later sweep.
    (admitted, uncertain)
}

fn publish_routes(candidate: SharedState, state: &ArcSwap<SharedState>, route_changes: &Notify) {
    let peers_changed = candidate.peer_app_ids != state.load().peer_app_ids;
    tracing::info!(peers = candidate.table.peer_count(), "updated ogate routes");
    state.store(Arc::new(candidate));
    if peers_changed {
        route_changes.notify_one();
    }
}

/// Validate that a reloaded config did not change fields that bind to
/// kernel / IPC resources we cannot swap mid-flight. Returns the offending
/// field name on conflict.
pub fn validate_reload(old: &OgateConfig, new: &OgateConfig) -> Result<(), &'static str> {
    if old.network != new.network {
        return Err("network");
    }
    if old.app != new.app {
        return Err("app");
    }
    if old.endpoint_id != new.endpoint_id {
        return Err("endpoint_id");
    }
    if old.iface_name != new.iface_name {
        return Err("iface_name");
    }
    if old.mtu != new.mtu {
        return Err("mtu");
    }
    if old.local_addr_v4 != new.local_addr_v4 {
        return Err("local_addr_v4");
    }
    if old.prefix_v4 != new.prefix_v4 {
        return Err("prefix_v4");
    }
    if old.local_addr_v6 != new.local_addr_v6 {
        return Err("local_addr_v6");
    }
    if old.prefix_v6 != new.prefix_v6 {
        return Err("prefix_v6");
    }
    if old.socket_path != new.socket_path {
        return Err("socket_path");
    }
    // `mode` and `peers` are intentionally reloadable.
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Binding {
    node_id: NodeId,
    app_id: [u8; 32],
}

struct BoundIpc {
    client: VeilClient,
    handle: AppHandle,
    binding: Binding,
}

const REBIND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REBIND_DELAY: Duration = Duration::from_secs(5);

async fn bind_ipc(cfg: &OgateConfig, expected: Option<Binding>) -> Result<BoundIpc, BridgeError> {
    let client = VeilClient::connect(&cfg.socket_path)
        .await
        .map_err(BridgeError::client)?;
    bind_client(client, cfg, expected).await
}

async fn bind_client(
    client: VeilClient,
    cfg: &OgateConfig,
    expected: Option<Binding>,
) -> Result<BoundIpc, BridgeError> {
    let node_id = client
        .node_identity()
        .await
        .map_err(BridgeError::client)?
        .node_id;
    if expected.is_some_and(|binding| binding.node_id != node_id) {
        return Err(BridgeError::IdentityChanged);
    }
    let namespace = namespace_for(&cfg.network);
    let handle = client
        .bind_named(&namespace, &cfg.app, cfg.endpoint_id)
        .await
        .map_err(BridgeError::client)?;
    let binding = Binding {
        node_id,
        app_id: *handle.app_id(),
    };
    if expected.is_some_and(|expected| binding != expected) {
        return Err(BridgeError::IdentityChanged);
    }
    tracing::info!(
        namespace,
        endpoint = cfg.endpoint_id,
        "bound ogate IPC endpoint"
    );
    Ok(BoundIpc {
        client,
        handle,
        binding,
    })
}

async fn reconnect_ipc(cfg: &OgateConfig, expected: Binding) -> BoundIpc {
    let mut delay = Duration::from_millis(250);
    loop {
        tokio::time::sleep(delay).await;
        match tokio::time::timeout(REBIND_TIMEOUT, bind_ipc(cfg, Some(expected))).await {
            Ok(Ok(link)) => return link,
            Ok(Err(error)) => tracing::warn!(%error, "ogate IPC rebind failed"),
            Err(_) => tracing::warn!("ogate IPC rebind timed out"),
        }
        delay = (delay * 2).min(MAX_REBIND_DELAY);
    }
}

struct Bridge {
    config_path: PathBuf,
    accepted: watch::Sender<OgateConfig>,
    hup: Arc<Mutex<Option<Signal>>>,
    reader: Arc<Mutex<Reader>>,
    writer: Arc<Mutex<Writer>>,
    cert_gate: Option<Arc<crate::app_cert_gate::AppCertGate>>,
    cert_message: Option<Arc<Vec<u8>>>,
    batching_enabled: bool,
}

enum LinkExit {
    Shutdown,
    DaemonDisconnected,
}

fn reload_signal() -> Option<Signal> {
    match signal(SignalKind::hangup()) {
        Ok(signal) => Some(signal),
        Err(error) => {
            tracing::warn!(%error, "SIGHUP handler install failed; reload disabled");
            None
        }
    }
}

/// Run the bridge with one TUN interface across daemon reconnects.
pub async fn run(config_path: PathBuf, cfg: OgateConfig) -> Result<(), BridgeError> {
    SharedState::build(&cfg)?;
    tracing::info!(socket = %cfg.socket_path.display(), "connecting to veil daemon");
    let mut link = bind_ipc(&cfg, None).await?;
    let expected = link.binding;
    // ── S2.B app-cert authority (optional) ──────────────────────────────
    let app_cert_gate: Option<Arc<crate::app_cert_gate::AppCertGate>> = match (
        &cfg.app_cert_trusted_owner_pubkey,
        cfg.app_cert_owner_algo,
        &cfg.app_cert_network_id,
    ) {
        (Some(pk), Some(algo), Some(nid)) => {
            let gate = crate::app_cert_gate::AppCertGate::from_config(pk, algo, nid)
                .map_err(|e| BridgeError::Cfg(format!("app_cert gate build: {e}").into()))?;
            tracing::info!(network_id = %nid, "app-cert gate active");
            Some(Arc::new(gate))
        }
        (None, None, None) => None,
        _ => {
            return Err(BridgeError::Cfg(
                "app_cert_trusted_owner_pubkey + app_cert_owner_algo + \
                 app_cert_network_id must all be set together (or none)."
                    .into(),
            ));
        }
    };
    let own_cert_blob: Option<Vec<u8>> = match &cfg.app_cert_path {
        Some(path) => {
            let bytes = std::fs::read(path).map_err(|e| {
                BridgeError::Cfg(format!("read app_cert_path={}: {e}", path.display()).into())
            })?;
            tracing::info!(
                path = %path.display(),
                bytes = bytes.len(),
                "loaded app-cert blob"
            );
            Some(bytes)
        }
        None => None,
    };
    let cert_message = own_cert_blob.as_deref().and_then(|blob| {
        let msg = crate::cert_message::encode_cert_message(blob);
        if msg.is_none() {
            tracing::error!("app certificate too large or empty");
        }
        msg.map(Arc::new)
    });
    let device = Device::new(&cfg).await.map_err(BridgeError::Tun)?;
    tracing::info!(iface = %device.name(), "TUN device up");
    let (reader, writer) = device.split();
    let batching_enabled = cfg.batch.enabled;
    let (accepted, _) = watch::channel(cfg);
    let bridge = Bridge {
        config_path,
        accepted,
        hup: Arc::new(Mutex::new(reload_signal())),
        reader: Arc::new(Mutex::new(reader)),
        writer: Arc::new(Mutex::new(writer)),
        cert_gate: app_cert_gate,
        cert_message,
        batching_enabled,
    };
    let mut stopping = std::pin::pin!(wait_for_shutdown());

    loop {
        match serve_link(&bridge, link, stopping.as_mut()).await? {
            LinkExit::Shutdown => return Ok(()),
            LinkExit::DaemonDisconnected => tracing::warn!("ogate IPC disconnected; rebinding"),
        }
        let cfg = bridge.accepted.borrow().clone();
        link = tokio::select! {
            _ = stopping.as_mut() => return Ok(()),
            link = reconnect_ipc(&cfg, expected) => link,
        };
    }
}

async fn serve_link(
    bridge: &Bridge,
    link: BoundIpc,
    mut stopping: Pin<&mut impl Future<Output = ()>>,
) -> Result<LinkExit, BridgeError> {
    let BoundIpc {
        mut client,
        handle,
        binding,
    } = link;
    let cfg = bridge.accepted.borrow().clone();
    let configured = SharedState::build(&cfg)?;
    let initial_state = if cfg.pnet_required {
        configured.with_pnet_admissions(&HashMap::new())
    } else {
        configured.clone()
    };
    let state = Arc::new(ArcSwap::from_pointee(initial_state));
    let endpoint_id = cfg.endpoint_id;
    let (app_sender, mut app_receiver) = handle.into_split();
    let app_sender = Arc::new(app_sender);

    // Keep a retained shutdown notification for egress even while it is writing.
    let (shutdown, shutdown_rx) = watch::channel(false);

    // ── S2.B sender-side: periodic cert broadcast ──────────────────────
    // When `app_cert_path` is set, ogate emits its cert to every
    // configured peer at startup (so receivers can populate their cache
    // before regular packets arrive) and then every 5 min thereafter (so
    // peers that came online late or restarted still get the cert).
    let route_changes = Arc::new(Notify::new());
    let cert_broadcast_task = bridge.cert_message.as_ref().map(|msg_bytes| {
        let msg_bytes = Arc::clone(msg_bytes);
        let app_sender = Arc::clone(&app_sender);
        let state = Arc::clone(&state);
        let route_changes = Arc::clone(&route_changes);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            loop {
                let snap = state.load_full();
                for &(peer_node_id, app_id) in &snap.peer_app_ids {
                    if state.load().app_id_for(&peer_node_id) == Some(app_id) {
                        let _ = app_sender
                            .send_owned(peer_node_id, app_id, endpoint_id, (*msg_bytes).clone())
                            .await;
                    }
                }
                tokio::select! {
                    _ = route_changes.notified() => {},
                    _ = tokio::time::sleep(Duration::from_secs(300)) => {},
                }
            }
        })
    });

    // ── Egress: TUN → veil (batched) ─────────────────────────────────
    //
    // Phase E27: instead of shipping one IPC frame per IP packet, coalesce
    // packets per peer destination into a batch envelope (BATCH_MAGIC + count
    // + N × (u16 len, ip-packet)).  Flush triggers:
    //   * a batch hits `EGRESS_FLUSH_BYTES` (size cap)
    //   * a batch hits 255 packets (count cap, enforced by `should_flush`)
    //   * `EGRESS_FLUSH_AFTER` elapses since the batch's first push
    //
    // Legacy peers parse the envelope's first byte as `version|IHL`, fail
    // both IPv4 (0x4N) and IPv6 (0x6N) checks, and silently drop. Upgraded
    // peers branch on `is_batch_envelope` in the ingress loop.
    // Resolve egress batch threshold ONCE at task spawn (env override).
    let egress_flush_bytes = egress_flush_bytes();
    if egress_flush_bytes != EGRESS_FLUSH_BYTES_DEFAULT {
        tracing::info!(
            bytes = egress_flush_bytes,
            "egress batch threshold overridden via OGATE_BATCH_BYTES"
        );
    }

    // Audit batch 2026-05-24 (M13): config-driven kill-switch.
    let batching_enabled = bridge.batching_enabled;
    tracing::info!(
        batching_enabled,
        "egress batching state — set [batch] enabled = false for rolling-upgrade safety"
    );

    let mut egress = {
        let state = Arc::clone(&state);
        let tun_r = Arc::clone(&bridge.reader);
        let mut shutdown = shutdown_rx;
        let app_sender = Arc::clone(&app_sender);
        tokio::spawn(async move {
            let mut tun_r = tun_r.lock().await;
            let mut batches = EgressBatches::with_ipc_prefix();
            let mut routing_config = Arc::clone(&state.load().routing_config);
            let enqueue = async |config: &Arc<()>, peer_nid, peer_app_id, buf, is_batch| {
                if !state
                    .load()
                    .permits_queued_egress(config, &peer_nid, peer_app_id)
                {
                    return;
                }
                let result = if is_batch {
                    app_sender
                        .send_prepared_recoverable(peer_nid, peer_app_id, endpoint_id, buf)
                        .await
                } else {
                    app_sender
                        .send_prepared(peer_nid, peer_app_id, endpoint_id, buf)
                        .await
                };
                if let Err(error) = result {
                    tracing::warn!(%error, "ogate egress send failed");
                }
            };
            loop {
                // Pick wake-up source: either the TUN reader OR a deadline timer
                // for the oldest pending batch.  `tokio::time::sleep_until` requires
                // a concrete Instant; if no batch is open, just sleep "forever"
                // (the TUN read will wake us first).
                let deadline = batches
                    .earliest_deadline()
                    .map(|first| first + EGRESS_FLUSH_AFTER);
                let timer = async {
                    match deadline {
                        Some(d) => tokio::time::sleep_until(d.into()).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                tokio::select! {
                    _ = shutdown.changed() => {
                        // Best-effort flush on graceful shutdown.
                        for (peer_nid, envelope, peer_app_id) in batches.drain_all() {
                            enqueue(&routing_config, peer_nid, peer_app_id, envelope, true).await;
                        }
                        break;
                    }
                    _ = timer => {
                        // Timer fired: flush every batch whose deadline has expired.
                        let cutoff = std::time::Instant::now() - EGRESS_FLUSH_AFTER;
                        for (peer_nid, envelope, peer_app_id) in batches.drain_expired(cutoff) {
                            enqueue(&routing_config, peer_nid, peer_app_id, envelope, true).await;
                        }
                    }
                    res = tun_r.read_packet_with_prefix(APP_IPC_SEND_PREFIX_BYTES) => match res {
                        Err(e) => {
                            return Err(BridgeError::Tun(e.into()));
                        }
                        Ok(buf) => {
                            // `buf` layout: [reserved prefix][IP packet bytes].
                            // The PREFIX region is filled in-place by the SDK's
                            // `send_prepared` when we forward `buf` verbatim
                            // (solo-ship and raw paths) — zero memcpy of the
                            // packet body downstream.
                            if buf.len() <= APP_IPC_SEND_PREFIX_BYTES { continue; }
                            let pkt = &buf[APP_IPC_SEND_PREFIX_BYTES..];
                            let Some((_src, dst)) = parse_ip_endpoints(pkt) else {
                                tracing::trace!("dropping non-ip packet from tun");
                                continue;
                            };
                            let snap = state.load();
                            let peer_nid = match snap.table.lookup_egress(dst) {
                                Decision::Forward(n) => {
                                    tracing::trace!(?dst, peer = %hex::encode(&n[..4]), "egress: forwarding to peer");
                                    n
                                }
                                Decision::NoRoute => {
                                    tracing::trace!(?dst, "egress: no peer for dst, dropping");
                                    continue;
                                }
                                other => {
                                    tracing::trace!(decision = ?other, "egress decision unexpected");
                                    continue;
                                }
                            };
                            let Some(peer_app_id) = snap.app_id_for(&peer_nid) else {
                                tracing::trace!("egress: peer route unavailable");
                                continue;
                            };
                            if !Arc::ptr_eq(&routing_config, &snap.routing_config) {
                                batches = EgressBatches::with_ipc_prefix();
                                routing_config = Arc::clone(&snap.routing_config);
                            }
                            // Drop the snap before await — `ArcSwap::load` returns
                            // a guard that should be short-lived.
                            drop(snap);

                            // Oversize guard (audit cycle-9 — completes cycle-8 H10):
                            // hoisted ABOVE the batching/raw split so it covers BOTH
                            // paths. A packet above the obfs4-safe payload ceiling makes
                            // wrap_frame return OversizedFrame, exits the writer task and
                            // tears down the WHOLE session. Previously the guard lived
                            // only in the batching branch's solo-ship sub-path, so with
                            // `[batch] enabled = false` (raw mode) a full-MTU packet still
                            // tore the session down. Drop just this packet; the peer
                            // retransmits at a smaller PMTU. Keep tunnel MTU ≤ the ceiling.
                            if pkt.len() > MAX_OBFS4_SOLO_PAYLOAD_BYTES {
                                tracing::warn!(
                                    peer = %hex::encode(peer_nid),
                                    len = pkt.len(),
                                    ceiling = MAX_OBFS4_SOLO_PAYLOAD_BYTES,
                                    "egress: dropping oversize packet (would exceed obfs4 \
                                     frame ceiling and tear down the session)",
                                );
                                continue;
                            }

                            if batching_enabled {
                                // Per-record size = u16 len + pkt bytes.
                                let pkt_len = pkt.len();
                                let record_size = 2 + pkt_len;
                                // Solo-ship: a single packet bigger than the
                                // batch cap can't EVER fit in a multi-pkt envelope
                                // — send raw to keep wire frame under the obfs4
                                // 16K ciphertext cap.  E26 behaviour for big pkts.
                                if record_size + 2 /* batch header */ > egress_flush_bytes {
                                    // (Oversize is already guarded above the
                                    // batching/raw split — this solo-ship path only
                                    // handles packets within the obfs4 ceiling.)
                                    // Flush any pending batch first to preserve
                                    // ordering relative to this big packet.
                                    if let Some(envelope) = batches.take_peer(&peer_nid) {
                                        enqueue(&routing_config, peer_nid, peer_app_id, envelope, true).await;
                                    }
                                    enqueue(&routing_config, peer_nid, peer_app_id, buf, false).await;
                                } else {
                                    // Pre-flush: if appending would cross the
                                    // threshold, flush the current batch FIRST,
                                    // then start a fresh batch with this packet.
                                    if batches.peek_mut(&peer_nid)
                                        .is_some_and(|batch| batch.len() + record_size > egress_flush_bytes)
                                        && let Some(envelope) = batches.take_peer(&peer_nid)
                                    {
                                        enqueue(&routing_config, peer_nid, peer_app_id, envelope, true).await;
                                    }
                                    let pb = batches.get_or_create(peer_nid, peer_app_id);
                                    pb.push(pkt);
                                    if pb.should_flush(egress_flush_bytes)
                                        && let Some(envelope) = batches.take_peer(&peer_nid)
                                    {
                                        enqueue(&routing_config, peer_nid, peer_app_id, envelope, true).await;
                                    }
                                }
                            } else {
                                // Raw mode (E27 kill-switch off): preserve E26
                                // wire-byte compatibility.  Zero-copy: SDK fills
                                // PREFIX inside `buf` and forwards as-is.
                                enqueue(&routing_config, peer_nid, peer_app_id, buf, false).await;
                            }
                        }
                    }
                }
            }
            Ok::<(), BridgeError>(())
        })
    };

    // ── Ingress: veil → TUN ──────────────────────────────────────────
    let mut ingress = {
        let state = Arc::clone(&state);
        let tun_w = Arc::clone(&bridge.writer);
        let app_cert_gate_for_ingress = bridge.cert_gate.clone();
        tokio::spawn(async move {
            let mut tun_w = tun_w.lock().await;
            let mut verified_peers = HashMap::new();
            loop {
                match app_receiver.recv().await {
                    Err(e) => {
                        tracing::error!(error = %e, "AppReceiver error; ingress task exiting");
                        break;
                    }
                    Ok(None) => {
                        tracing::warn!("AppReceiver closed; ingress task exiting");
                        break;
                    }
                    Ok(Some(im)) => {
                        // S2.B: cert message intercept BEFORE any IP-packet
                        // dispatch.  Marker 0xC0 is outside IPv4/IPv6 version
                        // nibbles + distinct from batch envelope (0xB1).
                        if crate::cert_message::is_cert_message(&im.data) {
                            match crate::cert_message::decode_cert_message(&im.data) {
                                Ok(blob) => {
                                    if let Some(gate) = app_cert_gate_for_ingress.as_ref() {
                                        match gate.verify(&blob, &im.src_node_id) {
                                            Ok(valid_until) => {
                                                verified_peers.insert(im.src_node_id, valid_until);
                                                tracing::info!(
                                                    src = %hex::encode(im.src_node_id),
                                                    valid_until,
                                                    "app-cert verified for peer"
                                                );
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    src = %hex::encode(im.src_node_id),
                                                    error = %e,
                                                    "app-cert verify failed; ignoring"
                                                );
                                            }
                                        }
                                    } else {
                                        // Gate not configured — silently swallow the
                                        // cert message (wire-compat for mixed deployment).
                                        tracing::debug!(
                                            src = %hex::encode(im.src_node_id),
                                            "ignoring unsolicited cert (gate not configured)"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        src = %hex::encode(im.src_node_id),
                                        error = e,
                                        "malformed cert message"
                                    );
                                }
                            }
                            continue; // Don't touch TUN-write path.
                        }
                        // S2.B admission gate: if app-cert authority configured,
                        // packets from unverified peers are dropped.
                        if app_cert_gate_for_ingress.is_some() {
                            let admitted = {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0);
                                match verified_peers.get(&im.src_node_id) {
                                    Some(0) => true, // sentinel: no expiry
                                    Some(&exp) if exp > now => true,
                                    _ => false,
                                }
                            };
                            if !admitted {
                                tracing::debug!(
                                    src = %hex::encode(im.src_node_id),
                                    "app-cert gate: dropping packet from unverified peer"
                                );
                                continue;
                            }
                        }
                        if is_batch_envelope(&im.data) {
                            // Phase E27: batched envelope.  Per-sub-packet
                            // MTU/route check; envelope-level MTU cap is NOT
                            // applied — batch buffer is naturally >MTU.
                            for pkt in BatchIter::new(&im.data) {
                                deliver_one(&mut tun_w, &state, &im.src_node_id, pkt).await;
                            }
                        } else {
                            // Legacy single-packet envelope.  Keep the
                            // pre-E27 MTU guard at envelope level (a compromised
                            // peer cannot inject a larger-than-MTU frame).
                            let mtu = state.load().mtu;
                            if im.data.len() > mtu as usize {
                                tracing::debug!(
                                    src = %hex::encode(im.src_node_id),
                                    len = im.data.len(),
                                    mtu,
                                    "ingress: dropping oversize packet",
                                );
                                continue;
                            }
                            deliver_one(&mut tun_w, &state, &im.src_node_id, &im.data).await;
                        }
                    }
                }
            }
        })
    };

    let routes = tokio::spawn(maintain_routes(
        bridge.config_path.clone(),
        bridge.accepted.clone(),
        Arc::clone(&bridge.hup),
        binding.node_id,
        configured,
        Arc::clone(&state),
        route_changes,
    ));
    let (outcome, ingress_finished, egress_finished) = tokio::select! {
        _ = stopping.as_mut() => (Ok(LinkExit::Shutdown), false, false),
        _ = client.wait_disconnected() => (Ok(LinkExit::DaemonDisconnected), false, false),
        result = &mut ingress => (
            result.map(|_| LinkExit::DaemonDisconnected).map_err(BridgeError::client),
            true,
            false,
        ),
        result = &mut egress => (
            result.map_err(BridgeError::client).and_then(|result| result)
                .map(|_| LinkExit::DaemonDisconnected),
            false,
            true,
        ),
    };

    routes.abort();
    let _ = routes.await;
    if let Some(task) = cert_broadcast_task {
        task.abort();
        let _ = task.await;
    }
    if !ingress_finished {
        ingress.abort();
        let _ = ingress.await;
    }
    if !egress_finished {
        if matches!(outcome, Ok(LinkExit::Shutdown)) {
            let _ = shutdown.send(true);
            if tokio::time::timeout(Duration::from_secs(1), &mut egress)
                .await
                .is_ok()
            {
                return outcome;
            }
        }
        // Pending packets belong to this binding, including its admission
        // snapshot. Never flush them into a replacement daemon.
        egress.abort();
        let _ = egress.await;
    }
    outcome
}

async fn maintain_routes(
    config_path: PathBuf,
    accepted: watch::Sender<OgateConfig>,
    hup: Arc<Mutex<Option<Signal>>>,
    expected_node: NodeId,
    mut configured: SharedState,
    state: Arc<ArcSwap<SharedState>>,
    route_changes: Arc<Notify>,
) {
    let mut config = accepted.borrow().clone();
    let mut hup = hup.lock().await;
    let mut admitted = HashMap::new();
    let mut connection = None;
    let mut next_peer = 0;
    let mut refresh = tokio::time::interval(PNET_REFRESH_PERIOD);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pace = tokio::time::interval(PNET_QUERY_SPACING);
    pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let reload = tokio::select! {
            _ = async {
                if next_peer == 0 {
                    refresh.tick().await;
                }
            }, if config.pnet_required => false,
            _ = async {
                match hup.as_mut() {
                    Some(hup) => hup.recv().await,
                    None => std::future::pending().await,
                }
            } => true,
        };
        if reload {
            let new = match OgateConfig::from_path(&config_path) {
                Ok(new) => new,
                Err(error) => {
                    tracing::warn!(%error, "could not reload ogate config");
                    continue;
                }
            };
            if let Err(field) = validate_reload(&config, &new) {
                tracing::warn!(field, "config change requires an ogate restart");
                continue;
            }
            configured = match SharedState::build(&new) {
                Ok(full) => full,
                Err(error) => {
                    tracing::warn!(%error, "could not build ogate routes");
                    continue;
                }
            };
            accepted.send_replace(new.clone());
            config = new;
            next_peer = 0;
            if !config.pnet_required {
                admitted.clear();
                connection = None;
                publish_routes(configured.clone(), &state, &route_changes);
                continue;
            }
            admitted.retain(|peer, _| configured.app_id_for(peer).is_some());
            publish_routes(
                configured.with_pnet_admissions(&admitted),
                &state,
                &route_changes,
            );
            refresh.reset();
        }

        if configured.peer_app_ids.is_empty() {
            continue;
        }
        if connection.is_none() {
            connection = connect_pnet_status(&config.socket_path, expected_node, &mut pace).await;
        }
        let end;
        let results;
        if let Some(client) = &connection {
            if client.supports_pnet_admission_batch() {
                end = (next_peer + veilclient::PNET_ADMISSION_BATCH_MAX_PEERS)
                    .min(configured.peer_app_ids.len());
                results =
                    query_pnet_batch(client, &configured.peer_app_ids[next_peer..end], &mut pace)
                        .await;
            } else {
                end = (next_peer + PNET_LEGACY_QUERY_GROUP).min(configured.peer_app_ids.len());
                let (legacy_results, uncertain) =
                    query_pnet_legacy(client, &configured.peer_app_ids[next_peer..end], &mut pace)
                        .await;
                if uncertain {
                    connection = None;
                }
                results = Some(legacy_results);
            }
        } else {
            end = 0;
            results = None;
        }
        let Some(mut results) = results else {
            connection = None;
            next_peer = 0;
            if !admitted.is_empty() {
                admitted.clear();
                publish_routes(
                    configured.with_pnet_admissions(&admitted),
                    &state,
                    &route_changes,
                );
            }
            continue;
        };
        let group = &configured.peer_app_ids[next_peer..end];
        let mut changed = false;
        for (peer, _) in group {
            match results.remove(peer) {
                Some(expiry) => changed |= admitted.insert(*peer, expiry) != Some(expiry),
                None => changed |= admitted.remove(peer).is_some(),
            }
        }
        if changed {
            publish_routes(
                configured.with_pnet_admissions(&admitted),
                &state,
                &route_changes,
            );
        }
        next_peer = if end == configured.peer_app_ids.len() {
            0
        } else {
            end
        };
    }
}

/// Per-packet ingress delivery: route lookup + MTU check + TUN write.
///
/// Shared between the legacy single-packet path and the batched-envelope
/// path so the security checks (anti-spoof, authorized-only, oversize drop)
/// run identically on each sub-packet.
async fn deliver_one(
    tun_w: &mut crate::tun::Writer,
    state: &ArcSwap<SharedState>,
    src_node_id: &NodeId,
    pkt: &[u8],
) {
    let snap = state.load();
    if pkt.len() > snap.mtu as usize {
        tracing::debug!(
            src = %hex::encode(src_node_id),
            len = pkt.len(),
            mtu = snap.mtu,
            "ingress: dropping oversize sub-packet",
        );
        return;
    }
    if !snap.cert_is_current(src_node_id) {
        tracing::debug!("ingress: dropping peer with expired P-Net certificate");
        return;
    }
    let src_ip = parse_ip_endpoints(pkt).map(|(s, _)| s);
    let decision = snap.table.lookup_ingress(src_node_id, src_ip);
    drop(snap);
    match decision {
        Decision::Forward(_) => {
            if let Err(e) = tun_w.write_packet(pkt).await {
                tracing::warn!(error = %e, "TUN write failed");
            }
        }
        Decision::Unauthorized => {
            tracing::debug!(
                src = %hex::encode(src_node_id),
                "ingress: dropping unauthorized peer",
            );
        }
        Decision::SpoofedSourceIp => {
            tracing::debug!(
                src = %hex::encode(src_node_id),
                "ingress: dropping spoofed source IP",
            );
        }
        Decision::NoRoute => {
            tracing::trace!("ingress: NoRoute (open mode anomaly)");
        }
    }
}

#[cfg(unix)]
async fn wait_for_shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "failed to install SIGTERM handler; only SIGINT will work");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    let mut intr = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = intr.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("ipc client: {0}")]
    Client(String),
    #[error("daemon identity or named endpoint changed")]
    IdentityChanged,
    #[error("tun: {0}")]
    Tun(#[from] crate::tun::TunError),
    #[error("routing: {0}")]
    Routing(String),
    #[error("config: {0}")]
    Cfg(Box<str>),
}

impl BridgeError {
    fn client(e: impl std::fmt::Display) -> Self {
        Self::Client(format!("{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AccessMode, PeerEntry};
    use std::net::Ipv4Addr;

    fn cfg() -> OgateConfig {
        OgateConfig {
            network: "test".into(),
            app: "ogate".into(),
            mode: AccessMode::Authorized,
            socket_path: "/run/veil/app.sock".into(),
            iface_name: "ogate0".into(),
            mtu: 1280,
            local_addr_v4: Some(Ipv4Addr::new(10, 99, 0, 1)),
            prefix_v4: 24,
            local_addr_v6: None,
            prefix_v6: 64,
            peers: vec![PeerEntry {
                node_id: "aa".repeat(32),
                addr_v4: Some(Ipv4Addr::new(10, 99, 0, 2)),
                addr_v6: None,
                name: None,
            }],
            endpoint_id: 1,
            runtime: Default::default(),
            logging: Default::default(),
            batch: Default::default(),
            pnet_required: false,
            app_cert_trusted_owner_pubkey: None,
            app_cert_owner_algo: None,
            app_cert_network_id: None,
            app_cert_path: None,
        }
    }

    #[test]
    fn shared_state_builds_with_app_ids() {
        let mut c = cfg();
        for (byte, host) in [(0xcc, 3), (0x88, 4)] {
            c.peers.push(PeerEntry {
                node_id: hex::encode([byte; 32]),
                addr_v4: Some(Ipv4Addr::new(10, 99, 0, host)),
                addr_v6: None,
                name: None,
            });
        }
        let state = SharedState::build(&c).unwrap();
        assert_eq!(state.peer_app_ids.len(), 3);
        for (byte, host) in [(0xaa, 2), (0xcc, 3), (0x88, 4)] {
            let node_id = [byte; 32];
            let address = Ipv4Addr::new(10, 99, 0, host).into();
            assert_eq!(
                state.table.lookup_egress(address),
                Decision::Forward(node_id)
            );
            assert_eq!(
                state.app_id_for(&node_id),
                Some(derive_app_id(&node_id, &c.network, &c.app))
            );
        }
        assert_eq!(state.app_id_for(&[0xbb; 32]), None);
    }

    #[test]
    fn pnet_status_requires_matching_peer_live_session_and_current_cert() {
        let peer = [0xaa; 32];
        let mut status = PnetStatus {
            admitted: true,
            has_cert: true,
            admin: false,
            valid_until_unix: 10,
            network_id: [0x01; 32],
            peer_node_id: peer,
        };
        assert!(pnet_status_admits(&peer, &status, 9));
        assert!(!pnet_status_admits(&peer, &status, 10));
        assert!(!pnet_status_admits(&peer, &status, 0));
        assert!(!pnet_status_admits(&[0xbb; 32], &status, 9));

        status.valid_until_unix = 0;
        assert!(pnet_status_admits(&peer, &status, 100));
        status.has_cert = false;
        assert!(!pnet_status_admits(&peer, &status, 100));
        status.has_cert = true;
        status.admitted = false;
        assert!(!pnet_status_admits(&peer, &status, 100));
    }

    #[test]
    fn pnet_route_can_recover_without_changing_config() {
        let mut config = cfg();
        config.pnet_required = true;
        let configured = SharedState::build(&config).unwrap();
        let peer = [0xaa; 32];
        let stranger = [0xbb; 32];
        let address = Ipv4Addr::new(10, 99, 0, 2).into();
        let disconnected = configured.with_pnet_admissions(&HashMap::new());
        assert_eq!(disconnected.table.lookup_egress(address), Decision::NoRoute);
        assert_eq!(
            disconnected.table.lookup_ingress(&peer, Some(address)),
            Decision::Unauthorized
        );
        assert_eq!(disconnected.app_id_for(&peer), None);

        let connected = configured.with_pnet_admissions(&HashMap::from([(peer, 0), (stranger, 0)]));
        assert_eq!(
            connected.table.lookup_egress(address),
            Decision::Forward(peer)
        );
        assert_eq!(
            connected.table.lookup_ingress(&peer, Some(address)),
            Decision::Forward(peer)
        );
        assert_eq!(
            connected.table.lookup_ingress(&stranger, Some(address)),
            Decision::Unauthorized
        );
        assert_eq!(connected.app_id_for(&peer), configured.app_id_for(&peer));
        assert_eq!(connected.app_id_for(&stranger), None);

        let expired = configured.with_pnet_admissions(&HashMap::from([(peer, 1)]));
        assert!(!expired.cert_is_current(&peer));
        assert_eq!(expired.app_id_for(&peer), None);
        let retired = configured.with_pnet_admissions(&HashMap::new());
        assert_eq!(retired.table.lookup_egress(address), Decision::NoRoute);
        assert_eq!(retired.app_id_for(&peer), None);
    }

    #[test]
    fn queued_packets_follow_current_admission_and_address_assignment() {
        let mut config = cfg();
        let peer = [0xaa; 32];
        let state = SharedState::build(&config).unwrap();
        let address_assignment = &state.routing_config;
        let app_id = state.app_id_for(&peer).unwrap();
        let connected = state.with_pnet_admissions(&HashMap::from([(peer, 0)]));
        assert!(connected.permits_queued_egress(address_assignment, &peer, app_id));
        let revoked = state.with_pnet_admissions(&HashMap::new());
        assert!(!revoked.permits_queued_egress(address_assignment, &peer, app_id));

        let old_address = config.peers[0].addr_v4;
        config.peers[0].addr_v4 = Some(Ipv4Addr::new(10, 99, 0, 3));
        config.peers.push(PeerEntry {
            node_id: "bb".repeat(32),
            addr_v4: old_address,
            addr_v6: None,
            name: None,
        });
        let reassigned = SharedState::build(&config).unwrap();
        assert_eq!(reassigned.app_id_for(&peer), Some(app_id));
        assert!(!reassigned.permits_queued_egress(address_assignment, &peer, app_id));
    }

    #[tokio::test]
    async fn pnet_routes_follow_daemon_admission_without_reload() {
        tokio::join!(
            exercise_pnet_sweep(34),
            exercise_pnet_sweep(256),
            exercise_pnet_sweep(1024),
        );
    }

    async fn exercise_pnet_sweep(peer_count: u16) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use veil_ipc::{IpcEndpoint, IpcServer, PnetStatusProvider};
        use veil_proto::PnetStatusResultPayload;

        struct Admission {
            live: AtomicBool,
            wrong_peer: AtomicBool,
        }

        impl PnetStatusProvider for Admission {
            fn peer_status(&self, peer: &NodeId) -> PnetStatusResultPayload {
                PnetStatusResultPayload {
                    admitted: self.live.load(Ordering::Relaxed),
                    has_cert: true,
                    admin: false,
                    valid_until_unix: 0,
                    network_id: [0x01; 32],
                    peer_node_id: if self.wrong_peer.load(Ordering::Relaxed) {
                        [0x77; 32]
                    } else {
                        *peer
                    },
                }
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("ipc");
        let admission = Arc::new(Admission {
            live: AtomicBool::new(false),
            wrong_peer: AtomicBool::new(false),
        });
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let mut server = IpcServer::new(
            IpcEndpoint::Unix(socket.clone()),
            shutdown,
            Arc::new(veil_app::AppEndpointRegistry::new()),
            [0x01; 32],
        )
        .with_pnet_status_provider(admission.clone());
        let server = tokio::spawn(async move { server.run().await.unwrap() });

        tokio::time::timeout(Duration::from_secs(3), async {
            while !socket.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("IPC server did not start");
        let mut config = cfg();
        config.socket_path = socket.clone();
        config.mode = AccessMode::Open;
        config.pnet_required = true;
        config.prefix_v4 = 16;
        for host in 3..=peer_count + 1 {
            let [hi, lo] = host.to_be_bytes();
            let mut id = [0; 32];
            id[..2].copy_from_slice(&[hi, lo]);
            config.peers.push(PeerEntry {
                node_id: hex::encode(id),
                addr_v4: Some(Ipv4Addr::new(10, 99, hi, lo)),
                addr_v6: None,
                name: None,
            });
        }
        let peer_count = usize::from(peer_count);
        assert_eq!(config.peers.len(), peer_count);
        let configured = SharedState::build(&config).unwrap();
        let initial = configured.with_pnet_admissions(&HashMap::new());
        let state = Arc::new(ArcSwap::from_pointee(initial));
        let changed = Arc::new(Notify::new());
        let peer = [0xaa; 32];
        let address = Ipv4Addr::new(10, 99, 0, 2).into();
        assert_eq!(state.load().table.lookup_egress(address), Decision::NoRoute);

        let updates = tokio::spawn(maintain_routes(
            directory.path().join("unused.toml"),
            watch::channel(config).0,
            Arc::new(Mutex::new(None)),
            [0x01; 32],
            configured,
            Arc::clone(&state),
            Arc::clone(&changed),
        ));

        let started = std::time::Instant::now();
        admission.live.store(true, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(4), async {
            while state.load().table.peer_count() != peer_count {
                changed.notified().await;
            }
        })
        .await
        .expect("admission batches did not converge within the local query quota");
        let admission_elapsed = started.elapsed();
        assert_eq!(
            state.load().table.lookup_egress(address),
            Decision::Forward(peer)
        );
        assert_eq!(
            state.load().table.lookup_ingress(&peer, Some(address)),
            Decision::Forward(peer)
        );

        let revoked = std::time::Instant::now();
        admission.live.store(false, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(8), async {
            while state.load().table.peer_count() != 0 {
                changed.notified().await;
            }
        })
        .await
        .expect("peer routes survived loss of session");
        eprintln!(
            "{peer_count} peers: admitted in {admission_elapsed:.3?}, withdrawn in {:.3?}",
            revoked.elapsed()
        );
        assert_eq!(state.load().table.lookup_egress(address), Decision::NoRoute);
        assert_eq!(
            state.load().table.lookup_ingress(&peer, Some(address)),
            Decision::Unauthorized
        );

        updates.abort();
        assert!(updates.await.unwrap_err().is_cancelled());

        let group = [(peer, [0u8; 32])];
        let mut pace = tokio::time::interval(PNET_QUERY_SPACING);
        let client = connect_pnet_status(&socket, [0x01; 32], &mut pace)
            .await
            .unwrap();
        assert!(client.supports_pnet_admission_batch());
        admission.live.store(true, Ordering::Relaxed);
        admission.wrong_peer.store(true, Ordering::Relaxed);
        // A provider mismatch cannot authorize the wrong peer on either path.
        assert!(
            query_pnet_batch(&client, &group, &mut pace)
                .await
                .unwrap()
                .is_empty()
        );
        let (legacy, uncertain) = query_pnet_legacy(&client, &group, &mut pace).await;
        assert!(legacy.is_empty() && uncertain);
        drop(client);

        admission.wrong_peer.store(false, Ordering::Relaxed);
        let client = connect_pnet_status(&socket, [0x01; 32], &mut pace)
            .await
            .unwrap();
        let fresh = query_pnet_batch(&client, &group, &mut pace).await.unwrap();
        assert_eq!(fresh.get(&peer), Some(&0));

        drop(client);
        stop.send(true).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn binding_recovers_after_daemon_restart_without_accepting_another_identity() {
        use veil_ipc::{IpcEndpoint, IpcServer};

        async fn start(
            socket: &Path,
            node: NodeId,
        ) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
            let (stop, shutdown) = watch::channel(false);
            let mut server = IpcServer::new(
                IpcEndpoint::Unix(socket.to_path_buf()),
                shutdown,
                Arc::new(veil_app::AppEndpointRegistry::new()),
                node,
            );
            let task = tokio::spawn(async move { server.run().await.unwrap() });
            tokio::time::timeout(Duration::from_secs(3), async {
                while !socket.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            (stop, task)
        }

        let directory = tempfile::tempdir().unwrap();
        let mut config = cfg();
        config.socket_path = directory.path().join("ipc");
        let node = [0xa1; 32];
        let (stop, daemon) = start(&config.socket_path, node).await;
        let BoundIpc {
            mut client,
            handle,
            binding,
        } = bind_ipc(&config, None).await.unwrap();
        let (_sender, _receiver) = handle.into_split();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), client.wait_disconnected())
                .await
                .is_err()
        );

        stop.send(true).unwrap();
        daemon.await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), client.wait_disconnected())
            .await
            .expect("connection close must be observable with split handles alive");

        let (stop, daemon) = start(&config.socket_path, [0xb2; 32]).await;
        assert!(matches!(
            bind_ipc(&config, Some(binding)).await,
            Err(BridgeError::IdentityChanged)
        ));
        stop.send(true).unwrap();
        daemon.await.unwrap();

        let (stop, daemon) = start(&config.socket_path, node).await;
        let restored =
            tokio::time::timeout(Duration::from_secs(3), reconnect_ipc(&config, binding))
                .await
                .expect("ogate did not rebind after restarting the original daemon");
        assert!(restored.binding == binding);
        drop(restored);
        stop.send(true).unwrap();
        daemon.await.unwrap();
    }

    #[test]
    fn reload_accepts_peer_table_changes() {
        let old = cfg();
        let mut new = cfg();
        new.peers.push(PeerEntry {
            node_id: "bb".repeat(32),
            addr_v4: Some(Ipv4Addr::new(10, 99, 0, 3)),
            addr_v6: None,
            name: None,
        });
        assert!(validate_reload(&old, &new).is_ok());
    }

    #[test]
    fn reload_accepts_mode_change() {
        let old = cfg();
        let mut new = cfg();
        new.mode = AccessMode::Open;
        assert!(validate_reload(&old, &new).is_ok());
    }

    #[test]
    fn reload_rejects_network_change() {
        let old = cfg();
        let mut new = cfg();
        new.network = "other".into();
        assert_eq!(validate_reload(&old, &new).unwrap_err(), "network");
    }

    #[test]
    fn reload_rejects_iface_change() {
        let old = cfg();
        let mut new = cfg();
        new.iface_name = "ogate7".into();
        assert_eq!(validate_reload(&old, &new).unwrap_err(), "iface_name");
    }

    #[test]
    fn reload_rejects_local_addr_change() {
        let old = cfg();
        let mut new = cfg();
        new.local_addr_v4 = Some(Ipv4Addr::new(10, 99, 0, 100));
        assert_eq!(validate_reload(&old, &new).unwrap_err(), "local_addr_v4");
    }
}
