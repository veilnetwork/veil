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
//! * **Reload**: `SIGHUP` → re-read config → validate non-changeable fields →
//!   atomic `state.store(new)`.
//!
//! On `ctrl_c` / `SIGTERM` all tasks exit and the function returns.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::Notify;
use veil_util::lock;
use veilclient::{APP_IPC_SEND_PREFIX_BYTES, VeilClient};

use crate::app_id::{derive_app_id, namespace_for};
use crate::batch::{BatchIter, EgressBatches, is_batch_envelope};
use crate::config::OgateConfig;
use crate::routing::{Decision, NodeId, RoutingTable, parse_ip_endpoints};
use crate::tun::Device;

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

/// Hard ceiling for a single solo-shipped packet's payload over obfs4.
///
/// Derived from `MAX_FRAME_CIPHERTEXT_BYTES = 16384` minus the worst-case
/// obfs4 padding (1024), obfs4 hdr+tag (17), session AEAD tag (16),
/// `FrameHeader` (24) and `AppSendPayload` header (72) — the same arithmetic
/// as [`EGRESS_FLUSH_BYTES_DEFAULT`]'s rationale. A solo packet ABOVE this
/// would make `wrap_frame` return `OversizedFrame`, exit the writer task and
/// tear down the whole session; we drop just that packet instead. Operators
/// should keep the tunnel MTU at or below this. (audit cycle-8 H10.)
const MAX_OBFS4_SOLO_PAYLOAD_BYTES: usize = 15_231;

// Compile-time invariant: the solo ceiling must stay strictly below the obfs4
// frame ciphertext cap (`veil_obfs4::MAX_FRAME_CIPHERTEXT_BYTES = 16 * 1024`),
// otherwise a solo packet at the ceiling could still trip OversizedFrame and
// tear down the session the H10 guard exists to protect.
const _: () = assert!(MAX_OBFS4_SOLO_PAYLOAD_BYTES < 16 * 1024);

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
pub struct SharedState {
    pub table: RoutingTable,
    /// Same peer set as the table, materialized as `(node_id, app_id)`
    /// to avoid recomputing BLAKE3 on every egress packet.
    pub peer_app_ids: Vec<(NodeId, [u8; 32])>,
    /// Configured virtual-iface MTU. Used by the ingress task to drop
    /// oversize packets BEFORE writing to TUN — a compromised peer cannot
    /// inject larger-than-expected frames that would either fragment
    /// unexpectedly or trip kernel-side anomaly handling.
    pub mtu: u16,
}

impl SharedState {
    pub fn build(cfg: &OgateConfig) -> Result<Self, BridgeError> {
        let table = RoutingTable::from_config(cfg).map_err(|e| BridgeError::Routing(e.into()))?;
        let peer_app_ids = table
            .peer_node_ids()
            .map(|nid| (*nid, derive_app_id(nid, &cfg.network, &cfg.app)))
            .collect();
        Ok(Self {
            table,
            peer_app_ids,
            mtu: cfg.mtu,
        })
    }

    fn app_id_for(&self, peer: &NodeId) -> Option<[u8; 32]> {
        self.peer_app_ids
            .iter()
            .find(|(n, _)| n == peer)
            .map(|(_, a)| *a)
    }
}

/// Filter a config's `[[peers]]` list, keeping only those whose
/// `node_id` is currently cert-verified by the daemon's P-Net gate.
///
/// Failure modes:
/// * Daemon RPC error ⇒ peer dropped from list + warning.
/// * `admitted=false` ⇒ no active session to peer; peer dropped + warn.
/// * `has_cert=false` ⇒ peer admitted in public mode but without cert; drop.
///
/// Called on startup AND on every SIGHUP reload (cycle-7 H4) — the reload
/// handler re-runs this before `SharedState::build` so a peer whose
/// MembershipCert was revoked/expired since the last load is dropped rather
/// than re-admitted to the routing table.
async fn filter_peers_by_pnet(cfg: &OgateConfig, client: &VeilClient) -> OgateConfig {
    let mut filtered = cfg.clone();
    let original_count = cfg.peers.len();
    filtered.peers.clear();
    for peer in &cfg.peers {
        let mut node_id = [0u8; 32];
        match hex::decode(&peer.node_id) {
            Ok(bytes) if bytes.len() == 32 => node_id.copy_from_slice(&bytes),
            _ => {
                // Validate() will reject this later — keep here so the
                // user-facing error message comes from the right place.
                filtered.peers.push(peer.clone());
                continue;
            }
        }
        match client.peer_pnet_status(&node_id).await {
            Ok(status) if status.admitted && status.has_cert => {
                filtered.peers.push(peer.clone());
            }
            Ok(status) => {
                tracing::warn!(
                    peer_node_id = %peer.node_id,
                    admitted = status.admitted,
                    has_cert = status.has_cert,
                    "pnet_required: filtering out peer (no valid cert)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    peer_node_id = %peer.node_id,
                    error = %e,
                    "pnet_required: peer_pnet_status query failed; filtering out peer"
                );
            }
        }
    }
    tracing::info!(
        original = original_count,
        admitted = filtered.peers.len(),
        "pnet_required filter applied"
    );
    filtered
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

/// Bring up the device + open the IPC handle + run the bridge loop.
///
/// Returns when all tasks exit (typically after SIGINT/SIGTERM).
///
/// `config_path` is held for the lifetime of the bridge so SIGHUP can
/// re-read the same file. The initial `cfg` must have been parsed from
/// that path.
pub async fn run(config_path: PathBuf, cfg: OgateConfig) -> Result<(), BridgeError> {
    // ── IPC handshake (moved earlier than initial-state build so we
    //    can query peer_pnet_status while filtering peers) ──────────────
    tracing::info!(socket = %cfg.socket_path.display(), "connecting to veil daemon");
    // `Arc` so the SIGHUP reload task can also query peer_pnet_status to
    // re-apply the P-Net filter on reload (see the reload handler below).
    let client = Arc::new(
        VeilClient::connect(&cfg.socket_path)
            .await
            .map_err(BridgeError::client)?,
    );

    // ── initial state ───────────────────────────────────────────────────
    // S2.A: filter peers by daemon-side P-Net cert verification if
    // `pnet_required = true`.  Each filtered-out peer logs a warning;
    // operators can either rotate the cert or drop the peer from config.
    let cfg = if cfg.pnet_required {
        filter_peers_by_pnet(&cfg, &client).await
    } else {
        cfg
    };
    let initial_state = SharedState::build(&cfg)?;
    tracing::info!(
        mode = ?initial_state.table.mode(),
        peers = initial_state.table.peer_count(),
        pnet_required = cfg.pnet_required,
        "initial routing state ready"
    );
    let state: Arc<ArcSwap<SharedState>> = Arc::new(ArcSwap::from_pointee(initial_state));
    let identity = client.node_identity().await.map_err(BridgeError::client)?;
    tracing::info!(node_id = %hex::encode(identity.node_id), "got local node identity");

    let ns = namespace_for(&cfg.network);
    let handle = client
        .bind_named(&ns, &cfg.app, cfg.endpoint_id)
        .await
        .map_err(BridgeError::client)?;
    let my_app_id = *handle.app_id();
    tracing::info!(
        namespace = %ns,
        name = %cfg.app,
        endpoint = cfg.endpoint_id,
        app_id = %hex::encode(my_app_id),
        "bound IPC endpoint"
    );

    // ── TUN device ──────────────────────────────────────────────────────
    let dev = Device::new(&cfg).await.map_err(BridgeError::Tun)?;
    tracing::info!(iface = %dev.name(), "TUN device up");
    let (mut tun_r, mut tun_w) = dev.split();

    let endpoint_id = cfg.endpoint_id;
    let (app_sender, mut app_receiver) = handle.into_split();
    // Arc-wrap the sender so the cert-broadcast task can share it with
    // the egress task without uncoordinated moves.  `send_*` methods take
    // `&self`, so Arc-deref works transparently.
    let app_sender = Arc::new(app_sender);

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
    // Per-peer verified-cert cache: node_id → valid_until_unix.
    // Sentinel `0` ⇒ no expiry; positive value ⇒ unix-second expiry.
    let verified_peers: Arc<std::sync::Mutex<std::collections::HashMap<[u8; 32], u64>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // Notify shared with all background tasks for clean shutdown.  Moved
    // earlier than its original position so the cert-broadcast task can
    // reference it during initialisation.
    let shutdown = Arc::new(Notify::new());

    // ── S2.B sender-side: periodic cert broadcast ──────────────────────
    // When `app_cert_path` is set, ogate emits its cert to every
    // configured peer at startup (so receivers can populate their cache
    // before regular packets arrive) and then every 5 min thereafter (so
    // peers that came online late or restarted still get the cert).
    let cert_broadcast_task: Option<tokio::task::JoinHandle<()>> = if let Some(blob) =
        own_cert_blob.as_ref()
    {
        let msg = crate::cert_message::encode_cert_message(blob);
        match msg {
            Some(msg_bytes) => {
                let msg_bytes = Arc::new(msg_bytes);
                let app_sender_for_cert = Arc::clone(&app_sender);
                let state_for_cert = Arc::clone(&state);
                let shutdown_for_cert = Arc::clone(&shutdown);
                Some(tokio::spawn(async move {
                    // Wait a brief moment so peers' ingress tasks are listening.
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    loop {
                        // Snapshot the current peer list (changes on SIGHUP reload).
                        let snap = state_for_cert.load();
                        for peer_node_id in snap.table.peer_node_ids() {
                            let app_id = snap.app_id_for(peer_node_id);
                            if let Some(app_id) = app_id {
                                let payload = (*msg_bytes).clone();
                                let _ = app_sender_for_cert
                                    .send_owned(*peer_node_id, app_id, endpoint_id, payload)
                                    .await;
                            }
                        }
                        // Wait 5 min or until shutdown.
                        tokio::select! {
                            _ = shutdown_for_cert.notified() => break,
                            _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {},
                        }
                    }
                }))
            }
            None => {
                tracing::error!("encode_cert_message returned None — cert blob too large or empty");
                None
            }
        }
    } else {
        None
    };

    // Hold the latest known config (used by reload to diff against).
    // Wrap in a plain Mutex because reload is rare; readers don't need
    // the live config (state holds the materialized derivations).
    let current_cfg = Arc::new(std::sync::Mutex::new(cfg.clone()));

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
    let batching_enabled = cfg.batch.enabled;
    tracing::info!(
        batching_enabled,
        "egress batching state — set [batch] enabled = false for rolling-upgrade safety"
    );

    let egress = {
        let state = Arc::clone(&state);
        let shutdown = Arc::clone(&shutdown);
        let app_sender = Arc::clone(&app_sender);
        tokio::spawn(async move {
            let mut batches = EgressBatches::new();
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
                    _ = shutdown.notified() => {
                        // Best-effort flush on graceful shutdown.
                        for (peer_nid, envelope, peer_app_id) in batches.drain_all() {
                            let _ = app_sender
                                .send_owned(peer_nid, peer_app_id, endpoint_id, envelope)
                                .await;
                        }
                        break;
                    }
                    _ = timer => {
                        // Timer fired: flush every batch whose deadline has expired.
                        let cutoff = std::time::Instant::now() - EGRESS_FLUSH_AFTER;
                        for (peer_nid, envelope, peer_app_id) in batches.drain_expired(cutoff) {
                            if let Err(e) = app_sender
                                .send_owned(peer_nid, peer_app_id, endpoint_id, envelope)
                                .await
                            {
                                tracing::warn!(error = %e, "egress: batch send failed");
                            }
                        }
                    }
                    res = tun_r.read_packet_with_prefix(APP_IPC_SEND_PREFIX_BYTES) => match res {
                        Err(e) => {
                            tracing::error!(error = %e, "TUN read failed; egress task exiting");
                            break;
                        }
                        Ok(buf) => {
                            // `buf` layout: [PREFIX uninit][IP packet bytes].
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
                                tracing::warn!("egress: peer in routing but missing app_id slot");
                                continue;
                            };
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
                                    if let Some(pb) = batches.peek_mut(&peer_nid)
                                        && !pb.is_empty()
                                    {
                                        let envelope = pb.take();
                                        let _ = app_sender
                                            .send_owned(peer_nid, peer_app_id, endpoint_id, envelope)
                                            .await;
                                    }
                                    // Zero-data-copy: SDK fills the PREFIX bytes
                                    // in `buf` in place and forwards the whole Vec.
                                    if let Err(e) = app_sender
                                        .send_prepared(peer_nid, peer_app_id, endpoint_id, buf)
                                        .await
                                    {
                                        tracing::warn!(error = %e, "egress: solo send failed");
                                    }
                                } else {
                                    // Pre-flush: if appending would cross the
                                    // threshold, flush the current batch FIRST,
                                    // then start a fresh batch with this packet.
                                    let pb = batches.get_or_create(peer_nid, peer_app_id);
                                    if !pb.is_empty()
                                        && pb.len() + record_size > egress_flush_bytes
                                    {
                                        let envelope = pb.take();
                                        if let Err(e) = app_sender
                                            .send_owned(peer_nid, peer_app_id, endpoint_id, envelope)
                                            .await
                                        {
                                            tracing::warn!(error = %e, "egress: pre-flush failed");
                                        }
                                    }
                                    // Re-borrow (take() may have made `pb` stale).
                                    let pb = batches.get_or_create(peer_nid, peer_app_id);
                                    pb.push(pkt);
                                    if pb.should_flush(egress_flush_bytes) {
                                        let envelope = pb.take();
                                        if let Err(e) = app_sender
                                            .send_owned(peer_nid, peer_app_id, endpoint_id, envelope)
                                            .await
                                        {
                                            tracing::warn!(error = %e, "egress: batch send failed");
                                        }
                                    }
                                }
                            } else {
                                // Raw mode (E27 kill-switch off): preserve E26
                                // wire-byte compatibility.  Zero-copy: SDK fills
                                // PREFIX inside `buf` and forwards as-is.
                                let _ = &mut batches;
                                let _ = pkt;
                                if let Err(e) = app_sender
                                    .send_prepared(peer_nid, peer_app_id, endpoint_id, buf)
                                    .await
                                {
                                    tracing::warn!(error = %e, "egress: raw send failed");
                                }
                            }
                        }
                    }
                }
            }
        })
    };

    // ── Ingress: veil → TUN ──────────────────────────────────────────
    let ingress = {
        let state = Arc::clone(&state);
        let shutdown = Arc::clone(&shutdown);
        let app_cert_gate_for_ingress = app_cert_gate.as_ref().map(Arc::clone);
        let verified_peers_for_ingress = Arc::clone(&verified_peers);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.notified() => break,
                    msg = app_receiver.recv() => match msg {
                        Err(e) => {
                            tracing::error!(error = %e, "AppReceiver error; ingress task exiting");
                            break;
                        }
                        Ok(None) => {
                            tracing::warn!("AppReceiver closed; ingress task exiting");
                            break;
                        }
                        Ok(Some(im)) => {
                            let snap = state.load();
                            // S2.B: cert message intercept BEFORE any IP-packet
                            // dispatch.  Marker 0xC0 is outside IPv4/IPv6 version
                            // nibbles + distinct from batch envelope (0xB1).
                            if crate::cert_message::is_cert_message(&im.data) {
                                match crate::cert_message::decode_cert_message(&im.data) {
                                    Ok(blob) => {
                                        if let Some(gate) = app_cert_gate_for_ingress.as_ref() {
                                            match gate.verify(&blob, &im.src_node_id) {
                                                Ok(valid_until) => {
                                                    let mut g = verified_peers_for_ingress
                                                        .lock()
                                                        .unwrap_or_else(|p| p.into_inner());
                                                    g.insert(im.src_node_id, valid_until);
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
                                    let g = verified_peers_for_ingress
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner());
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_secs())
                                        .unwrap_or(0);
                                    match g.get(&im.src_node_id) {
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
                                    deliver_one(
                                        &mut tun_w,
                                        &snap,
                                        &im.src_node_id,
                                        pkt,
                                    ).await;
                                }
                            } else {
                                // Legacy single-packet envelope.  Keep the
                                // pre-E27 MTU guard at envelope level (a compromised
                                // peer cannot inject a larger-than-MTU frame).
                                if im.data.len() > snap.mtu as usize {
                                    tracing::debug!(
                                        src = %hex::encode(im.src_node_id),
                                        len = im.data.len(),
                                        mtu = snap.mtu,
                                        "ingress: dropping oversize packet",
                                    );
                                    continue;
                                }
                                deliver_one(
                                    &mut tun_w,
                                    &snap,
                                    &im.src_node_id,
                                    &im.data,
                                ).await;
                            }
                        }
                    }
                }
            }
        })
    };

    // ── SIGHUP reload (Unix only) ───────────────────────────────────────
    #[cfg(unix)]
    let reload = {
        let state = Arc::clone(&state);
        let current_cfg = Arc::clone(&current_cfg);
        let shutdown = Arc::clone(&shutdown);
        let path = config_path.clone();
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut hup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "SIGHUP handler install failed; reload disabled");
                    return;
                }
            };
            loop {
                tokio::select! {
                    _ = shutdown.notified() => break,
                    sig = hup.recv() => {
                        if sig.is_none() { break; }
                        tracing::info!(path = %path.display(), "SIGHUP — reloading config");
                        let new_cfg = match OgateConfig::from_path(&path) {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!(error = %e, "reload: config read/parse failed; keeping current state");
                                continue;
                            }
                        };
                        let snapshot_old = lock!(current_cfg).clone();
                        if let Err(field) = validate_reload(&snapshot_old, &new_cfg) {
                            tracing::warn!(
                                field = %field,
                                "reload: cannot change `{field}` at runtime — restart required. Keeping current state.",
                            );
                            continue;
                        }
                        // SECURITY (cycle-7 H4): re-apply the P-Net peer filter on
                        // reload, exactly as startup does. Without this a revoked /
                        // expired MembershipCert peer was re-admitted to the routing
                        // table on any SIGHUP (even an unchanged file) and could
                        // inject TUN traffic until the next full restart.
                        let new_cfg = if new_cfg.pnet_required {
                            filter_peers_by_pnet(&new_cfg, &client).await
                        } else {
                            new_cfg
                        };
                        let new_state = match SharedState::build(&new_cfg) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(error = %e, "reload: rebuild failed; keeping current state");
                                continue;
                            }
                        };
                        let peers = new_state.table.peer_count();
                        let mode = new_state.table.mode();
                        state.store(Arc::new(new_state));
                        *lock!(current_cfg) = new_cfg;
                        tracing::info!(
                            mode = ?mode,
                            peers = peers,
                            "reloaded routing state"
                        );
                    }
                }
            }
        })
    };

    // ── Wait for shutdown signal ────────────────────────────────────────
    wait_for_shutdown().await;
    tracing::info!("shutdown signal received");
    shutdown.notify_waiters();

    let _ = egress.await;
    let _ = ingress.await;
    #[cfg(unix)]
    let _ = reload.await;
    if let Some(t) = cert_broadcast_task {
        let _ = t.await;
    }
    Ok(())
}

/// Per-packet ingress delivery: route lookup + MTU check + TUN write.
///
/// Shared between the legacy single-packet path and the batched-envelope
/// path so the security checks (anti-spoof, authorized-only, oversize drop)
/// run identically on each sub-packet.
async fn deliver_one(
    tun_w: &mut crate::tun::Writer,
    snap: &SharedState,
    src_node_id: &NodeId,
    pkt: &[u8],
) {
    if pkt.len() > snap.mtu as usize {
        tracing::debug!(
            src = %hex::encode(src_node_id),
            len = pkt.len(),
            mtu = snap.mtu,
            "ingress: dropping oversize sub-packet",
        );
        return;
    }
    let src_ip = parse_ip_endpoints(pkt).map(|(s, _)| s);
    match snap.table.lookup_ingress(src_node_id, src_ip) {
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
        let c = cfg();
        let s = SharedState::build(&c).unwrap();
        assert_eq!(s.peer_app_ids.len(), 1);
        // app_id matches BLAKE3(peer_node_id || "ogate.test" || "ogate")
        let nid = [0xaau8; 32];
        let expected = derive_app_id(&nid, &c.network, &c.app);
        assert_eq!(s.app_id_for(&nid), Some(expected));
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
