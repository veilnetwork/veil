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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::ops::Bound::{Excluded, Unbounded};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{Mutex, Notify, broadcast, watch};
use tokio::time::Instant;
use veil_identity::network_policy::VerifiedRoutePolicy;
use veil_proto::event_kind::{
    EVENTS_LAGGED, PNET_SESSION_ADMITTED, PNET_SESSION_ENDED, SESSION_ADMITTED, SESSIONS_CHANGED,
};
use veil_util::unix_secs_now_u64;
use veilclient::client::PnetStatus;
use veilclient::{APP_IPC_SEND_PREFIX_BYTES, AppHandle, PnetAuthority, VeilClient, VeilEvent};

use crate::app_id::{derive_app_id, namespace_for};
use crate::batch::{BatchIter, EgressBatches, is_batch_envelope};
use crate::config::OgateConfig;
use crate::packet_drops::{DropReason, PacketDrops, record_one};
use crate::routing::{Decision, NodeId, RoutingTable, parse_ip_endpoints};
use crate::signed_policy::{SignedRoutes, assigned_peers};
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
    policy_window: Option<(u64, u64)>,
    policy_revision: Option<u64>,
    configured_peers: usize,
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
        let configured_peers = peer_app_ids.len();
        Ok(Self {
            table,
            peer_app_ids,
            pnet_expiries: HashMap::new(),
            policy_window: None,
            policy_revision: None,
            configured_peers,
            routing_config: Arc::new(()),
            mtu: cfg.mtu,
        })
    }

    fn with_pnet_admissions(&self, admissions: &HashMap<NodeId, u64>) -> Self {
        let (table, peer_app_ids) = if admissions.len() <= self.peer_app_ids.len() / 8 {
            // For sparse admission, look up the admitted peers instead of
            // copying the configured table and discarding most of it.
            let mut peer_app_ids: Vec<_> = admissions
                .keys()
                .filter_map(|peer| {
                    self.peer_app_ids
                        .binary_search_by(|(node_id, _)| node_id.cmp(peer))
                        .ok()
                        .map(|index| self.peer_app_ids[index])
                })
                .collect();
            peer_app_ids.sort_unstable_by_key(|(peer, _)| *peer);
            let table = self
                .table
                .select_peers(peer_app_ids.iter().map(|(peer, _)| peer));
            (table, peer_app_ids)
        } else {
            // Dense admission favors scanning the sorted configuration
            // once over doing an indexed lookup for every admitted peer.
            let mut table = self.table.clone();
            table.retain_peers(|peer| admissions.contains_key(peer));
            let mut peer_app_ids = self.peer_app_ids.clone();
            peer_app_ids.retain(|(peer, _)| admissions.contains_key(peer));
            (table, peer_app_ids)
        };
        let pnet_expiries = peer_app_ids
            .iter()
            .filter_map(|(peer, _)| {
                let expires = admissions[peer];
                (expires != 0).then_some((*peer, expires))
            })
            .collect();
        Self {
            table,
            peer_app_ids,
            pnet_expiries,
            policy_window: self.policy_window,
            policy_revision: self.policy_revision,
            configured_peers: self.configured_peers,
            routing_config: Arc::clone(&self.routing_config),
            mtu: self.mtu,
        }
    }

    fn preserve_signed_admissions(
        &mut self,
        previous: &SharedState,
        admitted: &mut HashMap<NodeId, u64>,
        now: u64,
    ) {
        let Some((from, until)) = previous.policy_window else {
            admitted.clear();
            return;
        };
        if now == 0 || now < from || now >= until {
            admitted.clear();
            return;
        }

        // Only an unchanged route can use a previous admission. Keep the
        // earlier policy and certificate deadline until the daemon rechecks it.
        admitted.retain(|peer, expiry| {
            let deadline = if *expiry == 0 {
                until
            } else {
                (*expiry).min(until)
            };
            if now >= deadline || !self.table.same_peer_addresses(&previous.table, peer) {
                return false;
            }
            *expiry = deadline;
            true
        });

        if !admitted.is_empty()
            && previous
                .peer_app_ids
                .iter()
                .all(|(peer, _)| self.table.same_peer_addresses(&previous.table, peer))
        {
            // Include peers currently denied admission: a packet could have
            // been queued before they were denied within the previous policy.
            self.routing_config = Arc::clone(&previous.routing_config);
        }
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
        let expiry = self.pnet_expiries.get(peer).copied();
        if expiry.is_none() && self.policy_window.is_none() {
            return true;
        }
        let now = unix_secs_now_u64();
        now != 0 && expiry.is_none_or(|until| now < until) && self.policy_allows_at(now)
    }

    fn policy_allows_at(&self, now: u64) -> bool {
        self.policy_window
            .is_none_or(|(from, until)| now != 0 && now >= from && now < until)
    }

    fn active_peers_at(&self, now: u64) -> usize {
        if !self.policy_allows_at(now) {
            return 0;
        }
        let inactive = self
            .pnet_expiries
            .values()
            .filter(|&&until| now == 0 || now >= until)
            .count();
        self.peer_app_ids.len() - inactive
    }
}

const PNET_REFRESH_PERIOD: Duration = Duration::from_secs(5);
const PNET_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const PNET_BATCH_RETRY_AFTER: Duration = Duration::from_secs(2);
const PNET_LEGACY_QUERY_GROUP: usize = 8;
// Keep the ordinary snapshot cadence independent of how often the sweep
// yields to IPC events.
const PNET_LEGACY_SNAPSHOT_GROUP: usize = 16;
const PNET_LEGACY_PRIORITY_GROUP: usize = 4;
// Daemons admit 10 local queries per second per IPC client. Leave room for
// other local queries and avoid consuming the burst quota at startup.
const PNET_QUERY_SPACING: Duration = Duration::from_millis(125);
const PNET_RETRY_PERIOD: Duration = Duration::from_secs(1);
const PNET_RECENT_WINDOW: Duration = Duration::from_secs(30);
const PNET_SESSION_COALESCE: Duration = Duration::from_millis(100);
const PNET_EVENT_DRAIN_LIMIT: usize = 64;
const PNET_PRIORITY_RECHECK_SPACING: Duration = Duration::from_secs(1);
const PNET_PEER_HINT_TIMEOUT: Duration = Duration::from_millis(250);

fn pnet_session_refresh_spacing(peer_count: usize, group_size: usize) -> Duration {
    let batches = peer_count.div_ceil(group_size);
    // Limit the extra work under continuous churn. Once a table needs half or
    // more of the regular sweep window, use the regular cadence.
    let batches = u32::try_from(batches).unwrap_or(u32::MAX);
    (PNET_QUERY_SPACING * batches * 2)
        .max(PNET_RETRY_PERIOD)
        .min(PNET_REFRESH_PERIOD)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PriorityCheck {
    Withdrawal,
    Readmission,
}

struct SessionRefresh {
    events: broadcast::Receiver<VeilEvent>,
    pending: Option<Instant>,
    session_count: Option<u16>,
    pending_loss: Option<Instant>,
    pending_readmission: Option<Instant>,
    next_priority_check: Instant,
    loss_cursor: Option<NodeId>,
    admission_hints: BTreeSet<NodeId>,
    withdrawal_hints: BTreeSet<NodeId>,
}

impl SessionRefresh {
    fn new(events: broadcast::Receiver<VeilEvent>) -> Self {
        Self {
            events,
            pending: None,
            session_count: None,
            pending_loss: None,
            pending_readmission: None,
            next_priority_check: Instant::now(),
            loss_cursor: None,
            admission_hints: BTreeSet::new(),
            withdrawal_hints: BTreeSet::new(),
        }
    }

    fn drain_events(&mut self, configured: &[(NodeId, [u8; 32])]) {
        for _ in 0..PNET_EVENT_DRAIN_LIMIT {
            match self.events.try_recv() {
                Ok(event) => self.note_event(event, configured),
                Err(broadcast::error::TryRecvError::Lagged(_)) => self.note_lag(),
                Err(_) => break,
            }
        }
    }

    fn note_event(&mut self, event: VeilEvent, configured: &[(NodeId, [u8; 32])]) {
        match event.kind {
            EVENTS_LAGGED => self.note_lag(),
            SESSION_ADMITTED => self.note_readmission(),
            PNET_SESSION_ADMITTED | PNET_SESSION_ENDED => {
                // A daemon can carry many private sessions unrelated to this
                // gateway. Keep those peers out of its bounded hint queues.
                if let Ok(peer) = event.payload.try_into()
                    && configured
                        .binary_search_by_key(&peer, |(id, _)| *id)
                        .is_ok()
                {
                    let due = self.session_event_due();
                    let (hints, pending) = if event.kind == PNET_SESSION_ENDED {
                        (&mut self.withdrawal_hints, &mut self.pending_loss)
                    } else {
                        (&mut self.admission_hints, &mut self.pending_readmission)
                    };
                    if hints.len() < veil_proto::MAX_PEERS_LIST_ENTRIES {
                        hints.insert(peer);
                    }
                    pending.get_or_insert(due);
                }
            }
            SESSIONS_CHANGED => {
                let due = self.session_event_due();
                if let Ok(count) = event.payload.try_into().map(u16::from_be_bytes)
                    && self
                        .session_count
                        .replace(count)
                        .is_none_or(|previous| count < previous)
                {
                    self.pending_loss.get_or_insert(due);
                }
            }
            _ => {}
        }
    }

    fn session_event_due(&mut self) -> Instant {
        *self
            .pending
            .get_or_insert_with(|| Instant::now() + PNET_SESSION_COALESCE)
    }

    fn note_readmission(&mut self) {
        let due = self.session_event_due();
        self.pending_readmission.get_or_insert(due);
    }

    fn prioritize_admission_hints(
        &mut self,
        configured: &[(NodeId, [u8; 32])],
        admitted: &HashMap<NodeId, u64>,
        retry: &mut Vec<(NodeId, [u8; 32])>,
        limit: usize,
    ) {
        // Keep withdrawals first. A targeted hint can then precede peers
        // from a snapshot that might have omitted this newly admitted peer.
        let withdrawals = retry.partition_point(|(id, _)| admitted.contains_key(id));
        let hinted = self.take_targeted_hints(
            PriorityCheck::Readmission,
            configured,
            admitted,
            limit.saturating_sub(withdrawals),
        );
        if !hinted.is_empty() {
            retry.retain(|candidate| !hinted.contains(candidate));
            retry.splice(withdrawals..withdrawals, hinted);
        }
    }

    fn take_targeted_hints(
        &mut self,
        check: PriorityCheck,
        configured: &[(NodeId, [u8; 32])],
        admitted: &HashMap<NodeId, u64>,
        limit: usize,
    ) -> Vec<(NodeId, [u8; 32])> {
        let (hints, pending) = match check {
            PriorityCheck::Withdrawal => (&mut self.withdrawal_hints, &mut self.pending_loss),
            PriorityCheck::Readmission => {
                (&mut self.admission_hints, &mut self.pending_readmission)
            }
        };
        let mut candidates = Vec::new();
        while candidates.len() < limit
            && let Some(peer) = hints.pop_first()
        {
            if admitted.contains_key(&peer) == (check == PriorityCheck::Withdrawal)
                && let Ok(index) = configured.binary_search_by_key(&peer, |(id, _)| *id)
            {
                candidates.push(configured[index]);
            }
        }
        if !hints.is_empty() {
            let due = Instant::now() + PNET_PRIORITY_RECHECK_SPACING;
            self.pending.get_or_insert(due);
            pending.get_or_insert(due);
        }
        candidates
    }

    fn note_lag(&mut self) {
        // Either transition could have been lost. Use the existing paced
        // rechecks and let the next count start a fresh comparison.
        self.session_count = None;
        let now = Instant::now();
        self.pending = Some(now);
        self.pending_loss = Some(now);
        self.pending_readmission = Some(now);
    }

    fn priority_check(&self, normal_due: Option<Instant>) -> Option<(Instant, PriorityCheck)> {
        // Prefer the loss check when both hints coalesced into the same slot.
        [
            (self.pending_loss, PriorityCheck::Withdrawal),
            (self.pending_readmission, PriorityCheck::Readmission),
        ]
        .into_iter()
        .filter_map(|(due, check)| Some((due?.max(self.next_priority_check), check)))
        .filter(|(due, check)| {
            normal_due.is_none_or(|normal| {
                *due < normal
                    || (*due == normal
                        && *check == PriorityCheck::Withdrawal
                        && !self.withdrawal_hints.is_empty())
            })
        })
        .min_by_key(|(due, _)| *due)
    }
}

/// Scheduling hints from the previous authenticated checks. They survive an
/// IPC rebind, while the route table starts with no admissions on each bind.
#[derive(Default)]
struct RecentAdmissions {
    seen: BTreeMap<NodeId, Instant>,
    cursor: NodeId,
}

impl RecentAdmissions {
    fn remember_peer(&mut self, peer: NodeId, now: Instant) {
        self.seen.insert(peer, now);
        if self.seen.len() > veil_proto::MAX_PEERS_LIST_ENTRIES
            && let Some(oldest) = self.seen.iter().min_by_key(|(_, when)| **when)
        {
            let oldest_peer = *oldest.0;
            self.seen.remove(&oldest_peer);
        }
    }

    fn remember_peers(&mut self, peers: impl Iterator<Item = NodeId>, now: Instant) {
        for peer in peers.take(veil_proto::MAX_PEERS_LIST_ENTRIES) {
            self.remember_peer(peer, now);
        }
    }

    fn current_hints(&self, now: Instant) -> HashSet<NodeId> {
        self.seen
            .iter()
            .filter(|(_, seen)| now.duration_since(**seen) < PNET_RECENT_WINDOW)
            .map(|(peer, _)| *peer)
            .collect()
    }

    fn retry_group(
        &mut self,
        peers: &[(NodeId, [u8; 32])],
        admitted: &HashMap<NodeId, u64>,
        now: Instant,
        selected: &[(NodeId, [u8; 32])],
        limit: usize,
    ) -> Vec<(NodeId, [u8; 32])> {
        self.seen.retain(|peer, seen| {
            now.duration_since(*seen) < PNET_RECENT_WINDOW
                && peers.binary_search_by_key(peer, |(id, _)| *id).is_ok()
        });
        let group: Vec<_> = self
            .seen
            .range((Excluded(self.cursor), Unbounded))
            .chain(self.seen.range(..=self.cursor))
            .filter(|(peer, _)| !admitted.contains_key(*peer))
            .filter(|(peer, _)| !selected.iter().any(|(selected, _)| selected == *peer))
            .filter_map(|(peer, _)| {
                peers
                    .binary_search_by_key(peer, |(id, _)| *id)
                    .ok()
                    .map(|index| peers[index])
            })
            .take(limit.saturating_sub(selected.len()))
            .collect();
        if let Some((peer, _)) = group.last() {
            self.cursor = *peer;
        }
        group
    }
}

fn pnet_status_admits(peer: &NodeId, status: &PnetStatus, now: u64) -> bool {
    status.peer_node_id == *peer
        && status.admitted
        && status.has_cert
        && (status.valid_until_unix == 0 || (now != 0 && now < status.valid_until_unix))
}

async fn connect_pnet_status(
    socket: &Path,
    expected_node: NodeId,
    authority: Option<PnetAuthority>,
    pace: &mut tokio::time::Interval,
) -> Option<Arc<VeilClient>> {
    pace.tick().await;
    let connect = async {
        let client = VeilClient::connect_for_pnet_status(socket, authority.is_some())
            .await
            .map_err(BridgeError::client)?;
        if authority.is_some_and(|expected| {
            client.pnet_authority() != Some(expected) || !client.supports_pnet_admission_batch()
        }) {
            return Err(BridgeError::Cfg(
                "status IPC did not confirm the data connection's P-Net authority".into(),
            ));
        }
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

struct LivePeerHints {
    ids: HashSet<NodeId>,
    at_capacity: bool,
}

impl LivePeerHints {
    fn changed_peers(
        &self,
        configured: &[(NodeId, [u8; 32])],
        admitted: &HashMap<NodeId, u64>,
    ) -> Vec<(NodeId, [u8; 32])> {
        let limit = veilclient::PNET_ADMISSION_BATCH_MAX_PEERS;
        let candidates = self.ids.len() + if self.at_capacity { 0 } else { admitted.len() };
        if candidates <= configured.len() / 8 {
            return self.sparse_changed_peers(configured, admitted, limit);
        }

        let mut changed = Vec::new();
        // Recheck potentially stale routes ahead of new joins. A full
        // snapshot can omit live peers, so leave those absences to the sweep.
        if !self.at_capacity && !admitted.is_empty() {
            changed.extend(
                configured
                    .iter()
                    .copied()
                    .filter(|(id, _)| admitted.contains_key(id) && !self.ids.contains(id))
                    .take(limit),
            );
        }
        changed.extend(
            configured
                .iter()
                .copied()
                .filter(|(id, _)| self.ids.contains(id) && !admitted.contains_key(id))
                .take(limit - changed.len()),
        );
        changed
    }

    fn sparse_changed_peers(
        &self,
        configured: &[(NodeId, [u8; 32])],
        admitted: &HashMap<NodeId, u64>,
        limit: usize,
    ) -> Vec<(NodeId, [u8; 32])> {
        // Configured routes are sorted by NodeId. For a sparsely populated
        // gateway, look up just the observed changes instead of scanning all
        // configured peers. Preserve the sweep's ordering within each group.
        let lookup = |peer: &NodeId| configured.binary_search_by_key(peer, |(id, _)| *id).ok();
        let mut indices = Vec::new();
        if !self.at_capacity {
            indices.extend(
                admitted
                    .keys()
                    .filter(|peer| !self.ids.contains(*peer))
                    .filter_map(lookup),
            );
            indices.sort_unstable();
        }
        if indices.len() < limit {
            let joins_start = indices.len();
            indices.extend(
                self.ids
                    .iter()
                    .filter(|peer| !admitted.contains_key(*peer))
                    .filter_map(lookup),
            );
            indices[joins_start..].sort_unstable();
        }
        indices
            .into_iter()
            .take(limit)
            .map(|index| configured[index])
            .collect()
    }
}

fn withdrawal_candidates(
    configured: &[(NodeId, [u8; 32])],
    admitted: &HashMap<NodeId, u64>,
    live: Option<&LivePeerHints>,
    cursor: Option<NodeId>,
    limit: usize,
) -> Vec<(NodeId, [u8; 32])> {
    if admitted.len() <= limit {
        let mut installed: Vec<_> = admitted
            .keys()
            .filter_map(|peer| {
                configured
                    .binary_search_by_key(peer, |(id, _)| *id)
                    .ok()
                    .map(|index| configured[index])
            })
            .collect();
        installed.sort_unstable_by_key(|(id, _)| *id);
        return installed;
    }

    // A truncated snapshot can omit live peers. Those peers are only
    // scheduling candidates, and the cursor avoids recurring checks of
    // the same prefix when loss events arrive during the normal cooldown.
    let start = cursor.map_or(0, |cursor| {
        configured.partition_point(|(id, _)| *id <= cursor)
    });
    configured[start..]
        .iter()
        .chain(&configured[..start])
        .filter(|(id, _)| {
            admitted.contains_key(id) && live.is_none_or(|list| !list.ids.contains(id))
        })
        .take(limit)
        .copied()
        .collect()
}

async fn live_peer_hints(
    client: &VeilClient,
    pace: &mut tokio::time::Interval,
    retry_after_timeout: bool,
) -> Option<LivePeerHints> {
    let mut retried = false;
    let peers = loop {
        pace.tick().await;
        match tokio::time::timeout(PNET_PEER_HINT_TIMEOUT, client.peers()).await {
            Ok(Ok(peers)) => break peers,
            Ok(Err(error)) => {
                tracing::debug!(%error, "P-Net session hint query failed");
                return None;
            }
            Err(_) if retry_after_timeout && !retried => {
                // A missed hint after a session event can leave a rejoining
                // peer waiting for the next full sweep. Repeat the hint at the
                // existing query pace before resuming that sweep.
                retried = true;
                tracing::debug!("retrying P-Net session hint after timeout");
            }
            Err(_) => {
                tracing::debug!("P-Net session hint query timed out");
                return None;
            }
        }
    };
    Some(LivePeerHints {
        at_capacity: peers.len() >= veil_proto::MAX_PEERS_LIST_ENTRIES,
        ids: peers
            .into_iter()
            .filter(|entry| entry.state == veil_proto::peer_state::ACTIVE)
            .map(|entry| entry.node_id)
            .collect(),
    })
}

fn prioritize_peers(
    order: &[(NodeId, [u8; 32])],
    priority: &HashSet<NodeId>,
    sorted_by_node_id: bool,
) -> Option<Vec<(NodeId, [u8; 32])>> {
    if priority.is_empty() {
        return None;
    }
    // Keep every configured peer in the sweep and preserve the relative
    // order within each group. A sparse hint over a sorted configuration
    // can find the priority entries directly and copy the remaining spans.
    let indices: Vec<_> = if sorted_by_node_id && priority.len() <= order.len() / 8 {
        let mut indices: Vec<_> = priority
            .iter()
            .filter_map(|peer| order.binary_search_by_key(peer, |(id, _)| *id).ok())
            .collect();
        indices.sort_unstable();
        indices
    } else {
        order
            .iter()
            .enumerate()
            .filter_map(|(index, (peer, _))| priority.contains(peer).then_some(index))
            .collect()
    };
    if indices.is_empty() {
        return None;
    }
    let mut prioritized = Vec::with_capacity(order.len());
    prioritized.extend(indices.iter().map(|&index| order[index]));
    let mut start = 0;
    for index in indices {
        prioritized.extend_from_slice(&order[start..index]);
        start = index + 1;
    }
    prioritized.extend_from_slice(&order[start..]);
    Some(prioritized)
}

async fn query_pnet_batch(
    client: &VeilClient,
    peers: &[(NodeId, [u8; 32])],
    pace: &mut tokio::time::Interval,
) -> Option<HashMap<NodeId, u64>> {
    let ids: Vec<_> = peers.iter().map(|(node_id, _)| *node_id).collect();
    pace.tick().await;
    let deadline = Instant::now() + PNET_QUERY_TIMEOUT;
    let first =
        tokio::time::timeout(PNET_BATCH_RETRY_AFTER, client.peer_pnet_admissions(&ids)).await;
    let reply = match first {
        Ok(reply) => Ok(reply),
        Err(_) => {
            // The daemon can silently drop an overloaded batch. Retry once
            // at the same pace, without extending the fail-closed deadline.
            // The SDK assigns a new ID and ignores a late first reply.
            tracing::debug!("retrying P-Net admission batch after missing reply");
            tokio::time::timeout_at(deadline, async {
                pace.tick().await;
                client.peer_pnet_admissions(&ids).await
            })
            .await
        }
    };
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
    if old.signed_policy != new.signed_policy {
        return Err("signed_policy");
    }
    // Routing and the batch flush window are intentionally reloadable.
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
    authority: Option<PnetAuthority>,
}

const REBIND_TIMEOUT: Duration = Duration::from_secs(5);
const REBIND_SOCKET_POLL: Duration = Duration::from_millis(250);
const MAX_REBIND_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    changed: (i64, i64),
}

async fn socket_identity(path: &Path) -> Option<SocketIdentity> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    meta.file_type().is_socket().then(|| SocketIdentity {
        device: meta.dev(),
        inode: meta.ino(),
        changed: (meta.ctime(), meta.ctime_nsec()),
    })
}

async fn wait_to_rebind(
    path: &Path,
    previous: Option<SocketIdentity>,
    delay: Duration,
) -> Option<SocketIdentity> {
    let deadline = Instant::now() + delay;
    loop {
        tokio::time::sleep_until(deadline.min(Instant::now() + REBIND_SOCKET_POLL)).await;
        let current = socket_identity(path).await;
        // An endpoint replacement can wake the retry earlier. The ordinary
        // deadline still retries a socket whose metadata did not change.
        if current.is_some_and(|socket| Some(socket) != previous) || Instant::now() >= deadline {
            return current;
        }
    }
}

async fn connect_for_routes(socket: &Path, signed: bool) -> Result<VeilClient, BridgeError> {
    if signed {
        VeilClient::connect_with_pnet_authority(socket).await
    } else {
        VeilClient::connect(socket).await
    }
    .map_err(BridgeError::client)
}

async fn bind_ipc(
    cfg: &OgateConfig,
    expected: Option<Binding>,
    signed: Option<&SignedRoutes>,
) -> Result<BoundIpc, BridgeError> {
    let client = connect_for_routes(&cfg.socket_path, signed.is_some()).await?;
    let authority = signed
        .map(|policy| policy.authenticate(client.pnet_authority(), unix_secs_now_u64()))
        .transpose()
        .map_err(BridgeError::Policy)?;
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
        authority,
    })
}

async fn reconnect_ipc(
    cfg: &OgateConfig,
    expected: Binding,
    signed: Option<&SignedRoutes>,
) -> BoundIpc {
    let mut delay = REBIND_SOCKET_POLL;
    let mut endpoint = socket_identity(&cfg.socket_path).await;
    loop {
        endpoint = wait_to_rebind(&cfg.socket_path, endpoint, delay).await;
        match tokio::time::timeout(REBIND_TIMEOUT, bind_ipc(cfg, Some(expected), signed)).await {
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
    packet_drops: Option<Arc<PacketDrops>>,
    route_status: Option<watch::Sender<Option<Arc<ArcSwap<SharedState>>>>>,
    signed: Option<Arc<SignedRoutes>>,
}

struct RouteBinding {
    node_id: NodeId,
    signed: Option<(Arc<SignedRoutes>, PnetAuthority)>,
    recent: Arc<SyncMutex<RecentAdmissions>>,
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

async fn report_route_status(
    period: Duration,
    config: watch::Receiver<OgateConfig>,
    state: watch::Receiver<Option<Arc<ArcSwap<SharedState>>>>,
) {
    let mut ticks = tokio::time::interval(period);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The initial bind can complete before this task is first polled.
    ticks.tick().await;
    loop {
        ticks.tick().await;
        if !tracing::enabled!(target: "ogate::status", tracing::Level::INFO) {
            continue;
        }
        let (pnet_required, signed_policy) = {
            let config = config.borrow();
            (config.pnet_required, config.signed_policy.is_some())
        };
        let Some(state) = state.borrow().clone() else {
            tracing::info!(target: "ogate::status", ipc_connected = false, pnet_required,
                active_peers = 0, "ogate route status");
            continue;
        };
        let routes = state.load();
        let now = unix_secs_now_u64();
        let policy_state = if !signed_policy {
            None
        } else if routes.policy_window.is_none() {
            Some("unavailable")
        } else if routes.policy_allows_at(now) {
            Some("current")
        } else {
            Some("outside_validity_window")
        };
        tracing::info!(target: "ogate::status", ipc_connected = true, pnet_required,
            configured_peers = routes.configured_peers,
            published_peers = routes.peer_app_ids.len(),
            active_peers = routes.active_peers_at(now),
            policy_state,
            policy_revision = routes.policy_revision,
            route_valid_until_unix = routes.policy_window.map(|(_, until)| until),
            "ogate route status");
    }
}

/// Run the bridge with one TUN interface across daemon reconnects.
pub async fn run(config_path: PathBuf, cfg: OgateConfig) -> Result<(), BridgeError> {
    cfg.validate()
        .map_err(|error| BridgeError::Cfg(error.to_string().into()))?;
    SharedState::build(&cfg)?;
    let signed = cfg
        .signed_policy
        .clone()
        .map(SignedRoutes::open)
        .transpose()
        .map_err(BridgeError::Policy)?
        .map(Arc::new);
    tracing::info!(socket = %cfg.socket_path.display(), "connecting to veil daemon");
    let mut link = bind_ipc(&cfg, None, signed.as_deref()).await?;
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
    let mut reporters = tokio::task::JoinSet::new();
    let packet_drops = cfg.logging.packet_drop_report_secs.map(|seconds| {
        let counters = Arc::new(PacketDrops::default());
        let reporting = Arc::clone(&counters);
        reporters.spawn(async move {
            reporting
                .report_every(Duration::from_secs(u64::from(seconds.get())))
                .await;
        });
        counters
    });
    let route_status_period = cfg.logging.route_status_report_secs;
    let (accepted, accepted_config) = watch::channel(cfg);
    let route_status = route_status_period.map(|seconds| {
        let (status, snapshots) = watch::channel(None);
        reporters.spawn(report_route_status(
            Duration::from_secs(u64::from(seconds.get())),
            accepted_config,
            snapshots,
        ));
        status
    });
    let bridge = Bridge {
        config_path,
        accepted,
        hup: Arc::new(Mutex::new(reload_signal())),
        reader: Arc::new(Mutex::new(reader)),
        writer: Arc::new(Mutex::new(writer)),
        cert_gate: app_cert_gate,
        cert_message,
        batching_enabled,
        packet_drops,
        route_status,
        signed,
    };
    let mut stopping = std::pin::pin!(wait_for_shutdown());
    let recent = Arc::new(SyncMutex::new(RecentAdmissions::default()));

    loop {
        match serve_link(&bridge, link, Arc::clone(&recent), stopping.as_mut()).await? {
            LinkExit::Shutdown => return Ok(()),
            LinkExit::DaemonDisconnected => tracing::warn!("ogate IPC disconnected; rebinding"),
        }
        let cfg = bridge.accepted.borrow().clone();
        link = tokio::select! {
            _ = stopping.as_mut() => return Ok(()),
            link = reconnect_ipc(&cfg, expected, bridge.signed.as_deref()) => link,
        };
    }
}

async fn serve_link(
    bridge: &Bridge,
    link: BoundIpc,
    recent: Arc<SyncMutex<RecentAdmissions>>,
    mut stopping: Pin<&mut impl Future<Output = ()>>,
) -> Result<LinkExit, BridgeError> {
    let BoundIpc {
        mut client,
        handle,
        binding,
        authority,
    } = link;
    let signed = match &bridge.signed {
        Some(signed) => Some((
            Arc::clone(signed),
            authority
                .ok_or_else(|| BridgeError::Cfg("signed policy authority is missing".into()))?,
        )),
        None => None,
    };
    let cfg = bridge.accepted.borrow().clone();
    let configured = SharedState::build(&cfg)?;
    let initial_state = if cfg.pnet_required {
        configured.with_pnet_admissions(&HashMap::new())
    } else {
        configured.clone()
    };
    let state = Arc::new(ArcSwap::from_pointee(initial_state));
    if let Some(status) = &bridge.route_status {
        status.send_replace(Some(Arc::clone(&state)));
    }
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
    //   * the configured flush interval elapses since the batch's first push
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
    let flush_after = Duration::from_micros(u64::from(cfg.batch.flush_after_us));
    let mut batch_config = bridge.accepted.subscribe();
    tracing::info!(
        batching_enabled,
        flush_after_us = cfg.batch.flush_after_us,
        "egress batching state — set [batch] enabled = false for rolling-upgrade safety"
    );

    let mut egress = {
        let state = Arc::clone(&state);
        let tun_r = Arc::clone(&bridge.reader);
        let mut shutdown = shutdown_rx;
        let app_sender = Arc::clone(&app_sender);
        let packet_drops = bridge.packet_drops.clone();
        tokio::spawn(async move {
            let mut tun_r = tun_r.lock().await;
            let mut batches = EgressBatches::with_ipc_prefix();
            let mut buf = Vec::new();
            let mut flush_after = flush_after;
            let mut routing_config = Arc::clone(&state.load().routing_config);
            let enqueue =
                async |config: &Arc<()>, peer_nid, peer_app_id, buf: Vec<u8>, is_batch| {
                    if !state
                        .load()
                        .permits_queued_egress(config, &peer_nid, peer_app_id)
                    {
                        if let Some(counters) = &packet_drops {
                            // All queued batch envelopes are constructed locally.
                            let count = if is_batch {
                                buf.get(APP_IPC_SEND_PREFIX_BYTES + 1)
                                    .copied()
                                    .map_or(0, u64::from)
                            } else {
                                1
                            };
                            counters.record(DropReason::EgressQueuedRoute, count);
                        }
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
                        record_one(packet_drops.as_deref(), DropReason::EgressIpcFrame);
                        tracing::warn!(%error, "ogate egress send failed");
                    }
                };
            loop {
                // Pick wake-up source: either the TUN reader OR a deadline timer
                // for the oldest pending batch.  `tokio::time::sleep_until` requires
                // a concrete Instant; if no batch is open, just sleep "forever"
                // (the TUN read will wake us first).
                let deadline = batches.earliest_deadline();
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
                        let cutoff = std::time::Instant::now();
                        for (peer_nid, envelope, peer_app_id) in batches.drain_expired(cutoff) {
                            enqueue(&routing_config, peer_nid, peer_app_id, envelope, true).await;
                        }
                    }
                    res = tun_r.read_packet_into_with_prefix(APP_IPC_SEND_PREFIX_BYTES, &mut buf) => match res {
                        Err(e) => {
                            return Err(BridgeError::Tun(e.into()));
                        }
                        Ok(()) => {
                            // `buf` layout: [reserved prefix][IP packet bytes].
                            // The PREFIX region is filled in-place by the SDK's
                            // `send_prepared` when we forward `buf` verbatim
                            // (solo-ship and raw paths) — zero memcpy of the
                            // packet body downstream.
                            if buf.len() <= APP_IPC_SEND_PREFIX_BYTES {
                                record_one(packet_drops.as_deref(), DropReason::EgressInvalidIp);
                                continue;
                            }
                            let pkt = &buf[APP_IPC_SEND_PREFIX_BYTES..];
                            let Some((_src, dst)) = parse_ip_endpoints(pkt) else {
                                record_one(packet_drops.as_deref(), DropReason::EgressInvalidIp);
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
                                    record_one(packet_drops.as_deref(), DropReason::EgressNoRoute);
                                    tracing::trace!(?dst, "egress: no peer for dst, dropping");
                                    continue;
                                }
                                other => {
                                    tracing::trace!(decision = ?other, "egress decision unexpected");
                                    continue;
                                }
                            };
                            let Some(peer_app_id) = snap.app_id_for(&peer_nid) else {
                                record_one(packet_drops.as_deref(), DropReason::EgressAdmission);
                                tracing::trace!("egress: peer route unavailable");
                                continue;
                            };
                            if !Arc::ptr_eq(&routing_config, &snap.routing_config) {
                                if let Some(counters) = &packet_drops {
                                    counters.record(DropReason::EgressQueuedRoute, batches.pending_packet_count());
                                }
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
                                record_one(packet_drops.as_deref(), DropReason::EgressOversize);
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
                                    enqueue(&routing_config, peer_nid, peer_app_id, std::mem::take(&mut buf), false).await;
                                } else {
                                    // Pre-flush: if appending would cross the
                                    // threshold, flush the current batch FIRST,
                                    // then start a fresh batch with this packet.
                                    if batches.peek(&peer_nid)
                                        .is_some_and(|batch| batch.len() + record_size > egress_flush_bytes)
                                        && let Some(envelope) = batches.take_peer(&peer_nid)
                                    {
                                        enqueue(&routing_config, peer_nid, peer_app_id, envelope, true).await;
                                    }
                                    let pb = batches.push_packet(peer_nid, peer_app_id, pkt, || {
                                        if batch_config.has_changed().unwrap_or(false) {
                                            flush_after = Duration::from_micros(u64::from(
                                                batch_config.borrow_and_update().batch.flush_after_us,
                                            ));
                                        }
                                        flush_after
                                    });
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
                                enqueue(&routing_config, peer_nid, peer_app_id, std::mem::take(&mut buf), false).await;
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
        let packet_drops = bridge.packet_drops.clone();
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
                                record_one(
                                    packet_drops.as_deref(),
                                    DropReason::IngressAppCertFrame,
                                );
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
                                    &state,
                                    &im.src_node_id,
                                    pkt,
                                    packet_drops.as_deref(),
                                )
                                .await;
                            }
                        } else {
                            // Legacy single-packet envelope.  Keep the
                            // pre-E27 MTU guard at envelope level (a compromised
                            // peer cannot inject a larger-than-MTU frame).
                            let mtu = state.load().mtu;
                            if im.data.len() > mtu as usize {
                                record_one(packet_drops.as_deref(), DropReason::IngressOversize);
                                tracing::debug!(
                                    src = %hex::encode(im.src_node_id),
                                    len = im.data.len(),
                                    mtu,
                                    "ingress: dropping oversize packet",
                                );
                                continue;
                            }
                            deliver_one(
                                &mut tun_w,
                                &state,
                                &im.src_node_id,
                                &im.data,
                                packet_drops.as_deref(),
                            )
                            .await;
                        }
                    }
                }
            }
        })
    };

    let policy_sync = signed.as_ref().and_then(|(policy, authority)| {
        (policy.publish || !policy.mirrors.is_empty()).then(|| {
            let policy = Arc::clone(policy);
            let socket = cfg.socket_path.clone();
            let authority = *authority;
            tokio::spawn(async move {
                crate::policy_sync::run(policy, &socket, binding.node_id, authority).await;
            })
        })
    });
    let routes = tokio::spawn(maintain_routes(
        bridge.config_path.clone(),
        bridge.accepted.clone(),
        Arc::clone(&bridge.hup),
        RouteBinding {
            node_id: binding.node_id,
            signed,
            recent: Arc::clone(&recent),
        },
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

    if let Some(status) = &bridge.route_status {
        status.send_replace(None);
    }
    if let Some(task) = policy_sync {
        task.abort();
        let _ = task.await;
    }
    routes.abort();
    let _ = routes.await;
    if matches!(outcome, Ok(LinkExit::DaemonDisconnected))
        && bridge.signed.is_none()
        && bridge.accepted.borrow().pnet_required
    {
        let admitted = state.load();
        recent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remember_peers(
                admitted.peer_app_ids.iter().map(|(peer, _)| *peer),
                Instant::now(),
            );
    }
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

async fn build_signed_update(
    policy: Arc<SignedRoutes>,
    authority: PnetAuthority,
    config: &OgateConfig,
    node: &NodeId,
    active: Option<&Arc<VerifiedRoutePolicy>>,
) -> anyhow::Result<Option<(Arc<VerifiedRoutePolicy>, SharedState)>> {
    let snapshot = tokio::task::spawn_blocking(move || policy.refresh()).await??;
    let now = unix_secs_now_u64();
    snapshot.check_current(now)?;
    anyhow::ensure!(
        authority.is_current(now),
        "daemon local P-Net membership has expired"
    );
    if active.is_some_and(|active| Arc::ptr_eq(active, &snapshot)) {
        return Ok(None);
    }
    let mut routes = config.clone();
    routes.peers = assigned_peers(&snapshot, config, node)?;
    let mut state = SharedState::build(&routes)?;
    let until = if authority.local_valid_until_unix == 0 {
        snapshot.valid_until_unix
    } else {
        snapshot
            .valid_until_unix
            .min(authority.local_valid_until_unix)
    };
    state.policy_window = Some((snapshot.valid_from_unix, until));
    state.policy_revision = Some(snapshot.revision);
    Ok(Some((snapshot, state)))
}

fn prioritize_signed_admissions(
    previous_order: &[(NodeId, [u8; 32])],
    configured: &SharedState,
    admitted: &HashMap<NodeId, u64>,
) -> Option<Vec<(NodeId, [u8; 32])>> {
    if admitted.is_empty() {
        return None;
    }
    let mut order = Vec::with_capacity(configured.peer_app_ids.len());
    // Preserve the relative check order of carried admissions, so adding
    // addresses before them cannot delay their next check.
    order.extend(
        previous_order
            .iter()
            .copied()
            .filter(|(peer, _)| admitted.contains_key(peer)),
    );
    order.extend(
        configured
            .peer_app_ids
            .iter()
            .copied()
            .filter(|(peer, _)| !admitted.contains_key(peer)),
    );
    Some(order)
}

fn apply_admissions(
    group: &[(NodeId, [u8; 32])],
    mut results: HashMap<NodeId, u64>,
    admitted: &mut HashMap<NodeId, u64>,
    binding: &RouteBinding,
) -> bool {
    let signed = binding.signed.is_some();
    let lock_recent = || {
        binding
            .recent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    };
    let mut recent = signed.then(&lock_recent);
    let now = Instant::now();
    let mut changed = false;
    for (peer, _) in group {
        match results.remove(peer) {
            Some(expiry) => {
                if signed && let Some(recent) = recent.as_mut() {
                    recent.seen.insert(*peer, now);
                }
                changed |= admitted.insert(*peer, expiry) != Some(expiry);
            }
            None if admitted.remove(peer).is_some() => {
                if !signed {
                    recent
                        .get_or_insert_with(&lock_recent)
                        .remember_peer(*peer, now);
                }
                changed = true;
            }
            None => {}
        }
    }
    changed
}

async fn maintain_routes(
    config_path: PathBuf,
    accepted: watch::Sender<OgateConfig>,
    hup: Arc<Mutex<Option<Signal>>>,
    binding: RouteBinding,
    mut configured: SharedState,
    state: Arc<ArcSwap<SharedState>>,
    route_changes: Arc<Notify>,
) {
    let mut config = accepted.borrow().clone();
    let mut hup = hup.lock().await;
    let mut admitted = HashMap::new();
    let mut connection: Option<Arc<VeilClient>> = None;
    let mut session_refresh: Option<SessionRefresh> = None;
    let mut next_session_sweep = Instant::now();
    let mut active_policy = None;
    let mut policy_updates = binding.signed.as_ref().map(|(policy, _)| policy.updates());
    let mut admission_order = None;
    let mut next_peer = 0;
    let mut refresh = tokio::time::interval(PNET_REFRESH_PERIOD);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pace = tokio::time::interval(PNET_QUERY_SPACING);
    pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut retry_due = Instant::now();
    #[derive(PartialEq, Eq)]
    enum Wake {
        Sweep,
        Reload,
        Policy,
        SessionEvent(Result<VeilEvent, broadcast::error::RecvError>),
        SessionSweep,
        PrioritySweep,
    }
    loop {
        // Read a bounded group of buffered events before the next paced
        // query. One event per query can delay a hint behind busy sessions.
        if let Some(refresh) = session_refresh.as_mut() {
            refresh.drain_events(&configured.peer_app_ids);
        }
        let batched_admission = connection
            .as_ref()
            .is_none_or(|client| client.supports_pnet_admission_batch());
        let (group_size, priority_size) = if batched_admission {
            (
                veilclient::PNET_ADMISSION_BATCH_MAX_PEERS,
                veilclient::PNET_ADMISSION_BATCH_MAX_PEERS,
            )
        } else {
            (PNET_LEGACY_SNAPSHOT_GROUP, PNET_LEGACY_PRIORITY_GROUP)
        };
        let multiple_batches = configured.peer_app_ids.len() > group_size;
        let session_due = session_refresh.as_ref().and_then(|refresh| refresh.pending);
        let session_due_at = session_due.map(|due| due.max(next_session_sweep));
        let may_recheck_sessions = multiple_batches || next_peer == 0;
        let priority_check = session_refresh.as_mut().and_then(|refresh| {
            if !multiple_batches {
                refresh.admission_hints.clear();
            }
            if admitted.is_empty() {
                refresh.pending_loss = None;
            }
            if !multiple_batches || admitted.is_empty() {
                refresh.withdrawal_hints.clear();
            }
            multiple_batches
                .then(|| refresh.priority_check(session_due_at))
                .flatten()
        });
        let now = Instant::now();
        let priority_ready = priority_check.is_some_and(|(due, _)| due <= now);
        let sessions_ready =
            may_recheck_sessions && session_due_at.is_some_and(|due| due <= now) || priority_ready;
        let wake = tokio::select! {
            _ = async {
                if next_peer == 0 {
                    refresh.tick().await;
                }
            }, if config.pnet_required && !sessions_ready => Wake::Sweep,
            event = async {
                match session_refresh.as_mut() {
                    Some(refresh) => refresh.events.recv().await,
                    None => std::future::pending().await,
                }
            }, if !sessions_ready => Wake::SessionEvent(event),
            _ = async {
                match session_due_at {
                    Some(due) => tokio::time::sleep_until(due).await,
                    None => std::future::pending().await,
                }
            }, if may_recheck_sessions && !priority_ready => Wake::SessionSweep,
            _ = async {
                match priority_check {
                    Some((due, _)) => tokio::time::sleep_until(due).await,
                    None => std::future::pending().await,
                }
            } => Wake::PrioritySweep,
            _ = async {
                match hup.as_mut() {
                    Some(hup) => hup.recv().await,
                    None => std::future::pending().await,
                }
            } => Wake::Reload,
            _ = async {
                match policy_updates.as_mut() {
                    Some(updates) => { let _ = updates.changed().await; }
                    None => std::future::pending().await,
                }
            } => Wake::Policy,
        };
        if let Wake::SessionEvent(event) = wake {
            match event {
                Ok(event) => {
                    if let Some(refresh) = session_refresh.as_mut() {
                        refresh.note_event(event, &configured.peer_app_ids);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if let Some(refresh) = session_refresh.as_mut() {
                        refresh.note_lag();
                    }
                }
                Err(broadcast::error::RecvError::Closed) => session_refresh = None,
            }
            continue;
        }
        let priority = priority_check
            .filter(|_| wake == Wake::PrioritySweep)
            .map(|(_, check)| check);
        if let Some(refresh) = session_refresh.as_mut() {
            if wake == Wake::SessionSweep
                || !multiple_batches && session_due.is_some_and(|due| due <= Instant::now())
            {
                refresh.pending = None;
                refresh.pending_loss = None;
                refresh.pending_readmission = None;
            }
            match priority {
                Some(PriorityCheck::Withdrawal) => {
                    refresh.pending_loss = None;
                    refresh.next_priority_check = Instant::now() + PNET_PRIORITY_RECHECK_SPACING;
                }
                Some(PriorityCheck::Readmission) => refresh.pending_readmission = None,
                None => {}
            }
        }
        if wake == Wake::Reload {
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
            let window_changed = new.batch.flush_after_us != config.batch.flush_after_us;
            if binding.signed.is_some() {
                accepted.send_replace(new.clone());
                config = new;
                // Check the protected policy below. Keep the current sweep
                // cursor when the installed policy has not changed.
                if next_peer == 0 {
                    refresh.reset();
                }
            } else {
                // A timing change alone does not invalidate queued packets.
                // Changes to routing keep the existing new-state check.
                if !window_changed
                    || new.mode != config.mode
                    || new.pnet_required != config.pnet_required
                    || new.peers != config.peers
                {
                    configured = match SharedState::build(&new) {
                        Ok(full) => full,
                        Err(error) => {
                            tracing::warn!(%error, "could not build ogate routes");
                            continue;
                        }
                    };
                }
                config = new;
                next_peer = 0;
                admission_order = None;
                let routes = if config.pnet_required {
                    admitted.retain(|peer, _| configured.app_id_for(peer).is_some());
                    refresh.reset();
                    configured.with_pnet_admissions(&admitted)
                } else {
                    admitted.clear();
                    connection = None;
                    session_refresh = None;
                    configured.clone()
                };
                publish_routes(routes, &state, &route_changes);
                accepted.send_replace(config.clone());
            }
            if window_changed {
                tracing::info!(
                    flush_after_us = config.batch.flush_after_us,
                    "accepted ogate batch flush interval"
                );
            }
            if !config.pnet_required {
                continue;
            }
        }

        if let Some((policy, authority)) = &binding.signed
            && (next_peer == 0 || matches!(wake, Wake::Reload | Wake::Policy))
        {
            let update = build_signed_update(
                Arc::clone(policy),
                *authority,
                &config,
                &binding.node_id,
                active_policy.as_ref(),
            )
            .await;
            let changed = match update {
                Ok(Some((snapshot, mut routes))) => {
                    if connection
                        .as_ref()
                        .is_some_and(|client| !client.is_disconnected())
                    {
                        routes.preserve_signed_admissions(
                            &configured,
                            &mut admitted,
                            unix_secs_now_u64(),
                        );
                    } else {
                        admitted.clear();
                        connection = None;
                        session_refresh = None;
                    }
                    admission_order = prioritize_signed_admissions(
                        admission_order
                            .as_deref()
                            .unwrap_or(&configured.peer_app_ids),
                        &routes,
                        &admitted,
                    );
                    tracing::info!(revision = snapshot.revision, "loaded signed P-Net policy");
                    active_policy = Some(snapshot);
                    configured = routes;
                    true
                }
                Ok(None) => false,
                Err(error) => {
                    tracing::warn!(%error, "signed P-Net policy unavailable");
                    if active_policy.take().is_none() {
                        continue;
                    }
                    admitted.clear();
                    admission_order = None;
                    // Signed mode validates the base config with no manual
                    // peers. Reuse its empty route table on any policy error.
                    match SharedState::build(&config) {
                        Ok(empty) => configured = empty,
                        Err(error) => {
                            tracing::error!(%error, "could not rebuild empty signed policy routes");
                            configured = configured.with_pnet_admissions(&HashMap::new());
                        }
                    }
                    true
                }
            };
            if changed {
                next_peer = 0;
                publish_routes(
                    configured.with_pnet_admissions(&admitted),
                    &state,
                    &route_changes,
                );
            }
        }

        if configured.peer_app_ids.is_empty() {
            continue;
        }
        if wake == Wake::SessionSweep {
            next_session_sweep = Instant::now()
                + pnet_session_refresh_spacing(configured.peer_app_ids.len(), group_size);
            if next_peer == 0 {
                refresh.reset();
            }
        }
        let mut legacy_group_limit = PNET_LEGACY_QUERY_GROUP;
        if connection.is_none() {
            let authority = binding.signed.as_ref().map(|(_, authority)| *authority);
            connection =
                connect_pnet_status(&config.socket_path, binding.node_id, authority, &mut pace)
                    .await;
            if let Some(client) = &connection {
                let batched_admission = client.supports_pnet_admission_batch();
                session_refresh = Some(SessionRefresh::new(client.events_with_lag().await));
                let group_limit = if batched_admission {
                    veilclient::PNET_ADMISSION_BATCH_MAX_PEERS
                } else {
                    PNET_LEGACY_SNAPSHOT_GROUP
                };
                if next_peer == 0 && configured.peer_app_ids.len() > group_limit {
                    let recent = if binding.signed.is_none() {
                        binding
                            .recent
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .current_hints(Instant::now())
                    } else {
                        HashSet::new()
                    };
                    // PEERS predates batch admission. Try it once on the new
                    // status connection and use the result only for ordering.
                    let live = live_peer_hints(client, &mut pace, false).await;
                    for hints in std::iter::once(&recent).chain(live.as_ref().map(|live| &live.ids))
                    {
                        let order = admission_order
                            .as_deref()
                            .unwrap_or(&configured.peer_app_ids);
                        if let Some(prioritized) =
                            prioritize_peers(order, hints, admission_order.is_none())
                        {
                            if !batched_admission {
                                // Publish results for a short priority prefix
                                // before pacing queries to the rest of the table.
                                legacy_group_limit = prioritized
                                    .iter()
                                    .take(PNET_LEGACY_QUERY_GROUP)
                                    .take_while(|(peer, _)| hints.contains(peer))
                                    .count();
                            }
                            admission_order = Some(prioritized);
                        }
                    }
                }
            }
        }
        let order = admission_order
            .as_deref()
            .unwrap_or(&configured.peer_app_ids);
        // Recheck one batch of likely session changes, then resume the full
        // sweep at the same cursor. The snapshot never changes admission.
        let recheck_sessions = wake == Wake::SessionSweep && multiple_batches;
        let withdrawal = priority == Some(PriorityCheck::Withdrawal);
        let mut targeted = if (recheck_sessions || withdrawal)
            && let Some(refresh) = session_refresh.as_mut()
        {
            refresh.take_targeted_hints(
                PriorityCheck::Withdrawal,
                &configured.peer_app_ids,
                &admitted,
                priority_size,
            )
        } else {
            Vec::new()
        };
        let need_snapshot = (recheck_sessions && targeted.len() < priority_size)
            || (withdrawal && targeted.is_empty() && admitted.len() > priority_size);
        let live = if need_snapshot && let Some(client) = &connection {
            live_peer_hints(client, &mut pace, recheck_sessions && batched_admission).await
        } else {
            None
        };
        let mut retry = if withdrawal && !targeted.is_empty() {
            targeted
        } else if withdrawal {
            // Both the count and peer list are hints. Check each candidate
            // against the daemon's admission provider before changing routes.
            let cursor = session_refresh
                .as_ref()
                .and_then(|refresh| refresh.loss_cursor);
            let group = withdrawal_candidates(
                &configured.peer_app_ids,
                &admitted,
                live.as_ref(),
                cursor,
                priority_size,
            );
            if let Some((peer, _)) = group.last()
                && let Some(refresh) = session_refresh.as_mut()
            {
                refresh.loss_cursor = Some(*peer);
            }
            tracing::trace!(
                peers = group.len(),
                "rechecking P-Net routes after possible session loss"
            );
            group
        } else {
            if let Some(live) = &live {
                let mut inferred = live.changed_peers(&configured.peer_app_ids, &admitted);
                inferred.retain(|candidate| !targeted.contains(candidate));
                targeted.append(&mut inferred);
            }
            targeted
        };
        let legacy_snapshot_backlog =
            recheck_sessions && !batched_admission && retry.len() > priority_size;
        let readmission = priority == Some(PriorityCheck::Readmission);
        if (recheck_sessions || readmission)
            && let Some(refresh) = session_refresh.as_mut()
            && !refresh.admission_hints.is_empty()
        {
            refresh.prioritize_admission_hints(
                &configured.peer_app_ids,
                &admitted,
                &mut retry,
                priority_size,
            );
        }
        retry.truncate(priority_size);
        let signed_retry = binding.signed.is_some()
            && priority.is_none()
            && retry.is_empty()
            && Instant::now() >= retry_due;
        // A full or missing snapshot can hide a rejoining peer. Use free
        // places in this batch to recheck recently withdrawn manual routes.
        let incomplete_hint = binding.signed.is_none()
            && recheck_sessions
            && live.as_ref().is_none_or(|live| live.at_capacity)
            && retry.len() < priority_size;
        if (signed_retry || incomplete_hint || readmission) && connection.is_some() {
            let now = Instant::now();
            if signed_retry {
                retry_due = now + PNET_RETRY_PERIOD;
            }
            let recent = binding
                .recent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retry_group(
                    &configured.peer_app_ids,
                    &admitted,
                    now,
                    &retry,
                    priority_size,
                );
            retry.extend(recent);
        }
        // A readmission hint with no matching recent routes takes no IPC slot.
        if readmission
            && !retry.is_empty()
            && let Some(refresh) = session_refresh.as_mut()
        {
            let now = Instant::now();
            refresh.next_priority_check = now + PNET_PRIORITY_RECHECK_SPACING;
            if binding.signed.is_some() {
                retry_due = now + PNET_RETRY_PERIOD;
            }
        }
        if !retry.is_empty()
            && let Some(client) = &connection
        {
            // Older daemons use at most four paced unary queries per
            // priority round before the regular sweep resumes.
            let (response, reconnect_legacy) = if client.supports_pnet_admission_batch() {
                (query_pnet_batch(client, &retry, &mut pace).await, false)
            } else {
                let (results, uncertain) = query_pnet_legacy(client, &retry, &mut pace).await;
                (Some(results), uncertain)
            };
            match response {
                Some(results) => {
                    if apply_admissions(&retry, results, &mut admitted, &binding) {
                        publish_routes(
                            configured.with_pnet_admissions(&admitted),
                            &state,
                            &route_changes,
                        );
                        // Give the ordinary sweep a group between snapshots.
                        // Require progress before scheduling another snapshot:
                        // active but denied peers can stay listed.
                        if legacy_snapshot_backlog
                            && !reconnect_legacy
                            && let Some(refresh) = session_refresh.as_mut()
                        {
                            next_session_sweep = Instant::now() + PNET_PRIORITY_RECHECK_SPACING;
                            refresh.pending.get_or_insert(next_session_sweep);
                        }
                    }
                }
                None => connection = None,
            }
            if reconnect_legacy {
                // Match the ordinary legacy sweep: invalidate unconfirmed
                // routes in this group and discard potentially late replies.
                connection = None;
                session_refresh = None;
                continue;
            }
        }
        if priority.is_some() && connection.is_some() {
            continue;
        }
        let end;
        let results;
        if let Some(client) = &connection {
            if client.supports_pnet_admission_batch() {
                end = (next_peer + veilclient::PNET_ADMISSION_BATCH_MAX_PEERS).min(order.len());
                results = query_pnet_batch(client, &order[next_peer..end], &mut pace).await;
            } else {
                end = (next_peer + legacy_group_limit).min(order.len());
                let (legacy_results, uncertain) =
                    query_pnet_legacy(client, &order[next_peer..end], &mut pace).await;
                if uncertain {
                    connection = None;
                    session_refresh = None;
                }
                results = Some(legacy_results);
            }
        } else {
            end = 0;
            results = None;
        }
        let Some(results) = results else {
            connection = None;
            session_refresh = None;
            next_peer = 0;
            if !admitted.is_empty() {
                if binding.signed.is_none() {
                    binding
                        .recent
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remember_peers(admitted.keys().copied(), Instant::now());
                }
                admitted.clear();
                publish_routes(
                    configured.with_pnet_admissions(&admitted),
                    &state,
                    &route_changes,
                );
            }
            continue;
        };
        let group = &order[next_peer..end];
        if apply_admissions(group, results, &mut admitted, &binding) {
            publish_routes(
                configured.with_pnet_admissions(&admitted),
                &state,
                &route_changes,
            );
        }
        next_peer = if end == order.len() { 0 } else { end };
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
    packet_drops: Option<&PacketDrops>,
) {
    let snap = state.load();
    if pkt.len() > snap.mtu as usize {
        record_one(packet_drops, DropReason::IngressOversize);
        tracing::debug!(
            src = %hex::encode(src_node_id),
            len = pkt.len(),
            mtu = snap.mtu,
            "ingress: dropping oversize sub-packet",
        );
        return;
    }
    if !snap.cert_is_current(src_node_id) {
        record_one(packet_drops, DropReason::IngressExpired);
        tracing::debug!("ingress: dropping peer with expired P-Net certificate");
        return;
    }
    let src_ip = parse_ip_endpoints(pkt).map(|(s, _)| s);
    let decision = snap.table.lookup_ingress(src_node_id, src_ip);
    drop(snap);
    match decision {
        Decision::Forward(_) => {
            if let Err(e) = tun_w.write_packet(pkt).await {
                record_one(packet_drops, DropReason::IngressTunWrite);
                tracing::warn!(error = %e, "TUN write failed");
            }
        }
        Decision::Unauthorized => {
            record_one(packet_drops, DropReason::IngressUnauthorized);
            tracing::debug!(
                src = %hex::encode(src_node_id),
                "ingress: dropping unauthorized peer",
            );
        }
        Decision::SpoofedSourceIp => {
            record_one(packet_drops, DropReason::IngressBadSource);
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
    #[error("signed policy: {0}")]
    Policy(anyhow::Error),
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
            signed_policy: None,

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
    fn reported_route_count_obeys_certificate_and_policy_deadlines() {
        let mut config = cfg();
        config.pnet_required = true;
        config.peers.push(PeerEntry {
            node_id: "bb".repeat(32),
            addr_v4: Some(Ipv4Addr::new(10, 99, 0, 3)),
            addr_v6: None,
            name: None,
        });
        config.peers.push(PeerEntry {
            node_id: "cc".repeat(32),
            addr_v4: Some(Ipv4Addr::new(10, 99, 0, 4)),
            addr_v6: None,
            name: None,
        });
        let configured = SharedState::build(&config).unwrap();
        let mut active =
            configured.with_pnet_admissions(&HashMap::from([([0xaa; 32], 5), ([0xbb; 32], 0)]));
        assert_eq!(active.configured_peers, 3);
        assert_eq!(active.peer_app_ids.len(), 2);
        assert_eq!(active.active_peers_at(4), 2);
        assert_eq!(active.active_peers_at(5), 1);
        assert_eq!(active.active_peers_at(0), 1);
        active.policy_window = Some((3, 8));
        assert_eq!(active.active_peers_at(0), 0);
        assert_eq!(active.active_peers_at(2), 0);
        assert_eq!(active.active_peers_at(3), 2);
        assert_eq!(active.active_peers_at(5), 1);
        assert_eq!(active.active_peers_at(8), 0);
    }

    #[test]
    fn sparse_pnet_routes_keep_dual_stack_admission_and_source_checks() {
        let mut config = pnet_sweep_config(Path::new("unused"), 4096);
        config.mode = AccessMode::Authorized;
        config.peers[0].addr_v6 = Some("fd00::2".parse().unwrap());
        let configured = SharedState::build(&config).unwrap();
        let peer = [0xaa; 32];
        let stranger = [0xbb; 32];
        let mut expired = [0; 32];
        expired[1] = 3;
        let active = configured.with_pnet_admissions(&HashMap::from([
            (stranger, 0),
            (peer, 0),
            (expired, 1),
        ]));

        assert_eq!(active.table.peer_count(), 2);
        assert_eq!(active.peer_app_ids[0].0, expired);
        assert_eq!(active.peer_app_ids[1].0, peer);
        assert_eq!(active.app_id_for(&peer), configured.app_id_for(&peer));
        assert_eq!(active.app_id_for(&expired), None);
        assert_eq!(active.app_id_for(&stranger), None);
        let generation = &configured.routing_config;
        assert!(active.permits_queued_egress(generation, &peer, active.app_id_for(&peer).unwrap()));

        for ip in ["10.99.0.2", "fd00::2"] {
            let ip = ip.parse().unwrap();
            assert_eq!(active.table.lookup_egress(ip), Decision::Forward(peer));
            assert_eq!(
                active.table.lookup_ingress(&peer, Some(ip)),
                Decision::Forward(peer)
            );
            assert_eq!(
                active.table.lookup_ingress(&stranger, Some(ip)),
                Decision::Unauthorized
            );
        }
        let unassigned = "10.99.0.4".parse().unwrap();
        assert_eq!(active.table.lookup_egress(unassigned), Decision::NoRoute);
        assert_eq!(
            active.table.lookup_ingress(&peer, Some(unassigned)),
            Decision::SpoofedSourceIp
        );
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

    #[test]
    fn policy_and_peer_validity_each_gate_packet_dispatch() {
        let mut state = SharedState::build(&cfg()).unwrap();
        let peer = [0xaa; 32];
        let app_id = state.app_id_for(&peer).unwrap();
        let generation = Arc::clone(&state.routing_config);
        let now = unix_secs_now_u64();
        state.policy_window = Some((1, now + 60));
        state.pnet_expiries.insert(peer, now + 60);
        assert!(state.permits_queued_egress(&generation, &peer, app_id));
        state.policy_window = Some((now + 30, now + 60));
        assert!(!state.cert_is_current(&peer));
        state.policy_window = Some((1, now));
        assert!(!state.permits_queued_egress(&generation, &peer, app_id));
        state.policy_window = Some((1, now + 60));
        state.pnet_expiries.insert(peer, now);
        assert!(!state.cert_is_current(&peer));
    }

    #[test]
    fn signed_update_carries_only_current_unchanged_admissions_in_check_order() {
        let mut config = cfg();
        config.pnet_required = true;
        for (byte, host) in [(0xa0, 3), (0xab, 4), (0xac, 5), (0xad, 6)] {
            config.peers.push(PeerEntry {
                node_id: hex::encode([byte; 32]),
                addr_v4: Some(Ipv4Addr::new(10, 99, 0, host)),
                addr_v6: Some(format!("fd00::{host}").parse().unwrap()),
                name: None,
            });
        }
        let mut previous = SharedState::build(&config).unwrap();
        previous.policy_window = Some((10, 120));
        let mut admissions = HashMap::from([
            ([0xaa; 32], 106),
            ([0xa0; 32], 0),
            ([0xab; 32], 0),
            ([0xac; 32], 140),
            ([0xad; 32], 100),
        ]);
        config.peers[2].addr_v6 = Some("fd00::99".parse().unwrap());
        config.peers[3].node_id = hex::encode([0x10; 32]);
        let mut next = SharedState::build(&config).unwrap();
        next.policy_window = Some((10, 200));
        next.preserve_signed_admissions(&previous, &mut admissions, 100);
        assert_eq!(
            admissions,
            HashMap::from([([0xaa; 32], 106), ([0xa0; 32], 120)])
        );

        let mut previous_order = previous.peer_app_ids.clone();
        previous_order.swap(0, 1);
        let order = prioritize_signed_admissions(&previous_order, &next, &admissions).unwrap();
        assert_eq!(
            order.iter().map(|entry| entry.0[0]).collect::<Vec<_>>(),
            [0xaa, 0xa0, 0x10, 0xab, 0xad]
        );

        let active = next.with_pnet_admissions(&admissions);
        assert_eq!(
            active
                .table
                .lookup_egress(Ipv4Addr::new(10, 99, 0, 2).into()),
            Decision::Forward([0xaa; 32])
        );
        for host in 4..=6 {
            assert_eq!(
                active
                    .table
                    .lookup_egress(Ipv4Addr::new(10, 99, 0, host).into()),
                Decision::NoRoute
            );
        }

        let mut expired_admissions = HashMap::from([([0xa0; 32], 0)]);
        next.preserve_signed_admissions(&previous, &mut expired_admissions, 120);
        assert!(expired_admissions.is_empty());
    }

    #[test]
    fn signed_update_keeps_packet_batches_only_for_unchanged_assignments() {
        let mut config = cfg();
        config.peers.push(PeerEntry {
            node_id: hex::encode([0xbb; 32]),
            addr_v4: Some(Ipv4Addr::new(10, 99, 0, 3)),
            addr_v6: None,
            name: None,
        });
        let mut previous = SharedState::build(&config).unwrap();
        previous.policy_window = Some((10, 120));
        let mut admitted = HashMap::from([([0xaa; 32], 0)]);
        config.peers.push(PeerEntry {
            node_id: hex::encode([0xcc; 32]),
            addr_v4: Some(Ipv4Addr::new(10, 99, 0, 4)),
            addr_v6: None,
            name: None,
        });
        let mut expanded = SharedState::build(&config).unwrap();
        expanded.preserve_signed_admissions(&previous, &mut admitted, 100);
        assert!(Arc::ptr_eq(
            &expanded.routing_config,
            &previous.routing_config
        ));

        config.peers[1].addr_v4 = Some(Ipv4Addr::new(10, 99, 0, 5));
        let mut reassigned = SharedState::build(&config).unwrap();
        reassigned.preserve_signed_admissions(&previous, &mut admitted, 100);
        assert_eq!(admitted, HashMap::from([([0xaa; 32], 120)]));
        assert!(!Arc::ptr_eq(
            &reassigned.routing_config,
            &previous.routing_config
        ));
    }

    #[test]
    fn startup_priority_preserves_both_groups_and_ignores_unconfigured_peers() {
        let sorted: Vec<_> = (0..96).map(|id| ([id; 32], [id + 1; 32])).collect();
        let priority = HashSet::from([[7; 32], [73; 32], [92; 32], [220; 32]]);
        let expected: Vec<_> = [sorted[7], sorted[73], sorted[92]]
            .into_iter()
            .chain(
                sorted
                    .iter()
                    .copied()
                    .filter(|(id, _)| !priority.contains(id)),
            )
            .collect();
        assert_eq!(prioritize_peers(&sorted, &priority, true), Some(expected));
        assert_eq!(
            prioritize_peers(&sorted, &HashSet::from([[220; 32]]), true),
            None
        );

        let mut reordered = sorted.clone();
        reordered.swap(0, 92);
        reordered.swap(1, 82);
        let order = prioritize_peers(&reordered, &priority, false).unwrap();
        assert_eq!(&order[..3], &[sorted[92], sorted[7], sorted[73]]);
        assert!(
            order[3..].iter().copied().eq(reordered
                .iter()
                .copied()
                .filter(|(id, _)| !priority.contains(id)))
        );
    }

    #[test]
    fn sparse_session_hints_match_dense_order_and_respect_a_full_snapshot() {
        fn id(index: u16) -> NodeId {
            let mut id = [0; 32];
            id[..2].copy_from_slice(&index.to_be_bytes());
            id
        }

        let configured: Vec<_> = (0..4096).map(|index| (id(index), [17; 32])).collect();
        // All of the changes fit inside this prefix. Using this prefix alone
        // selects the dense path while the full table selects the sparse path.
        let dense = &configured[..256];
        let limit = veilclient::PNET_ADMISSION_BATCH_MAX_PEERS;
        let admitted: HashMap<_, _> = (100..104)
            .chain(160..220)
            .chain([5000])
            .map(|index| (id(index), 0))
            .collect();
        let live: HashSet<_> = (0..90).chain(160..220).chain([5100]).map(id).collect();
        for at_capacity in [false, true] {
            let hints = LivePeerHints {
                ids: live.clone(),
                at_capacity,
            };
            let sparse = hints.changed_peers(&configured, &admitted);
            assert_eq!(sparse, hints.changed_peers(dense, &admitted));
            let withdrawn = if at_capacity { 100..100 } else { 100..104 };
            let expected: Vec<_> = withdrawn
                .chain(0..90)
                .take(limit)
                .map(|index| (id(index), [17; 32]))
                .collect();
            assert_eq!(sparse, expected);
        }
    }

    #[test]
    fn unconfigured_sessions_cannot_fill_either_targeted_hint_queue() {
        let peer = [0xaa; 32];
        let configured = [(peer, [1; 32])];
        for (kind, check, admitted) in [
            (
                PNET_SESSION_ADMITTED,
                PriorityCheck::Readmission,
                HashMap::new(),
            ),
            (
                PNET_SESSION_ENDED,
                PriorityCheck::Withdrawal,
                HashMap::from([(peer, 0)]),
            ),
        ] {
            let (_, events) = broadcast::channel(1);
            let mut refresh = SessionRefresh::new(events);
            for index in 0..veil_proto::MAX_PEERS_LIST_ENTRIES {
                let mut unrelated = [0xbb; 32];
                unrelated[..2].copy_from_slice(&(index as u16).to_be_bytes());
                refresh.note_event(
                    VeilEvent {
                        kind,
                        payload: unrelated.to_vec(),
                    },
                    &configured,
                );
            }
            assert!(refresh.pending.is_none());
            refresh.note_event(
                VeilEvent {
                    kind,
                    payload: peer.to_vec(),
                },
                &configured,
            );
            assert_eq!(
                refresh.take_targeted_hints(check, &configured, &admitted, 1),
                configured
            );
        }
    }

    #[test]
    fn withdrawal_and_readmission_share_the_early_check_interval() {
        let now = Instant::now();
        let next = now + PNET_PRIORITY_RECHECK_SPACING;
        let (_, events) = broadcast::channel(1);
        let mut refresh = SessionRefresh {
            pending: Some(now),
            session_count: Some(2),
            pending_loss: Some(now),
            pending_readmission: Some(now),
            next_priority_check: next,
            ..SessionRefresh::new(events)
        };
        assert!(refresh.priority_check(Some(next)).is_none());
        assert!(matches!(
            refresh.priority_check(None),
            Some((due, PriorityCheck::Withdrawal)) if due == next
        ));
        refresh.pending_loss = None;
        assert!(matches!(
            refresh.priority_check(None),
            Some((due, PriorityCheck::Readmission)) if due == next
        ));
    }

    #[test]
    fn signed_retry_uses_bounded_round_robin_and_prunes_old_candidates() {
        let now = Instant::now();
        let peers: Vec<_> = (1..=67).map(|id| ([id; 32], [0; 32])).collect();
        let mut recent = RecentAdmissions {
            seen: (1..=68).map(|id| ([id; 32], now)).collect(),
            cursor: [0; 32],
        };
        recent.seen.insert([2; 32], now - PNET_RECENT_WINDOW);
        let live = HashMap::from([([1; 32], 0)]);

        let batch = recent.retry_group(
            &peers,
            &live,
            now,
            &[],
            veilclient::PNET_ADMISSION_BATCH_MAX_PEERS,
        );
        assert_eq!(batch.len(), veilclient::PNET_ADMISSION_BATCH_MAX_PEERS);
        assert_eq!(batch[0].0, [3; 32]);
        assert_eq!(batch.last().unwrap().0, [66; 32]);
        assert_eq!(
            recent.retry_group(
                &peers,
                &live,
                now,
                &[],
                veilclient::PNET_ADMISSION_BATCH_MAX_PEERS
            )[0]
            .0,
            [67; 32]
        );
        assert!(!recent.seen.contains_key(&[2; 32]));
        assert!(!recent.seen.contains_key(&[68; 32]));
    }

    #[tokio::test]
    async fn pnet_batch_retries_a_missing_reply_and_keeps_the_original_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{UnixListener, UnixStream};
        use veil_proto::ipc::IPC_HELLO_OK_PNET_ADMISSION_BATCH;
        use veil_proto::{
            AppIpcHelloOkPayload, FrameFamily, FrameHeader, HEADER_SIZE, IPC_PROTOCOL_VERSION,
            LocalAppMsg, codec,
        };
        use veilclient::PnetAdmission;

        async fn read_frame(stream: &mut UnixStream) -> (FrameHeader, Vec<u8>) {
            let mut bytes = [0; HEADER_SIZE];
            stream.read_exact(&mut bytes).await.unwrap();
            let header = codec::decode_header(&bytes).unwrap();
            let mut body = vec![0; header.body_len as usize];
            stream.read_exact(&mut body).await.unwrap();
            (header, body)
        }

        async fn write_frame(stream: &mut UnixStream, mut header: FrameHeader, body: &[u8]) {
            header.body_len = body.len() as u32;
            stream
                .write_all(&codec::encode_header(&header))
                .await
                .unwrap();
            stream.write_all(body).await.unwrap();
        }

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("ipc");
        let listener = UnixListener::bind(&socket).unwrap();
        let peer = [0xaa; 32];
        let daemon = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (hello, _) = read_frame(&mut stream).await;
            assert_eq!(hello.msg_type, LocalAppMsg::AppHello as u16);
            let mut header =
                FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppHelloOk as u16);
            header.flags = IPC_HELLO_OK_PNET_ADMISSION_BATCH;
            let body = AppIpcHelloOkPayload {
                version: IPC_PROTOCOL_VERSION,
                client_token: [0; 16],
            };
            write_frame(&mut stream, header, &body.encode()).await;

            let mut previous = 0;
            for query in 0..4 {
                let (request, body) = read_frame(&mut stream).await;
                assert_eq!(
                    request.msg_type,
                    LocalAppMsg::PnetAdmissionBatchQuery as u16
                );
                assert_eq!(body, peer);
                assert_ne!(request.request_id, 0);
                assert_ne!(request.request_id, previous);
                if query == 1 {
                    // Old approval appears after the retry was sent. Only the
                    // retry's denial is valid for this round.
                    for (request_id, expiry) in [(previous, Some(0)), (request.request_id, None)] {
                        let mut header = FrameHeader::new(
                            FrameFamily::LocalApp as u8,
                            LocalAppMsg::PnetAdmissionBatchResult as u16,
                        );
                        header.request_id = request_id;
                        let entry = PnetAdmission {
                            peer_node_id: peer,
                            valid_until_unix: expiry,
                        };
                        write_frame(&mut stream, header, &entry.encode()).await;
                    }
                }
                previous = request.request_id;
            }
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        });

        let client = VeilClient::connect(&socket).await.unwrap();
        let group = [(peer, [0; 32])];
        let mut pace = tokio::time::interval(PNET_QUERY_SPACING);
        assert_eq!(
            query_pnet_batch(&client, &group, &mut pace).await,
            Some(HashMap::new())
        );
        let started = Instant::now();
        assert!(query_pnet_batch(&client, &group, &mut pace).await.is_none());
        assert!(
            (PNET_QUERY_TIMEOUT..PNET_QUERY_TIMEOUT + PNET_BATCH_RETRY_AFTER)
                .contains(&started.elapsed())
        );
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), daemon)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn pnet_routes_follow_daemon_admission_without_reload() {
        tokio::join!(
            exercise_pnet_sweep(34, false, SweepHint::None),
            exercise_pnet_sweep(256, false, SweepHint::None),
            exercise_pnet_sweep(1024, false, SweepHint::None),
        );
    }

    #[tokio::test]
    async fn pnet_session_events_accelerate_route_withdrawal() {
        tokio::join!(
            exercise_pnet_sweep(34, true, SweepHint::None),
            exercise_pnet_sweep(1024, true, SweepHint::None)
        );
    }

    #[tokio::test]
    async fn pnet_snapshot_prioritizes_live_peers_and_checks_unlisted_routes() {
        exercise_pnet_sweep(1024, true, SweepHint::Snapshot).await;
    }

    fn pnet_sweep_config(socket: &Path, peer_count: u16) -> OgateConfig {
        let mut config = cfg();
        config.socket_path = socket.to_owned();
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
        config
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pnet_session_changes_recheck_routes_before_a_large_sweep_finishes() {
        exercise_pnet_session_rejoin(SessionHintScenario::Delayed).await;
    }

    #[tokio::test]
    async fn pnet_rechecks_recently_withdrawn_route_omitted_from_the_peer_list() {
        exercise_pnet_session_rejoin(SessionHintScenario::Capped).await;
    }

    #[tokio::test]
    async fn pnet_session_withdrawal_precedes_a_full_batch_of_joins() {
        exercise_pnet_session_rejoin(SessionHintScenario::JoinBurst).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sparse_withdrawals_recheck_during_the_snapshot_cooldown() {
        exercise_pnet_session_rejoin(SessionHintScenario::RapidWithdrawal).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dense_withdrawals_recheck_during_the_snapshot_cooldown() {
        exercise_pnet_session_rejoin(SessionHintScenario::RapidDenseWithdrawal).await;
    }

    #[tokio::test]
    async fn routes_reconcile_after_the_daemon_event_bus_drops_a_session_change() {
        exercise_pnet_session_rejoin(SessionHintScenario::EventBusLag).await;
    }

    #[tokio::test]
    async fn a_targeted_hint_checks_an_omitted_peer_after_unconfigured_session_events() {
        exercise_pnet_session_rejoin(SessionHintScenario::CappedFirstAdmission).await;
    }

    #[tokio::test]
    async fn a_targeted_withdrawal_rechecks_a_peer_still_in_a_full_peer_list() {
        exercise_pnet_session_rejoin(SessionHintScenario::TargetedWithdrawal).await;
    }

    #[test]
    fn capped_withdrawal_candidates_rotate_without_repeating_a_prefix() {
        let limit = veilclient::PNET_ADMISSION_BATCH_MAX_PEERS;
        let configured: Vec<_> = (0..200).map(|id| ([id; 32], [id; 32])).collect();
        let admitted = configured.iter().map(|(id, _)| (*id, 0)).collect();
        let capped = LivePeerHints {
            at_capacity: true,
            ids: configured[..10].iter().map(|(id, _)| *id).collect(),
        };

        let first = withdrawal_candidates(&configured, &admitted, Some(&capped), None, limit);
        assert_eq!(first.as_slice(), &configured[10..10 + limit]);
        let second = withdrawal_candidates(
            &configured,
            &admitted,
            Some(&capped),
            first.last().map(|(peer, _)| *peer),
            limit,
        );
        assert_eq!(second.as_slice(), &configured[10 + limit..10 + 2 * limit]);
        let wrapped = withdrawal_candidates(
            &configured,
            &admitted,
            None,
            configured.last().map(|(peer, _)| *peer),
            limit,
        );
        assert_eq!(wrapped.as_slice(), &configured[..limit]);
    }

    enum SessionHintScenario {
        Delayed,
        Capped,
        JoinBurst,
        RapidWithdrawal,
        RapidDenseWithdrawal,
        EventBusLag,
        CappedFirstAdmission,
        TargetedWithdrawal,
    }

    async fn exercise_pnet_session_rejoin(scenario: SessionHintScenario) {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use veil_ipc::{EventBus, IpcEndpoint, IpcServer, PeerListProvider, PnetStatusProvider};
        use veil_proto::{EventPayload, PeersListEntry, PeersListPayload, PnetStatusResultPayload};

        const PEER: NodeId = [0xaa; 32];
        const FIRST_JOIN: u16 = 3600;
        const END_JOINS: u16 = FIRST_JOIN + veilclient::PNET_ADMISSION_BATCH_MAX_PEERS as u16;
        struct Session {
            active: AtomicBool,
            peer_checks: AtomicUsize,
            other_admitted: u16,
            hints: AtomicUsize,
            delay_next_hint: AtomicBool,
            capped_list: AtomicBool,
            list_stale_peer: bool,
            join_burst: AtomicBool,
            first_changed: SyncMutex<Option<NodeId>>,
            past_first_batch: Notify,
        }
        impl PeerListProvider for Session {
            fn list_peers(&self) -> PeersListPayload {
                self.hints.fetch_add(1, Ordering::Relaxed);
                if self.delay_next_hint.swap(false, Ordering::Relaxed) {
                    std::thread::sleep(PNET_PEER_HINT_TIMEOUT + Duration::from_millis(100));
                    return PeersListPayload { peers: Vec::new() };
                }
                if self.capped_list.load(Ordering::Relaxed) {
                    let peers = (0..veil_proto::MAX_PEERS_LIST_ENTRIES)
                        .map(|index| {
                            let mut node_id = [0xbb; 32];
                            node_id[..2].copy_from_slice(&(index as u16).to_be_bytes());
                            if index == 0 && self.list_stale_peer {
                                node_id = PEER;
                            } else if index == 0 {
                                node_id = [0; 32];
                                node_id[1] = 3;
                            }
                            PeersListEntry {
                                node_id,
                                state: veil_proto::peer_state::ACTIVE,
                                direction: veil_proto::peer_direction::INBOUND,
                                transport: Vec::new(),
                                caps: None,
                            }
                        })
                        .collect();
                    return PeersListPayload { peers };
                }
                let mut peers: Vec<_> = self
                    .active
                    .load(Ordering::Relaxed)
                    .then(|| PeersListEntry {
                        node_id: PEER,
                        state: veil_proto::peer_state::ACTIVE,
                        direction: veil_proto::peer_direction::INBOUND,
                        transport: Vec::new(),
                        caps: None,
                    })
                    .into_iter()
                    .collect();
                peers.extend((3..3 + self.other_admitted).map(|host| {
                    let mut node_id = [0; 32];
                    node_id[..2].copy_from_slice(&host.to_be_bytes());
                    PeersListEntry {
                        node_id,
                        state: veil_proto::peer_state::ACTIVE,
                        direction: veil_proto::peer_direction::INBOUND,
                        transport: Vec::new(),
                        caps: None,
                    }
                }));
                if self.join_burst.load(Ordering::Relaxed) {
                    peers.extend((FIRST_JOIN..END_JOINS).map(|host| {
                        let mut node_id = [0; 32];
                        node_id[..2].copy_from_slice(&host.to_be_bytes());
                        PeersListEntry {
                            node_id,
                            state: veil_proto::peer_state::ACTIVE,
                            direction: veil_proto::peer_direction::INBOUND,
                            transport: Vec::new(),
                            caps: None,
                        }
                    }));
                }
                PeersListPayload { peers }
            }
        }
        impl PnetStatusProvider for Session {
            fn peer_status(&self, peer: &NodeId) -> PnetStatusResultPayload {
                if *peer == PEER {
                    self.peer_checks.fetch_add(1, Ordering::Relaxed);
                }
                if peer[..2] == 128_u16.to_be_bytes() {
                    self.past_first_batch.notify_one();
                }
                // Only the first join lacks admission, even though all of
                // them have live sessions according to the snapshot.
                let joining = self.join_burst.load(Ordering::Relaxed)
                    && (FIRST_JOIN + 1..END_JOINS)
                        .contains(&u16::from_be_bytes([peer[0], peer[1]]));
                if self.join_burst.load(Ordering::Relaxed) && (*peer == PEER || joining) {
                    self.first_changed.lock().unwrap().get_or_insert(*peer);
                }
                let retained =
                    (3..3 + self.other_admitted).contains(&u16::from_be_bytes([peer[0], peer[1]]));
                PnetStatusResultPayload {
                    admitted: retained
                        || joining
                        || *peer == PEER && self.active.load(Ordering::Relaxed),
                    has_cert: retained || joining || *peer == PEER,
                    admin: false,
                    valid_until_unix: 0,
                    network_id: [0x01; 32],
                    peer_node_id: *peer,
                }
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("ipc");
        let targeted_withdrawal = matches!(scenario, SessionHintScenario::TargetedWithdrawal);
        let other_admitted: u16 = if targeted_withdrawal
            || matches!(scenario, SessionHintScenario::RapidDenseWithdrawal)
        {
            96
        } else {
            0
        };
        let first_admission = matches!(scenario, SessionHintScenario::CappedFirstAdmission);
        let session = Arc::new(Session {
            active: AtomicBool::new(!first_admission),
            peer_checks: AtomicUsize::new(0),
            other_admitted,
            hints: AtomicUsize::new(0),
            delay_next_hint: AtomicBool::new(false),
            capped_list: AtomicBool::new(first_admission),
            list_stale_peer: targeted_withdrawal,
            join_burst: AtomicBool::new(false),
            first_changed: SyncMutex::new(None),
            past_first_batch: Notify::new(),
        });
        let events = Arc::new(if matches!(scenario, SessionHintScenario::EventBusLag) {
            EventBus::with_capacity(1)
        } else if first_admission {
            // Keep the whole burst on the event bus so the test exercises
            // the gateway's bounded hint queue, not IPC event loss.
            EventBus::with_capacity(2 * veil_proto::MAX_PEERS_LIST_ENTRIES)
        } else {
            EventBus::new()
        });
        let (stop, shutdown) = watch::channel(false);
        let mut server = IpcServer::new(
            IpcEndpoint::Unix(socket.clone()),
            shutdown,
            Arc::new(veil_app::AppEndpointRegistry::new()),
            [0x01; 32],
        )
        .with_pnet_status_provider(session.clone())
        .with_peer_list_provider(session.clone())
        .with_event_bus(events.clone());
        let server = tokio::spawn(async move { server.run().await.unwrap() });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !socket.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("IPC server did not start");

        let config = pnet_sweep_config(&socket, 4096);
        let configured = SharedState::build(&config).unwrap();
        let state = Arc::new(ArcSwap::from_pointee(
            configured.with_pnet_admissions(&HashMap::new()),
        ));
        let changes = Arc::new(Notify::new());
        let recent = Arc::new(SyncMutex::new(RecentAdmissions::default()));
        let updates = tokio::spawn(maintain_routes(
            directory.path().join("unused.toml"),
            watch::channel(config).0,
            Arc::new(Mutex::new(None)),
            RouteBinding {
                node_id: [0x01; 32],
                signed: None,
                recent: Arc::clone(&recent),
            },
            configured,
            Arc::clone(&state),
            Arc::clone(&changes),
        ));
        tokio::time::timeout(Duration::from_secs(3), session.past_first_batch.notified())
            .await
            .expect("the large sweep did not start");
        let address = Ipv4Addr::new(10, 99, 0, 2).into();
        if first_admission {
            let existing_client = VeilClient::connect(&socket).await.unwrap();
            let mut existing_events = existing_client.events().await;
            let publish_hint = || {
                assert_ne!(
                    events.publish(EventPayload {
                        kind: PNET_SESSION_ADMITTED,
                        payload: PEER.to_vec(),
                    }),
                    0
                );
            };
            assert_eq!(session.peer_checks.load(Ordering::Relaxed), 0);
            for index in 0..veil_proto::MAX_PEERS_LIST_ENTRIES {
                let mut unrelated = [0xbb; 32];
                unrelated[..2].copy_from_slice(&(index as u16).to_be_bytes());
                assert_ne!(
                    events.publish(EventPayload {
                        kind: PNET_SESSION_ADMITTED,
                        payload: unrelated.to_vec(),
                    }),
                    0
                );
            }
            publish_hint();
            tokio::time::timeout(Duration::from_secs(2), async {
                for _ in 0..=veil_proto::MAX_PEERS_LIST_ENTRIES {
                    let event = existing_events.recv().await.unwrap();
                    assert_eq!(event.kind, SESSION_ADMITTED);
                    assert!(event.payload.is_empty());
                }
            })
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while session.peer_checks.load(Ordering::Relaxed) == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("a capped peer list hid the targeted peer from admission checks");
            assert_eq!(state.load().table.lookup_egress(address), Decision::NoRoute);
            session.active.store(true, Ordering::Relaxed);
            publish_hint();
        }
        let initial_route_count = usize::from(other_admitted + 1);
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.load().table.peer_count() != initial_route_count {
                changes.notified().await;
            }
        })
        .await
        .expect("initial routes were not published");
        assert_eq!(
            state.load().table.lookup_egress(address),
            Decision::Forward(PEER)
        );

        if matches!(
            scenario,
            SessionHintScenario::RapidWithdrawal | SessionHintScenario::RapidDenseWithdrawal
        ) {
            let previous = session.hints.load(Ordering::Relaxed);
            assert_ne!(
                events.publish(EventPayload {
                    kind: SESSIONS_CHANGED,
                    payload: (other_admitted + 1).to_be_bytes().to_vec(),
                }),
                0
            );
            tokio::time::timeout(Duration::from_secs(2), async {
                while session.hints.load(Ordering::Relaxed) == previous {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the normal session snapshot was not requested");
        }

        let publish_targeted_loss = || {
            assert_ne!(
                events.publish(EventPayload {
                    kind: PNET_SESSION_ENDED,
                    payload: PEER.to_vec(),
                }),
                0
            );
        };
        if targeted_withdrawal {
            // A replacement may already own the peer when an old runner
            // closes. A fresh positive status must preserve this route.
            session.capped_list.store(true, Ordering::Relaxed);
            let checks = session.peer_checks.load(Ordering::Relaxed);
            publish_targeted_loss();
            tokio::time::timeout(Duration::from_secs(2), async {
                while session.peer_checks.load(Ordering::Relaxed) == checks {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the targeted close did not check the current session");
            assert_eq!(
                state.load().table.lookup_egress(address),
                Decision::Forward(PEER)
            );
        }

        session.active.store(false, Ordering::Relaxed);
        session.join_burst.store(
            matches!(scenario, SessionHintScenario::JoinBurst),
            Ordering::Relaxed,
        );
        if targeted_withdrawal {
            publish_targeted_loss();
        } else {
            assert_ne!(
                events.publish(EventPayload {
                    kind: SESSIONS_CHANGED,
                    payload: other_admitted.to_be_bytes().to_vec(),
                }),
                0
            );
        }
        if matches!(scenario, SessionHintScenario::EventBusLag) {
            // The current-thread runtime cannot deliver either event until
            // this task yields, so only the unrelated event is retained.
            assert_ne!(
                events.publish(EventPayload {
                    kind: veil_proto::event_kind::MOBILE_TIER_CHANGED,
                    payload: vec![0],
                }),
                0
            );
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.load().table.lookup_egress(address) != Decision::NoRoute {
                changes.notified().await;
            }
        })
        .await
        .expect("route withdrawal waited for the full admission sweep");
        if other_admitted != 0 {
            assert_eq!(state.load().table.peer_count(), usize::from(other_admitted));
        }
        assert_eq!(
            state.load().table.lookup_ingress(&PEER, Some(address)),
            Decision::Unauthorized
        );
        if matches!(scenario, SessionHintScenario::JoinBurst) {
            assert_eq!(*session.first_changed.lock().unwrap(), Some(PEER));
            let [hi, lo] = FIRST_JOIN.to_be_bytes();
            assert_eq!(
                state
                    .load()
                    .table
                    .lookup_egress(Ipv4Addr::new(10, 99, hi, lo).into()),
                Decision::NoRoute
            );
            let [hi, lo] = (FIRST_JOIN + 1).to_be_bytes();
            let mut node_id = [0; 32];
            node_id[..2].copy_from_slice(&[hi, lo]);
            assert_eq!(
                state
                    .load()
                    .table
                    .lookup_egress(Ipv4Addr::new(10, 99, hi, lo).into()),
                Decision::Forward(node_id)
            );
        }

        session.active.store(true, Ordering::Relaxed);
        session.capped_list.store(
            matches!(scenario, SessionHintScenario::Capped),
            Ordering::Relaxed,
        );
        if matches!(scenario, SessionHintScenario::Delayed) {
            recent.lock().unwrap().seen.clear();
            session.delay_next_hint.store(true, Ordering::Relaxed);
        }
        assert_ne!(
            events.publish(EventPayload {
                kind: SESSION_ADMITTED,
                payload: Vec::new(),
            }),
            0
        );
        let restore_deadline = match scenario {
            SessionHintScenario::Capped
            | SessionHintScenario::RapidWithdrawal
            | SessionHintScenario::RapidDenseWithdrawal => Duration::from_secs(2),
            _ => PNET_REFRESH_PERIOD + Duration::from_secs(1),
        };
        tokio::time::timeout(restore_deadline, async {
            while state.load().table.lookup_egress(address) != Decision::Forward(PEER) {
                changes.notified().await;
            }
        })
        .await
        .expect("route restoration did not use the session admission event");
        assert!(!session.delay_next_hint.load(Ordering::Relaxed));
        assert_eq!(
            state
                .load()
                .table
                .lookup_egress(Ipv4Addr::new(10, 99, 0, 3).into()),
            if other_admitted == 0 {
                Decision::NoRoute
            } else {
                let mut peer = [0; 32];
                peer[1] = 3;
                Decision::Forward(peer)
            }
        );

        updates.abort();
        assert!(updates.await.unwrap_err().is_cancelled());
        stop.send(true).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pnet_prioritizes_a_recent_route_without_a_live_peer_snapshot() {
        exercise_pnet_sweep(1024, true, SweepHint::Recent).await;
    }

    enum SweepHint {
        None,
        Snapshot,
        Recent,
    }

    async fn exercise_pnet_sweep(peer_count: u16, publish_session_events: bool, hint: SweepHint) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use veil_ipc::{EventBus, IpcEndpoint, IpcServer, PeerListProvider, PnetStatusProvider};
        use veil_proto::{EventPayload, PeersListEntry, PeersListPayload, PnetStatusResultPayload};

        struct LivePeerHint;

        impl PeerListProvider for LivePeerHint {
            fn list_peers(&self) -> PeersListPayload {
                PeersListPayload {
                    peers: vec![PeersListEntry {
                        node_id: [0xaa; 32],
                        state: veil_proto::peer_state::ACTIVE,
                        direction: veil_proto::peer_direction::INBOUND,
                        transport: vec![],
                        caps: None,
                    }],
                }
            }
        }

        struct Admission {
            live: AtomicBool,
            wrong_peer: AtomicBool,
            first: SyncMutex<Option<NodeId>>,
        }

        impl PnetStatusProvider for Admission {
            fn peer_status(&self, peer: &NodeId) -> PnetStatusResultPayload {
                self.first.lock().unwrap().get_or_insert(*peer);
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
            first: SyncMutex::new(None),
        });
        let events = Arc::new(EventBus::new());
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let mut server = IpcServer::new(
            IpcEndpoint::Unix(socket.clone()),
            shutdown,
            Arc::new(veil_app::AppEndpointRegistry::new()),
            [0x01; 32],
        )
        .with_pnet_status_provider(admission.clone())
        .with_event_bus(events.clone());
        if matches!(hint, SweepHint::Snapshot) {
            server = server.with_peer_list_provider(Arc::new(LivePeerHint));
        }
        let server = tokio::spawn(async move { server.run().await.unwrap() });

        tokio::time::timeout(Duration::from_secs(3), async {
            while !socket.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("IPC server did not start");
        let config = pnet_sweep_config(&socket, peer_count);
        let peer_count = usize::from(peer_count);
        assert_eq!(config.peers.len(), peer_count);
        let configured = SharedState::build(&config).unwrap();
        let initial = configured.with_pnet_admissions(&HashMap::new());
        let state = Arc::new(ArcSwap::from_pointee(initial));
        let changed = Arc::new(Notify::new());
        let peer = [0xaa; 32];
        let mut recent = RecentAdmissions::default();
        if matches!(hint, SweepHint::Recent) {
            recent.remember_peer(peer, Instant::now());
        }
        let address = Ipv4Addr::new(10, 99, 0, 2).into();
        assert_eq!(state.load().table.lookup_egress(address), Decision::NoRoute);

        let updates = tokio::spawn(maintain_routes(
            directory.path().join("unused.toml"),
            watch::channel(config).0,
            Arc::new(Mutex::new(None)),
            RouteBinding {
                node_id: [0x01; 32],
                signed: None,
                recent: Arc::new(SyncMutex::new(recent)),
            },
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
        if !matches!(hint, SweepHint::None) {
            assert_eq!(*admission.first.lock().unwrap(), Some(peer));
        }
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
        let deadline = if publish_session_events {
            for _ in 0..64 {
                assert_ne!(
                    events.publish(EventPayload {
                        kind: SESSIONS_CHANGED,
                        payload: vec![0, 1],
                    }),
                    0
                );
            }
            Duration::from_secs(4)
        } else {
            Duration::from_secs(8)
        };
        tokio::time::timeout(deadline, async {
            while state.load().table.peer_count() != 0 {
                changed.notified().await;
            }
        })
        .await
        .expect("peer routes survived loss of session");
        eprintln!(
            "{peer_count} peers (session events {publish_session_events}): admitted in {admission_elapsed:.3?}, withdrawn in {:.3?}",
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
        let client = connect_pnet_status(&socket, [0x01; 32], None, &mut pace)
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
        let client = connect_pnet_status(&socket, [0x01; 32], None, &mut pace)
            .await
            .unwrap();
        let fresh = query_pnet_batch(&client, &group, &mut pace).await.unwrap();
        assert_eq!(fresh.get(&peer), Some(&0));

        drop(client);
        stop.send(true).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_new_ipc_socket_interrupts_rebind_backoff() {
        use tokio::net::UnixListener;

        for stale in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("ipc");
            let old_listener = stale.then(|| UnixListener::bind(&path).unwrap());
            let previous = socket_identity(&path).await;
            assert_eq!(previous.is_some(), stale);

            let wait_path = path.clone();
            let mut retry = tokio::spawn(async move {
                wait_to_rebind(&wait_path, previous, MAX_REBIND_DELAY).await
            });
            if old_listener.is_some() {
                std::fs::remove_file(&path).unwrap();
            }
            std::fs::write(&path, b"not a socket").unwrap();
            assert!(
                tokio::time::timeout(REBIND_SOCKET_POLL * 2, &mut retry)
                    .await
                    .is_err()
            );

            std::fs::remove_file(&path).unwrap();
            let _new_listener = UnixListener::bind(&path).unwrap();
            let observed = tokio::time::timeout(Duration::from_secs(2), retry)
                .await
                .expect("new socket did not advance the retry")
                .unwrap();
            assert!(observed.is_some());
            assert_ne!(observed, previous);
        }
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
            ..
        } = bind_ipc(&config, None, None).await.unwrap();
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
            bind_ipc(&config, Some(binding), None).await,
            Err(BridgeError::IdentityChanged)
        ));
        stop.send(true).unwrap();
        daemon.await.unwrap();

        let (stop, daemon) = start(&config.socket_path, node).await;
        let restored = tokio::time::timeout(
            Duration::from_secs(3),
            reconnect_ipc(&config, binding, None),
        )
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
    fn reload_accepts_batch_window_change() {
        let old = cfg();
        let mut new = old.clone();
        new.batch.flush_after_us = 1_600;
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
