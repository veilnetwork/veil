//! Spawn-helpers for the node's long-running service tasks:
//! `spawn_socks5_task`: SOCKS5 ingress proxy.
//! `spawn_exit_proxy_task`: exit-proxy listener.
//! `spawn_bootstrap_task`: bootstrap-peer connect + retry loop.
//! `spawn_route_miss_handler`: handles ROUTE_MISS frames from the
//! dispatcher, triggering re-discovery for unknown dst peers.
//! `spawn_ipc_server`: local IPC server (Unix socket / TCP loopback).
//! `spawn_pending_ack_tick`: retransmit scheduler for the
//! reliable-delivery ack tracker.
//!
//! Extracted from `runtime/mod.rs` during refactor.
//! Each helper captures the state it needs via `Arc::clone` and
//! installs the resulting JoinHandle on `self.tasks`.

use std::sync::Arc;
use veil_util::{lock, rlock, wlock};

use crate::types::{NodeIdBytes, PeerConfigEntry, PeerId};
use veil_cfg;
use veil_ipc::{IpcServer, path::default_ipc_socket_path};
use veil_proto::{EventPayload, event_kind};

use super::{
    NodeRuntime, derive_node_id_from_bootstrap_peer, lock_state, lock_tasks, supervised_spawn,
};

/// Maximum number of bootstrap-discovered seeds a single source (one HTTPS
/// bundle or one DNS answer) may dial at join. A signed bundle can legitimately
/// carry hundreds of peers; dialing all of them — and flooding the k-buckets
/// with `add_contact` — at the exact moment the routing table is emptiest is an
/// eclipse-pressure / thundering-herd vector from one source. Matches the
/// discovered-peer cache cap (`MAX_DISCOVERED_PEERS = 32`). The DHT keeps
/// learning peers organically after join, so this only bounds the initial burst.
const MAX_BOOTSTRAP_SEEDS_PER_SOURCE: usize = 32;

/// Bound on the authenticated-onion final-hop verify queue. The sync
/// dispatcher `try_send`s decoded `AuthAppDeliver`s here; the verifier drains
/// serially (one DHT resolve at a time). Overflow drops at the dispatcher —
/// best-effort, the sender learns from an app-layer timeout. 256 absorbs a
/// reasonable burst without letting a flood pin memory.
const AUTH_DELIVER_CHANNEL_CAP: usize = 256;

/// Per-message timeout for resolving the sender's identity document during
/// authenticated-delivery verification. Bounds head-of-line blocking on the
/// serial verify queue when a sender's document is unreachable.
const AUTH_DELIVER_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Resolve the sender, verify (signature + freshness + subkey), replay-check,
/// and deliver one COMPLETE authenticated message with the VERIFIED sender
/// node_id. Shared by the direct-onion (`Full`) and rendezvous (reassembled
/// `Fragment`) paths. Every failure is logged and dropped — never surfaced to
/// the anonymous sender (that would leak recipient liveness).
async fn process_auth_deliver(
    auth: veil_proto::AuthAppDeliver,
    access: &super::NodeServices,
    logger: &Arc<veil_observability::NodeLogger>,
    replay_cache: &veil_identity::auth_deliver::AuthDeliverReplayCache,
    local_node_id: &[u8; 32],
    freshness_window: u64,
    now_unix: u64,
    // True when the message arrived DOWN one of OUR ephemeral reply circuits —
    // the peer answering something we sent LIVE (me→R proof for the stall
    // detector). False for inbound via our rendezvous registration / session.
    via_reply_circuit: bool,
) {
    // 1. Resolve the sender's identity document (DHT), bound to EXACTLY the
    //    claimed sender_node_id — no migration follow: a migrated-away signer
    //    must fail closed.
    let sender_doc = match access
        .resolve_one_identity_doc(auth.sender_node_id, now_unix, AUTH_DELIVER_RESOLVE_TIMEOUT)
        .await
    {
        Ok((_, doc)) => doc,
        Err(e) => {
            logger.info(
                "anonymity.auth_deliver.resolve_failed",
                format!(
                    "cannot resolve sender {} identity: {e}",
                    veil_util::hex_short(&auth.sender_node_id),
                ),
            );
            return;
        }
    };

    // 2. Verify recipient binding, sender↔doc match, freshness, subkey, sig.
    if let Err(e) = veil_identity::auth_deliver::verify_auth_deliver(
        &auth,
        &sender_doc,
        local_node_id,
        now_unix,
        freshness_window,
    ) {
        logger.info(
            "anonymity.auth_deliver.verify_failed",
            format!(
                "auth delivery from {} rejected: {e}",
                veil_util::hex_short(&auth.sender_node_id),
            ),
        );
        return;
    }

    // 3. Replay check AFTER signature verify, so a forger cannot poison the
    //    cache with bogus (sender, nonce) entries to suppress a real sender.
    if let Err(e) = replay_cache.check_and_record(&auth.sender_node_id, auth.nonce, now_unix) {
        logger.info(
            "anonymity.auth_deliver.replay",
            format!(
                "replayed auth delivery from {} (nonce={}): {e}",
                veil_util::hex_short(&auth.sender_node_id),
                auth.nonce,
            ),
        );
        return;
    }

    // Clear the sender-side stall streak ONLY when the peer answered through
    // one of OUR ephemeral reply circuits: a stashed (mailbox) copy of our
    // message carries no reply block, so a reply-circuit answer proves OUR
    // LIVE introduce reached them. A generic verified inbound (their message
    // via OUR rendezvous registration) only proves them→us — clearing on it
    // masked a dead me→them live path whenever the reverse direction was
    // healthy (their live ACK for a mailbox-delivered message kept resetting
    // the streak, the fan-out never widened, and every message paid the
    // mailbox latency).
    if via_reply_circuit {
        access.anonymity.send_stall.note_answer(&auth.sender_node_id);
    }

    // 4. Deliver with the VERIFIED sender node_id. If the message carried a
    //    one-time reply path, store it daemon-side and surface a non-zero
    //    reply_id so the app can reply (the block never crosses to the app).
    let data_len = auth.data.len();
    let endpoint_id = auth.endpoint_id;
    let sender_node_id = auth.sender_node_id;
    let app_id = auth.app_id;
    let reply_id = match auth.reply_block {
        // D3: the reply block is owned by the app that received this message
        // (`app_id`); only that app may later reply through it.
        Some(rb) => access
            .anonymity
            .reply_block_store
            .store(rb, app_id, now_unix),
        None => 0,
    };
    let delivered = access.dispatcher.app_registry.route_ipc_deliver_with_reply(
        sender_node_id,
        [0u8; 32], // AuthAppDeliver carries no src_app_id in v1
        app_id,
        endpoint_id,
        veil_bufpool::pooled_shared_from_vec(auth.data),
        reply_id,
    );
    if delivered {
        logger.info(
            "anonymity.auth_deliver.delivered",
            format!(
                "delivered {data_len} B from verified sender {} to endpoint_id={endpoint_id}",
                veil_util::hex_short(&sender_node_id),
            ),
        );
    } else {
        logger.info(
            "anonymity.auth_deliver.unbound",
            format!(
                "no app bound to endpoint_id={endpoint_id}; {data_len} B from {} dropped",
                veil_util::hex_short(&sender_node_id),
            ),
        );
    }
}

// ── rendezvous-recipient lifecycle (Epic 482 v1) ─────────────────────────────

/// How often the rendezvous-recipient task re-checks its registration. A short
/// backstop that catches any session-close event missed via a broadcast
/// `Lagged`; event-driven wakes do the bulk of the work.
const RENDEZVOUS_RECIPIENT_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
/// Min-interval debounce gate for event-driven re-checks: coalesces a burst of
/// `SESSIONS_CHANGED` events into at most one re-check per window.
const RENDEZVOUS_SESSION_EVENT_DEBOUNCE: std::time::Duration =
    std::time::Duration::from_millis(100);
/// Max extra random jitter (ms) added per backstop tick so the re-register
/// cadence is not a fixed, identity-linkable heartbeat.
const RENDEZVOUS_TICK_JITTER_MS: u64 = 3000;
/// Ad validity window the recipient requests (the maintenance tick refreshes the
/// published ad before half-life). Comfortably longer than the check interval
/// (RENDEZVOUS_RECIPIENT_CHECK_INTERVAL = 15s), but kept SHORT on purpose: this
/// is also how long a STALE ad (a previous-relay/cookie ad a sender resolved +
/// cached before the receiver rotated) stays usable. At 1h it black-holed
/// delivery for up to an hour after a receiver restart (the sender's cached ad
/// pointed at a relay the receiver no longer registers → cookie_unknown on every
/// introduce). 10 min bounds that self-heal window while the ~15s refresh keeps
/// the live ad alive with ~40x margin. pub(crate) so the initial onion-service
/// register (runtime::mod) uses the same window, not the 24h directory default.
pub(crate) const RENDEZVOUS_AD_VALIDITY_SECS: u64 = 600;
/// Re-register with the (still-live) current relay every N ticks — the relay's
/// cookie map is in-memory, so this survives a relay restart.
const RENDEZVOUS_REREGISTER_EVERY_TICKS: u64 = 5;

pub(crate) type LiveSessions = Arc<
    std::sync::Mutex<std::collections::BTreeMap<crate::types::LinkId, crate::types::SessionInfo>>,
>;

/// True iff there is an Active session to `node_id`.
fn rendezvous_session_live(live: &LiveSessions, node_id: &[u8; 32]) -> bool {
    let g = lock!(live);
    g.values().any(|info| {
        info.state == crate::types::SessionState::Active
            && info
                .node_id
                .as_ref()
                .is_some_and(|n| n.as_bytes() == node_id)
    })
}

/// True iff `node_id` has a relay-directory entry in our local DHT shard — i.e.
/// it is `relay_capable` AND published, so a sender can resolve + reach it.
fn rendezvous_relay_published(dht: &Arc<veil_dht::KademliaService>, node_id: &[u8; 32]) -> bool {
    dht.get_local(&veil_anonymity::directory::relay_directory_dht_key(node_id))
        .is_some()
}

/// Handshake-advertised peer capability flags (`node_id → cap bitset`), cloned
/// from the dispatcher's `peer_cap_flags`.
pub(crate) type PeerCapFlags = Arc<std::sync::RwLock<std::collections::HashMap<[u8; 32], u8>>>;

/// True iff `node_id` advertised the `ANONYMITY_RELAY` capability in its handshake
/// (cached in `peer_cap_flags`). This is the RELIABLE relay signal for a
/// CONNECTED peer: unlike [`rendezvous_relay_published`] it needs no DHT
/// FIND_VALUE for the relay-directory entry — that lookup is flaky on a sparse
/// network and its cached entry expires, which churned the recipient task's
/// `no_relay` even while it held a live session to a perfectly good relay. A
/// node we are connected to that advertised ANONYMITY_RELAY is a valid
/// rendezvous relay regardless of whether its RD has propagated to our local DHT
/// shard. `CAN_RELAY` is deliberately insufficient: it is the ordinary transport
/// forwarding bit, not an opt-in to carry onion anonymity circuits.
fn peer_advertised_anonymity_relay(cap_flags: &PeerCapFlags, node_id: &[u8; 32]) -> bool {
    cap_flags
        .read()
        .ok()
        .and_then(|m| m.get(node_id).copied())
        .is_some_and(|f| f & veil_proto::session::cap_flags::ANONYMITY_RELAY != 0)
}

/// Pick a rendezvous relay: a session-live, published peer. If `pinned` is
/// non-empty, restrict to that operator list; otherwise auto-pick.
pub(crate) fn pick_rendezvous_relay(
    live: &LiveSessions,
    dht: &Arc<veil_dht::KademliaService>,
    pinned: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let connected: Vec<[u8; 32]> = {
        let g = lock!(live);
        g.values()
            .filter(|i| i.state == crate::types::SessionState::Active)
            .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes()))
            .collect()
    };
    if !pinned.is_empty() {
        // Operator pin = TRUSTED relay: register at a connected one WITHOUT the
        // RD-discovery check (which is unreliable on a sparse DHT and churns the
        // registration). Honour the configured order deterministically (intent).
        return pinned.iter().copied().find(|p| connected.contains(p));
    }
    // M-1: pick a RANDOM eligible relay rather than the first in iteration
    // order. `connected` derives from HashMap iteration, which is fixed within a
    // process, so `.find()` reused the SAME rendezvous point for every service
    // registered by this node — concentrating load on one relay and making the
    // node's rendezvous choice predictable. Each new registration now draws an
    // independent R from the published-eligible set.
    let eligible: Vec<[u8; 32]> = connected
        .into_iter()
        .filter(|c| rendezvous_relay_published(dht, c))
        .collect();
    if eligible.is_empty() {
        return None;
    }
    use rand_core::{OsRng, RngCore};
    let idx = (OsRng.next_u64() % eligible.len() as u64) as usize;
    Some(eligible[idx])
}

/// Derive the 16-byte rendezvous auth-cookie DETERMINISTICALLY from a node_id:
/// the two 16-byte halves XOR-folded. Stable across process restarts and
/// bit-for-bit identical to the app-side derivation
/// (`MailboxService._deriveCookie`), so the node's built-in receiver task and the
/// app's mailbox publisher converge on ONE cookie per identity instead of each
/// minting a random one. A random cookie made the two mechanisms advertise the
/// same relay under DIFFERENT cookies, so a sender that resolved one publisher
/// slot used a cookie the other slot's subscriber never registered → the relay
/// dropped the introduce (`cookie_unknown`). The node_id is public (it keys the
/// ad), so a derived cookie reveals nothing the ad does not already.
pub(crate) fn rendezvous_cookie_from_node_id(node_id: &[u8; 32]) -> [u8; 16] {
    let mut cookie = [0u8; 16];
    for i in 0..16 {
        cookie[i] = node_id[i] ^ node_id[i + 16];
    }
    cookie
}

/// Order two node_ids by Kademlia XOR distance to `anchor`: compare `a ^ anchor`
/// against `b ^ anchor` as big-endian 256-bit integers.
fn xor_distance_cmp(anchor: &[u8; 32], a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for i in 0..32 {
        let (da, db) = (a[i] ^ anchor[i], b[i] ^ anchor[i]);
        if da != db {
            return da.cmp(&db);
        }
    }
    std::cmp::Ordering::Equal
}

/// Like [`pick_rendezvous_relay`] but DETERMINISTIC: order published-eligible
/// connected relays by Kademlia XOR distance to `anchor` (the receiver's own
/// node_id), then cap them to the number of rendezvous-ad slots.
///
/// A receiver registers the same cookie at every returned relay: mobile/obfs
/// sessions can churn between seeds faster than a replacement ad propagates,
/// so a single active registration turns every still-valid ad for the previous
/// relay into a temporary black hole. Different receiver anchors still spread
/// the preferred (slot-0) relay across the network. Pinned relays retain their
/// operator order.
pub(crate) fn pick_rendezvous_relays_deterministic(
    live: &LiveSessions,
    dht: &Arc<veil_dht::KademliaService>,
    cap_flags: &PeerCapFlags,
    pinned: &[[u8; 32]],
    anchor: &[u8; 32],
) -> Vec<[u8; 32]> {
    let connected: Vec<[u8; 32]> = {
        let g = lock!(live);
        g.values()
            .filter(|i| i.state == crate::types::SessionState::Active)
            .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes()))
            .collect()
    };
    let mut eligible = if !pinned.is_empty() {
        // Operator-pinned relays are TRUSTED rendezvous points: register at a
        // connected one WITHOUT requiring its relay-directory entry (RD) to be
        // DHT-discoverable first. On a small/sparse network the warm FIND_VALUE
        // for the RD is unreliable and the cached entry expires, so demanding it
        // churns the registration (no_relay) even though the relay IS connected
        // and the operator explicitly asserted it is a rendezvous relay. The RD
        // check is for AUTO-discovery of UNtrusted relays — redundant for an
        // explicit pin. Honour the pin order deterministically.
        pinned
            .iter()
            .copied()
            .filter(|p| connected.contains(p))
            .collect::<Vec<_>>()
    } else {
        let mut relays = connected
            .into_iter()
            .filter(|c| {
                rendezvous_relay_published(dht, c) || peer_advertised_anonymity_relay(cap_flags, c)
            })
            .collect::<Vec<_>>();
        relays.sort_by(|a, b| xor_distance_cmp(anchor, a, b));
        relays
    };
    eligible.dedup();
    eligible.truncate(veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS as usize);
    eligible
}

/// Cold-start rendezvous discovery: actively FIND_VALUE the relay-directory
/// entries of our CONNECTED peers and cache the VERIFIED ones locally, so
/// [`pick_rendezvous_relay`] (which only reads `dht.get_local`) can find a relay
/// without waiting for passive Kademlia replication to deliver one — a fresh
/// node holds no connected relay's entry, so onion registration would stall for
/// up to a full DHT republish interval. Bounded per call to cap RPC fan-out.
/// Returns how many fresh entries were cached.
pub(crate) async fn warm_connected_relay_directory(
    live: &LiveSessions,
    dht: &Arc<veil_dht::KademliaService>,
    outbox: &Arc<dyn veil_dht::FrameRouter>,
    logger: &Arc<veil_observability::NodeLogger>,
    cap_flags: Option<&PeerCapFlags>,
) -> usize {
    const MAX_WARM_PER_TICK: usize = 4;
    let connected: Vec<[u8; 32]> = {
        let g = lock!(live);
        g.values()
            .filter(|i| i.state == crate::types::SessionState::Active)
            .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes()))
            .collect()
    };
    let mut cached = 0usize;
    for peer in connected {
        // Do not recursively probe every connected peer's relay-directory key.
        // Ordinary transport relays / app endpoints do not publish anonymity
        // relay-directory entries, so their key is a permanent miss; probing it
        // on every stream-open looks like DHT abuse to relay nodes and can get a
        // sender auto-banned mid-transfer. A fresh handshake capability bit is a
        // cheaper and stronger filter than speculative DHT lookup.
        if cap_flags.is_some_and(|flags| !peer_advertised_anonymity_relay(flags, &peer)) {
            continue;
        }
        if cached >= MAX_WARM_PER_TICK {
            break;
        }
        let key = veil_anonymity::directory::relay_directory_dht_key(&peer);
        // Skip only when the local entry is present AND fresh by the SAME
        // freshness predicate the consumers apply (`discover_relay_hops`).
        // A bare `get_local().is_some()` skip left a hole: an entry still in
        // the store but past DEFAULT_FRESHNESS_WINDOW_SECS is filtered out by
        // every circuit-building consumer, so the warm "succeeded" while the
        // reply path kept failing NoRelays until the relay's next republish
        // happened to propagate here.
        {
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let fresh = !veil_anonymity::directory::discover_relay_hops(
                &[peer],
                |n| dht.get_local(&veil_anonymity::directory::relay_directory_dht_key(n)),
                now_unix,
                veil_anonymity::directory::DEFAULT_FRESHNESS_WINDOW_SECS,
            )
            .is_empty();
            if fresh {
                continue; // already known locally AND fresh
            }
        }
        // Every `peer` here is a CONNECTED session peer, so ask it DIRECTLY for
        // its OWN relay-directory entry (deterministic single hop — it answers
        // its own key from get_local) before falling back to the iterative walk.
        // The walk converges toward the RD key and can fail to ever query the
        // holder on the sparse pinned-seed net, where the RD entry lives ONLY at
        // its relay (store_local, never replicated to the key's K-closest) and
        // the relay is XOR-far from its own key — device-observed have:0 under
        // 3/3 live seed sessions (2026-07-07).
        let bytes = match dht.find_value_from_peer(peer, key, Arc::clone(outbox)).await {
            Some(b) => Some(b),
            None => {
                dht.find_value_iterative_network(key, Arc::clone(outbox))
                    .await
            }
        };
        let Some(bytes) = bytes else {
            continue; // peer published nothing (not a relay) or unreachable
        };
        // SECURITY: the bytes are attacker-supplied until checked. Only cache an
        // entry that decodes, verifies its OWN signature, AND is bound to THIS
        // peer's node_id — else a peer could serve an entry under another node's
        // key (it's a well-known DHT key) and steer our rendezvous choice.
        match veil_anonymity::directory::decode_entry(&bytes) {
            Ok(entry)
                if entry.node_id == peer
                    && veil_anonymity::directory::verify_entry(&entry).is_ok() =>
            {
                dht.store_local(key, bytes);
                cached += 1;
            }
            Ok(_) => logger.warn(
                "anonymity.relay_directory.rejected",
                format!(
                    "relay-directory entry for {} failed node-id bind or signature",
                    veil_util::hex_short(&peer)
                ),
            ),
            Err(e) => logger.warn(
                "anonymity.relay_directory.decode_failed",
                format!("peer={} err={e}", veil_util::hex_short(&peer)),
            ),
        }
    }
    cached
}

/// Send a `RegisterRendezvous` frame to `relay` over its live session (inlines
/// `NodeRuntime::register_with_rendezvous`, which is unavailable from the task's
/// `NodeServices` handle).
///
/// Returns `true` iff the frame was actually queued on the relay's session (the
/// relay is in the tx registry). `false` means the picked "live session" has no
/// tx channel yet, so the caller MUST NOT treat the relay as registered — a
/// fire-and-forget send must not be claimed as a registration that never left.
pub(crate) fn rendezvous_register_with(
    session_tx_registry: &Arc<std::sync::RwLock<veil_session::SessionTxRegistry>>,
    anonymity: &Arc<super::anonymity_state::AnonymityState>,
    relay: &[u8; 32],
    cookie: [u8; 16],
) -> bool {
    use veil_anonymity::rendezvous::RegisterRendezvousPayload;
    use veil_proto::{
        codec::encode_header,
        family::{FrameFamily, RelayChainMsg},
        header::FrameHeader,
    };
    let receiver_x25519_pk = x25519_dalek::PublicKey::from(anonymity.x25519_sk.as_ref()).to_bytes();
    let req = RegisterRendezvousPayload {
        receiver_x25519_pk,
        auth_cookie: cookie,
    };
    let body = req.encode();
    let mut hdr = FrameHeader::new(
        FrameFamily::RelayChain as u8,
        RelayChainMsg::RegisterRendezvous as u16,
    );
    hdr.body_len = body.len() as u32;
    hdr.set_priority(veil_proto::priority::INTERACTIVE);
    let mut frame = encode_header(&hdr).to_vec();
    frame.extend_from_slice(&body);
    let guard = wlock!(session_tx_registry);
    guard.send_to(relay, veil_proto::priority::INTERACTIVE, frame)
}

/// Register/refresh a rendezvous publisher entry (the maintenance tick publishes
/// the signed ad from it). Dedups by (relay, cookie). Inlines
/// `NodeRuntime::register_rendezvous_publisher`.
pub(crate) fn rendezvous_register_publisher(
    anonymity: &Arc<super::anonymity_state::AnonymityState>,
    relay: &[u8; 32],
    cookie: [u8; 16],
    validity_window_secs: u64,
    ephemeral_ad_identity: Option<veil_anonymity::rendezvous::EphemeralAdIdentity>,
) {
    let entry = veil_anonymity::rendezvous::RendezvousPublisherEntry {
        rendezvous_node_id: *relay,
        auth_cookie: cookie,
        validity_window_secs,
        push_envelope: Vec::new(),
        wake_hmac_envelope: Vec::new(),
        // Onion/ephemeral ads are reached via the blinded descriptor, not
        // mailbox PUTs — they advertise no relay KEM key.
        rendezvous_kem_algo: 0,
        rendezvous_kem_pk: Vec::new(),
        ephemeral_ad_identity,
    };
    let mut entries = lock!(anonymity.rendezvous_publisher_entries);
    if let Some(pos) = entries
        .iter()
        .position(|e| e.rendezvous_node_id == *relay && e.auth_cookie == cookie)
    {
        // PRESERVE a KEM key already advertised for this (relay, cookie). The app
        // registers the relay's KEM pk (mailbox-by-discovery, the deposit target)
        // and the built-in recipient task re-registers the SAME (relay, cookie)
        // KEM-LESS on its tick — a full overwrite would DROP the KEM, so a sender
        // resolves the ad with usable(KEM)=0 and cannot deposit offline mail
        // (observed on-device as a persistent stash failure). Carry the existing
        // KEM forward; this entry still functions as a rendezvous publisher, it
        // just keeps the mailbox KEM it already had.
        let mut entry = entry;
        let existing = &entries[pos];
        if !existing.rendezvous_kem_pk.is_empty() {
            entry.rendezvous_kem_algo = existing.rendezvous_kem_algo;
            entry.rendezvous_kem_pk = existing.rendezvous_kem_pk.clone();
        }
        entries[pos] = entry;
    } else {
        entries.push(entry);
    }
}

/// Like [`rendezvous_register_publisher`] but for a PLAIN (sovereign-signed)
/// publisher that ALSO advertises the relay's KEM key — so a sender resolving
/// the v5 ad can anonymously deposit a mailbox PUT at the relay. Dedups by
/// (relay, cookie). The app-IPC entry point for mailbox-by-discovery.
pub(crate) fn rendezvous_register_publisher_with_kem(
    anonymity: &Arc<super::anonymity_state::AnonymityState>,
    relay: &[u8; 32],
    cookie: [u8; 16],
    validity_window_secs: u64,
    relay_kem_algo: u8,
    relay_kem_pk: Vec<u8>,
) {
    let entry = veil_anonymity::rendezvous::RendezvousPublisherEntry {
        rendezvous_node_id: *relay,
        auth_cookie: cookie,
        validity_window_secs,
        push_envelope: Vec::new(),
        wake_hmac_envelope: Vec::new(),
        rendezvous_kem_algo: relay_kem_algo,
        rendezvous_kem_pk: relay_kem_pk,
        // Plain rendezvous receiver — signed under the sovereign identity so
        // senders discover it by the receiver's real node_id.
        ephemeral_ad_identity: None,
    };
    let mut entries = lock!(anonymity.rendezvous_publisher_entries);
    if let Some(pos) = entries
        .iter()
        .position(|e| e.rendezvous_node_id == *relay && e.auth_cookie == cookie)
    {
        entries[pos] = entry;
    } else {
        entries.push(entry);
    }
}

/// Shared cold-path re-pick + re-register for the rendezvous-recipient task.
///
/// SINGLE source of truth for the `!current_ok` block, called from BOTH the
/// backstop-tick arm and the event-driven (`SESSIONS_CHANGED`) arm so the two
/// can never drift. It re-applies the stickiness gate itself (early-returns when
/// the current relay's session is still live), so it is idempotent and safe to
/// call from either arm — an event for an unrelated peer is a no-op while the
/// current relay stays live. Must be an `async fn` (not a closure) because it
/// awaits [`warm_connected_relay_directory`] and async closures are unstable;
/// `current` is `&mut` so it mutates the long-lived loop local, `log_key` lets
/// the tick vs event arm emit distinct observability keys.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn rendezvous_recipient_recheck(
    current: &mut Option<[u8; 32]>,
    live_sessions: &LiveSessions,
    dht: &Arc<veil_dht::KademliaService>,
    cap_flags: &PeerCapFlags,
    outbox: &Arc<dyn veil_dht::FrameRouter>,
    session_tx_registry: &Arc<std::sync::RwLock<veil_session::SessionTxRegistry>>,
    anonymity: &Arc<super::anonymity_state::AnonymityState>,
    identity: &Arc<super::identity_state::IdentityState>,
    logger: &Arc<veil_observability::NodeLogger>,
    pinned: &[[u8; 32]],
    local_node_id: &[u8; 32],
    cookie: [u8; 16],
    log_key: &'static str,
    force: bool,
) {
    let current_ok = current.is_some_and(|r| rendezvous_session_live(live_sessions, &r));
    if current_ok && !force {
        return;
    }
    // Cold-start: actively pull + verify connected peers' relay-directory
    // entries into the local store so pick (get_local) can find one without
    // waiting on passive DHT replication.
    warm_connected_relay_directory(live_sessions, dht, outbox, logger, Some(cap_flags)).await;
    let candidates =
        pick_rendezvous_relays_deterministic(live_sessions, dht, cap_flags, pinned, local_node_id);
    let mut registered = Vec::with_capacity(candidates.len());
    for relay in candidates {
        if rendezvous_register_with(session_tx_registry, anonymity, &relay, cookie) {
            rendezvous_register_publisher(
                anonymity,
                &relay,
                cookie,
                RENDEZVOUS_AD_VALIDITY_SECS,
                None,
            );
            registered.push(relay);
        } else {
            logger.info(
                "anonymity.rendezvous_recipient.send_failed",
                format!(
                    "relay {} not yet sendable (no tx channel); retrying",
                    veil_util::hex_short(&relay),
                ),
            );
        }
    }
    if registered.is_empty() {
        *current = None;
        logger.info(
            "anonymity.rendezvous_recipient.no_relay",
            "no reachable published rendezvous relay yet; retrying",
        );
        return;
    }

    // Keep only live plain-identity slots for this cookie. Ephemeral onion
    // services have independent publisher identities and must not be touched.
    let live_set: std::collections::HashSet<_> = registered.iter().copied().collect();
    lock!(anonymity.rendezvous_publisher_entries).retain(|entry| {
        entry.ephemeral_ad_identity.is_some()
            || entry.auth_cookie != cookie
            || live_set.contains(&entry.rendezvous_node_id)
    });
    *current = registered.first().copied();
    logger.info(
        log_key,
        format!(
            "registered with {} rendezvous relays: {}",
            registered.len(),
            registered
                .iter()
                .map(veil_util::hex_short)
                .collect::<Vec<_>>()
                .join(","),
        ),
    );
    let published = super::NodeRuntime::tick_publish_rendezvous_ads(
        &anonymity.rendezvous_publisher_entries,
        anonymity.x25519_sk.as_ref(),
        identity.local_identity.as_ref(),
        dht,
        logger,
        Some(session_tx_registry),
    );
    if published > 0 {
        logger.info(
            "anonymity.rendezvous_recipient.published_immediate",
            format!("published {published} rendezvous ad(s) after registration"),
        );
    }
}

impl NodeRuntime {
    // ── proxy runtime wiring ───────────────────────────────────────

    /// Spawn the SOCKS5 ingress proxy if `config.proxy.socks5.enabled`.
    ///
    /// Creates an `VeilConnector` backed by the shared `session_tx_registry`
    /// and dispatcher routing tables, then starts the `Socks5Proxy` listener.
    pub fn spawn_socks5_task(&mut self, config: &veil_cfg::Config) {
        // spawn logic lives in `node/proxy/tasks.rs`.
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let ctx = crate::proxy::tasks::Socks5SpawnCtx {
            config,
            shutdown_tx,
            logger: &self.logger,
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            local_node_id: self.identity.local_identity.node_id,
            pending_stream_receipts: Arc::clone(&self.dispatcher.pending_stream_receipts),
            veil_stream_rx: Arc::clone(&self.dispatcher.veil_stream_rx),
            wire_stream_counter: Arc::clone(&self.wire_stream_counter),
            metrics: self.metrics.clone(),
        };
        if let Some(handle) = crate::proxy::tasks::spawn_socks5(ctx) {
            lock_tasks(&self.tasks).background.push(handle);
        }
    }

    /// Spawn the exit proxy accept loop if `config.proxy.exit.enabled`.
    pub fn spawn_exit_proxy_task(&mut self, config: &veil_cfg::Config) {
        // spawn logic lives in `node/proxy/tasks.rs`.
        let ctx = crate::proxy::tasks::ExitProxySpawnCtx {
            config,
            logger: &self.logger,
            dispatcher: &self.dispatcher,
            app_registry: Arc::clone(&self.app_registry),
            session_tx_registry: Arc::clone(&self.session_tx_registry),
        };
        if let Some(handle) = crate::proxy::tasks::spawn_exit_proxy(ctx) {
            lock_tasks(&self.tasks).background.push(handle);
        }
    }

    /// Spawn the bootstrap task.
    ///
    /// For each `BootstrapPeer` in config:
    /// 1. Derives the peer's node_id and adds it to the local DHT routing table.
    /// 2. Opens an outbound session to the bootstrap peer.
    /// 3. Sends FIND_NODE(local_node_id) via the DHT NetworkPeerQuerier.
    /// 4. Adds the returned contacts to the local DHT routing table.
    /// 5. Closes the session if the bootstrap peer is not in `config.peers`.
    pub fn spawn_bootstrap_task(&mut self, config: &veil_cfg::Config) {
        // A bootstrap node listed in `builtin_seeds` would otherwise try to
        // connect to itself when its config has no `bootstrap_peers` (the
        // normal state for seed deployments). Compare base64 pubkeys — same
        // encoding used in IdentityConfig and BootstrapPeer.
        let my_pubkey = self.identity.local_identity.public_key.clone();

        // 4th bootstrap fallback — peers we've personally
        // handshaken in a prior run. Loaded from disk into
        // `self.discovered_peers_cache`; here we splice them into the
        // `bootstrap_peers` list (deduplicated by pubkey) BEFORE the
        // builtin-seeds / DNS fallbacks run. Censor that takes down
        // (1) operator config + (2) builtin seeds + (3) DNS still
        // can't invalidate (4) without per-user blocking.
        let cached = filter_self_seeds(lock!(self.discovered_peers_cache).snapshot(), &my_pubkey);
        if !cached.is_empty() {
            let mut patched = config.clone();
            // Dedup against the operator-curated list using the same
            // helper the HTTPS layer uses so all
            // bootstrap layers share one dedup contract.
            let existing: std::collections::HashSet<String> = patched
                .bootstrap_peers
                .iter()
                .map(|p| p.public_key.clone())
                .collect();
            let added = filter_already_known(cached, &existing);
            if !added.is_empty() {
                self.logger.info(
                    "bootstrap.cache.augment",
                    format!(
                        "added {} discovered-peer(s) to bootstrap candidates (config has {})",
                        added.len(),
                        patched.bootstrap_peers.len(),
                    ),
                );
                patched.bootstrap_peers.extend(added);
                return self.spawn_bootstrap_task(&patched);
            }
        }

        // HTTPS bootstrap fetch. Runs UNCONDITIONALLY when
        // any URL is configured — operator may have stale
        // `bootstrap_peers` (censored IPs) AND a fresh HTTPS endpoint
        // returning rotated seeds. Each URL is fetched concurrently;
        // discovered peers are registered + dialed via the same
        // outbound-connector path the DNS layer uses.
        // Fail-closed gate (audit cycle-9 BOOT-UNPIN): without an issuer pin,
        // signed_preferred accepts ANY internally-valid bundle — an attacker
        // who controls the HTTPS origin (CDN/CA/hosting/mirror compromise)
        // can serve their own validly-signed seed list and the fetcher merges
        // it. A pin is the only author authentication. Refuse to fetch
        // unpinned bootstrap unless an operator explicitly opts in
        // (production → trusted_bundle_issuer_pubkey; dev/testnet →
        // allow_unpinned_signed_bootstrap / legacy_allow_unsigned_bootstrap).
        let https_urls_present = !config.global.bootstrap_https_urls.is_empty();
        let https_pinned_or_opted_in = config.global.trusted_bundle_issuer_pubkey.is_some()
            || config.global.allow_unpinned_signed_bootstrap
            || config.global.legacy_allow_unsigned_bootstrap;
        if https_urls_present && !https_pinned_or_opted_in {
            self.logger.error(
                "bootstrap.https.fail_closed",
                format!(
                    "{} HTTPS bootstrap URL(s) configured without \
                     trusted_bundle_issuer_pubkey — refusing to fetch unpinned bootstrap \
                     (an HTTPS-origin compromise could serve a validly-signed attacker \
                     bundle). Set trusted_bundle_issuer_pubkey for production, or \
                     allow_unpinned_signed_bootstrap = true for dev/testnet.",
                    config.global.bootstrap_https_urls.len(),
                ),
            );
        }
        // BOOT-UNPIN scope fix (diff-audit 2026-06-12): gate ONLY the HTTPS
        // fetch. The prior `return` here exited the WHOLE task, so a node with
        // valid bootstrap_peers + one unpinned HTTPS URL lost ALL startup
        // bootstrap (configured peers / DNS / builtin seeds below). Those must
        // still run when the HTTPS branch is refused.
        if https_urls_present && https_pinned_or_opted_in {
            let logger = self.logger.clone();
            let urls = config.global.bootstrap_https_urls.clone();
            let transport_ctx = self.transport_ctx.clone();
            // Policy (the unpinned-without-opt-in case already failed closed
            // above): pinned issuer → signed-required + pin (authenticates the
            // bundle author); else `legacy_allow_unsigned_bootstrap` → accept raw
            // JSON; else (`allow_unpinned_signed_bootstrap`) → signed_preferred,
            // which verifies the envelope's self-embedded key only (NO author
            // authentication — dev/testnet opt-in, gated above).
            let bootstrap_policy = match config.global.trusted_bundle_issuer_pubkey.as_deref() {
                Some(pk) => veil_bootstrap::https::BootstrapHttpsPolicy::signed_required(pk),
                None if config.global.legacy_allow_unsigned_bootstrap => {
                    veil_bootstrap::https::BootstrapHttpsPolicy::legacy_unsigned()
                }
                None => veil_bootstrap::https::BootstrapHttpsPolicy::signed_preferred(),
            };
            // 481.4: `.onion` URLs in the list are routed through this Tor
            // SOCKS proxy (plaintext HTTP over the Tor circuit); clearnet URLs
            // ignore it.  The issuer pin (if any) is reused for `.onion`
            // signature verification, which is ALWAYS required regardless of
            // `legacy_allow_unsigned_bootstrap`.
            let bootstrap_tor_proxy = config.global.bootstrap_tor_socks_proxy.clone();
            let bootstrap_issuer_pk = config.global.trusted_bundle_issuer_pubkey.clone();
            let state = Arc::clone(&self.state);
            let dht = Arc::clone(&self.dht);
            let access = self.access();
            let shutdown_tx = self.shutdown_tx.clone();
            let tasks = Arc::clone(&self.tasks);
            let my_pubkey_async = my_pubkey.clone();
            // Snapshot every pubkey we already know about (operator-curated
            // bootstrap_peers + configured peers + cache). Captured here
            // SYNCHRONOUSLY so we don't race against concurrent reloads /
            // cache upserts inside the spawned task. Snapshot is one-shot
            // — peers added AFTER the HTTPS fetch task starts won't be
            // deduped, but that race is benign (worst case: one extra dial).
            let mut known_pubkeys: std::collections::HashSet<String> = config
                .bootstrap_peers
                .iter()
                .map(|p| p.public_key.clone())
                .collect();
            for p in &config.peers {
                known_pubkeys.insert(p.public_key.clone());
            }
            for cached in lock!(self.discovered_peers_cache).snapshot() {
                known_pubkeys.insert(cached.public_key);
            }
            let handle = supervised_spawn(
                Arc::clone(&self.logger),
                "bootstrap_https",
                async move {
                    // Multi-URL fetch with failover. The pure
                    // function lives in `node/bootstrap/https.rs` so it can
                    // be unit-tested with a stub fetcher; here we just
                    // close over `transport_ctx` to bind it to real HTTPS.
                    let aggregated =
                        {
                            let ctx_ref = &transport_ctx;
                            let policy_ref = &bootstrap_policy;
                            let tor_proxy_ref = bootstrap_tor_proxy.as_deref();
                            let issuer_pk_ref = bootstrap_issuer_pk.as_deref();
                            veil_bootstrap::https::aggregate_seeds_via_failover(
                                &urls,
                                move |url: &str| {
                                    let url = url.to_owned();
                                    async move {
                                        use veil_bootstrap::https::BootstrapRoute;
                                        // 481.4: route `.onion` URLs through the Tor
                                        // SOCKS proxy (plaintext HTTP over Tor +
                                        // mandatory signed bundle); clearnet URLs use
                                        // the PKI-verified HTTPS path as before. The
                                        // decision is the pure `classify_bootstrap_url`.
                                        match veil_bootstrap::https::classify_bootstrap_url(
                                        &url,
                                        tor_proxy_ref,
                                    ) {
                                        BootstrapRoute::Tor(proxy) => {
                                            veil_bootstrap::https::fetch_seeds_via_tor(
                                                &url, proxy, issuer_pk_ref,
                                            )
                                            .await
                                        }
                                        BootstrapRoute::OnionNoProxy => Err(
                                            veil_bootstrap::https::HttpsBootstrapError::Transport(
                                                format!(
                                                    "skipping .onion bootstrap URL `{url}`: set \
                                                     [global] bootstrap_tor_socks_proxy (e.g. \
                                                     socks5://127.0.0.1:9050) to enable Tor"
                                                ),
                                            ),
                                        ),
                                        BootstrapRoute::Clearnet => {
                                            veil_bootstrap::https::fetch_seeds_https_with_policy(
                                                &url, ctx_ref, policy_ref,
                                            )
                                            .await
                                        }
                                    }
                                    }
                                },
                            )
                            .await
                        };
                    for (url, count) in &aggregated.per_url_seed_counts {
                        logger.info(
                            "bootstrap.https.found",
                            format!("{count} seed(s) from {url}"),
                        );
                    }
                    for (url, err) in &aggregated.per_url_errors {
                        logger.warn(
                            "bootstrap.https.fetch_failed",
                            format!("url={url} err={err}"),
                        );
                    }
                    let all_seeds = aggregated.seeds;
                    // Filter chain: drop self, drop pubkeys already known to
                    // the runtime (operator config, configured peers, cache)
                    // then dedupe within the HTTPS results themselves
                    // (operator may host the same peer at multiple CDN
                    // endpoints for redundancy).
                    let pre_filter_count = all_seeds.len();
                    let after_self = filter_self_seeds(all_seeds, &my_pubkey_async);
                    let after_known = filter_already_known(after_self, &known_pubkeys);
                    let mut seen: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    let seeds: Vec<_> = after_known
                        .into_iter()
                        .filter(|p| seen.insert(p.public_key.clone()))
                        .collect();
                    if seeds.len() < pre_filter_count {
                        logger.info(
                        "bootstrap.https.dedup",
                        format!(
                            "dropped {} duplicate / self / already-known peer(s) from HTTPS bundle",
                            pre_filter_count - seeds.len(),
                        ),
                    );
                    }
                    if seeds.is_empty() {
                        return;
                    }
                    if seeds.len() > MAX_BOOTSTRAP_SEEDS_PER_SOURCE {
                        logger.warn(
                            "bootstrap.https.capped",
                            format!(
                                "dialing {} of {} HTTPS-discovered seeds (per-source cap, anti-eclipse)",
                                MAX_BOOTSTRAP_SEEDS_PER_SOURCE,
                                seeds.len(),
                            ),
                        );
                    }
                    // HTTPS_SEEDS_BASE namespace — sits between DNS and the
                    // synthetic/gateway range (>= GATEWAY_SYNTHETIC) so the
                    // discovered-peer cache skips these too. Distinct from
                    // APP_ADDED_BASE (cycle-7 M3: the two used to collide on
                    // 0x8800_0000); see `types::synthetic_peer_id`.
                    for (i, bp) in seeds
                        .iter()
                        .take(MAX_BOOTSTRAP_SEEDS_PER_SOURCE)
                        .enumerate()
                    {
                        let Some(node_id_bytes) = derive_node_id_from_bootstrap_peer(bp) else {
                            continue;
                        };
                        let hex = veil_util::hex_str(&node_id_bytes);
                        let Ok(node_id) = <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex)
                        else {
                            continue;
                        };

                        dht.add_contact(veil_dht::routing::Contact::new(
                            node_id_bytes,
                            &bp.transport,
                        ));

                        let peer_id = PeerId::new(
                            crate::types::synthetic_peer_id::HTTPS_SEEDS_BASE
                                .wrapping_add(i as u32),
                        );
                        let entry = PeerConfigEntry {
                            peer_id,
                            node_id,
                            public_key: bp.public_key.clone(),
                            nonce: bp.nonce.clone(),
                            transport: bp.transport.clone(),
                            algo: bp.algo,
                            tls_cert: bp.tls_cert.clone(),
                            tls_key: None,
                            tls_ca_cert: bp.tls_ca_cert.clone(),
                            bootstrap_only: true,
                            source: crate::types::PeerSource::Bootstrap,
                        };
                        lock_state(&state).peers.insert(peer_id, entry.clone());
                        if let Some(ref stx) = shutdown_tx {
                            let handles = crate::outbound_connector::spawn_outbound_peers(
                                vec![entry],
                                &access,
                                stx,
                            );
                            lock_tasks(&tasks).sessions.extend(handles);
                        }
                    }
                },
            );
            lock_tasks(&self.tasks).sessions.push(handle);
        }

        // if both peers and bootstrap_peers are empty, try
        // builtin seeds and DNS discovery as fallback.
        if config.bootstrap_peers.is_empty() && config.peers.is_empty() {
            let builtin = filter_self_seeds(veil_bootstrap::builtin_seeds(), &my_pubkey);
            if !builtin.is_empty() {
                self.logger.info(
                    "bootstrap.builtin",
                    format!(
                        "using {} builtin seed(s) (no peers/bootstrap_peers configured)",
                        builtin.len()
                    ),
                );
                let mut patched = config.clone();
                patched.bootstrap_peers = builtin;
                return self.spawn_bootstrap_task(&patched);
            }
            // No builtin seeds — try DNS discovery asynchronously.
            let logger = self.logger.clone();
            let domain = config
                .global
                .bootstrap_dns_domain
                .clone()
                .unwrap_or_else(|| veil_bootstrap::dns::DEFAULT_BOOTSTRAP_DOMAIN.to_owned());
            let state = Arc::clone(&self.state);
            let dht = Arc::clone(&self.dht);
            let access = self.access();
            let shutdown_tx = self.shutdown_tx.clone();
            let tasks = Arc::clone(&self.tasks);
            let my_pubkey_async = my_pubkey.clone();
            let handle = supervised_spawn(Arc::clone(&self.logger), "bootstrap_dns", async move {
                let seeds = filter_self_seeds(
                    veil_bootstrap::discover_seeds_dns(&domain).await,
                    &my_pubkey_async,
                );
                if seeds.is_empty() {
                    logger.info(
                        "bootstrap.dns.empty",
                        format!("no seeds from DNS domain={domain}"),
                    );
                    return;
                }
                logger.info(
                    "bootstrap.dns.found",
                    format!("{} seed(s) from DNS domain={domain}", seeds.len()),
                );
                if seeds.len() > MAX_BOOTSTRAP_SEEDS_PER_SOURCE {
                    logger.warn(
                        "bootstrap.dns.capped",
                        format!(
                            "dialing {} of {} DNS-discovered seeds (per-source cap, anti-eclipse)",
                            MAX_BOOTSTRAP_SEEDS_PER_SOURCE,
                            seeds.len(),
                        ),
                    );
                }
                // Register and connect to each discovered seed.
                for (i, bp) in seeds
                    .iter()
                    .take(MAX_BOOTSTRAP_SEEDS_PER_SOURCE)
                    .enumerate()
                {
                    let Some(node_id_bytes) = derive_node_id_from_bootstrap_peer(bp) else {
                        continue;
                    };
                    let hex = veil_util::hex_str(&node_id_bytes);
                    let Ok(node_id) = <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex)
                    else {
                        continue;
                    };

                    dht.add_contact(veil_dht::routing::Contact::new(
                        node_id_bytes,
                        &bp.transport,
                    ));

                    let peer_id = PeerId::new(0x8000_0000u32.wrapping_add(i as u32));
                    let entry = PeerConfigEntry {
                        peer_id,
                        node_id,
                        public_key: bp.public_key.clone(),
                        nonce: bp.nonce.clone(),
                        transport: bp.transport.clone(),
                        algo: bp.algo,
                        tls_cert: bp.tls_cert.clone(),
                        tls_key: None,
                        tls_ca_cert: bp.tls_ca_cert.clone(),
                        bootstrap_only: true,
                        source: crate::types::PeerSource::Bootstrap,
                    };
                    lock_state(&state).peers.insert(peer_id, entry.clone());
                    if let Some(ref stx) = shutdown_tx {
                        let handles = crate::outbound_connector::spawn_outbound_peers(
                            vec![entry],
                            &access,
                            stx,
                        );
                        lock_tasks(&tasks).sessions.extend(handles);
                    }
                }
            });
            lock_tasks(&self.tasks).sessions.push(handle);
            return;
        }
        if config.bootstrap_peers.is_empty() {
            return;
        }

        // Collect node_id bytes for all peers in config.peers so we can
        // distinguish bootstrap-only peers from regular configured peers.
        let bootstrap_node_ids: std::collections::HashSet<[u8; 32]> = config
            .peers
            .iter()
            .filter_map(|p| veil_cfg::NodeId::from_public_key(p.algo, &p.public_key).ok())
            .map(|id| *id.as_bytes())
            .collect();

        for (i, bp) in config.bootstrap_peers.iter().enumerate() {
            if bp.public_key == my_pubkey {
                self.logger.info(
                    "bootstrap.skip_self",
                    format!(
                        "skipping bootstrap_peer with our own public_key (transport={})",
                        veil_util::redact_addr_for_log(&bp.transport)
                    ),
                );
                continue;
            }
            let Some(node_id_bytes) = derive_node_id_from_bootstrap_peer(bp) else {
                self.logger.warn(
                    "bootstrap.bad_peer",
                    format!("cannot derive node_id from public_key={}", bp.public_key),
                );
                continue;
            };

            let hex = veil_util::hex_str(&node_id_bytes);
            let Ok(node_id) = <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex) else {
                continue;
            };

            // Add to DHT routing table so iterative lookups can reach it.
            self.dht.add_contact(veil_dht::routing::Contact::new(
                node_id_bytes,
                &bp.transport,
            ));

            self.logger.info(
                "bootstrap.contact_added",
                format!(
                    "transport={} node_id={}",
                    veil_util::redact_addr_for_log(&bp.transport),
                    veil_util::hex_short(&node_id_bytes)
                ),
            );

            let is_bootstrap_only = !bootstrap_node_ids.contains(&node_id_bytes);
            if !is_bootstrap_only {
                // Already a regular configured peer — outbound connector handles it.
                continue;
            }

            // Synthetic peer_id for bootstrap-only peers: high bit set to avoid
            // conflicts with configured peer IDs (which are typically small integers).
            let peer_id = PeerId::new(0x8000_0000u32.wrapping_add(i as u32));

            let entry = PeerConfigEntry {
                peer_id,
                node_id,
                public_key: bp.public_key.clone(),
                nonce: bp.nonce.clone(),
                transport: bp.transport.clone(),
                algo: bp.algo,
                tls_cert: bp.tls_cert.clone(),
                tls_key: None,
                tls_ca_cert: bp.tls_ca_cert.clone(),
                bootstrap_only: true,
                source: crate::types::PeerSource::Bootstrap,
            };

            self.logger.info(
                "bootstrap.connecting",
                format!(
                    "transport={} node_id={}",
                    veil_util::redact_addr_for_log(&bp.transport),
                    veil_util::hex_short(&node_id_bytes)
                ),
            );

            // Register in state so connect_peer_active can find the peer config.
            lock_state(&self.state).peers.insert(peer_id, entry.clone());

            if let Some(ref shutdown_tx) = self.shutdown_tx {
                let handles = crate::outbound_connector::spawn_outbound_peers(
                    vec![entry],
                    &self.access(),
                    shutdown_tx,
                );
                lock_tasks(&self.tasks).sessions.extend(handles);
            }
        }
    }

    /// Spawn the bootstrap watchdog — partition-recovery loop.
    ///
    /// `spawn_bootstrap_task` runs once at startup and the outbound
    /// connectors it creates are `bootstrap_only=true`, meaning the
    /// connector task terminates when the first session ends. If the
    /// cluster later fragments (every direct session torn down through
    /// some combination of bans, network split, or peer crashes), the
    /// daemon is stuck "online but isolated": `dht.republish` emits
    /// `under_count fan-out=0` indefinitely, but nothing re-dials the
    /// operator-curated `bootstrap_peers` list to recover.
    ///
    /// This watchdog samples `live_sessions.len` every
    /// `CHECK_INTERVAL`. After `ZERO_STREAK_THRESHOLD` consecutive
    /// zero-session ticks (≈ 90 s by default — long enough that a brief
    /// network blip doesn't trip a needless re-dial), it respawns the
    /// outbound connectors for the operator-configured bootstrap peers.
    /// A `COOLDOWN` between retries prevents a thundering herd if the
    /// bootstrap hosts themselves are temporarily unreachable.
    ///
    /// Only the operator-curated `bootstrap_peers` list is re-dialed —
    /// DNS / HTTPS / cache fallbacks are deliberately skipped here
    /// because they're discovery mechanisms for *initial* bootstrap;
    /// they belong in startup, not in steady-state partition recovery.
    pub fn spawn_bootstrap_watchdog_task(&mut self, config: &veil_cfg::Config) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        if config.bootstrap_peers.is_empty() {
            // No operator-curated bootstrap list — nothing to retry.
            return;
        }

        let mut shutdown_rx = shutdown_tx.subscribe();
        let shutdown_tx_clone = shutdown_tx.clone();
        let logger = Arc::clone(&self.logger);
        let live_sessions = Arc::clone(&self.live_sessions);
        let state = Arc::clone(&self.state);
        let dht = Arc::clone(&self.dht);
        let access = self.access();
        let tasks = Arc::clone(&self.tasks);
        let metrics = self.metrics.clone();
        let my_pubkey = self.identity.local_identity.public_key.clone();
        let bootstrap_peers = config.bootstrap_peers.clone();

        let handle = supervised_spawn(Arc::clone(&self.logger), "bootstrap_watchdog", async move {
            let mut interval = tokio::time::interval(BOOTSTRAP_WATCHDOG_CHECK_INTERVAL);
            interval.tick().await; // skip immediate first tick
            let mut zero_streak: u32 = 0;
            let mut last_retry: Option<tokio::time::Instant> = None;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let session_count = veil_util::lock!(live_sessions).len();
                        let prev_streak = zero_streak;
                        zero_streak = if session_count == 0 {
                            zero_streak.saturating_add(1)
                        } else {
                            0
                        };
                        let decision = evaluate_watchdog_tick(
                            session_count,
                            zero_streak,
                            BOOTSTRAP_WATCHDOG_ZERO_STREAK_THRESHOLD,
                            last_retry.map(|t| t.elapsed()),
                            BOOTSTRAP_WATCHDOG_COOLDOWN,
                        );
                        match decision {
                            WatchdogDecision::Idle => {
                                if prev_streak > 0 {
                                    logger.info(
                                        "bootstrap.watchdog.recovered",
                                        format!(
                                            "session count back to {} after {} zero-tick(s)",
                                            session_count, prev_streak,
                                        ),
                                    );
                                }
                                continue;
                            }
                            WatchdogDecision::Wait => continue,
                            WatchdogDecision::Retry => {}
                        }

                        logger.warn(
                            "bootstrap.watchdog.retry",
                            format!(
                                "zero sessions for {}s — re-dialing {} bootstrap peer(s)",
                                zero_streak.saturating_mul(
                                    BOOTSTRAP_WATCHDOG_CHECK_INTERVAL.as_secs() as u32,
                                ),
                                bootstrap_peers.len(),
                            ),
                        );
                        if let Some(m) = metrics.as_ref() {
                            m.inc_bootstrap_watchdog_retries();
                        }
                        last_retry = Some(tokio::time::Instant::now());

                        for (i, bp) in bootstrap_peers.iter().enumerate() {
                            if bp.public_key == my_pubkey {
                                continue;
                            }
                            let Some(node_id_bytes) = derive_node_id_from_bootstrap_peer(bp)
                            else {
                                continue;
                            };
                            let hex = veil_util::hex_str(&node_id_bytes);
                            let Ok(node_id) =
                                <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex)
                            else {
                                continue;
                            };

                            dht.add_contact(veil_dht::routing::Contact::new(
                                node_id_bytes,
                                &bp.transport,
                            ));

                            let peer_id =
                                PeerId::new(0x8000_0000u32.wrapping_add(i as u32));
                            let entry = PeerConfigEntry {
                                peer_id,
                                node_id,
                                public_key: bp.public_key.clone(),
                                nonce: bp.nonce.clone(),
                                transport: bp.transport.clone(),
                                algo: bp.algo,
                                tls_cert: bp.tls_cert.clone(),
                                tls_key: None,
                                tls_ca_cert: bp.tls_ca_cert.clone(),
                                bootstrap_only: true,
                                source: crate::types::PeerSource::Bootstrap,
                            };
                            lock_state(&state).peers.insert(peer_id, entry.clone());

                            let handles =
                                crate::outbound_connector::spawn_outbound_peers(
                                    vec![entry],
                                    &access,
                                    &shutdown_tx_clone,
                                );
                            // Funnel through push_session_handle so the
                            // 256-entry prune-on-overflow logic catches
                            // the stale JoinHandles from prior retry
                            // waves; raw `extend` bypasses pruning and
                            // grows the Vec linearly with retry count.
                            {
                                let mut t = lock_tasks(&tasks);
                                if t.sessions.len() + handles.len() >= 256 {
                                    t.sessions.retain(|h| !h.is_finished());
                                }
                                t.sessions.extend(handles);
                            }
                        }
                    }
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Spawn the route-miss handler.
    ///
    /// When `FrameDispatcher` can't forward a `DELIVERY_FORWARD` frame (no
    /// direct session, no route-cache hit), it pushes the destination node_id
    /// to `route_miss_tx`. This task receives those destinations, floods a
    /// `ROUTE_REQUEST` to all connected peers, and retries delivery up to 3
    /// times with exponential backoff (500 ms → 1 s → 2 s).
    ///
    /// on route discovery success the handler used to drain a
    /// mailbox for that destination; with mailbox removed it now simply
    /// signals route_updated and the application layer retries delivery.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_route_miss_handler(
        &mut self,
        route_request_backoff_ms: [u64; 3],
        partition_threshold: f64,
        dht_fallback_timeout_ms: u64,
        dht_fallback_backpressure_threshold_pct: u8,
        dht_fallback_adaptive: bool,
        dht_fallback_priority_mult: [u16; 2],
        dht_fallback_enabled: bool,
    ) {
        // a: extracted to `node/routing/miss_handler.rs`.
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        // bounded channel — route-miss signals are best-effort; excess are dropped.
        let (tx, rx) = tokio::sync::mpsc::channel::<([u8; 32], u8)>(
            veil_proto::budget::ROUTE_MISS_CHANNEL_CAP,
        );
        *lock!(self.dispatcher.route_miss_tx) = Some(tx);

        // miss_handler now takes trait-typed deps (FrameBroadcaster
        // RoutingMetrics, RoutingLogger). Concretes coerce via the impls in
        // veil-observability + the SessionTxBroadcaster adapter.
        let broadcaster: Arc<dyn veil_types::FrameBroadcaster> = Arc::new(
            veil_session::glue::SessionTxBroadcaster::new(Arc::clone(&self.session_tx_registry)),
        );
        let metrics: Option<Arc<dyn veil_routing::RoutingMetrics>> = self
            .metrics
            .clone()
            .map(|m| m as Arc<dyn veil_routing::RoutingMetrics>);
        let logger: Arc<dyn veil_routing::RoutingLogger> = self.logger.clone();
        let ctx = veil_routing::miss_handler::MissHandlerCtx {
            shutdown_rx: shutdown_tx.subscribe(),
            rx,
            broadcaster,
            route_cache: Arc::clone(&self.routing.route_cache),
            route_updated: Arc::clone(&self.dispatcher.route_updated),
            local_node_id: *self.identity.local_identity.node_id.as_bytes(),
            signing_key: self.dispatcher.crypto.local_signing_key.clone(),
            metrics,
            logger,
            route_request_backoff_ms,
            partition_threshold,
            // wire the iterative-DHT fallback so that after RouteRequest flood
            // retries are exhausted we fire a RecursiveQuery(FIND_NODE) to seed
            // route_cache (does NOT dial — see dht_fallback.rs module docs).
            // `dht_fallback_enabled = false` unwires it entirely: the
            // miss-handler then records the partition and drops, exactly the
            // pre-fallback behaviour. The always-on recursive-relay, which
            // carries the actual cross-topology delivery, is unaffected.
            iterative_dht_fallback: if dht_fallback_enabled {
                Some(Arc::new(crate::dht_fallback::DhtRouteFallback::new(
                    self.access(),
                    dht_fallback_timeout_ms,
                    dht_fallback_backpressure_threshold_pct,
                    dht_fallback_adaptive,
                    dht_fallback_priority_mult,
                )))
            } else {
                None
            },
        };
        let handle = veil_routing::miss_handler::spawn(ctx);
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Spawn the authenticated-onion final-hop verify+deliver handler
    /// (Epic 482 v1; see `docs/internal/PLAN_AUTHENTICATED_ONION_DELIVERY.md`).
    ///
    /// The sync `FrameDispatcher` decodes inbound `APP_DELIVER_AUTH` cells and
    /// `try_send`s the `AuthAppDeliver` to `auth_deliver_tx`. This task drains
    /// the channel and, for each message: resolves the sender's identity
    /// document over DHT, runs `verify_auth_deliver` (recipient binding,
    /// sender↔doc match, freshness, subkey validity, signature), checks the
    /// per-sender replay cache, and on success delivers to the addressed local
    /// endpoint with the VERIFIED sender node_id — the property the onion
    /// transport alone cannot give (it hides location, not origin).
    ///
    /// Every failure (unresolvable sender, bad signature, stale, replay,
    /// unbound endpoint) is logged and dropped — never surfaced to the sender,
    /// which would leak recipient liveness. Processing is serial; head-of-line
    /// blocking is bounded by `AUTH_DELIVER_RESOLVE_TIMEOUT`.
    pub fn spawn_auth_deliver_handler(&mut self) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<veil_dispatcher::AuthDeliverInbound>(
            AUTH_DELIVER_CHANNEL_CAP,
        );
        *lock!(self.dispatcher.auth_deliver_tx) = Some(tx);

        let mut shutdown_rx = shutdown_tx.subscribe();
        let access = self.access();
        let logger = Arc::clone(&self.logger);
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        // Δ2-b: clone the PERSISTENT replay cache off AnonymityState (which
        // survives reload) rather than building a fresh one per spawn — so a
        // config reload no longer resets the (sender, nonce) replay window.
        let replay_cache = Arc::clone(&self.anonymity.auth_deliver_replay_cache);
        let freshness_window = veil_identity::auth_deliver::DEFAULT_AUTH_DELIVER_FRESHNESS_SECS;
        // Reassembles fragmented authenticated messages from the rendezvous path
        // (the direct onion path delivers whole `Full` messages). Single-owner —
        // the task processes serially, so no lock.
        let mut reassembler = veil_identity::auth_deliver::AuthDeliverReassembler::new();

        let handle = supervised_spawn(
            Arc::clone(&self.logger),
            "auth_deliver_handler",
            async move {
                loop {
                    tokio::select! {
                        maybe = rx.recv() => {
                            let Some(inbound) = maybe else { break };
                            let now_unix = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            // Resolve a complete AuthAppDeliver from the inbound:
                            // a Full message arrives whole; Fragments reassemble.
                            // via_reply: whether it came DOWN one of OUR reply
                            // circuits (for a fragmented message: the flag of
                            // the COMPLETING fragment — replies/ACKs are single-
                            // fragment, so this is exact where it matters).
                            let mut via_reply = false;
                            let auth = match inbound {
                                veil_dispatcher::AuthDeliverInbound::Full(a) => Some(*a),
                                veil_dispatcher::AuthDeliverInbound::Fragment {
                                    frag,
                                    via_reply_circuit,
                                } => {
                                    via_reply = via_reply_circuit;
                                    use veil_identity::auth_deliver::ReassembleOutcome;
                                    match reassembler.push(frag, now_unix) {
                                        ReassembleOutcome::Complete(bytes) => {
                                            match veil_proto::AuthAppDeliver::decode(&bytes) {
                                                Ok(a) => Some(a),
                                                Err(e) => {
                                                    logger.info(
                                                        "anonymity.auth_deliver.reassembled_decode_failed",
                                                        format!("reassembled AuthAppDeliver decode: {e}"),
                                                    );
                                                    None
                                                }
                                            }
                                        }
                                        ReassembleOutcome::Pending => None,
                                        ReassembleOutcome::Rejected => {
                                            logger.info(
                                                "anonymity.auth_deliver.fragment_rejected",
                                                "auth-deliver fragment rejected (bounds/inconsistent)",
                                            );
                                            None
                                        }
                                    }
                                }
                            };
                            if let Some(auth) = auth {
                                process_auth_deliver(
                                    auth,
                                    &access,
                                    &logger,
                                    &replay_cache,
                                    &local_node_id,
                                    freshness_window,
                                    now_unix,
                                    via_reply,
                                )
                                .await;
                            }
                        }
                        Ok(_) = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            },
        );
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Spawn the rendezvous-recipient lifecycle (Epic 482 v1). No-op unless
    /// `[anonymity].receive_anonymous`. Picks a reachable published rendezvous
    /// relay, registers with it (so it forwards introduces addressed to our
    /// cookie) and registers a publisher entry (the maintenance tick publishes
    /// the signed `RendezvousAd`). Re-registers on relay-session loss / failover
    /// and periodically (the relay's cookie map is in-memory).
    pub fn spawn_rendezvous_recipient_task(&mut self, config: &veil_cfg::Config) {
        if !config.anonymity.receive_anonymous {
            return;
        }
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        // SAME EventBus that SessionGuard::drop publishes SESSIONS_CHANGED on, so
        // a session-close event-driven wake re-registers within the reconnect RTT
        // instead of waiting up to a full backstop tick.
        let event_bus = Arc::clone(&self.event_bus);
        let logger = Arc::clone(&self.logger);
        let dht = Arc::clone(&self.dht);
        let live_sessions = Arc::clone(&self.live_sessions);
        // Handshake-advertised peer capabilities — lets the relay picker confirm
        // a CONNECTED relay (CAN_RELAY) without a flaky DHT relay-directory
        // FIND_VALUE, which churned the registration with `no_relay`.
        let peer_cap_flags = Arc::clone(&self.dispatcher.crypto.peer_cap_flags);
        let session_tx_registry = Arc::clone(&self.session_tx_registry);
        let anonymity = Arc::clone(&self.anonymity);
        let identity = Arc::clone(&self.identity);
        // RPC outbox for active FIND_VALUE of connected peers' relay-directory
        // entries (cold-start discovery — see warm_connected_relay_directory).
        let session_outbox = Arc::clone(&self.session_outbox);
        // Operator-pinned rendezvous relays (node-id hex), if any.
        let pinned: Vec<[u8; 32]> = config
            .anonymity
            .rendezvous_relays
            .iter()
            .filter_map(|s| {
                <veil_cfg::NodeId as std::str::FromStr>::from_str(s)
                    .ok()
                    .map(|n| *n.as_bytes())
            })
            .collect();
        // DETERMINISTIC cookie tying our published ad to our relay registration:
        // XOR-folded from our node_id so it is STABLE across restarts AND bit-for-
        // bit identical to the app-side mailbox publisher
        // (`MailboxService._deriveCookie`). A random per-process cookie made the
        // built-in receiver task and the app's mailbox advertise the SAME relay
        // under DIFFERENT cookies, so a sender that resolved one publisher slot
        // used a cookie the other slot's subscriber never registered → the relay
        // dropped the introduce (`cookie_unknown`) and incoming delivery silently
        // failed. The node_id is public (it keys the ad), so this leaks nothing.
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        let cookie = rendezvous_cookie_from_node_id(&local_node_id);

        let handle = supervised_spawn(
            Arc::clone(&self.logger),
            "rendezvous_recipient",
            async move {
                let outbox: Arc<dyn veil_dht::FrameRouter> = session_outbox;
                let mut interval = tokio::time::interval(RENDEZVOUS_RECIPIENT_CHECK_INTERVAL);
                // Don't let the backstop burst-catch-up after time spent in the
                // event arm or the jitter sleep.
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut current: Option<[u8; 32]> = None;
                let mut ticks: u64 = 0;
                let mut sessions_rx = event_bus.subscribe();
                // Seed one debounce-window in the past so the FIRST session change
                // re-checks immediately.
                let mut last_event_check =
                    tokio::time::Instant::now() - RENDEZVOUS_SESSION_EVENT_DEBOUNCE;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            ticks = ticks.wrapping_add(1);
                            // Per-tick fresh random jitter (0..3s) so the backstop
                            // cadence is not a fixed, identity-linkable heartbeat.
                            // MissedTickBehavior::Delay keeps this sleep from
                            // bursting the backstop.
                            {
                                use rand_core::{OsRng, RngCore};
                                let j = OsRng.next_u64() % RENDEZVOUS_TICK_JITTER_MS;
                                if j > 0 {
                                    tokio::time::sleep(
                                        std::time::Duration::from_millis(j),
                                    )
                                    .await;
                                }
                            }
                            // STICKINESS (cold-start churn fix): keep the current
                            // relay as long as our SESSION to it is live. We must
                            // NOT abandon a working relay just because its
                            // relay-directory entry transiently aged out of our
                            // LOCAL store (`get_local` has a TTL; it's refreshed
                            // only on `!current_ok`, a chicken-and-egg). The old
                            // `&& rendezvous_relay_published` made `current_ok`
                            // flip false roughly hourly even with the session up,
                            // so the recipient re-picked a RANDOM relay — churning
                            // the published ad so a cold sender resolves a relay we
                            // already left (+ unregistered from) and its introduce
                            // black-holes. The directory entry is still required at
                            // PICK time (`pick_rendezvous_relay`) to build the
                            // circuit; for KEEPING, session liveness is the bound.
                            let current_ok = current
                                .is_some_and(|r| rendezvous_session_live(&live_sessions, &r));
                            if !current_ok {
                                rendezvous_recipient_recheck(
                                    &mut current,
                                    &live_sessions,
                                    &dht,
                                    &peer_cap_flags,
                                    &outbox,
                                    &session_tx_registry,
                                    &anonymity,
                                    &identity,
                                    &logger,
                                    &pinned,
                                    &local_node_id,
                                    cookie,
                                    "anonymity.rendezvous_recipient.registered",
                                    false,
                                )
                                .await;
                            } else if ticks.is_multiple_of(RENDEZVOUS_REREGISTER_EVERY_TICKS) {
                                // Refresh every live replica registration. Relay
                                // subscriber maps are in-memory, and sessions to
                                // mobile/obfs peers can churn independently.
                                rendezvous_recipient_recheck(
                                    &mut current,
                                    &live_sessions,
                                    &dht,
                                    &peer_cap_flags,
                                    &outbox,
                                    &session_tx_registry,
                                    &anonymity,
                                    &identity,
                                    &logger,
                                    &pinned,
                                    &local_node_id,
                                    cookie,
                                    "anonymity.rendezvous_recipient.refreshed",
                                    true,
                                )
                                .await;
                            }
                        }
                        recv = sessions_rx.recv() => {
                            // Event-driven wake: collapse the no-subscriber window
                            // from a full backstop tick to the reconnect+register
                            // RTT. The shared fn re-applies the stickiness gate, so
                            // an event for an unrelated peer is a no-op while the
                            // current relay stays live.
                            let changed = match recv {
                                Ok(ev) => {
                                    ev.kind == veil_proto::event_kind::SESSIONS_CHANGED
                                }
                                // Buffer overflowed: re-check anyway (the shared fn
                                // is a no-op when current_ok); the backstop tick
                                // catches anything dropped.
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => true,
                                // Bus dropped (shutdown); exit the loop.
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            };
                            if changed {
                                let now = tokio::time::Instant::now();
                                if now.duration_since(last_event_check)
                                    >= RENDEZVOUS_SESSION_EVENT_DEBOUNCE
                                {
                                    last_event_check = now;
                                    // Coalesce a burst: drain queued events
                                    // non-blockingly so a 200+/s storm collapses
                                    // into a SINGLE re-check.
                                    loop {
                                        match sessions_rx.try_recv() {
                                            Ok(_) => {}
                                            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                                                break
                                            }
                                            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                                                break
                                            }
                                            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                                                break
                                            }
                                        }
                                    }
                                    rendezvous_recipient_recheck(
                                        &mut current,
                                        &live_sessions,
                                        &dht,
                                        &peer_cap_flags,
                                        &outbox,
                                        &session_tx_registry,
                                        &anonymity,
                                        &identity,
                                        &logger,
                                        &pinned,
                                        &local_node_id,
                                        cookie,
                                        "anonymity.rendezvous_recipient.event_driven_reregister",
                                        true,
                                    )
                                    .await;
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            },
        );
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    pub fn spawn_ipc_server(&mut self, config: &veil_cfg::Config) {
        // b: IPC server now supports both Unix-domain socket and
        // TCP-loopback backends, so spawning it works on every platform.
        if !config.ipc.enabled {
            return;
        }
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        // b: dispatch on `ipc.socket_uri` (Unix or TCP-loopback).
        // `socket_path` remains the legacy fallback for Unix-only deployments.
        // Pass config-file dir so TCP-endpoint sidecars land NEXT TO the
        // config (multi-node-friendly default; multi nodes on the same host
        // each have their own config dir → no clobbering).
        let config_dir = self.config_path.parent();
        let default_runtime_dir = veil_cfg::runtime_veil_dir();
        let endpoint = match veil_ipc::path::resolve_ipc_endpoint(
            &config.ipc,
            config_dir,
            &default_runtime_dir,
        ) {
            Ok(ep) => ep,
            Err(e) => {
                self.logger.warn(
                    "ipc.config.invalid",
                    format!("could not resolve [ipc] endpoint, ipc disabled: {e}"),
                );
                return;
            }
        };
        let anchor_for_log =
            match veil_ipc::path::ipc_anchor_path(&config.ipc, config_dir, &default_runtime_dir) {
                Ok(p) => p,
                Err(_) => default_ipc_socket_path(),
            };
        self.logger
            .info("ipc.start", format!("anchor={}", anchor_for_log.display()));
        let node_id = *self.identity.local_identity.node_id.as_bytes();
        let app_registry = Arc::clone(&self.app_registry);
        // veil-ipc's IpcServer takes Arc<dyn FrameBroadcaster>.
        // Wrap our concrete Arc<RwLock<SessionTxRegistry>> in the production
        // SessionTxBroadcaster adapter so the trait dispatch matches.
        let session_tx_broadcaster: Arc<dyn veil_types::FrameBroadcaster> = Arc::new(
            veil_session::glue::SessionTxBroadcaster::new(Arc::clone(&self.session_tx_registry)),
        );
        let route_cache = Arc::clone(&self.routing.route_cache);
        let route_updated = Arc::clone(&self.dispatcher.route_updated);
        // Epic 486.1 slice 3 (audit batch 2026-05-23): construct cold-start
        // ML-KEM EK resolver and attach it to the IPC server.  When the IPC
        // sender's local `peer_mlkem_keys` cache misses for a target node_id,
        // the resolver fetches + verifies the recipient's EK from DHT (instance
        // registry walk + cert chain) and populates the cache.
        // One concrete resolver instance serves BOTH the ML-KEM EK lookup AND
        // the relay-X25519-by-node_id lookup (`RelayKeyResolver`) — they share
        // the same DHT walk + document fetch, so we coerce the single Arc into
        // both trait objects rather than building two.
        let dht_key_resolver = Arc::new(crate::mlkem_resolver::DhtMlKemEkResolver::new(
            Arc::clone(&self.dht),
            Arc::clone(&self.session_tx_registry),
            Arc::clone(&self.dispatcher.pending_recursive),
            *self.identity.local_identity.node_id.as_bytes(),
            Arc::clone(&self.identity.peer_mlkem_keys),
            Arc::clone(&self.identity.peer_mlkem_certs),
            Arc::clone(&self.logger),
        ));
        let mlkem_ek_resolver: Arc<dyn veil_types::MlKemEkResolver> =
            Arc::clone(&dht_key_resolver) as Arc<dyn veil_types::MlKemEkResolver>;
        let relay_key_resolver: Arc<dyn veil_types::RelayKeyResolver> =
            dht_key_resolver as Arc<dyn veil_types::RelayKeyResolver>;
        // Authenticated anonymous (onion/rendezvous) sender for the IPC
        // `anonymous_authenticated` flag. Holds the access bundle + the
        // configured circuit length.
        let anon_onion_sender: Arc<dyn veil_types::AnonOnionSender> =
            Arc::new(RuntimeAnonOnionSender::new(
                self.access(),
                config.anonymity.default_hop_count.unwrap_or(2).max(1) as usize,
            ));
        let mut server = IpcServer::new(endpoint, shutdown_rx, app_registry, node_id)
            .with_session_tx_registry(session_tx_broadcaster)
            // Cross-node IPC STREAM_OPEN forwarding: share the dispatcher's
            // inbound routing tables + the runtime-wide wire stream-id counter
            // (also used by VeilConnector) so remote streams bridge cleanly.
            .with_stream_bridge(veil_ipc::bridge::IpcStreamBridge {
                veil_stream_rx: Arc::clone(&self.dispatcher.veil_stream_rx),
                pending_receipts: Arc::clone(&self.dispatcher.pending_stream_receipts),
                wire_stream_counter: Arc::clone(&self.wire_stream_counter),
            })
            .with_route_cache(route_cache)
            .with_route_updated(route_updated)
            .with_e2e_keys(Arc::clone(&self.identity.peer_mlkem_keys))
            .with_mlkem_ek_resolver(mlkem_ek_resolver)
            .with_relay_key_resolver(relay_key_resolver)
            .with_anon_onion_sender(anon_onion_sender)
            // Offline-mailbox seal/open (node-side E2E crypto). DORMANT — no app
            // sends MailboxSeal/Open yet; wired so the path is live once an app
            // does.
            .with_mailbox_crypto_sink(std::sync::Arc::new(self.mailbox_crypto()))
            .with_trace_sample_rate(config.routing.trace_sample_rate)
            .with_pending_ack(Arc::clone(&self.dispatcher.pending_ack))
            .with_pending_recursive(Arc::clone(&self.dispatcher.pending_recursive));
        if let Some(ref m) = self.metrics {
            server = server.with_metrics(Arc::clone(m) as Arc<dyn veil_ipc::IpcMetrics>);
        }
        let anycast_policy = match config.anycast.resolve_policy {
            veil_cfg::AnycastResolvePolicyKind::BestEffort => {
                veil_anycast::AnycastResolvePolicy::BestEffort
            }
            veil_cfg::AnycastResolvePolicyKind::SignedOnly => {
                veil_anycast::AnycastResolvePolicy::SignedOnly
            }
            veil_cfg::AnycastResolvePolicyKind::SignedBound => {
                veil_anycast::AnycastResolvePolicy::SignedBound
            }
        };
        // Audit batch 2026-05-25 phase O (cross-audit #3 closure):
        // if sovereign identity wired AND uses Ed25519, configure
        // anycast to auto-sign all advertise calls (including those
        // initiated through IPC `AnycastAdvertise`).  Resolvers running
        // `SignedOnly` / `SignedBound` will admit our records.  PQ-only
        // sovereign identities (Falcon-512) fall through to unsigned
        // v1 advertise — caller-side opt-in to sign would require Falcon
        // anycast support, which is a separate wire-compat exercise.
        let mut anycast_svc_builder = veil_anycast::AnycastService::new(
            Arc::clone(&self.dht),
            *self.identity.local_identity.node_id.as_bytes(),
        )
        .with_policy(anycast_policy);
        if let Some(sov) = self.identity.sovereign_identity.as_ref() {
            // A1 (audit) fix: algo-generic owner-signer — signs v2 (Ed25519) OR
            // v3 (Falcon-512 / hybrid) records, so a PQ-only sovereign signs too
            // instead of falling back to unsigned advertise. `sig_key_idx = 0`
            // (master) follows the IdentityDocument convention and is required
            // for the BLAKE3(owner_pubkey)==node_id owner-binding.
            if let Some((algo_byte, owner_pubkey, sign)) = sov.anycast_owner_signer() {
                match veil_types::SignatureAlgorithm::from_wire_byte(algo_byte) {
                    Some(algo) => {
                        anycast_svc_builder = anycast_svc_builder.with_signer(
                            veil_anycast::AnycastSigner::new(algo, owner_pubkey, 0, sign),
                        );
                    }
                    None => {
                        // Unreachable in practice: `identity_sk.algo()` only ever
                        // yields a known wire byte. Guard rather than panic.
                        self.logger.warn(
                            "anycast.signing.unknown_algo",
                            "sovereign identity reports an unrecognized signature \
                             algorithm byte: anycast records will be published \
                             UNSIGNED",
                        );
                    }
                }
            } else {
                // `anycast_owner_signer` returns `None` only for a non-standalone
                // (multi-device subkey) identity: its key is NOT the master, so a
                // signed record's owner_pubkey could not satisfy the binding and
                // verifiers would reject it. Such records would go out effectively
                // unverifiable, so we publish UNSIGNED instead — peers on the
                // default `SignedBound` resolve policy drop those, so anycast
                // advertise is disabled for subkey identities. Surface it.
                self.logger.warn(
                    "anycast.signing.subkey_cannot_bind",
                    "sovereign identity is a multi-device subkey (not standalone \
                     master): it cannot satisfy the anycast owner-binding, so \
                     records are published UNSIGNED and dropped by peers running \
                     the default SignedBound resolve policy — anycast advertise is \
                     effectively disabled for this identity",
                );
            }
        }
        let anycast_svc = Arc::new(anycast_svc_builder);
        server = server.with_anycast_service(anycast_svc);
        // share the hint registry so IPC clients can query it.
        server = server.with_hint_registry(Arc::clone(&self.hint_registry));
        // reuse the runtime-wide push-event bus. IpcServer
        // subscribes one receiver per connected client; runtime
        // publishers (session insert/remove sites + MobileEventForwarder)
        // share the same Arc so every event reaches every connected app.
        let event_bus: Arc<veil_ipc::EventBus> = Arc::clone(&self.event_bus);
        server = server.with_event_bus(Arc::clone(&event_bus));
        // 489.5: install mobile-event sink so apps can
        // toggle background mode and notify network-state changes via IPC.
        // The forwarder also publishes MOBILE_TIER_CHANGED events on
        // every tier transition.
        let mobile_sink: Arc<dyn veil_ipc::MobileEventSink> = Arc::new(
            crate::mobile_sink::MobileEventForwarder::new(
                Arc::clone(&self.logger),
                Arc::clone(&self.gateway_failover_notify),
                Arc::clone(&self.force_reconnect_notify),
                Arc::clone(&self.session_tx_registry),
            )
            .with_event_bus(Arc::clone(&event_bus)),
        );
        server = server.with_mobile_event_sink(mobile_sink);
        // surface daemon's signing-pubkey + algo to IPC clients
        // so Flutter / Swift / Kotlin UIs can display "you are: …" without
        // scraping VEIL_LOCAL_NODE_ID env or admin-socket round-trip.
        // Decode the base64 pubkey once at IPC-server construction; if
        // decoding fails fall back to empty bytes (clients still get node_id).
        let identity_pubkey_bytes = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(self.identity.local_identity.public_key.as_bytes())
                .unwrap_or_default()
        };
        server = server.with_local_identity(
            self.identity.local_identity.algo.wire_byte(),
            identity_pubkey_bytes,
        );
        // peer-list provider — answers `LocalAppMsg::GetPeers`
        // by snapshotting `live_sessions` (cheap mutex-and-clone, no
        // network I/O). Without it Flutter UI has to poll mobile_status
        // through admin socket, which requires admin-token (operator-only).
        let peer_list: Arc<dyn veil_ipc::PeerListProvider> = Arc::new(
            crate::peer_list_provider::LiveSessionsPeerList::new(Arc::clone(&self.live_sessions)),
        );
        server = server.with_peer_list_provider(peer_list);
        // S2.A: P-Net status provider — surfaces verified cert state
        // to IPC consumers (ogate / oproxy) for app-layer admission
        // decisions.  Empty cache (public-mode daemon) ⇒ all queries
        // reply has_cert=false; strict-p_net apps reject downstream.
        let pnet_status: Arc<dyn veil_ipc::PnetStatusProvider> =
            Arc::new(crate::pnet_status_provider::DaemonPnetStatus::new(
                Arc::clone(&self.verified_peer_certs),
                Arc::clone(&self.live_sessions),
            ));
        server = server.with_pnet_status_provider(pnet_status);
        // bootstrap-URI join sink — handles `JoinBootstrapUri`
        // requests by decoding the URI and registering the resulting
        // peer for outbound dial. Critical for Flutter onboarding —
        // without it, an app receiving an `veil:` deep-link would
        // have to either re-implement the decode (Argon2id + Ed25519)
        // in Dart or shell out to veil-cli (impossible on Android).
        // Runtime-owned dial drain for app-added bootstrap peers. The IPC sink
        // can't spawn an outbound connector (needs &NodeServices + the shutdown
        // watch::Sender); it hands each registered peer over this channel and
        // this task — which holds both — spawns the reconnect loop. (audit
        // cycle-10: app-added peers were previously never dialed; the old
        // gateway_failover_notify kick woke a loop that only dials gateways.)
        let bootstrap_join: Arc<dyn veil_ipc::BootstrapJoinSink> = {
            // Rep-B-2: bound the app-added-peer dial queue so an IPC client
            // looping BootstrapJoin can't grow it without limit. A full queue
            // drops the dial (peer stays registered; dialed later) rather than
            // accumulating unboundedly.
            const BOOTSTRAP_JOIN_DIAL_QUEUE: usize = 128;
            let (dial_tx, mut dial_rx) = tokio::sync::mpsc::channel::<crate::types::PeerConfigEntry>(
                BOOTSTRAP_JOIN_DIAL_QUEUE,
            );
            if let Some(shutdown_tx) = &self.shutdown_tx {
                let dial_access = self.access();
                let dial_shutdown_tx = shutdown_tx.clone();
                let mut dial_shutdown_rx = shutdown_tx.subscribe();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = dial_shutdown_rx.changed() => break,
                            recv = dial_rx.recv() => match recv {
                                Some(entry) => {
                                    let _ = crate::outbound_connector::spawn_outbound_peers(
                                        vec![entry],
                                        &dial_access,
                                        &dial_shutdown_tx,
                                    );
                                }
                                None => break, // forwarder dropped → no more joins
                            },
                        }
                    }
                });
            }
            Arc::new(crate::bootstrap_join::BootstrapJoinForwarder::new(
                Arc::clone(&self.logger),
                Arc::clone(&self.state),
                Arc::clone(&self.dht),
                dial_tx,
            ))
        };
        server = server.with_bootstrap_join_sink(bootstrap_join);
        // bootstrap-invite-create sink (Epic 489.7 generator side).
        // Snapshot the daemon's `[identity]` keypair + first advertise URI
        // at register time — used by `CreateBootstrapInvite` IPC to
        // assemble a canonical `veil:bootstrap?…` URI (plain) or
        // `veil:pair?…` (when caller supplies a passphrase).
        let invite_create_sink: Arc<dyn veil_ipc::BootstrapInviteCreateSink> = {
            let identity_snap = Some((
                self.identity.local_identity.algo,
                self.identity.local_identity.public_key.clone(),
                self.identity.local_identity.nonce.clone(),
            ));
            let transport_snap = self.listens().into_iter().find_map(|l| {
                // Prefer explicit `advertise` (public hostname behind
                // nginx) over bind transport (e.g. tcp://0.0.0.0:443);
                // matches the CLI `bootstrap invite` address-picking
                // logic and what a live peer can actually dial.
                l.advertise.clone().or(Some(l.transport.clone()))
            });
            Arc::new(crate::bootstrap_invite_create::BootstrapInviteCreator::new(
                Arc::clone(&self.logger),
                identity_snap,
                transport_snap,
            ))
        };
        server = server.with_bootstrap_invite_create_sink(invite_create_sink);
        // multi-device pairing sinks (Epic 489.8).  One forwarder
        // instance handles both Source + Target sides — wire surface
        // shipped; ceremony plumbing fills in a follow-up slice.
        let veil_dir = self
            .config_path
            .parent()
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        let pairing_fwd = Arc::new(crate::pairing_forwarder::PairingForwarder::new(
            Arc::clone(&self.logger),
            veil_dir,
            self.identity.sovereign_identity.clone(),
        ));
        let pair_src: Arc<dyn veil_ipc::PairSourceSink> = pairing_fwd.clone();
        let pair_tgt: Arc<dyn veil_ipc::PairTargetSink> = pairing_fwd;
        server = server
            .with_pair_source_sink(pair_src)
            .with_pair_target_sink(pair_tgt);
        // mobile-status provider — answers `GetMobileStatus`
        // queries with current tier + battery + factors snapshot.
        let mobile_status: Arc<dyn veil_ipc::MobileStatusProvider> = Arc::new(
            crate::mobile_status_provider::RuntimeMobileStatus::new(self.config_path.clone()),
        );
        server = server.with_mobile_status_provider(mobile_status);
        //.2: push-envelope sink — handles `LocalAppMsg::SetPushEnvelope`
        // by routing to `NodeRuntime::set_rendezvous_push_envelope`. Without it
        // IPC handler responds with `NoMatchingRendezvous` for every client request
        // (graceful degradation on nodes without active rendezvous publications).
        let push_envelope_sink: Arc<dyn veil_ipc::PushEnvelopeSink> =
            Arc::new(RendezvousPushEnvelopeForwarder::new(Arc::clone(
                &self.anonymity.rendezvous_publisher_entries,
            )));
        server = server.with_push_envelope_sink(push_envelope_sink);
        // In-network deposit-wake LISTENER: every node may be a mailbox
        // RECEIVER (not just relays), so bind the wake endpoint unconditionally
        // — an inbound wake datagram from a relay becomes a MAILBOX_WAKE event
        // the client SDK turns into an immediate drain. Nodes older than this
        // endpoint simply have nothing bound and drop the wake silently.
        if let Some(host) = self.builtin_app_host.as_mut() {
            let wake_ctx = host.make_context(
                *self.identity.local_identity.node_id.as_bytes(),
                Arc::clone(&self.app_registry),
            );
            crate::builtin::spawn_mailbox_wake_listener(
                host,
                wake_ctx,
                Arc::clone(&self.event_bus),
            );
        }
        //.4 P2/P3: wire mailbox IPC bridge
        // + push-dispatch task. Only present when operator opted in
        // (`mailbox.enabled`). Without it, `MailboxPut/Fetch/Ack`
        // reply with graceful "not a mailbox relay" / empty list / no-op.
        if let Some(mailbox) = self.mailbox_state.mailbox.as_ref() {
            // bounded channel. See
            // `crate::builtin::mailbox::PUSH_TRIGGER_QUEUE_CAP`
            // doc-comment for buffer-size rationale.
            let (push_tx, push_rx) = tokio::sync::mpsc::channel::<PushTrigger>(
                crate::builtin::mailbox::PUSH_TRIGGER_QUEUE_CAP,
            );
            // Clone the sender BEFORE moving into IPC bridge so the
            // built-in app service (spawned below) gets the same
            // channel — both put paths trigger pushes uniformly.
            let push_tx_for_app = push_tx.clone();
            let bridge: Arc<dyn veil_ipc::MailboxBackend> = Arc::new(MailboxIpcBridge::new(
                Arc::clone(mailbox),
                self.dispatcher.mailbox_cookie_registry.clone(),
                push_tx,
                Some(Arc::clone(&self.event_bus)),
            ));
            server = server.with_mailbox_backend(bridge);
            //.4 P6: build push dispatcher from operator
            // config. Falls back to LogOnly when no FCM/APNs creds
            // are configured (default — daemon doesn't contact any
            // third party). See `build_push_dispatcher` for
            // per-provider error handling.
            //
            //.4 followup: wrap in HotReloadDispatcher so
            // operators can rotate FCM/APNs credentials without
            // restarting the daemon. The mtime-watch task spawned
            // below polls credential paths every 60 s and swaps the
            // inner dispatcher in-place when either file changes.
            let initial_dispatcher = build_push_dispatcher(&config.mailbox.push);
            let hot_reload = Arc::new(HotReloadDispatcher::new(initial_dispatcher));
            let dispatcher: Arc<dyn veil_push::PushDispatcher> =
                Arc::clone(&hot_reload) as Arc<dyn veil_push::PushDispatcher>;
            // Spawn the cred-watch task — only when at least one
            // provider is configured (otherwise mtime polling on
            // empty paths is pointless and noisy).
            if config.mailbox.push.fcm_enabled() || config.mailbox.push.apns_enabled() {
                let watch_cfg = config.mailbox.push.clone();
                let watch_shutdown = shutdown_tx.subscribe();
                let watch_handle = tokio::spawn(push_creds_watch_task(
                    watch_cfg,
                    Arc::clone(&hot_reload),
                    watch_shutdown,
                ));
                lock_tasks(&self.tasks).sessions.push(watch_handle);
            }
            // Push task only runs if the relay has an X25519 secret
            // (otherwise unseal is impossible). Already guaranteed
            // by `mailbox.enabled` requiring `anonymity.relay_capable`
            // for sealing semantics — but we check defensively.
            if let Some(sk) = self.dispatcher.anonymity_x25519_sk.as_ref() {
                let sk_clone = Arc::clone(sk);
                let require_wake_hmac = config.mailbox.push.require_wake_hmac;
                if !require_wake_hmac {
                    // Startup advisory (audit cycle-2): with the gate off, the
                    // relay falls back to an UNauthenticated wake-only push for
                    // any receiver that hasn't uploaded a wake-HMAC envelope —
                    // forgeable by anyone who learns the push token. Operators
                    // who control their client fleet should enable the gate.
                    log::warn!(
                        "veil-push: [mailbox.push] require_wake_hmac is OFF — unauthenticated \
                         wake-only pushes are permitted (forgeable battery-drain/nuisance \
                         vector); set require_wake_hmac = true once clients opt into wake-HMAC"
                    );
                }
                let push_handle = tokio::spawn(push_dispatch_task(
                    push_rx,
                    sk_clone,
                    dispatcher,
                    require_wake_hmac,
                ));
                lock_tasks(&self.tasks).sessions.push(push_handle);
            }
            //.4 P5b: spawn the mailbox built-in app
            // service. Receives `MailboxPutPayload` from senders over
            // the veil app-message channel (cross-node fanout path)
            // and calls the same `Mailbox::put` the IPC bridge uses.
            // Both paths share the push_trigger channel — the dispatch
            // task drains regardless of source.
            //
            // Reuses `push_tx` cloned above so app-route puts trigger
            // pushes the same way IPC-route puts do.
            // Anonymous-reply egress for network FETCH (built BEFORE the mutable
            // `builtin_app_host` borrow so `self.access()` is free to borrow).
            // Gated on the relay X25519 secret like push: without it the node
            // can't run the onion send the reply needs. hop_count is nominal —
            // a reply routes over the requester's one-time reply path.
            let mailbox_reply_sender: Option<Arc<dyn veil_types::AnonOnionSender>> =
                self.dispatcher.anonymity_x25519_sk.is_some().then(|| {
                    Arc::new(RuntimeAnonOnionSender::new(self.access(), 2))
                        as Arc<dyn veil_types::AnonOnionSender>
                });
            if let Some(host) = self.builtin_app_host.as_mut() {
                let app_ctx = host.make_context(
                    *self.identity.local_identity.node_id.as_bytes(),
                    Arc::clone(&self.app_registry),
                );
                let push_tx_opt = if self.dispatcher.anonymity_x25519_sk.is_some() {
                    Some(push_tx_for_app)
                } else {
                    // No relay X25519 secret = can't unseal envelopes
                    // anyway. Drop the cloned sender so push triggers
                    // from the app service silently no-op.
                    drop(push_tx_for_app);
                    None
                };
                // In-network deposit WAKE sender: on a stored deposit, send a
                // tiny empty datagram to the receiver's wake endpoint over its
                // LIVE direct session with this relay (SessionTxRegistry is the
                // liveness test — no session, no frame). Debounced per receiver
                // so a backlog flush can't storm a client; a dropped wake only
                // costs latency (the poll schedule still drains). No new
                // linkage: the relay already stores deposits addressed to R's
                // public node_id AND authenticates R's session; the timing
                // profile equals the live-introduce forward it performs anyway.
                let wake_sender: crate::builtin::MailboxWakeSender = {
                    const WAKE_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(2);
                    const MAX_WAKE_DEBOUNCE_ENTRIES: usize = 1024;
                    let tx_registry = Arc::clone(&self.session_tx_registry);
                    let last_wake: std::sync::Mutex<
                        std::collections::HashMap<[u8; 32], std::time::Instant>,
                    > = std::sync::Mutex::new(std::collections::HashMap::new());
                    Arc::new(move |receiver: &[u8; 32]| -> bool {
                        {
                            let mut m = last_wake.lock().unwrap_or_else(|p| p.into_inner());
                            let now = std::time::Instant::now();
                            if m.get(receiver)
                                .is_some_and(|t| now.duration_since(*t) < WAKE_DEBOUNCE)
                            {
                                return false;
                            }
                            if m.len() >= MAX_WAKE_DEBOUNCE_ENTRIES {
                                m.retain(|_, t| now.duration_since(*t) < WAKE_DEBOUNCE);
                            }
                            m.insert(*receiver, now);
                        }
                        let payload = veil_proto::AppSendPayload {
                            src_app_id: veil_mailbox::MAILBOX_APP_ID,
                            app_id: veil_mailbox::MAILBOX_APP_ID,
                            endpoint_id: veil_mailbox::MAILBOX_WAKE_ENDPOINT_ID,
                            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
                        };
                        let body = payload.encode();
                        let mut hdr = veil_proto::header::FrameHeader::new(
                            veil_proto::family::FrameFamily::App as u8,
                            veil_proto::family::AppMsg::AppSend as u16,
                        );
                        hdr.body_len = body.len() as u32;
                        hdr.set_priority(veil_proto::priority::INTERACTIVE);
                        let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
                        frame.extend_from_slice(&body);
                        let guard = wlock!(tx_registry);
                        guard.send_to(receiver, veil_proto::priority::INTERACTIVE, frame)
                    })
                };
                crate::builtin::spawn_mailbox_app_service(
                    host,
                    app_ctx,
                    Arc::clone(mailbox),
                    push_tx_opt,
                    mailbox_reply_sender,
                    Some(wake_sender),
                );
            }
        }
        //.4 P4: wire sender-side outbox
        // bridge. Always wired when outbox opened successfully —
        // every node sends, so peer-sync is universally beneficial.
        if let Some(outbox) = self.mailbox_state.outbox.as_ref() {
            let bridge: Arc<dyn veil_ipc::OutboxBackend> =
                Arc::new(OutboxIpcBridge::new(Arc::clone(outbox)));
            server = server.with_outbox_backend(bridge);
        }
        //.4 P0: publish the relay-side
        // X25519 public key to apps via `NodeIdentityPayload`. Apps
        // need this exact key to seal push-envelopes that this relay
        // can later decrypt. `None` when the operator did not opt
        // into `anonymity.relay_capable` — apps see the field as
        // absent and must pick a different relay for sealing.
        if let Some(relay_pk) = self.anonymity_x25519_pk() {
            server = server.with_relay_x25519_pubkey(relay_pk);
        }
        //.4 P5c: wire the rendezvous-replica resolver
        // so apps can lookup K candidate mailbox-relays for a
        // receiver via IPC. Always wired — even on nodes without
        // `mailbox.enabled`, because senders need lookup to find
        // OTHER nodes' replicas (asymmetric: lookup-side vs
        // serve-side roles).
        let resolver: Arc<dyn veil_ipc::RendezvousReplicaResolver> =
            Arc::new(RendezvousResolverImpl::new(
                Arc::clone(&self.dht),
                Arc::clone(&self.session_tx_registry),
                Arc::clone(&self.dispatcher.pending_recursive),
                *self.identity.local_identity.node_id.as_bytes(),
                Arc::clone(&self.anonymity.rendezvous_resolve_cache),
                Arc::clone(&self.logger),
            ));
        server = server.with_rendezvous_resolver(resolver);
        // log IpcServer::run failure instead of swallowing.
        // Previously `let _ = server.run.await` made bind failures, rename
        // collisions on stale sockets, and any future `Err`-path in the run
        // loop completely invisible — operators would see `ipc.start` in the
        // log followed by silence, with no listener actually attached to the
        // socket file. Surfacing the error cost is one log line, gain is
        // every silent IPC failure becomes diagnosable on the spot.
        let logger = Arc::clone(&self.logger);
        let handle = tokio::spawn(async move {
            if let Err(e) = server.run().await {
                logger.error(
                    "ipc.run.exit_err",
                    format!("IPC server run loop exited with error: {e}"),
                );
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Spawn the background tick task that drives `PendingAckTracker` retransmits.
    ///
    /// Runs at `DELIVERY_ACK_CHECK_INTERVAL_MS` intervals. For each timed-out
    /// entry it either retransmits (via session_tx_registry) or fires a
    /// `AppSendFailed` event to the originating app via the local app registry.
    /// Refresh-ahead for rendezvous route resolution: re-walk the DHT for
    /// recently-messaged receivers BEFORE their resolve-cache entry expires,
    /// so the send path always finds a warm cache. Without this, any send
    /// cadence slower than [`RENDEZVOUS_RESOLVE_CACHE_TTL`] pays the full
    /// recursive walk (up to its multi-second timeout) synchronously inside
    /// the send — the dominant residual send-latency tail once first-hop
    /// liveness is guarded. Scope: only receivers send-resolved within the
    /// activity window (marked via `note_send_use`); a node that stops
    /// messaging adds zero steady-state DHT load after the window drains.
    pub fn spawn_rendezvous_resolve_refresh_task(&mut self) {
        // Re-resolve entries that expire within this margin. Must exceed the
        // tick so an entry can't expire between two ticks unseen; TTL 15s −
        // 6s = re-walk from age ~9s, i.e. roughly one walk per TTL per
        // active receiver.
        const REFRESH_AHEAD: std::time::Duration = std::time::Duration::from_secs(6);
        const TICK: std::time::Duration = std::time::Duration::from_secs(5);
        // A receiver stays in the proactive set this long after the last
        // send-path resolve; afterwards it must be re-marked by a real send.
        // Mirrors the dormant-peer give-up philosophy: a dead conversation
        // must not keep loading the DHT.
        const ACTIVE_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);
        const AD_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(3500);

        let dht = Arc::clone(&self.dht);
        let session_tx_registry = Arc::clone(&self.session_tx_registry);
        let pending_recursive = Arc::clone(&self.dispatcher.pending_recursive);
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        let resolve_cache = Arc::clone(&self.anonymity.rendezvous_resolve_cache);
        let logger = Arc::clone(&self.logger);
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();

        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(TICK);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = shutdown_rx.changed() => { break; }
                }
                let candidates = resolve_cache.refresh_candidates(ACTIVE_WINDOW, REFRESH_AHEAD);
                for receiver_id in candidates {
                    let refreshed = resolve_fresh_rendezvous_ads(
                        &dht,
                        &session_tx_registry,
                        &pending_recursive,
                        local_node_id,
                        &resolve_cache,
                        &logger,
                        receiver_id,
                        AD_RESOLVE_TIMEOUT,
                        true, // force: bypass fast-paths, don't re-mark activity
                    )
                    .await;
                    logger.debug(
                        "anonymity.rendezvous.resolve.refresh_ahead",
                        format!(
                            "receiver={} candidates={}",
                            veil_util::hex_short(&receiver_id),
                            refreshed.len(),
                        ),
                    );
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    pub fn spawn_pending_ack_tick(&mut self) {
        use veil_dispatcher::pending_ack::AckTickOutcome;
        use veil_proto::budget::DELIVERY_ACK_CHECK_INTERVAL_MS;

        let pending_ack = Arc::clone(&self.dispatcher.pending_ack);
        let session_tx_registry = Arc::clone(&self.session_tx_registry);
        let route_cache = Arc::clone(&self.routing.route_cache);
        let app_registry = Arc::clone(&self.app_registry);
        let logger = Arc::clone(&self.logger);
        // shared loss tracker — same instance the delivery handler
        // writes successes into. Tick path counts losses and periodically
        // demote_via on threshold breach.
        let loss_tracker = Arc::clone(&self.dispatcher.loss_tracker);
        // Signal 2 (Epic 482.3/482.4 Phase A): feed exhausted-retransmit
        // delivery failures into the anonymity relay-reputation ledger so a
        // relay that repeatedly drops relayed frames is downweighted in future
        // circuit hop selection. Guarded below to relayed timeouts only.
        let relay_reputation = Arc::clone(&self.anonymity.relay_reputation);
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();

        let handle = tokio::spawn(async move {
            let interval = std::time::Duration::from_millis(DELIVERY_ACK_CHECK_INTERVAL_MS);
            let mut ticker = tokio::time::interval(interval);
            // per-peer "last warned" so we don't spam INFO logs every
            // tick the moment a loss-rate stays above threshold for minutes.
            let mut last_warned: std::collections::HashMap<NodeIdBytes, std::time::Instant> =
                Default::default();
            const WARN_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);
            const LOSS_THRESHOLD: f32 = 0.20;
            const MIN_SAMPLES: u32 = 10;
            const DEMOTE_FACTOR: f64 = 2.0;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = shutdown_rx.changed() => { break; }
                }

                // roll over loss tracker windows + act on breaches.
                // Cheap (HashMap iter); no-op for peers whose window hasn't
                // elapsed yet.
                let evals = loss_tracker.evaluate_window();
                for (peer, rate, samples) in evals {
                    if samples < MIN_SAMPLES {
                        // Insufficient samples — no signal either way.
                        continue;
                    }
                    if rate > LOSS_THRESHOLD {
                        wlock!(route_cache).demote_via(&peer, DEMOTE_FACTOR);
                        let now = std::time::Instant::now();
                        let warn = last_warned
                            .get(&peer)
                            .is_none_or(|&t| now.duration_since(t) >= WARN_COOLDOWN);
                        if warn {
                            last_warned.insert(peer, now);
                            logger.warn(
                                "session.health.degraded",
                                format!(
                                    "peer={} loss_rate={:.0}% samples={} demoted_via_factor={DEMOTE_FACTOR}",
                                    veil_util::hex_short(&peer),
                                    rate * 100.0,
                                    samples,
                                ),
                            );
                        }
                    } else if last_warned.remove(&peer).is_some() {
                        // Was degraded, now back below threshold with enough
                        // samples to trust the recovery — log once and
                        // re-arm the warn cooldown for any future regression.
                        logger.info(
                            "session.health.recovered",
                            format!(
                                "peer={} loss_rate={:.0}% samples={}",
                                veil_util::hex_short(&peer),
                                rate * 100.0,
                                samples,
                            ),
                        );
                    }
                }

                let outcomes = lock!(pending_ack).tick();
                if outcomes.is_empty() {
                    continue;
                }

                // Snapshot route-cache re-route hops for every retransmit BEFORE
                // taking the registry, to preserve the canonical lock order
                // (route_cache → session_tx_registry). The route_cache guard is
                // dropped before `reg` is acquired, so the two never coexist —
                // the previous code held `reg` across the per-outcome route_cache
                // read (the inverted order the workspace was audited to avoid).
                let reroute_hops: std::collections::HashMap<[u8; 32], [u8; 32]> = {
                    let rc = rlock!(route_cache);
                    outcomes
                        .iter()
                        .filter_map(|o| match o {
                            AckTickOutcome::Retransmit { dst_node_id, .. } => {
                                rc.lookup(dst_node_id).map(|hop| (*dst_node_id, hop))
                            }
                            _ => None,
                        })
                        .collect()
                };

                let reg = rlock!(session_tx_registry);
                for outcome in outcomes {
                    match outcome {
                        AckTickOutcome::Retransmit {
                            next_hop,
                            dst_node_id,
                            frame_bytes,
                            content_id,
                            attempt,
                        } => {
                            // this attempt timed out without DELIVERY_ACK —
                            // count it as a loss against the in-flight next_hop so the
                            // periodic eval sees fresh data.
                            loss_tracker.record_loss(next_hop);
                            // log `attempt` so retransmit escalation is visible
                            // in debug traces (previously `attempt` was set but ignored).
                            logger.info(
                                "delivery.retransmit",
                                format!(
                                    "content_id={} dst={} next_hop={} attempt={}",
                                    veil_util::hex_short(&content_id),
                                    veil_util::hex_short(&dst_node_id),
                                    veil_util::hex_short(&next_hop),
                                    attempt,
                                ),
                            );
                            // Try original hop first.
                            let sent = reg.send_to(
                                &next_hop,
                                veil_proto::header::priority::INTERACTIVE,
                                frame_bytes.to_vec(),
                            );
                            if !sent {
                                // Original hop dead — re-route via the
                                // pre-computed route-cache hop (looked up above,
                                // before the registry guard was taken).
                                if let Some(new_hop) = reroute_hops.get(&dst_node_id).copied() {
                                    // Patch next_hop_node_id in the frame (bytes 24..56
                                    // right after the 24-byte header).
                                    let mut patched = frame_bytes.to_vec();
                                    let hs = veil_proto::header::HEADER_SIZE;
                                    if patched.len() >= hs + 32 {
                                        patched[hs..hs + 32].copy_from_slice(&new_hop);
                                        if reg.send_to(
                                            &new_hop,
                                            veil_proto::header::priority::INTERACTIVE,
                                            patched,
                                        ) {
                                            // Update stored next_hop for future retransmits.
                                            lock!(pending_ack)
                                                .update_next_hop(&content_id, new_hop);
                                        }
                                    }
                                }
                            }
                        }
                        AckTickOutcome::Failed {
                            content_id,
                            src_app_id,
                            next_hop,
                            dst_node_id,
                        } => {
                            // final attempt also failed — record the
                            // loss before notifying the app.
                            loss_tracker.record_loss(next_hop);
                            // Signal 2 (Phase A): blame the RELAY only for a
                            // relayed timeout. When next_hop == dst_node_id the
                            // frame went direct to the recipient, so the timeout
                            // means the DESTINATION is offline — not a relay
                            // misbehaving — and attributing it would unfairly
                            // bury a node (the ledger has no decay). The record
                            // is per-sender-local and only ever consulted by the
                            // anonymity circuit picker, so a non-relay next_hop
                            // that slips through is harmless (never a candidate).
                            if next_hop != dst_node_id {
                                relay_reputation.record_failure(next_hop);
                            }
                            // Notify the originating IPC application that all
                            // retransmit attempts for this message have been
                            // exhausted. The app receives AppSendFailed on its
                            // IPC stream and can surface a delivery-failure event.
                            app_registry.route_delivery_failed(src_app_id, content_id);
                        }
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}

// ── T1.2: push-envelope IPC forwarder ────────────────────────────
//
// Hooks `LocalAppMsg::SetPushEnvelope` IPC requests to
// `NodeRuntime::set_rendezvous_push_envelope` without round-trip through NodeRuntime
// itself — holds an Arc clone of `rendezvous_publisher_entries` Mutex and
// performs the in-place update on lookup. Mirrors the pattern of
// `MobileEventForwarder` (which holds runtime sync-Notify clones).

pub struct RendezvousPushEnvelopeForwarder {
    entries: Arc<std::sync::Mutex<Vec<veil_anonymity::rendezvous::RendezvousPublisherEntry>>>,
}

impl RendezvousPushEnvelopeForwarder {
    fn new(
        entries: Arc<std::sync::Mutex<Vec<veil_anonymity::rendezvous::RendezvousPublisherEntry>>>,
    ) -> Self {
        Self { entries }
    }
}

impl veil_ipc::PushEnvelopeSink for RendezvousPushEnvelopeForwarder {
    fn set_rendezvous_push_envelope(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        envelope: Vec<u8>,
    ) -> bool {
        let mut entries = lock!(self.entries);
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.rendezvous_node_id == rendezvous_node_id && e.auth_cookie == auth_cookie)
        {
            entry.push_envelope = envelope;
            true
        } else {
            false
        }
    }

    fn set_rendezvous_wake_hmac_envelope(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        envelope: Vec<u8>,
    ) -> bool {
        let mut entries = lock!(self.entries);
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.rendezvous_node_id == rendezvous_node_id && e.auth_cookie == auth_cookie)
        {
            entry.wake_hmac_envelope = envelope;
            true
        } else {
            false
        }
    }
}

// ── T1.4 P2/P3: mailbox IPC bridge ──────────────────────────────
//
// Routes `LocalAppMsg::MailboxPut/Fetch/Ack` to a wrapped
// `veil_mailbox::Mailbox`.
//
// Cookie auth (Fetch/Ack): verified against the dispatcher's
// `RendezvousRegistry` — the same `cookie -> peer_node_id` mapping
// populated when a receiver `register_with_rendezvous`-ed with this
// relay. Mismatch returns empty list / removed=0 so the cookie is
// not a probing oracle. T1.4 P3 fixes a P2 bug that
// matched against `rendezvous_publisher_entries` (receiver-side, not
// relay-side) — those entries are owned by the receiver and are
// never present on the relay's runtime.
//
// Push trigger (Put): when `push_envelope` is provided and storage
// returned `Stored`, the bridge sends `(receiver_id, envelope)` to a
// background tokio task via an unbounded mpsc. The task unseals the
// envelope with the relay's X25519 sk and dispatches a wake-push via
// the configured `PushDispatcher`. Fire-and-forget — the IPC reply
// reports only the storage outcome, not the push success.

// Trigger sent over the mpsc to the push-dispatch task. Imported
// from `crate::builtin::mailbox` so the IPC bridge and the
// built-in app service feed the same channel.
use crate::builtin::PushTrigger;

pub struct MailboxIpcBridge {
    mailbox: Arc<veil_mailbox::Mailbox>,
    /// PRIVATE mailbox fetch-cookie registry (NOT the published rendezvous
    /// cookie) — authorizes fetch/ack. `None` when the node is not a mailbox
    /// relay, in which case fetch/ack are unauthorised.
    mailbox_cookie_registry: Option<
        Arc<std::sync::RwLock<veil_anonymity::mailbox_cookie_registry::MailboxCookieRegistry>>,
    >,
    push_trigger_tx: tokio::sync::mpsc::Sender<PushTrigger>,
    /// Event bus used to publish `MAILBOX_DRAINED` notifications after
    /// every authorised fetch.  Optional so non-IPC test contexts can
    /// construct the bridge without a live bus; production wiring always
    /// supplies one (see `service_tasks` ctor at the call site).
    event_bus: Option<Arc<veil_ipc::EventBus>>,
}

impl MailboxIpcBridge {
    fn new(
        mailbox: Arc<veil_mailbox::Mailbox>,
        mailbox_cookie_registry: Option<
            Arc<std::sync::RwLock<veil_anonymity::mailbox_cookie_registry::MailboxCookieRegistry>>,
        >,
        push_trigger_tx: tokio::sync::mpsc::Sender<PushTrigger>,
        event_bus: Option<Arc<veil_ipc::EventBus>>,
    ) -> Self {
        Self {
            mailbox,
            mailbox_cookie_registry,
            push_trigger_tx,
            event_bus,
        }
    }

    /// Verify `auth_cookie` against this receiver's PRIVATE mailbox fetch
    /// cookies (registered via `RelayChainMsg::RegisterMailboxCookie`, never the
    /// published rendezvous cookie). Constant-time over the receiver's ≤2 valid
    /// cookies. Without a registry (node not a mailbox relay) returns false.
    fn cookie_authorised(&self, receiver_id: [u8; 32], auth_cookie: [u8; 16]) -> bool {
        let Some(reg) = &self.mailbox_cookie_registry else {
            return false;
        };
        reg.read()
            .map(|r| r.is_authorised(&receiver_id, &auth_cookie))
            .unwrap_or(false)
    }
}

impl veil_ipc::MailboxBackend for MailboxIpcBridge {
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
    ) -> Option<veil_ipc::MailboxPutOutcome> {
        // audit U14: route through `put_with_capability` (not the trusted
        // legacy `put`) so the relay's `require_capability_token` policy is
        // enforced for IPC deposits too, and a token-bearing local client can
        // satisfy it. This also makes the CapabilityRequired/CapabilityInvalid
        // outcome arms below reachable (they were dead on the legacy path).
        let outcome = match self.mailbox.put_with_capability(
            receiver_id,
            content_id,
            sender_id,
            blob,
            capability_token.as_deref(),
        ) {
            Ok(o) => o,
            Err(e) => {
                log::warn!("veil-mailbox: put failed: {e}");
                return None;
            }
        };
        let mapped = match outcome {
            veil_mailbox::PutOutcome::Stored { evicted } => {
                // Fire-and-forget push trigger when sender supplied an
                // envelope. Dropped silently if the channel's task
                // already exited (shouldn't happen during normal
                // operation; debug-asserted in tests).
                if let Some(env) = push_envelope.filter(|e| !e.is_empty()) {
                    // audit: bounded `try_send` — drop on
                    // overflow rather than block the IPC handler.
                    if self
                        .push_trigger_tx
                        .try_send(PushTrigger {
                            receiver_id,
                            envelope: env,
                            content_id,
                            // Epic 489.10 slice 4.4: forward the sealed wake-HMAC
                            // envelope so the push-dispatch task can mint an
                            // authenticated wake payload bound to this content_id.
                            wake_hmac_envelope,
                        })
                        .is_err()
                    {
                        log::warn!(
                            "veil-mailbox: push-trigger queue full — dropping \
                             trigger for receiver (push is wake-hint only)"
                        );
                    }
                }
                veil_ipc::MailboxPutOutcome::Stored { evicted }
            }
            veil_mailbox::PutOutcome::Duplicate => veil_ipc::MailboxPutOutcome::Duplicate,
            veil_mailbox::PutOutcome::QuotaPerReceiverExceeded { .. } => {
                veil_ipc::MailboxPutOutcome::QuotaPerReceiverExceeded
            }
            veil_mailbox::PutOutcome::QuotaGlobalExceeded { .. } => {
                veil_ipc::MailboxPutOutcome::QuotaGlobalExceeded
            }
            veil_mailbox::PutOutcome::RateLimited => veil_ipc::MailboxPutOutcome::RateLimited,
            veil_mailbox::PutOutcome::CapabilityRequired => {
                veil_ipc::MailboxPutOutcome::CapabilityRequired
            }
            veil_mailbox::PutOutcome::CapabilityInvalid => {
                veil_ipc::MailboxPutOutcome::CapabilityInvalid
            }
            veil_mailbox::PutOutcome::QuotaPerSenderExceeded { .. } => {
                veil_ipc::MailboxPutOutcome::QuotaPerSenderExceeded
            }
        };
        Some(mapped)
    }

    fn fetch(
        &self,
        receiver_id: [u8; 32],
        auth_cookie: [u8; 16],
    ) -> Option<Vec<veil_ipc::MailboxBlobOut>> {
        if !self.cookie_authorised(receiver_id, auth_cookie) {
            // Return Some(empty) — caller cannot distinguish "wrong
            // cookie" from "no blobs", so the cookie isn't a probing
            // oracle.  Wrong-cookie path bypasses MAILBOX_DRAINED publish
            // so a bad-cookie probe cannot serve as a fan-out oracle to
            // event subscribers (would also be a wakeup-loop trigger if
            // the iOS BG handler awaits the event before completing).
            return Some(Vec::new());
        }
        match self.mailbox.fetch(receiver_id) {
            Ok(blobs) => {
                let out: Vec<veil_ipc::MailboxBlobOut> = blobs
                    .into_iter()
                    .map(|b| veil_ipc::MailboxBlobOut {
                        sender_id: b.sender_id,
                        content_id: b.content_id,
                        deposited_at: b.deposited_at,
                        blob: b.blob,
                    })
                    .collect();
                // Publish MAILBOX_DRAINED so BG-handler consumers
                // (iOS BGProcessingTask / Android background workers)
                // can `setTaskCompleted` precisely at drain completion
                // instead of padding to a hardcoded timeout.  Best-effort
                // — zero subscribers is the steady state and not an error.
                if let Some(bus) = &self.event_bus {
                    let count = u32::try_from(out.len()).unwrap_or(u32::MAX);
                    bus.publish(EventPayload {
                        kind: event_kind::MAILBOX_DRAINED,
                        payload: count.to_be_bytes().to_vec(),
                    });
                }
                Some(out)
            }
            Err(e) => {
                log::warn!("veil-mailbox: fetch failed: {e}");
                None
            }
        }
    }

    fn ack(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        auth_cookie: [u8; 16],
    ) -> Option<bool> {
        if !self.cookie_authorised(receiver_id, auth_cookie) {
            return Some(false);
        }
        match self.mailbox.ack(receiver_id, content_id) {
            Ok(b) => Some(b),
            Err(e) => {
                log::warn!("veil-mailbox: ack failed: {e}");
                None
            }
        }
    }
}

// ── T1.4 P4: outbox IPC bridge ──────────────────────────────────
//
// Routes `LocalAppMsg::OutboxPut/FindMissing/Ack` to a wrapped
// `veil_mailbox::Outbox`. No auth — outbox is sender-local; the
// only IPC client is the sender's own app.

pub struct OutboxIpcBridge {
    outbox: Arc<veil_mailbox::Outbox>,
}

impl OutboxIpcBridge {
    fn new(outbox: Arc<veil_mailbox::Outbox>) -> Self {
        Self { outbox }
    }
}

impl veil_ipc::OutboxBackend for OutboxIpcBridge {
    fn put(&self, receiver_id: [u8; 32], content_id: [u8; 32], blob: Vec<u8>) -> bool {
        match self.outbox.put(receiver_id, content_id, blob) {
            Ok(()) => true,
            Err(e) => {
                log::warn!("veil-mailbox: outbox put failed: {e}");
                false
            }
        }
    }

    fn find_missing(
        &self,
        receiver_id: [u8; 32],
        since: u64,
        bloom_bytes: Vec<u8>,
    ) -> Option<Vec<veil_ipc::OutboxEntryOut>> {
        let bloom = match veil_bloom::BloomFilter::decode(&bloom_bytes) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("veil-mailbox: peer's bloom filter rejected: {e}");
                return Some(Vec::new());
            }
        };
        match self.outbox.find_missing(receiver_id, since, &bloom) {
            Ok(entries) => Some(
                entries
                    .into_iter()
                    .map(|e| veil_ipc::OutboxEntryOut {
                        content_id: e.content_id,
                        deposited_at: e.deposited_at,
                        blob: e.blob,
                    })
                    .collect(),
            ),
            Err(e) => {
                log::warn!("veil-mailbox: outbox find_missing failed: {e}");
                None
            }
        }
    }

    fn ack(&self, receiver_id: [u8; 32], content_id: [u8; 32]) -> bool {
        match self.outbox.ack(receiver_id, content_id) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("veil-mailbox: outbox ack failed: {e}");
                false
            }
        }
    }
}

// ── T1.4 P6: build push dispatcher from operator config ────────
//
// Returns a `LogOnlyDispatcher` if neither FCM nor APNs creds are
// configured (default — operator did not opt into real push), or a
// `ProviderRouter` wrapping the configured providers otherwise.
//
// Per-provider failures (file not found, malformed key) downgrade
// that provider to "absent" but don't fail the daemon — operator
// sees a WARN log and the other provider (if configured) keeps
// working. Worst case: both providers fail to load, daemon falls
// back to LogOnly.

pub fn build_push_dispatcher(
    cfg: &veil_cfg::MailboxPushConfig,
) -> Arc<dyn veil_push::PushDispatcher> {
    // Loud startup signal for a partial APNs credential set. `apns_enabled()`
    // is all-or-nothing, so a half-filled APNs block (e.g. only `apns_p8_path`)
    // silently disables real push and falls back to LogOnly — wake delivery is
    // lost with no error. `veil-cli config validate` rejects this
    // (mailbox_push_apns_partial_config), but the daemon doesn't run full
    // validation at startup, so warn here too.
    {
        let apns_fields_set = [
            !cfg.apns_p8_path.is_empty(),
            !cfg.apns_key_id.is_empty(),
            !cfg.apns_team_id.is_empty(),
            !cfg.apns_bundle_id.is_empty(),
        ]
        .iter()
        .filter(|x| **x)
        .count();
        if apns_fields_set != 0 && apns_fields_set != 4 {
            log::warn!(
                "veil-push: APNs config is PARTIAL ({apns_fields_set}/4 of \
                 apns_p8_path/apns_key_id/apns_team_id/apns_bundle_id set) — \
                 APNs push is DISABLED and the daemon is falling back to \
                 log-only for APNs tokens. Set all four fields, or clear them \
                 all to silence this. Run `veil-cli config validate`.",
            );
        }
    }
    let fcm_dispatcher = build_fcm_dispatcher(cfg);
    let apns_dispatcher = build_apns_dispatcher(cfg);

    if fcm_dispatcher.is_none() && apns_dispatcher.is_none() {
        log::info!("veil-push: no provider credentials configured — falling back to LogOnly",);
        return Arc::new(veil_push::LogOnlyDispatcher);
    }
    log::info!(
        "veil-push: provider router (fcm={}, apns={})",
        fcm_dispatcher.is_some(),
        apns_dispatcher.is_some(),
    );
    Arc::new(veil_push::ProviderRouter::new(
        fcm_dispatcher,
        apns_dispatcher,
    ))
}

pub fn build_fcm_dispatcher(
    cfg: &veil_cfg::MailboxPushConfig,
) -> Option<Arc<dyn veil_push::PushDispatcher>> {
    if !cfg.fcm_enabled() {
        return None;
    }
    match veil_push::FcmDispatcher::from_service_account_path(&cfg.fcm_credentials_path) {
        Ok(d) => {
            log::info!(
                "veil-push: FCM dispatcher loaded from {}",
                cfg.fcm_credentials_path,
            );
            Some(d as Arc<dyn veil_push::PushDispatcher>)
        }
        Err(e) => {
            log::warn!(
                "veil-push: FCM credentials at {} failed to load: {e} — provider disabled",
                cfg.fcm_credentials_path,
            );
            None
        }
    }
}

pub fn build_apns_dispatcher(
    cfg: &veil_cfg::MailboxPushConfig,
) -> Option<Arc<dyn veil_push::PushDispatcher>> {
    if !cfg.apns_enabled() {
        return None;
    }
    let env = match cfg.apns_environment.as_str() {
        "" | "production" | "prod" => veil_push::ApnsEnvironment::Production,
        "sandbox" | "dev" | "development" => veil_push::ApnsEnvironment::Sandbox,
        other => {
            log::warn!("veil-push: unknown apns_environment {other:?}, defaulting to production",);
            veil_push::ApnsEnvironment::Production
        }
    };
    match veil_push::ApnsDispatcher::from_p8_path(
        &cfg.apns_p8_path,
        cfg.apns_key_id.clone(),
        cfg.apns_team_id.clone(),
        cfg.apns_bundle_id.clone(),
        env,
    ) {
        Ok(d) => {
            log::info!(
                "veil-push: APNs dispatcher loaded (key_id={}, team_id={}, env={:?})",
                cfg.apns_key_id,
                cfg.apns_team_id,
                env,
            );
            Some(d as Arc<dyn veil_push::PushDispatcher>)
        }
        Err(e) => {
            log::warn!(
                "veil-push: APNs key at {} failed to load: {e} — provider disabled",
                cfg.apns_p8_path,
            );
            None
        }
    }
}

// ── T1.4 followup: hot-reload of FCM/APNs credentials ──────────
//
// Wraps the configured `PushDispatcher` in a tokio RwLock so the
// inner dispatcher can be atomically swapped in/out at runtime when
// the operator rotates credentials. An mtime-watch task polls the
// credential file paths every 60 s; on detected change it rebuilds
// the dispatcher and swaps it in.
//
// This is a deliberate poll-not-notify design: filesystem-watch APIs
// (inotify on Linux, kqueue on BSD) introduce platform-specific
// dependencies and edge cases (file replaced via atomic-rename loses
// the watch). Polling mtime every 60 s is plenty fast for a
// credential rotation operation that operators trigger maybe once a
// quarter, and survives any rename / atomic-replace tactic.

pub struct HotReloadDispatcher {
    inner: tokio::sync::RwLock<Arc<dyn veil_push::PushDispatcher>>,
}

impl HotReloadDispatcher {
    fn new(initial: Arc<dyn veil_push::PushDispatcher>) -> Self {
        Self {
            inner: tokio::sync::RwLock::new(initial),
        }
    }

    async fn swap(&self, new: Arc<dyn veil_push::PushDispatcher>) {
        let mut g = self.inner.write().await;
        *g = new;
    }
}

#[async_trait::async_trait]
impl veil_push::PushDispatcher for HotReloadDispatcher {
    async fn dispatch(
        &self,
        token: &veil_push::PushToken,
        wake_payload: &[u8],
    ) -> Result<(), veil_push::PushError> {
        // Read-lock + clone the Arc — RwLock not held across the
        // potentially-long HTTP call. Push triggers are rare events
        // (per-blob, not per-frame) so the lock contention here is
        // negligible.
        let dispatcher = {
            let g = self.inner.read().await;
            Arc::clone(&*g)
        };
        dispatcher.dispatch(token, wake_payload).await
    }
}

/// Modification time of `path` in seconds since UNIX_EPOCH, or 0 if
/// the file is missing / metadata read failed. Treats missing-file vs
/// present-file as different mtimes so a credential file appearing
/// or disappearing triggers a swap.
pub fn file_mtime_secs(path: &str) -> u64 {
    if path.is_empty() {
        return 0;
    }
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Background task that polls the FCM/APNs credential file mtimes
/// every 60 s and rebuilds the dispatcher when either changes.
/// Returns when `shutdown` fires.
async fn push_creds_watch_task(
    cfg: veil_cfg::MailboxPushConfig,
    hot_reload: Arc<HotReloadDispatcher>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut last_fcm = file_mtime_secs(&cfg.fcm_credentials_path);
    let mut last_apns = file_mtime_secs(&cfg.apns_p8_path);
    let interval = std::time::Duration::from_secs(60);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let cur_fcm = file_mtime_secs(&cfg.fcm_credentials_path);
                let cur_apns = file_mtime_secs(&cfg.apns_p8_path);
                if cur_fcm != last_fcm || cur_apns != last_apns {
                    log::info!(
                        "veil-push: credential mtime changed (fcm: {last_fcm} → {cur_fcm}, \
                         apns: {last_apns} → {cur_apns}) — rebuilding dispatcher",
                    );
                    let new_dispatcher = build_push_dispatcher(&cfg);
                    hot_reload.swap(new_dispatcher).await;
                    last_fcm = cur_fcm;
                    last_apns = cur_apns;
                }
            }
            _ = shutdown.changed() => {
                log::info!("veil-push: cred-watch task stopping");
                break;
            }
        }
    }
}

// ── T1.4 P5c: rendezvous-replica resolver ──────────────────────
//
// Replica-aware lookup for the receiver's RendezvousAd. Apps call
// `LocalAppMsg::LookupRendezvousReplicas` → IPC server → this impl, which
// periodically compares independently-served DHT values instead of accepting
// one still-valid local mirror forever. This matters because receiver relay
// rotation invalidates reachability before the old signed ad itself expires.

pub struct RendezvousResolverImpl {
    dht: Arc<veil_dht::KademliaService>,
    // Shared refs for the recursive DHT walk (so resolve_replicas can find a
    // receiver's rendezvous ad CROSS-NODE, not just in the local mirror cache).
    session_tx_registry: Arc<std::sync::RwLock<veil_session::SessionTxRegistry>>,
    pending_recursive: Arc<
        std::sync::Mutex<std::collections::HashMap<[u8; 16], veil_dispatcher::PendingRecursive>>,
    >,
    local_node_id: [u8; 32],
    resolve_cache: Arc<super::anonymity_state::RendezvousResolveCache>,
    logger: Arc<veil_observability::NodeLogger>,
}

impl RendezvousResolverImpl {
    fn new(
        dht: Arc<veil_dht::KademliaService>,
        session_tx_registry: Arc<std::sync::RwLock<veil_session::SessionTxRegistry>>,
        pending_recursive: Arc<
            std::sync::Mutex<
                std::collections::HashMap<[u8; 16], veil_dispatcher::PendingRecursive>,
            >,
        >,
        local_node_id: [u8; 32],
        resolve_cache: Arc<super::anonymity_state::RendezvousResolveCache>,
        logger: Arc<veil_observability::NodeLogger>,
    ) -> Self {
        Self {
            dht,
            session_tx_registry,
            pending_recursive,
            local_node_id,
            resolve_cache,
            logger,
        }
    }
}

/// Resolve every requested rendezvous-ad slot from independent connected DHT
/// peers, compare all still-valid signed candidates by publication time, and
/// write the winner for each slot back into the local mirror.  A plain
/// `recursive_dht_get` cannot do this: its valid-local fast path returns an old
/// ad immediately, even after the receiver moved to another relay, so the
/// sender keeps producing `cookie_unknown` until the ad expires.
#[allow(clippy::too_many_arguments)]
pub(super) async fn resolve_fresh_rendezvous_ads(
    dht: &Arc<veil_dht::KademliaService>,
    session_tx_registry: &Arc<std::sync::RwLock<veil_session::SessionTxRegistry>>,
    pending_recursive: &Arc<
        std::sync::Mutex<std::collections::HashMap<[u8; 16], veil_dispatcher::PendingRecursive>>,
    >,
    local_node_id: [u8; 32],
    resolve_cache: &Arc<super::anonymity_state::RendezvousResolveCache>,
    logger: &Arc<veil_observability::NodeLogger>,
    receiver_id: [u8; 32],
    timeout: std::time::Duration,
    // `true` for the background refresh-ahead task: bypass the cache
    // fast-paths (the entry is still TTL-fresh — that's WHY it can be
    // re-walked before a send hits an expired one) and don't mark the
    // receiver as send-active (the refresher must not keep itself alive).
    force_refresh: bool,
) -> Vec<veil_anonymity::rendezvous::RendezvousAd> {
    use veil_anonymity::rendezvous::{
        MAX_RENDEZVOUS_AD_SLOTS, decode_rendezvous_ad, is_currently_valid,
        rendezvous_ad_dht_key_at, verify_rendezvous_ad,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if !force_refresh {
        // Feed the refresh-ahead task: this receiver is being actively sent
        // to, keep its route warm for the activity window.
        resolve_cache.note_send_use(receiver_id);
        if let Some(ads) = resolve_cache.get(&receiver_id, now) {
            return ads;
        }
    }
    let _refresh_guard = resolve_cache.lock_refresh(receiver_id).await;
    // Another send may have completed the refresh while this one waited for
    // the per-recipient single-flight lock.
    if !force_refresh
        && let Some(ads) = resolve_cache.get(&receiver_id, now)
    {
        return ads;
    }

    // Always fill the cache from every system slot. The IPC caller may request
    // only one returned replica, but caching that partial lookup would hide a
    // fresher ad in another slot from the live send path for the cache TTL.
    let walks = (0..MAX_RENDEZVOUS_AD_SLOTS).map(|idx| {
        let key = rendezvous_ad_dht_key_at(&receiver_id, idx);
        async move {
            let candidates = crate::mlkem_resolver::recursive_dht_get_candidates(
                dht,
                session_tx_registry,
                pending_recursive,
                local_node_id,
                key,
                timeout,
                // Query every normal replication holder we can reach directly.
                // On the three-seed production topology this deliberately asks
                // all three instead of accepting whichever seed replies first.
                veil_proto::budget::DHT_REPLICATION_K,
                |bytes| {
                    decode_rendezvous_ad(bytes)
                        .ok()
                        .filter(|ad| ad.receiver_node_id == receiver_id)
                        .filter(|ad| verify_rendezvous_ad(ad).is_ok())
                        .filter(|ad| is_currently_valid(ad, now).is_ok())
                        .is_some()
                },
            )
            .await;
            (idx, key, candidates)
        }
    });

    let mut ads = Vec::new();
    for (_idx, key, candidates) in futures::future::join_all(walks).await {
        let mut decoded: Vec<_> = candidates
            .into_iter()
            .filter_map(|bytes| decode_rendezvous_ad(&bytes).ok().map(|ad| (ad, bytes)))
            .collect();
        // Repair the ordinary local DHT mirror with this slot's newest
        // publication. The short resolve cache still controls when the next
        // network comparison happens; the local write merely keeps other DHT
        // consumers from seeing a known-older value meanwhile.
        decoded.sort_by_key(|(ad, _)| std::cmp::Reverse(ad.valid_from_unix));
        if let Some((_, bytes)) = decoded.first() {
            dht.store_local(key, bytes.clone());
        }
        ads.extend(decoded.into_iter().map(|(ad, _)| ad));
    }

    // Dedupe identical signed ads returned by several replica holders, while
    // preserving distinct relay/slot publications for the caller's policy.
    ads.sort_by(|a, b| {
        b.valid_from_unix
            .cmp(&a.valid_from_unix)
            .then_with(|| a.rendezvous_node_id.cmp(&b.rendezvous_node_id))
            .then_with(|| a.auth_cookie.cmp(&b.auth_cookie))
    });
    ads.dedup_by(|a, b| {
        a.valid_from_unix == b.valid_from_unix
            && a.rendezvous_node_id == b.rendezvous_node_id
            && a.auth_cookie == b.auth_cookie
    });

    if !ads.is_empty() {
        logger.info(
            "anonymity.rendezvous.resolve.refreshed",
            format!(
                "receiver={} candidates={} freshest_relay={} valid_from={}",
                veil_util::hex_short(&receiver_id),
                ads.len(),
                veil_util::hex_short(&ads[0].rendezvous_node_id),
                ads[0].valid_from_unix,
            ),
        );
        resolve_cache.put(receiver_id, ads.clone());
    }
    ads
}

/// Adapts the runtime's `NodeServices` to the IPC-layer [`veil_types::
/// AnonOnionSender`] trait, so the `anonymous_authenticated` send flag can
/// originate an authenticated anonymous onion send without veil-ipc depending
/// on veil-node-runtime. Holds the access bundle + the configured hop count.
struct RuntimeAnonOnionSender {
    access: super::NodeServices,
    hop_count: usize,
}

impl RuntimeAnonOnionSender {
    fn new(access: super::NodeServices, hop_count: usize) -> Self {
        Self { access, hop_count }
    }
}

fn replicas_from_freshest_ads(
    mut ads: Vec<veil_anonymity::rendezvous::RendezvousAd>,
    cap: usize,
) -> Vec<veil_ipc::ResolvedReplica> {
    // GENERATION gate (mirrors the live-introduce spread): the receiver
    // re-signs all its plain ads together with one shared valid_from stamp
    // (see tick_publish_rendezvous_ads), so the newest stamp identifies its
    // CURRENT relay set. Depositing at a relay from an older generation puts
    // the blob where the receiver may no longer be registered or drain —
    // wasted (or lost, if every copy lands stale). Small skew tolerance for
    // ads fetched from lagging replicas mid-republish.
    const DEPOSIT_GENERATION_SKEW_SECS: u64 = 30;
    if let Some(newest) = ads.iter().map(|a| a.valid_from_unix).max() {
        let gated: Vec<_> = ads
            .iter()
            .filter(|a| {
                a.valid_from_unix.saturating_add(DEPOSIT_GENERATION_SKEW_SECS) >= newest
            })
            .cloned()
            .collect();
        // Never gate down to nothing usable: an all-stale view (resolver hit
        // only lagging replicas) still deposits somewhere rather than failing.
        if !gated.is_empty() {
            ads = gated;
        }
    }
    ads.sort_by(|a, b| {
        // Prefer an ad that carries a usable KEM key. A KEM-less ad (empty
        // `rendezvous_kem_pk`) can never be sealed to for offline delivery, so it
        // must lose to ANY KEM-bearing ad regardless of recency — otherwise a
        // stale, long-lived KEM-less ad (e.g. a pre-KEM-preserve publisher's 24h
        // ad) outranks the publisher's fresh but shorter-lived KEM ad purely by
        // `valid_until`, the sender resolves the KEM-less one, and offline
        // delivery to that receiver silently fails (usable(KEM)=0 at the sender).
        // Only when NO KEM-bearing ad exists do we fall back to a KEM-less one.
        let a_kemless = a.rendezvous_kem_pk.is_empty();
        let b_kemless = b.rendezvous_kem_pk.is_empty();
        a_kemless
            .cmp(&b_kemless) // false (KEM-bearing) sorts before true (KEM-less)
            // Then prefer the most-recently-PUBLISHED ad, by `valid_from_unix`
            // (set to now_unix at publish — see maintenance.rs) — NOT
            // `valid_until_unix`. The ad's `auth_cookie` is PER-PERIOD
            // (derive_onion_auth_cookie(seed, now/86400)), so an ad published in a
            // previous period carries an OLD cookie that no longer matches what the
            // receiver currently registers at its relay. Ranking by `valid_until`
            // preferred a yesterday-published 24h ad (old cookie, long window) over
            // today's 1h ad (fresh cookie, short window): the sender copied the old
            // cookie into its introduce and the relay dropped EVERY introduce with
            // `cookie_unknown` (observed ~95-98% loss on the onion content path).
            // `valid_from` makes the current-period ad win, so its cookie matches
            // the receiver's live registration.
            .then_with(|| b.valid_from_unix.cmp(&a.valid_from_unix))
            .then_with(|| a.rendezvous_node_id.cmp(&b.rendezvous_node_id))
    });

    let mut out = Vec::with_capacity(cap);
    let mut seen_relays: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for ad in ads {
        if !seen_relays.insert(ad.rendezvous_node_id) {
            continue;
        }
        out.push(veil_ipc::ResolvedReplica {
            relay_node_id: ad.rendezvous_node_id,
            valid_until_unix: ad.valid_until_unix,
            push_envelope: ad.push_envelope,
            capability_token: ad.capability_token,
            wake_hmac_envelope: ad.wake_hmac_envelope,
            rendezvous_kem_algo: ad.rendezvous_kem_algo,
            rendezvous_kem_pk: ad.rendezvous_kem_pk,
        });
        if out.len() >= cap {
            break;
        }
    }
    out
}

impl veil_types::AnonOnionSender for RuntimeAnonOnionSender {
    fn send_authenticated<'a>(
        &'a self,
        receiver_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_anonymous_authenticated_to(
                    receiver_node_id,
                    app_id,
                    endpoint_id,
                    data,
                    self.hop_count,
                    None,
                )
                .await
        })
    }

    fn send_authenticated_with_reply<'a>(
        &'a self,
        receiver_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
        reply_app_id: [u8; 32],
        reply_endpoint_id: u32,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_anonymous_authenticated_to(
                    receiver_node_id,
                    app_id,
                    endpoint_id,
                    data,
                    self.hop_count,
                    Some((reply_app_id, reply_endpoint_id)),
                )
                .await
        })
    }

    fn send_authenticated_direct_with_reply<'a>(
        &'a self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
        reply_app_id: [u8; 32],
        reply_endpoint_id: u32,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            // The FETCH's reply path builds an onion circuit, which needs the
            // connected relays' relay-directory entries (R terminus + middles)
            // fresh in the LOCAL store. Those cached entries expire between the
            // relays' republish rounds, so a whole drain pass used to fail
            // bursty NoRelays ("status 2") until a republish drifted in.
            // Actively re-warm first — the exact pre-warm the ad-resolving
            // send path already runs; no-op (zero RPC) when everything is
            // cached and fresh.
            let outbox: Arc<dyn veil_dht::FrameRouter> =
                Arc::clone(&self.access.session_outbox) as Arc<dyn veil_dht::FrameRouter>;
            warm_connected_relay_directory(
                &self.access.live_sessions,
                &self.access.dht,
                &outbox,
                &self.access.logger,
                Some(&self.access.dispatcher.crypto.peer_cap_flags),
            )
            .await;
            // Reverse-leg RD-staleness fix: the reply block's circuit
            // (`select_onion_relay_path`) needs R + `REPLY_CIRCUIT_HOPS-1` middles
            // with fresh RDs. The connected warm above caches only session-backed
            // relays' RDs — one on mobile — so the reply path fails
            // `middles_insufficient` / `have: 0` and the drain's ACK never returns.
            // Additionally pull the KNOWN relay set's RDs over whatever session
            // exists (bounded + freshness-gated → no-op when already warm).
            {
                let mut relays: Vec<[u8; 32]> = self
                    .access
                    .dht
                    .routing_table_contacts()
                    .into_iter()
                    .map(|c| c.node_id)
                    .collect();
                // Union in the ACTIVE live-session relays. The reply circuit's
                // middle selection (`select_onion_relay_path_to`) draws candidates
                // from routing_table ∪ live_sessions, but this warm sourced only the
                // routing table. On mobile the seeds are frequently present as live
                // sessions yet ABSENT from the routing table (it thins across Doze),
                // so their RD was never fetched here → the middle selection filtered
                // them as missing → `middles_insufficient` → the drain's reply circuit
                // never built and desktop→phone stalled intermittently. Mirror the
                // selector's candidate set so every relay it might pick as a middle
                // gets its RD warmed first. Freshness-gated + capped ⇒ a no-op (zero
                // RPC) whenever those RDs are already fresh, so no extra radio wakeups.
                {
                    let g = lock!(self.access.live_sessions);
                    relays.extend(
                        g.values()
                            .filter(|i| i.state == crate::types::SessionState::Active)
                            .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes())),
                    );
                }
                relays.sort_unstable();
                relays.dedup();
                self.access
                    .warm_known_relay_directory(
                        &relays,
                        6,
                        std::time::Duration::from_secs(5),
                    )
                    .await;
            }
            // The KEM-key-given mailbox FETCH: route a source-routed onion
            // straight to the known relay (NO ad resolve), authenticated, with a
            // one-time reply block so the relay answers over our return circuit.
            self.access
                .send_anonymous_authenticated_direct_with_reply(
                    target_node_id,
                    target_x25519_pk,
                    app_id,
                    endpoint_id,
                    data,
                    self.hop_count,
                    Some((reply_app_id, reply_endpoint_id)),
                )
                .map_err(|e| {
                    // Every daemon-side FETCH rejection funnels through here
                    // before the coarse AnonOnionSendError→u16 collapse the
                    // client reports as "status 2" — log the real SenderError
                    // so failure bursts are diagnosable.
                    log::warn!(
                        "mailbox.fetch.send_failed relay={} err={e:?}",
                        veil_util::hex_short(&target_node_id),
                    );
                    super::map_sender_err(e)
                })
        })
    }

    fn send_reply<'a>(
        &'a self,
        reply_id: u64,
        data: &'a [u8],
        src_app_id: [u8; 32],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_reply(reply_id, data, self.hop_count, src_app_id)
                .await
        })
    }

    fn register_onion_service<'a>(
        &'a self,
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .register_onion_service(hop_count)
                .map(|_cookie| ())
        })
    }

    fn register_rendezvous_publisher(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        validity_window_secs: u64,
        relay_kem_algo: u8,
        relay_kem_pk: Vec<u8>,
    ) {
        rendezvous_register_publisher_with_kem(
            &self.access.anonymity,
            &rendezvous_node_id,
            auth_cookie,
            validity_window_secs,
            relay_kem_algo,
            relay_kem_pk,
        );
    }

    fn send_to_onion_service<'a>(
        &'a self,
        service_identity_vk: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_to_onion_service(
                    service_identity_vk,
                    app_id,
                    endpoint_id,
                    data,
                    hop_count,
                    None,
                )
                .await
        })
    }

    fn send_to_onion_service_anonymous<'a>(
        &'a self,
        service_identity_vk: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &'a [u8],
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_to_onion_service_anonymous(
                    service_identity_vk,
                    app_id,
                    endpoint_id,
                    src_app_id,
                    data,
                    hop_count,
                )
                .await
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn send_anonymous_direct<'a>(
        &'a self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &'a [u8],
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_anonymous(
                    target_node_id,
                    target_x25519_pk,
                    target_app_id,
                    target_endpoint_id,
                    src_app_id,
                    data,
                    hop_count,
                )
                .map_err(super::map_sender_err)
        })
    }
}

impl veil_ipc::RendezvousReplicaResolver for RendezvousResolverImpl {
    fn resolve_replicas<'a>(
        &'a self,
        receiver_id: [u8; 32],
        max_replicas: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Vec<veil_ipc::ResolvedReplica>> + Send + 'a>,
    > {
        Box::pin(async move {
            // Walk every slot up to caller's cap or system max
            // whichever is lower. Slot 0 produces the same key as
            // legacy single-key publishers, so pre-T1.4 senders still
            // see one entry; new senders see all K configured slots.
            let cap = max_replicas
                .max(1)
                .min(veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS as usize);
            // Walk all slots CONCURRENTLY — bounded total ≈ ONE walk's timeout,
            // not cap × timeout — so resolve_replicas returns within the IPC
            // reply window (5s) even when every slot misses (e.g. the ad hasn't
            // replicated yet). The local-fast-path validator only trusts a cached
            // ad that decodes, verifies, names this receiver, and is currently
            // valid (mirror-cache-poison resistant); remote results re-verified.
            let ads = resolve_fresh_rendezvous_ads(
                &self.dht,
                &self.session_tx_registry,
                &self.pending_recursive,
                self.local_node_id,
                &self.resolve_cache,
                &self.logger,
                receiver_id,
                std::time::Duration::from_millis(3500),
                false,
            )
            .await;
            // Prefer the freshest signed ad before relay dedup. This avoids
            // returning a stale pre-cookie-fix ad just because it was in a
            // lower-numbered slot for the same relay.
            replicas_from_freshest_ads(ads, cap)
        })
    }
}

/// Mint an authenticated wake payload (Epic 489.10 slice 4.4) from a sealed
/// `WakeHmacKey` envelope.
///
/// Returns the 72-byte `ts || content_id || hmac` payload on success, or an
/// EMPTY `Vec` (wake-only fallback) when there is no envelope, the envelope
/// unseals to the wrong key length, or the unseal fails — a wake-envelope
/// problem must never drop the trigger, only degrade to the legacy wake-only
/// push. `ts` is taken as a parameter so this stays a pure, testable function;
/// the live caller passes `SystemTime::now()`.
fn mint_wake_payload(
    wake_hmac_envelope: Option<&[u8]>,
    relay_sk: &x25519_dalek::StaticSecret,
    content_id: &[u8; 32],
    receiver_id: &[u8; 32],
    ts: u64,
) -> Vec<u8> {
    match wake_hmac_envelope {
        Some(env) if !env.is_empty() => {
            match veil_anonymity::push_envelope::unseal_push_envelope(env, relay_sk) {
                Ok(mut kb) if kb.len() == veil_crypto::wake_hmac::WAKE_HMAC_KEY_LEN => {
                    use zeroize::Zeroize as _;
                    let mut key_arr = [0u8; veil_crypto::wake_hmac::WAKE_HMAC_KEY_LEN];
                    key_arr.copy_from_slice(&kb);
                    // Scrub the heap copy returned by `unseal_push_envelope` as
                    // soon as it's transferred into the fixed array — otherwise
                    // the receiver's long-lived wake key lingers in freed heap.
                    kb.zeroize();
                    let key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes(key_arr);
                    // `from_bytes` took `key_arr` by Copy, so the stack array
                    // still holds the key; scrub it too. Only `key`
                    // (ZeroizeOnDrop) may carry the secret past this point —
                    // matching `wake_hmac.rs`'s own zeroization guarantee.
                    key_arr.zeroize();
                    let tag = veil_crypto::wake_hmac::compute_wake_hmac(
                        &key,
                        ts,
                        content_id,
                        receiver_id,
                    );
                    veil_crypto::wake_hmac::encode_wake_payload(ts, content_id, &tag).to_vec()
                }
                Ok(_) => {
                    log::warn!(
                        "veil-push: wake envelope unsealed to wrong key length for receiver {} — wake-only fallback",
                        hex_short(receiver_id),
                    );
                    Vec::new()
                }
                Err(e) => {
                    log::warn!(
                        "veil-push: wake envelope unseal failed for receiver {}: {e} — wake-only fallback",
                        hex_short(receiver_id),
                    );
                    Vec::new()
                }
            }
        }
        _ => Vec::new(),
    }
}

/// Background task that consumes [`PushTrigger`]s, unseals each
/// envelope with the relay's X25519 secret, and dispatches the recovered
/// FCM/APNs token [`veil_push::PushDispatcher`].
///
/// Errors at every step are logged at WARN and the task moves on to
/// the next trigger — a malformed envelope on one push must not stall
/// the rest. The relay does not retry: undelivered pushes are the
/// sender's problem (peer-sync in P4 will retransmit anyway).
async fn push_dispatch_task(
    mut rx: tokio::sync::mpsc::Receiver<PushTrigger>,
    relay_sk: Arc<x25519_dalek::StaticSecret>,
    dispatcher: Arc<dyn veil_push::PushDispatcher>,
    require_wake_hmac: bool,
) {
    while let Some(trigger) = rx.recv().await {
        let plaintext =
            match veil_anonymity::push_envelope::unseal_push_envelope(&trigger.envelope, &relay_sk)
            {
                Ok(p) => p,
                Err(e) => {
                    log::warn!(
                        "veil-push: unseal failed for receiver {}: {e}",
                        hex_short(&trigger.receiver_id),
                    );
                    continue;
                }
            };
        let token = match veil_push::PushToken::decode(&plaintext) {
            Ok(t) => t,
            Err(e) => {
                log::warn!(
                    "veil-push: token decode failed for receiver {}: {e}",
                    hex_short(&trigger.receiver_id),
                );
                continue;
            }
        };
        // Mint an authenticated wake payload when the sender forwarded a sealed
        // WakeHmacKey envelope; otherwise fall back to the legacy wake-only push
        // (empty payload) — never drop the trigger on a wake-envelope problem.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let wake_payload: Vec<u8> = mint_wake_payload(
            trigger.wake_hmac_envelope.as_deref(),
            &relay_sk,
            &trigger.content_id,
            &trigger.receiver_id,
            ts,
        );
        // Production gate (audit cycle-2): when the operator requires
        // authenticated wakes, refuse to emit the legacy wake-only push
        // (empty payload) — an unauthenticated wake is forgeable by anyone who
        // learns the push token and is a battery-drain/nuisance vector. The
        // receiver must opt into wake-HMAC (upload a sealed envelope) to be
        // woken under this policy.
        if require_wake_hmac && wake_payload.is_empty() {
            log::warn!(
                "veil-push: dropping unauthenticated wake-only push for receiver {} \
                 (require_wake_hmac=true; receiver has not uploaded a wake-HMAC envelope)",
                hex_short(&trigger.receiver_id),
            );
            continue;
        }
        if let Err(e) = dispatcher.dispatch(&token, &wake_payload).await {
            log::warn!(
                "veil-push: dispatch failed for receiver {} provider {:?}: {e}",
                hex_short(&trigger.receiver_id),
                token.provider,
            );
        }
    }
}

pub fn hex_short(node_id: &[u8; 32]) -> String {
    let mut out = String::with_capacity(16);
    for b in node_id.iter().take(8) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Drop bootstrap-peer entries whose `public_key` matches our own. Prevents
/// a node listed in `builtin_seeds` (or in DNS) from dialing itself when
/// its own `bootstrap_peers` is empty.
pub fn filter_self_seeds(
    peers: Vec<veil_cfg::BootstrapPeer>,
    my_pubkey: &str,
) -> Vec<veil_cfg::BootstrapPeer> {
    peers
        .into_iter()
        .filter(|p| p.public_key != my_pubkey)
        .collect()
}

/// dedup hardening: drop bootstrap-peer entries whose
/// `public_key` already appears in `known_pubkeys`. Used by the HTTPS
/// fetch task so a peer listed in BOTH the operator's
/// `[[bootstrap_peers]]` AND an HTTPS bundle (or in BOTH the
/// discovered-peer cache AND an HTTPS bundle) doesn't get dialed
/// twice. Real-world impact: an operator who hosts the same seed
/// list at two CDN endpoints, or who pins a friend in
/// `bootstrap_peers` while also fetching them from HTTPS, would
/// otherwise burn double the battery + create twice the
/// DPI-visible handshake traffic per startup.
pub fn filter_already_known(
    peers: Vec<veil_cfg::BootstrapPeer>,
    known_pubkeys: &std::collections::HashSet<String>,
) -> Vec<veil_cfg::BootstrapPeer> {
    peers
        .into_iter()
        .filter(|p| !known_pubkeys.contains(&p.public_key))
        .collect()
}

// ── BootstrapWatchdog tunables + decision logic ──────────────────────────────
//
// Sampled by `spawn_bootstrap_watchdog_task`. Exposed at module scope (instead
// of being inlined as `const` inside the spawn helper) so the pure decision
// function `evaluate_watchdog_tick` can be exercised by unit tests with
// arbitrary mock inputs, without needing to drive the real 30 s × 3 timing.

pub const BOOTSTRAP_WATCHDOG_CHECK_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(30);
pub const BOOTSTRAP_WATCHDOG_ZERO_STREAK_THRESHOLD: u32 = 3;
pub const BOOTSTRAP_WATCHDOG_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogDecision {
    /// Sessions are healthy — do nothing this tick.
    Idle,
    /// Sessions are zero but threshold not yet reached, OR we are still
    /// inside the cool-down window since the last retry.
    Wait,
    /// Conditions met — fire re-dial of the bootstrap list this tick.
    Retry,
}

/// Decide what the watchdog should do on the current tick. `zero_streak`
/// is the NEW value (already incremented by the caller for this tick if
/// `session_count == 0`). `last_retry_elapsed` is `None` if no retry has
/// ever fired yet — that allows an immediate retry as soon as the streak
/// threshold is reached.
pub fn evaluate_watchdog_tick(
    session_count: usize,
    zero_streak: u32,
    threshold: u32,
    last_retry_elapsed: Option<std::time::Duration>,
    cooldown: std::time::Duration,
) -> WatchdogDecision {
    if session_count > 0 {
        return WatchdogDecision::Idle;
    }
    if zero_streak < threshold {
        return WatchdogDecision::Wait;
    }
    if let Some(elapsed) = last_retry_elapsed
        && elapsed < cooldown
    {
        return WatchdogDecision::Wait;
    }
    WatchdogDecision::Retry
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_cfg::{BootstrapPeer, SignatureAlgorithm};

    fn peer(pk: &str) -> BootstrapPeer {
        BootstrapPeer {
            transport: format!("tls://{pk}.example:9906"),
            public_key: pk.to_owned(),
            nonce: "AAAA".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }
    }

    fn test_rendezvous_ad(
        relay_tag: u8,
        valid_until_unix: u64,
        kem_tag: u8,
    ) -> veil_anonymity::rendezvous::RendezvousAd {
        veil_anonymity::rendezvous::RendezvousAd {
            receiver_node_id: [0x11; 32],
            rendezvous_node_id: [relay_tag; 32],
            auth_cookie: [0x22; 16],
            receiver_x25519_pk: [0x33; 32],
            // Freshness now ranks by valid_from (publish time); make the helper's
            // valid_from track its valid_until so the existing "higher rank wins"
            // tests still express the same ordering. The dedicated divergence test
            // below sets valid_from / valid_until independently.
            valid_from_unix: 1_700_000_000 + valid_until_unix,
            valid_until_unix,
            issuer_pk: String::new(),
            issuer_algo: veil_types::SignatureAlgorithm::Ed25519,
            signature: Vec::new(),
            push_envelope: Vec::new(),
            capability_token: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: vec![kem_tag; 32],
            wire_version: 5,
        }
    }

    #[test]
    fn kemless_reregister_preserves_existing_kem() {
        // The app registers the relay's KEM pk (mailbox-by-discovery deposit
        // target); veil's built-in receiver task then re-registers the SAME
        // (relay, cookie) KEM-LESS on its tick. A full overwrite would drop the
        // KEM and a sender would resolve usable(KEM)=0 (cannot deposit offline
        // mail) — so the KEM-less path must PRESERVE an existing KEM.
        let sk = std::sync::Arc::new(x25519_dalek::StaticSecret::from([7u8; 32]));
        let state = std::sync::Arc::new(crate::runtime::anonymity_state::AnonymityState::new(
            false,
            0,
            sk,
            None,
            Vec::new(),
        ));
        let relay = [0xAB; 32];
        let cookie = [0xCD; 16];
        let kem = vec![0x42u8; 32];

        rendezvous_register_publisher_with_kem(&state, &relay, cookie, 3600, 1, kem.clone());
        rendezvous_register_publisher(&state, &relay, cookie, 3600, None);

        let entries = lock!(state.rendezvous_publisher_entries);
        assert_eq!(entries.len(), 1, "same (relay,cookie) dedups to one entry");
        assert_eq!(
            entries[0].rendezvous_kem_pk, kem,
            "KEM key must survive a KEM-less re-register (else usable(KEM)=0)"
        );
        assert_eq!(entries[0].rendezvous_kem_algo, 1);
    }

    #[test]
    fn kem_register_overwrites_kemless() {
        // The reverse order must ALSO end KEM-bearing: a KEM-less entry first,
        // then the app's KEM register, leaves the entry with the KEM.
        let sk = std::sync::Arc::new(x25519_dalek::StaticSecret::from([9u8; 32]));
        let state = std::sync::Arc::new(crate::runtime::anonymity_state::AnonymityState::new(
            false,
            0,
            sk,
            None,
            Vec::new(),
        ));
        let relay = [0x01; 32];
        let cookie = [0x02; 16];
        let kem = vec![0x55u8; 32];

        rendezvous_register_publisher(&state, &relay, cookie, 3600, None);
        rendezvous_register_publisher_with_kem(&state, &relay, cookie, 3600, 1, kem.clone());

        let entries = lock!(state.rendezvous_publisher_entries);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rendezvous_kem_pk, kem);
    }

    #[test]
    fn rendezvous_replicas_prefer_freshest_before_relay_dedup() {
        // Same-generation stamps (within the deposit skew window): the same
        // relay's freshest ad wins the dedup, the other relay stays.
        let stale_same_relay = test_rendezvous_ad(0xA1, 280, 1);
        let fresh_other_relay = test_rendezvous_ad(0xB2, 290, 2);
        let fresh_same_relay = test_rendezvous_ad(0xA1, 300, 3);

        let out = replicas_from_freshest_ads(
            vec![stale_same_relay, fresh_other_relay, fresh_same_relay],
            8,
        );

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].relay_node_id, [0xA1; 32]);
        assert_eq!(out[0].valid_until_unix, 300);
        assert_eq!(out[0].rendezvous_kem_pk, vec![3; 32]);
        assert_eq!(out[1].relay_node_id, [0xB2; 32]);
        assert_eq!(out[1].valid_until_unix, 290);
    }

    #[test]
    fn rendezvous_replicas_gate_out_older_generations() {
        // The receiver batch-stamps all its plain ads with one valid_from (see
        // tick_publish_rendezvous_ads), so a much older stamp is a PREVIOUS
        // relay set — depositing there wastes (or loses) the blob. The gate
        // drops it, but never gates down to an empty result.
        let old_generation = test_rendezvous_ad(0xA1, 100, 1);
        let current = test_rendezvous_ad(0xB2, 300, 2);

        let out = replicas_from_freshest_ads(
            vec![old_generation.clone(), current],
            8,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].relay_node_id, [0xB2; 32]);

        // An all-stale view (resolver hit only lagging replicas) still
        // deposits somewhere rather than failing.
        let out = replicas_from_freshest_ads(vec![old_generation], 8);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].relay_node_id, [0xA1; 32]);
    }

    #[test]
    fn rendezvous_replicas_prefer_kem_bearing_over_a_fresher_kemless() {
        // The on-device regression: a stale KEM-LESS ad with a LATER valid_until
        // must NOT shadow a fresh KEM-bearing ad — sealing offline mail needs the
        // KEM key, so a KEM-less winner means usable(KEM)=0 and delivery fails.
        let stale_kemless = veil_anonymity::rendezvous::RendezvousAd {
            rendezvous_kem_pk: Vec::new(), // no relay KEM key
            ..test_rendezvous_ad(0xA1, 120, 0)
        };
        // Slightly earlier stamp, same generation (within the deposit skew
        // window) — a KEM-bearing ad must still outrank the KEM-less one.
        let fresh_kem = test_rendezvous_ad(0xB2, 100, 7);

        let out = replicas_from_freshest_ads(vec![stale_kemless, fresh_kem], 8);

        assert_eq!(out.len(), 2);
        // The KEM-bearing ad wins despite its EARLIER valid_until.
        assert_eq!(out[0].relay_node_id, [0xB2; 32]);
        assert_eq!(out[0].rendezvous_kem_pk, vec![7; 32]);
        // The KEM-less ad is still returned, but only as the last-resort fallback.
        assert_eq!(out[1].relay_node_id, [0xA1; 32]);
        assert!(out[1].rendezvous_kem_pk.is_empty());
    }

    #[test]
    fn rendezvous_replicas_prefer_freshest_published_not_longest_valid() {
        // THE cookie_unknown root cause. The auth_cookie is per-PERIOD, so the ad
        // PUBLISHED most recently (highest valid_from) carries the cookie that
        // matches the receiver's current registration. A stale ad published in a
        // previous period but with a LONGER validity window (later valid_until)
        // carries an OLD cookie. Selection must prefer the fresh-publish ad even
        // though it expires sooner — otherwise the sender's introduce is dropped
        // with cookie_unknown. Same relay so dedup keeps exactly one.
        let now = 1_700_000_000u64;
        let stale_long = veil_anonymity::rendezvous::RendezvousAd {
            rendezvous_node_id: [0xA1; 32],
            valid_from_unix: now - 86_400, // published yesterday (old-period cookie)
            valid_until_unix: now + 3600,  // ...but a long 24h-ish window
            rendezvous_kem_pk: vec![1; 32],
            ..test_rendezvous_ad(0xA1, 0, 1)
        };
        let fresh_short = veil_anonymity::rendezvous::RendezvousAd {
            rendezvous_node_id: [0xA1; 32],
            valid_from_unix: now,        // published now (current-period cookie)
            valid_until_unix: now + 600, // ...short window — would LOSE on valid_until
            rendezvous_kem_pk: vec![2; 32],
            ..test_rendezvous_ad(0xA1, 0, 2)
        };
        let out = replicas_from_freshest_ads(vec![stale_long, fresh_short], 8);
        assert_eq!(out.len(), 1, "same relay dedups to one");
        assert_eq!(
            out[0].rendezvous_kem_pk,
            vec![2; 32],
            "the freshest-PUBLISHED ad (current-period cookie) must win, not the \
             longest-valid stale one",
        );
    }

    #[test]
    fn rendezvous_replicas_respect_cap_after_freshness_sort() {
        let out = replicas_from_freshest_ads(
            vec![
                test_rendezvous_ad(0xA1, 100, 1),
                test_rendezvous_ad(0xB2, 300, 2),
                test_rendezvous_ad(0xC3, 200, 3),
            ],
            1,
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].relay_node_id, [0xB2; 32]);
        assert_eq!(out[0].valid_until_unix, 300);
    }

    #[test]
    fn filter_self_seeds_drops_matching_pubkey() {
        let peers = vec![peer("ME"), peer("OTHER1"), peer("OTHER2")];
        let kept = filter_self_seeds(peers, "ME");
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|p| p.public_key != "ME"));
    }

    // ── deterministic rendezvous cookie + relay anchor ────────────────────

    #[test]
    fn rendezvous_cookie_is_deterministic_xor_fold() {
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8; // 0,1,..,31
        }
        let c = rendezvous_cookie_from_node_id(&id);
        // XOR-fold: c[i] = id[i] ^ id[i+16]; here i ^ (i+16) == 16 for all i.
        assert_eq!(c, [16u8; 16]);
        // Deterministic: same input → same cookie, every call.
        assert_eq!(c, rendezvous_cookie_from_node_id(&id));
    }

    #[test]
    fn rendezvous_cookie_matches_app_side_derivation() {
        // Mirror of Dart `MailboxService._deriveCookie` (c[i] = id[i] ^ id[i+16]).
        let id: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x5a);
        let want: [u8; 16] = std::array::from_fn(|i| id[i] ^ id[i + 16]);
        assert_eq!(rendezvous_cookie_from_node_id(&id), want);
    }

    #[test]
    fn xor_distance_cmp_orders_by_kademlia_metric() {
        use std::cmp::Ordering;
        let anchor = [0u8; 32];
        let near = {
            let mut n = [0u8; 32];
            n[31] = 1; // distance 1
            n
        };
        let far = {
            let mut f = [0u8; 32];
            f[0] = 1; // distance 2^248
            f
        };
        assert_eq!(xor_distance_cmp(&anchor, &near, &far), Ordering::Less);
        assert_eq!(xor_distance_cmp(&anchor, &far, &near), Ordering::Greater);
        assert_eq!(xor_distance_cmp(&anchor, &near, &near), Ordering::Equal);
    }

    #[test]
    fn xor_distance_min_is_stable_and_anchor_relative() {
        // The closest-to-anchor relay is picked deterministically, and DIFFERENT
        // anchors (receivers) select DIFFERENT relays from the same set — the
        // load-spreading property that replaces the old random draw.
        let relays = [[0x10u8; 32], [0x20u8; 32], [0x30u8; 32]];
        let pick = |anchor: &[u8; 32]| {
            *relays
                .iter()
                .min_by(|a, b| xor_distance_cmp(anchor, a, b))
                .unwrap()
        };
        // Anchor near 0x10 → picks 0x10; stable across repeated calls.
        assert_eq!(pick(&[0x11u8; 32]), [0x10u8; 32]);
        assert_eq!(pick(&[0x11u8; 32]), [0x10u8; 32]);
        // A different receiver anchors elsewhere → different relay.
        assert_eq!(pick(&[0x2eu8; 32]), [0x20u8; 32]);
    }

    #[test]
    fn rendezvous_replica_picker_keeps_all_connected_pins_up_to_slot_cap() {
        use crate::types::{LinkId, NodeId, SessionInfo, SessionSource, SessionState};

        let pinned: Vec<[u8; 32]> = (1u8..=10).map(|n| [n; 32]).collect();
        let mut sessions = std::collections::BTreeMap::new();
        for (idx, node) in pinned.iter().enumerate() {
            sessions.insert(
                LinkId::new(idx as u64 + 1),
                SessionInfo {
                    link_id: LinkId::new(idx as u64 + 1),
                    node_id: Some(NodeId::from(*node)),
                    nonce: None,
                    matched_peer_id: None,
                    source: SessionSource::Inbound(crate::types::ListenId::new(1)),
                    listener_handle: None,
                    state: SessionState::Active,
                    transport: "test".to_owned(),
                    remote_addr: None,
                    description: String::new(),
                },
            );
        }
        let live = Arc::new(std::sync::Mutex::new(sessions));
        let dht = Arc::new(veil_dht::KademliaService::new([9u8; 32]));
        let caps = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));

        let got = pick_rendezvous_relays_deterministic(&live, &dht, &caps, &pinned, &[9u8; 32]);
        assert_eq!(
            got,
            pinned[..veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS as usize]
        );
    }

    #[test]
    fn rendezvous_replica_picker_requires_anonymity_relay_capability() {
        use crate::types::{LinkId, NodeId, SessionInfo, SessionSource, SessionState};

        let ordinary_relay = [0x11u8; 32];
        let anonymity_relay = [0x22u8; 32];
        let mut sessions = std::collections::BTreeMap::new();
        for (idx, node) in [ordinary_relay, anonymity_relay].iter().enumerate() {
            sessions.insert(
                LinkId::new(idx as u64 + 1),
                SessionInfo {
                    link_id: LinkId::new(idx as u64 + 1),
                    node_id: Some(NodeId::from(*node)),
                    nonce: None,
                    matched_peer_id: None,
                    source: SessionSource::Inbound(crate::types::ListenId::new(1)),
                    listener_handle: None,
                    state: SessionState::Active,
                    transport: "test".to_owned(),
                    remote_addr: None,
                    description: String::new(),
                },
            );
        }
        let live = Arc::new(std::sync::Mutex::new(sessions));
        let dht = Arc::new(veil_dht::KademliaService::new([9u8; 32]));
        let caps = Arc::new(std::sync::RwLock::new(std::collections::HashMap::from([
            (ordinary_relay, veil_proto::session::cap_flags::CAN_RELAY),
            (
                anonymity_relay,
                veil_proto::session::cap_flags::CAN_RELAY
                    | veil_proto::session::cap_flags::ANONYMITY_RELAY,
            ),
        ])));

        let got = pick_rendezvous_relays_deterministic(&live, &dht, &caps, &[], &[9u8; 32]);
        assert_eq!(
            got,
            vec![anonymity_relay],
            "ordinary CAN_RELAY transport peers must not become onion rendezvous relays",
        );
    }

    // ── BootstrapWatchdog: decision-fn coverage ──────────────────────────
    //
    // Drives `evaluate_watchdog_tick` with mock inputs covering every
    // transition (sessions OK, streak below threshold, streak reached
    // but inside cool-down, streak reached past cool-down, first-ever
    // retry). The real watchdog loop is a thin wrapper around this fn
    // plus a 30 s tokio interval, so behavioural coverage of the decision
    // logic is enough to catch logic regressions without 90 s real-clock tests.

    const TEST_THRESHOLD: u32 = 3;
    const TEST_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(300);

    #[test]
    fn watchdog_idle_when_sessions_present() {
        assert_eq!(
            evaluate_watchdog_tick(1, 0, TEST_THRESHOLD, None, TEST_COOLDOWN),
            WatchdogDecision::Idle,
        );
        assert_eq!(
            evaluate_watchdog_tick(7, 5, TEST_THRESHOLD, None, TEST_COOLDOWN),
            WatchdogDecision::Idle,
            "non-zero session count overrides any prior zero-streak",
        );
    }

    #[test]
    fn watchdog_waits_below_threshold() {
        for streak in 0..TEST_THRESHOLD {
            assert_eq!(
                evaluate_watchdog_tick(0, streak, TEST_THRESHOLD, None, TEST_COOLDOWN),
                WatchdogDecision::Wait,
                "streak={streak} below threshold should Wait",
            );
        }
    }

    #[test]
    fn watchdog_retries_immediately_on_first_threshold_hit() {
        assert_eq!(
            evaluate_watchdog_tick(0, TEST_THRESHOLD, TEST_THRESHOLD, None, TEST_COOLDOWN),
            WatchdogDecision::Retry,
            "first-ever retry must fire as soon as threshold is reached",
        );
    }

    #[test]
    fn watchdog_waits_inside_cooldown() {
        // Streak past threshold, but only 60 s elapsed since last retry
        // — cool-down is 300 s, so we wait.
        assert_eq!(
            evaluate_watchdog_tick(
                0,
                TEST_THRESHOLD + 10,
                TEST_THRESHOLD,
                Some(std::time::Duration::from_secs(60)),
                TEST_COOLDOWN,
            ),
            WatchdogDecision::Wait,
        );
    }

    #[test]
    fn watchdog_retries_after_cooldown_expires() {
        // Streak past threshold, cool-down fully elapsed → retry.
        assert_eq!(
            evaluate_watchdog_tick(
                0,
                TEST_THRESHOLD + 10,
                TEST_THRESHOLD,
                Some(TEST_COOLDOWN + std::time::Duration::from_secs(1)),
                TEST_COOLDOWN,
            ),
            WatchdogDecision::Retry,
        );
    }

    #[test]
    fn watchdog_treats_threshold_zero_as_immediate() {
        // Edge case: threshold=0 means "fire on first zero-tick".
        // saturating math should not panic, decision should be Retry.
        assert_eq!(
            evaluate_watchdog_tick(0, 1, 0, None, TEST_COOLDOWN),
            WatchdogDecision::Retry,
        );
    }

    #[test]
    fn filter_self_seeds_keeps_all_when_self_absent() {
        let peers = vec![peer("A"), peer("B")];
        let kept = filter_self_seeds(peers.clone(), "Z");
        assert_eq!(kept, peers);
    }

    #[test]
    fn filter_self_seeds_handles_empty() {
        assert!(filter_self_seeds(vec![], "ME").is_empty());
    }

    // ── dedup hardening ────────────────────────────────────────────

    fn pkset(pks: &[&str]) -> std::collections::HashSet<String> {
        pks.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn epic481_4_dedup_drops_pubkey_already_in_bootstrap_peers() {
        let known = pkset(&["IN_BOOTSTRAP"]);
        let kept = filter_already_known(
            vec![peer("IN_BOOTSTRAP"), peer("FRESH"), peer("ALSO_FRESH")],
            &known,
        );
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|p| p.public_key != "IN_BOOTSTRAP"));
    }

    #[test]
    fn epic481_4_dedup_drops_pubkey_already_in_cache() {
        // The cache snapshot contributes pubkeys to `known_pubkeys` —
        // verify the helper drops a peer whose pubkey came from there.
        let known = pkset(&["FRIEND_FROM_LAST_RUN"]);
        let kept =
            filter_already_known(vec![peer("FRIEND_FROM_LAST_RUN"), peer("NEW_SEED")], &known);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].public_key, "NEW_SEED");
    }

    #[test]
    fn epic481_4_dedup_keeps_all_when_known_is_empty() {
        let known = std::collections::HashSet::new();
        let peers = vec![peer("A"), peer("B"), peer("C")];
        let kept = filter_already_known(peers.clone(), &known);
        assert_eq!(kept, peers);
    }

    #[test]
    fn epic481_4_dedup_handles_empty_input() {
        let known = pkset(&["A", "B"]);
        assert!(filter_already_known(vec![], &known).is_empty());
    }

    #[test]
    fn epic481_4_dedup_drops_all_when_every_pubkey_known() {
        // Pathological case: HTTPS bundle returns ONLY pubkeys we
        // already know. Result: empty Vec, no double-dialing — the
        // task's downstream `if seeds.is_empty { return; }` will
        // skip all per-peer registration, which is the correct
        // behaviour (saves CPU + battery + DPI-visible handshakes).
        let known = pkset(&["A", "B", "C"]);
        let kept = filter_already_known(vec![peer("A"), peer("B"), peer("C")], &known);
        assert!(
            kept.is_empty(),
            "every pubkey already known → nothing to add"
        );
    }

    // ── Hot-reload of FCM/APNs creds (T1.4 followup) ────────────────────

    use std::sync::atomic::{AtomicUsize, Ordering};
    use veil_push::{LogOnlyDispatcher, PushDispatcher, PushProvider, PushToken};

    /// Counts dispatch invocations so the test can assert which
    /// dispatcher served which call after a swap.
    struct CountingDispatcher {
        tag: &'static str,
        count: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl PushDispatcher for CountingDispatcher {
        async fn dispatch(
            &self,
            _token: &PushToken,
            _wake_payload: &[u8],
        ) -> Result<(), veil_push::PushError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            log::info!("counting-dispatcher: tag={}", self.tag);
            Ok(())
        }
    }

    fn fake_token() -> PushToken {
        PushToken {
            provider: PushProvider::Fcm,
            token: b"fake".to_vec(),
        }
    }

    #[tokio::test]
    async fn t1_4_followup_hot_reload_initial_dispatcher_handles_calls() {
        let counting = Arc::new(CountingDispatcher {
            tag: "initial",
            count: AtomicUsize::new(0),
        });
        let hot = Arc::new(HotReloadDispatcher::new(
            Arc::clone(&counting) as Arc<dyn PushDispatcher>
        ));
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        assert_eq!(counting.count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn t1_4_followup_hot_reload_swap_redirects_calls() {
        let first = Arc::new(CountingDispatcher {
            tag: "first",
            count: AtomicUsize::new(0),
        });
        let second = Arc::new(CountingDispatcher {
            tag: "second",
            count: AtomicUsize::new(0),
        });
        let hot = Arc::new(HotReloadDispatcher::new(
            Arc::clone(&first) as Arc<dyn PushDispatcher>
        ));
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        // Swap.
        hot.swap(Arc::clone(&second) as Arc<dyn PushDispatcher>)
            .await;
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        // First saw exactly 1 call, second saw 2.
        assert_eq!(first.count.load(Ordering::SeqCst), 1);
        assert_eq!(second.count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn t1_4_followup_hot_reload_swap_to_log_only_keeps_dispatcher_alive() {
        // Edge case: operator deletes both creds files between
        // checks → mtime change → rebuild gives LogOnly.
        // Verify the wrapper continues serving without panic.
        let initial: Arc<dyn PushDispatcher> = Arc::new(LogOnlyDispatcher);
        let hot = Arc::new(HotReloadDispatcher::new(initial));
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        let new: Arc<dyn PushDispatcher> = Arc::new(LogOnlyDispatcher);
        hot.swap(new).await;
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        // No panic = test passes.
    }

    #[test]
    fn t1_4_followup_file_mtime_secs_returns_zero_on_missing() {
        assert_eq!(file_mtime_secs(""), 0);
        assert_eq!(file_mtime_secs("/this/path/definitely/does/not/exist"), 0);
    }

    #[test]
    fn t1_4_followup_file_mtime_secs_changes_when_file_touched() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_string_lossy().into_owned();
        let m1 = file_mtime_secs(&path);
        // Touch the file (write resets mtime to now). Sleep enough
        // that a 1-second-resolution filesystem (e.g. ext4) sees a
        // change.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(&path, b"changed").unwrap();
        let m2 = file_mtime_secs(&path);
        assert!(m2 > m1, "mtime should increase after touch ({m1} → {m2})");
    }

    // ── Epic 489.10 slice 4.4: relay-side wake-HMAC mint ────────────────

    fn fixture_relay_x25519() -> (x25519_dalek::StaticSecret, [u8; 32]) {
        use rand_core::OsRng;
        let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    #[test]
    fn t489_10_mint_round_trip_verifies_valid_with_content_id() {
        use veil_crypto::wake_hmac::{WakeHmacKey, WakePayloadVerdict, verify_wake_payload};

        let (relay_sk, relay_pk) = fixture_relay_x25519();
        // Receiver generates a wake-HMAC key and seals it to the relay's
        // X25519 pubkey (slice 4.3.2). Keep a copy of the key bytes so the
        // test can act as the verifying receiver.
        let key = WakeHmacKey::generate();
        let key_bytes = *key.as_bytes();
        let envelope =
            veil_anonymity::push_envelope::seal_push_envelope(&key_bytes, &relay_pk).unwrap();

        let content_id = [0x42u8; 32];
        let receiver_id = [0x99u8; 32];
        let ts = 1_700_000_000u64;

        // Relay mints the authenticated wake payload.
        let payload = mint_wake_payload(Some(&envelope), &relay_sk, &content_id, &receiver_id, ts);
        assert_eq!(
            payload.len(),
            veil_crypto::wake_hmac::WAKE_PAYLOAD_LEN,
            "mint must yield a 72-byte wake payload"
        );

        // Receiver verifies with its own copy of the key.
        let verify_key = WakeHmacKey::from_bytes(key_bytes);
        let verdict = verify_wake_payload(&verify_key, &payload, &receiver_id, ts + 10);
        assert_eq!(
            verdict,
            WakePayloadVerdict::Valid { ts, content_id },
            "minted payload must verify Valid with the bound content_id"
        );
    }

    #[test]
    fn t489_10_mint_none_envelope_yields_empty_wake_only() {
        let (relay_sk, _relay_pk) = fixture_relay_x25519();
        let payload = mint_wake_payload(None, &relay_sk, &[0u8; 32], &[1u8; 32], 1_700_000_000);
        assert!(
            payload.is_empty(),
            "None envelope must fall back to wake-only (empty payload)"
        );
        // Empty slice (sender sent an empty envelope) is also wake-only.
        let payload_empty =
            mint_wake_payload(Some(&[]), &relay_sk, &[0u8; 32], &[1u8; 32], 1_700_000_000);
        assert!(payload_empty.is_empty());
    }

    #[test]
    fn t489_10_mint_wrong_relay_key_yields_empty_wake_only() {
        use veil_crypto::wake_hmac::WakeHmacKey;
        // Envelope sealed to one relay; a different relay sk cannot unseal it,
        // so the mint degrades to wake-only rather than dropping the trigger.
        let (_relay_sk, relay_pk) = fixture_relay_x25519();
        let (attacker_sk, _attacker_pk) = fixture_relay_x25519();
        let key_bytes = *WakeHmacKey::generate().as_bytes();
        let envelope =
            veil_anonymity::push_envelope::seal_push_envelope(&key_bytes, &relay_pk).unwrap();
        let payload = mint_wake_payload(Some(&envelope), &attacker_sk, &[7u8; 32], &[8u8; 32], 123);
        assert!(
            payload.is_empty(),
            "unseal failure (wrong relay key) must fall back to wake-only"
        );
    }

    /// Drive `push_dispatch_task` with a trigger that has NO wake-HMAC envelope
    /// (→ empty/wake-only payload) and assert the dispatch count under each
    /// `require_wake_hmac` setting.
    async fn run_wake_only_trigger(require_wake_hmac: bool) -> usize {
        let (relay_sk, relay_pk) = fixture_relay_x25519();
        // Seal a valid push token so unseal + decode succeed and we reach the gate.
        let envelope =
            veil_anonymity::push_envelope::seal_push_envelope(&fake_token().encode(), &relay_pk)
                .unwrap();
        let counting = Arc::new(CountingDispatcher {
            tag: "gate",
            count: AtomicUsize::new(0),
        });
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(push_dispatch_task(
            rx,
            Arc::new(relay_sk),
            Arc::clone(&counting) as Arc<dyn PushDispatcher>,
            require_wake_hmac,
        ));
        tx.send(PushTrigger {
            receiver_id: [1u8; 32],
            envelope,
            content_id: [2u8; 32],
            wake_hmac_envelope: None, // legacy wake-only
        })
        .await
        .unwrap();
        drop(tx); // close the channel so the task loop terminates
        task.await.unwrap();
        counting.count.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn require_wake_hmac_drops_unauthenticated_wake_only_push() {
        assert_eq!(
            run_wake_only_trigger(true).await,
            0,
            "gate ON: an unauthenticated wake-only push must be dropped"
        );
    }

    #[tokio::test]
    async fn wake_only_push_dispatched_when_gate_off() {
        assert_eq!(
            run_wake_only_trigger(false).await,
            1,
            "gate OFF: legacy wake-only push is still dispatched (back-compat)"
        );
    }
}
