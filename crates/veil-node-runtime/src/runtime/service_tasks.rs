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

use super::{NodeRuntime, lock_state, lock_tasks, supervised_spawn};

/// Maximum number of bootstrap-discovered seeds a single source (one HTTPS
/// bundle or one DNS answer) may dial at join. A signed bundle can legitimately
/// carry hundreds of peers; dialing all of them — and flooding the k-buckets
/// with `add_contact` — at the exact moment the routing table is emptiest is an
/// eclipse-pressure / thundering-herd vector from one source. Matches the
/// discovered-peer cache cap (`MAX_DISCOVERED_PEERS = 32`). The DHT keeps
/// learning peers organically after join, so this only bounds the initial burst.
pub(crate) const MAX_BOOTSTRAP_SEEDS_PER_SOURCE: usize = 32;

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

/// Clone one tracked Forward frame for a retry, patching its direct next hop.
/// Chunk carriers additionally receive a fresh outer `content_id`: relay
/// replay caches key on that id, while reassembly keys on the inner
/// `(transfer_id, chunk_index, orig_content_id)`, so this preserves terminal
/// dedup/ACK semantics and lets a piece lost after hop one traverse again.
/// Ordinary ACK-tracked frames retain their terminal content id and advance the
/// bounded Forward delivery-attempt suffix instead.
fn prepare_ack_retransmit_frame(frame: &[u8], next_hop: [u8; 32], attempt: u32) -> Option<Vec<u8>> {
    use rand_core::RngCore;
    use veil_proto::delivery::{
        CHUNKED_ENVELOPE_MARKER, FORWARD_DELIVERY_ATTEMPT_MARKER, OFFSET_CONTENT_ID, OFFSET_PAYLOAD,
    };

    let header = veil_proto::header::HEADER_SIZE;
    let envelope = header.checked_add(32)?;
    let payload_offset = envelope.checked_add(OFFSET_PAYLOAD)?;
    let content_id_offset = envelope.checked_add(OFFSET_CONTENT_ID)?;
    if frame.len() <= payload_offset || frame.len() < content_id_offset.checked_add(32)? {
        return None;
    }
    let mut out = frame.to_vec();
    out[header..header + 32].copy_from_slice(&next_hop);
    if out[payload_offset] == CHUNKED_ENVELOPE_MARKER {
        let mut content_id = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut content_id);
        out[content_id_offset..content_id_offset + 32].copy_from_slice(&content_id);
    } else if out.len() >= 2 && out[out.len() - 2] == FORWARD_DELIVERY_ATTEMPT_MARKER {
        let attempt = u8::try_from(attempt).ok()?;
        let last = out.len() - 1;
        out[last] = attempt;
    }
    Some(out)
}

/// Resolve the sender, verify (signature + freshness + subkey), replay-check,
/// and deliver one COMPLETE authenticated message with the VERIFIED sender
/// node_id. Shared by the direct-onion (`Full`) and rendezvous (reassembled
/// `Fragment`) paths. Every failure is logged and dropped — never surfaced to
/// the anonymous sender (that would leak recipient liveness).
#[allow(clippy::too_many_arguments)]
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
    //    The Ok value is the device_id of the subkey that verified:
    //    `sender_node_id` is the IDENTITY shared by a whole device family, and
    //    the `sig_key_idx` subkey is the one place the protocol names the
    //    member device that actually signed. Endpoint handlers that must act
    //    per-device (the mailbox keys boxes by fetcher id) get it from this
    //    proof, not from anything the sender claims.
    let sender_device_id = match veil_identity::auth_deliver::verify_auth_deliver(
        &auth,
        &sender_doc,
        local_node_id,
        now_unix,
        freshness_window,
    ) {
        Ok(dev) => dev,
        Err(e) => {
            logger.info(
                "anonymity.auth_deliver.verify_failed",
                format!(
                    "auth delivery from {} rejected: {e}",
                    veil_util::hex_short(&auth.sender_node_id),
                ),
            );
            return;
        }
    };

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
        access
            .anonymity
            .send_stall
            .note_answer(&auth.sender_node_id);
    }

    // 4. Deliver with the VERIFIED sender node_id. If the message carried a
    //    one-time reply path, store it daemon-side and surface a non-zero
    //    reply_id so the app can reply (the block never crosses to the app).
    let data_len = auth.data.len();
    let endpoint_id = auth.endpoint_id;
    let sender_node_id = auth.sender_node_id;
    let app_id = auth.app_id;
    let reply_id = if auth.reply_blocks.is_empty() {
        0
    } else {
        // D3: the reply blocks are owned by the app that received this message
        // (`app_id`); only that app may later reply through them.
        access
            .anonymity
            .reply_block_store
            .store(auth.reply_blocks, app_id, now_unix)
    };
    let delivered = access.dispatcher.app_registry.route_ipc_deliver_with_reply(
        sender_node_id,
        // The signature over this message was verified against the sender's
        // identity document just above — the strongest provenance there is.
        veil_app::registry::SenderProvenance::Signed,
        // The verified signer DEVICE (from the same signature) — the only
        // delivery path entitled to pass `Some` here.
        Some(sender_device_id),
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

/// Decode and deliver one completely reassembled anonymous AppDeliver. The
/// sender controls the encrypted payload, so attribution is forced to the
/// anonymous zero node id even if a malicious fragment stream encoded another
/// value. App-level capability MACs remain responsible for authorization.
fn process_anonymous_deliver(
    bytes: &[u8],
    access: &super::NodeServices,
    logger: &Arc<veil_observability::NodeLogger>,
) {
    let deliver = match veil_proto::AppDeliverPayload::decode(bytes) {
        Ok(value) => value,
        Err(error) => {
            logger.info(
                "anonymity.anonymous_deliver.reassembled_decode_failed",
                format!("reassembled AppDeliverPayload decode: {error}"),
            );
            return;
        }
    };
    let data_len = deliver.data.len();
    let endpoint_id = deliver.endpoint_id;
    let delivered = access.dispatcher.app_registry.route_ipc_deliver(
        [0u8; 32],
        // Attribution is forced to the anonymous zero id — there is nothing to
        // authenticate, and saying so is the point.
        veil_app::registry::SenderProvenance::Claimed,
        deliver.src_app_id,
        deliver.app_id,
        endpoint_id,
        deliver.data,
    );
    if delivered {
        logger.info(
            "anonymity.anonymous_deliver.delivered",
            format!(
                "delivered {data_len} reassembled anonymous bytes to endpoint_id={endpoint_id}"
            ),
        );
    } else {
        logger.info(
            "anonymity.anonymous_deliver.unbound",
            format!("no app bound to endpoint_id={endpoint_id}; {data_len} bytes dropped"),
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
/// (RENDEZVOUS_RECIPIENT_CHECK_INTERVAL = 15s). pub(crate) so the initial
/// onion-service register (runtime::mod) uses the same window, not the 24h
/// directory default.
///
/// RAISED 600 -> 1800 because the reason for 600 was solved elsewhere and
/// nobody came back for it. It was shortened 1h -> 10min on 2026-06-28
/// ("so a stale cached ad self-heals fast"): a sender holding a cached
/// previous-relay ad kept firing introduces into a relay the receiver had
/// left, and `cookie_unknown` is deliberately silent, so the ad's own expiry
/// was the only thing that ended it. Five days later, 2026-07-03, the
/// sender-side stall self-heal landed (`AnonSendStallTracker`): three
/// un-answered sends drop the resolve cache and widen the fan-out. The
/// black-hole window is now bounded by THAT — ~3 sends and at most one forced
/// re-resolve per ANON_SEND_WIDEN_SECS — not by this constant.
///
/// What this does NOT relax: reacting to a real change. The maintenance guard
/// republishes when the published ad's (relay, cookie, KEM, window) differs
/// from the live publisher entry, independently of freshness — so a rotated
/// relay is republished at once. Only the periodic refresh of an UNCHANGED ad
/// is slowed, and that refresh is what an idle phone pays for: measured at
/// 600s it cost one recursive STORE + FIND_VALUE per ad slot per ~333 s,
/// eight slots at a time, 17.8% of an idle phone's traffic on one link.
///
/// Not raised further than 1800 in one step: this is a live-network property,
/// and 3x is enough to measure the effect against the same stand.
pub(crate) const RENDEZVOUS_AD_VALIDITY_SECS: u64 = 1800;

/// The maintenance tick republishes at half the window, so that half must stay
/// clear of the cadence at which the recipient task re-registers — otherwise an
/// ad would spend part of its life expired between refreshes. Guards against
/// INVERSION, not against any particular value: the long-standing 600 passes it
/// (300 against 75) and so does 1800 (900 against 75). Compile-time so an edit
/// to either constant cannot quietly cross the line.
const _: () = assert!(
    RENDEZVOUS_AD_VALIDITY_SECS / 2
        > RENDEZVOUS_RECIPIENT_CHECK_INTERVAL.as_secs() * RENDEZVOUS_REREGISTER_EVERY_TICKS * 2,
    "ad half-life must stay clear of the re-register cadence",
);
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
pub(crate) fn peer_advertised_anonymity_relay(
    cap_flags: &PeerCapFlags,
    node_id: &[u8; 32],
) -> bool {
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
        let bytes = match dht
            .find_value_from_peer(peer, key, Arc::clone(outbox))
            .await
        {
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
/// Put `entry` into the registry, or refuse because there is no slot for it.
///
/// Refuse, rather than accept and drop it later. The tick publishes only the
/// first `MAX_RENDEZVOUS_AD_SLOTS` entries, so a ninth was accepted, kept in
/// memory, cloned on every tick, and never published — the caller was told its
/// mailbox was live when it was undiscoverable (report17 V17-M6).
///
/// An entry that REPLACES one already held always fits: it takes a slot that
/// is already accounted for. That is also the path the built-in recipient task
/// takes on every tick, so refusing it would break a working publisher.
///
/// Returns whether the registry now holds this entry.
/// Whether an entry can ever become an ad, checked BEFORE it takes a slot.
///
/// The slots are bounded and the publish tick signs what is in them, so an
/// entry the signer will refuse costs a slot that a working publisher could
/// have had — and costs it silently, because the refusal happens later, on a
/// tick, in a log line nobody is reading. The registration itself answered
/// "registered" (report20 V18-M4).
///
/// The bounds are the SIGNER'S, named from its own constants rather than
/// copied as numbers, so an entry that passes here is one `sign_rendezvous_ad_v5`
/// accepts. `now_unix == 0` means "do not judge the expiry" — the clock is not
/// always available where this is called from, and a stale stamp is the one
/// thing here that stops being true on its own.
pub(crate) fn publisher_entry_is_publishable(
    entry: &veil_anonymity::rendezvous::RendezvousPublisherEntry,
    now_unix: u64,
) -> Result<(), &'static str> {
    use veil_anonymity::rendezvous::{
        MAX_PUSH_ENVELOPE_LEN, MAX_RENDEZVOUS_KEM_PK_LEN, MAX_VALIDITY_WINDOW_SECS,
        MAX_WAKE_HMAC_ENVELOPE_LEN, RENDEZVOUS_KEM_ALGO_X25519,
    };
    if entry.validity_window_secs == 0 {
        return Err("a validity window of zero is an ad that is expired when signed");
    }
    if entry.validity_window_secs > MAX_VALIDITY_WINDOW_SECS {
        return Err("validity window past the signer's cap");
    }
    if entry.push_envelope.len() > MAX_PUSH_ENVELOPE_LEN {
        return Err("push envelope past the signer's cap");
    }
    if entry.wake_hmac_envelope.len() > MAX_WAKE_HMAC_ENVELOPE_LEN {
        return Err("wake HMAC envelope past the signer's cap");
    }
    if entry.rendezvous_kem_pk.len() > MAX_RENDEZVOUS_KEM_PK_LEN {
        return Err("relay KEM key past the signer's cap");
    }
    // The algorithm and the key are one fact. An algorithm with no key
    // advertises nothing, and a key under the "no key advertised" algorithm is
    // a key no sender will use.
    if entry.rendezvous_kem_algo != RENDEZVOUS_KEM_ALGO_X25519 && entry.rendezvous_kem_pk.is_empty()
    {
        return Err("a relay KEM algorithm was named with no key to go with it");
    }
    // A relay key that has already expired makes `ad_valid_until` refuse the
    // ad on every tick, for as long as the entry sits in its slot.
    if now_unix > 0
        && entry.rendezvous_kem_valid_until_unix > 0
        && entry.rendezvous_kem_valid_until_unix <= now_unix
    {
        return Err("the relay key's stamp is already in the past");
    }
    Ok(())
}

pub(crate) fn insert_publisher_entry(
    entries: &mut Vec<veil_anonymity::rendezvous::RendezvousPublisherEntry>,
    entry: veil_anonymity::rendezvous::RendezvousPublisherEntry,
) -> bool {
    // VALIDATED BEFORE IT TAKES ANYTHING. The slots are bounded and the publish
    // tick signs what is in them, so an entry the signer will refuse costs a
    // slot a working publisher could have had — and costs it silently, because
    // the refusal happens later, on a tick, in a log line nobody reads, while
    // the registration itself answered "registered" (report20 V18-M4).
    //
    // The clock is deliberately not consulted here: this runs under the
    // registry lock on paths that have no reason to read the time, and the one
    // check that needs it — a relay stamp already in the past — is a fact that
    // changes on its own. The callers that hold a clock pass it.
    if let Err(why) = publisher_entry_is_publishable(&entry, 0) {
        log::warn!("anonymity.rendezvous_publisher: registration refused — {why}");
        return false;
    }
    let slots = veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS as usize;
    if let Some(pos) = entries.iter().position(|e| {
        e.rendezvous_node_id == entry.rendezvous_node_id && e.auth_cookie == entry.auth_cookie
    }) {
        // PRESERVE a KEM key already advertised for this (relay, cookie). The app
        // registers the relay's KEM pk (mailbox-by-discovery, the deposit target)
        // and the built-in recipient task re-registers the SAME (relay, cookie)
        // KEM-LESS on its tick — a full overwrite would DROP the KEM, so a sender
        // resolves the ad with usable(KEM)=0 and cannot deposit offline mail
        // (observed on-device as a persistent stash failure). Carry the existing
        // KEM forward; this entry still functions as a rendezvous publisher, it
        // just keeps the mailbox KEM it already had.
        //
        // Only a KEM-LESS re-registration inherits. An entry that carries its
        // OWN key is a rotation and must replace the key, its algorithm and
        // its expiry AS ONE: carrying them separately advertised the OLD key
        // under the NEW key's lifetime, so a rotated-out key stayed sealable
        // for another full window (report20 V18-M2) and the rotation itself
        // never reached a single sender.
        let mut entry = entry;
        let existing = &entries[pos];
        if entry.rendezvous_kem_pk.is_empty() && !existing.rendezvous_kem_pk.is_empty() {
            entry.rendezvous_kem_algo = existing.rendezvous_kem_algo;
            entry.rendezvous_kem_pk = existing.rendezvous_kem_pk.clone();
            entry.rendezvous_kem_valid_until_unix = existing.rendezvous_kem_valid_until_unix;
        }
        entries[pos] = entry;
        return true;
    }
    if entries.len() >= slots {
        return false;
    }
    entries.push(entry);
    true
}

pub(crate) fn rendezvous_register_publisher(
    anonymity: &Arc<super::anonymity_state::AnonymityState>,
    relay: &[u8; 32],
    cookie: [u8; 16],
    validity_window_secs: u64,
    ephemeral_ad_identity: Option<veil_anonymity::rendezvous::EphemeralAdIdentity>,
) -> bool {
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
        rendezvous_kem_valid_until_unix: 0,
    };
    insert_publisher_entry(&mut lock!(anonymity.rendezvous_publisher_entries), entry)
}

/// Like [`rendezvous_register_publisher`] but for a PLAIN (sovereign-signed)
/// publisher that ALSO advertises the relay's KEM key — so a sender resolving
/// the v5 ad can anonymously deposit a mailbox PUT at the relay. Dedups by
/// (relay, cookie). The app-IPC entry point for mailbox-by-discovery.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rendezvous_register_publisher_with_kem(
    anonymity: &Arc<super::anonymity_state::AnonymityState>,
    relay: &[u8; 32],
    cookie: [u8; 16],
    validity_window_secs: u64,
    relay_kem_algo: u8,
    relay_kem_pk: Vec<u8>,
    relay_kem_valid_until_unix: u64,
) -> bool {
    let entry = veil_anonymity::rendezvous::RendezvousPublisherEntry {
        rendezvous_node_id: *relay,
        auth_cookie: cookie,
        validity_window_secs,
        push_envelope: Vec::new(),
        wake_hmac_envelope: Vec::new(),
        rendezvous_kem_algo: relay_kem_algo,
        rendezvous_kem_pk: relay_kem_pk,
        rendezvous_kem_valid_until_unix: relay_kem_valid_until_unix,
        // Plain rendezvous receiver — signed under the sovereign identity so
        // senders discover it by the receiver's real node_id.
        ephemeral_ad_identity: None,
    };
    insert_publisher_entry(&mut lock!(anonymity.rendezvous_publisher_entries), entry)
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
            // The publisher slots are BOUNDED, and a refusal means this relay
            // gets no ad — so it is not a relay we are reachable through and
            // must not be counted as one. Counting it anyway put a relay with
            // no advertisement in `current`, and the node then waited at a
            // meeting point no sender was ever told about (report20 V18-M13).
            if !rendezvous_register_publisher(
                anonymity,
                &relay,
                cookie,
                RENDEZVOUS_AD_VALIDITY_SECS,
                None,
            ) {
                logger.info(
                    "anonymity.rendezvous_recipient.no_ad_slot",
                    format!(
                        "relay {} took no publisher slot (all {} in use); not counted \
                         as registered",
                        veil_util::hex_short(&relay),
                        veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS,
                    ),
                );
                continue;
            }
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

    pub(crate) fn proxy_mlkem_ek_resolver(&self) -> Arc<dyn veil_types::MlKemEkResolver> {
        Arc::new(crate::mlkem_resolver::DhtMlKemEkResolver::new(
            Arc::clone(&self.dht),
            Arc::clone(&self.session_tx_registry),
            Arc::clone(&self.dispatcher.pending_recursive),
            *self.identity.local_identity.node_id.as_bytes(),
            Arc::clone(&self.identity.peer_mlkem_keys),
            Arc::clone(&self.identity.peer_ratchet_keys),
            Arc::clone(&self.identity.peer_mlkem_certs),
            Arc::clone(&self.identity.peer_mlkem_cert_store),
            Arc::clone(&self.logger),
        ))
    }

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
            dispatcher: Arc::clone(&self.dispatcher),
            mlkem_ek_resolver: self.proxy_mlkem_ek_resolver(),
            local_node_id: self.identity.local_identity.node_id,
            pending_stream_receipts: Arc::clone(&self.dispatcher.pending_stream_receipts),
            veil_stream_rx: Arc::clone(&self.dispatcher.veil_stream_rx),
            wire_stream_counter: Arc::clone(&self.wire_stream_counter),
            metrics: self.metrics.clone(),
        };
        for handle in crate::proxy::tasks::spawn_socks5(ctx) {
            lock_tasks(&self.tasks).background.push(handle);
        }
    }

    /// Spawn the exit proxy accept loop if `config.proxy.exit.enabled`.
    pub fn spawn_exit_proxy_task(&mut self, config: &veil_cfg::Config) {
        // spawn logic lives in `node/proxy/tasks.rs`.
        let ctx = crate::proxy::tasks::ExitProxySpawnCtx {
            config,
            logger: &self.logger,
            dispatcher: Arc::clone(&self.dispatcher),
            app_registry: Arc::clone(&self.app_registry),
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            mlkem_ek_resolver: self.proxy_mlkem_ek_resolver(),
        };
        if let Some(handle) = crate::proxy::tasks::spawn_exit_proxy(ctx) {
            lock_tasks(&self.tasks).background.push(handle);
        }
    }

    /// Spawn the always-available endpoint that terminates E2E DHT-routed
    /// proxy APP frames. Both ingress-only and exit-only nodes need it because
    /// receipts and stream data travel in both directions.
    pub fn spawn_routed_app_frames_task(&mut self) {
        let handle = crate::proxy::routed_frames::spawn_routed_app_frame_endpoint(
            Arc::clone(&self.dispatcher),
            Arc::clone(&self.app_registry),
            Arc::clone(&self.session_tx_registry),
            self.proxy_mlkem_ek_resolver(),
            Arc::clone(&self.logger),
        );
        lock_tasks(&self.tasks).background.push(handle);
    }

    /// Install a rotated ML-KEM keypair and, only if it took, ask the sovereign
    /// republish to fire now.
    ///
    /// Split out of the rotation tick so the pairing is testable. Announcing
    /// unconditionally would publish a cert around a key the ring refused —
    /// advertising an encapsulation key the node cannot decrypt for — and
    /// announcing never would leave the node advertising the key it just
    /// replaced until the 6h tick came round. Neither is visible from inside
    /// the spawned task.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rotate_and_announce(
        keys: &veil_e2e::MlKemSeedRing,
        republish_now: &tokio::sync::Notify,
        now_unix: u64,
        epoch: u64,
        dk: [u8; veil_e2e::DK_SEED_BYTES],
        ek: [u8; veil_e2e::EK_BYTES],
        overlap_secs: u64,
    ) -> Result<(), veil_e2e::RotateRejected> {
        keys.rotate(now_unix, epoch, dk, ek, overlap_secs)?;
        republish_now.notify_waiters();
        Ok(())
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
        let mut anonymous_reassembler = veil_identity::auth_deliver::AuthDeliverReassembler::new();

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
                                    // OBSERVABILITY (log-only): name each
                                    // fragment BEFORE reassembly — a message
                                    // stuck forever Pending (some fragments
                                    // never arrived) was invisible: neither
                                    // rejected nor delivered.
                                    logger.debug(
                                        "anonymity.auth_deliver.fragment",
                                        format!(
                                            "auth fragment {}/{} msg_id[..4]={} \
                                             ({} B, via_reply={via_reply_circuit})",
                                            frag.frag_idx.saturating_add(1),
                                            frag.frag_count,
                                            veil_util::hex_str(&frag.msg_id[..4]),
                                            frag.chunk.len(),
                                        ),
                                    );
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
                                },
                                veil_dispatcher::AuthDeliverInbound::AnonymousFragment { frag } => {
                                    use veil_identity::auth_deliver::ReassembleOutcome;
                                    match anonymous_reassembler.push(frag, now_unix) {
                                        ReassembleOutcome::Complete(bytes) => {
                                            process_anonymous_deliver(&bytes, &access, &logger);
                                        }
                                        ReassembleOutcome::Pending => {}
                                        ReassembleOutcome::Rejected => logger.info(
                                            "anonymity.anonymous_deliver.fragment_rejected",
                                            "anonymous AppDeliver fragment rejected (bounds/inconsistent)",
                                        ),
                                    }
                                    None
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
        // The address we RECEIVE under, which is the identity's — not the
        // transport key's. They are the same value for every node in the field
        // today and diverge only once a device gets a transport key of its own;
        // at that moment a device still listening under its transport id would
        // be waiting where nobody sends, looking reachable from every angle.
        let local_node_id = self.receiver_node_id();
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
                            frames,
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
                                    "content_id={} dst={} next_hop={} attempt={} frames={}",
                                    veil_util::hex_short(&content_id),
                                    veil_util::hex_short(&dst_node_id),
                                    veil_util::hex_short(&next_hop),
                                    attempt,
                                    frames.len(),
                                ),
                            );
                            // Every chunk carrier gets a fresh OUTER content id
                            // per attempt. Its transfer/index/original id stays
                            // unchanged, so the destination fills only missing
                            // pieces while relay replay caches cannot suppress a
                            // retry that was lost after the first hop.
                            let send_batch = |hop: [u8; 32]| -> bool {
                                for frame in frames.iter() {
                                    let Some(prepared) =
                                        prepare_ack_retransmit_frame(frame, hop, attempt)
                                    else {
                                        return false;
                                    };
                                    if !reg.send_to(
                                        &hop,
                                        veil_proto::header::priority::INTERACTIVE,
                                        prepared,
                                    ) {
                                        return false;
                                    }
                                }
                                true
                            };
                            // Try original hop first.
                            let sent = send_batch(next_hop);
                            if !sent {
                                // Original hop dead — re-route via the
                                // pre-computed route-cache hop (looked up above,
                                // before the registry guard was taken).
                                if let Some(new_hop) = reroute_hops.get(&dst_node_id).copied()
                                    && send_batch(new_hop)
                                {
                                    // Update stored next_hop for future retransmits.
                                    lock!(pending_ack).update_next_hop(&content_id, new_hop);
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
    pub(crate) fn new(
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

/// Enrol a send-path receiver in the refresh-ahead set — unless it is us.
///
/// The proactive set exists to spare the SEND path a synchronous DHT walk, and
/// no send goes to our own rendezvous ad: reaching ourselves needs no route.
/// Enrolling self turns a one-off self-resolve into a standing subscription,
/// because the refresher re-walks every member once per cache TTL forever.
///
/// Measured 23.08 on an idle phone with zero contacts: **2536** FIND_VALUE
/// walks of its OWN eight ad slots in 80 minutes, dead on 15.0s, **53%** of
/// every DHT frame it exchanged. The refresh task's own doc promises "a node
/// that stops messaging adds zero steady-state DHT load"; for the single
/// receiver id that can never be messaged, that promise was inverted.
///
/// Self still resolves on demand — the mailbox drain's cold path needs it. It
/// just does not buy a standing subscription.
fn note_send_target(
    resolve_cache: &Arc<super::anonymity_state::RendezvousResolveCache>,
    receiver_id: [u8; 32],
    local_node_id: [u8; 32],
) {
    if receiver_id == local_node_id {
        // WHICH caller resolves self was not answerable from any log —
        // measurement could name the frames and the keys, never the origin.
        // Left as an instrument rather than another guess.
        log::debug!(
            "rendezvous.resolve.self receiver={} — walking, not enrolling in refresh-ahead",
            veil_util::hex_short(&receiver_id),
        );
        return;
    }
    resolve_cache.note_send_use(receiver_id);
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
        //
        // OURSELF never qualifies. The proactive set exists to spare the SEND
        // path a synchronous walk, and no send goes to our own rendezvous ad —
        // reaching ourselves needs no route. Enrolling self turned a one-off
        // self-resolve into a permanent 8-walks-per-TTL loop: measured 23.08 on
        // an idle phone with zero contacts, 2536 FIND_VALUE walks of its OWN ad
        // slots in 80 minutes, dead on 15.0s, 53% of every DHT frame it
        // exchanged. The doc on the refresh task promises "a node that stops
        // messaging adds zero steady-state DHT load"; for the one receiver id
        // that can never be messaged, that promise was inverted.
        //
        // Resolving self still WORKS — the walk below runs as asked, and the
        // mailbox drain's cold path depends on it. It just does not buy a
        // standing subscription to re-walk forever.
        note_send_target(resolve_cache, receiver_id, local_node_id);
        if let Some(ads) = resolve_cache.get(&receiver_id, now) {
            return ads;
        }
    }
    let _refresh_guard = resolve_cache.lock_refresh(receiver_id).await;
    // Another send may have completed the refresh while this one waited for
    // the per-recipient single-flight lock.
    if !force_refresh && let Some(ads) = resolve_cache.get(&receiver_id, now) {
        return ads;
    }

    // Always fill the cache from every system slot. The IPC caller may request
    // only one returned replica, but caching that partial lookup would hide a
    // fresher ad in another slot from the live send path for the cache TTL.
    // OUR OWN ad needs no network. The walk exists because a cached ad can be
    // stale — the receiver may have moved to another relay since it was
    // resolved. For our own ad that cannot happen: we ARE the receiver, and
    // the local mirror is exactly what we wrote when we published. Asking the
    // network where our own advertisement is means asking strangers what we
    // just told them.
    //
    // Measured 23.08 on an idle node: the pinned-circuit refresh
    // (`CIRCUIT_IDLE_REFRESH_AFTER`) drove one full 8-slot walk of our OWN
    // slots every ~304 s, forever — the node's log shows one of them starting
    // 22 s after `rendezvous_ad.published` wrote the very ads it went looking
    // for. That was about half of all recursive DHT traffic an idle phone
    // exchanged.
    //
    // Falls through to the walk when the mirror holds nothing: the mailbox
    // drain's cold path (not registered anywhere yet) depends on it, and so
    // does a node whose ads have expired.
    let mut ads = Vec::new();
    if receiver_id == local_node_id {
        ads.extend(
            (0..MAX_RENDEZVOUS_AD_SLOTS)
                .filter_map(|idx| dht.get_local(&rendezvous_ad_dht_key_at(&receiver_id, idx)))
                .filter_map(|bytes| decode_rendezvous_ad(&bytes).ok())
                .filter(|ad| ad.receiver_node_id == receiver_id)
                .filter(|ad| verify_rendezvous_ad(ad).is_ok())
                .filter(|ad| is_currently_valid(ad, now).is_ok()),
        );
    }
    let from_local_mirror = !ads.is_empty();

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

    for (_idx, key, candidates) in if ads.is_empty() {
        futures::future::join_all(walks).await
    } else {
        Vec::new()
    } {
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
                "receiver={} source={} candidates={} freshest_relay={} valid_from={}",
                veil_util::hex_short(&receiver_id),
                // Say WHERE the ads came from. Without this the line reads
                // "refreshed" for a purely local read and an operator counting
                // it would see a DHT walk that never happened — the instrument
                // lying by its own name.
                if from_local_mirror { "local" } else { "dht" },
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
pub(crate) struct RuntimeAnonOnionSender {
    access: super::NodeServices,
    hop_count: usize,
}

impl RuntimeAnonOnionSender {
    pub(crate) fn new(access: super::NodeServices, hop_count: usize) -> Self {
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
                a.valid_from_unix
                    .saturating_add(DEPOSIT_GENERATION_SKEW_SECS)
                    >= newest
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
        reply: Option<([u8; 32], u32)>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            // Cold-boot / no-session gate: the reply-path warm below and
            // `select_onion_relay_path` resolve relay directories OVER live
            // sessions. On the FIRST drain tick right after arm — before any
            // handshake completes — there are zero active sessions, so the warm
            // is a no-op and select returns have:0, emitting a spurious
            // `reply_path_failed` / `send_failed` WARN (device-observed: exactly
            // one per cold boot, then the next tick succeeds once a session is
            // up). Skip this round quietly and return NoRelays (NOT Ok, so the
            // caller does not mark the relay drained) — the drain retries and,
            // with a session up, the RD warms in one direct hop and the fetch
            // lands.
            {
                let active = lock!(self.access.live_sessions)
                    .values()
                    .filter(|i| i.state == crate::types::SessionState::Active)
                    .count();
                if active == 0 {
                    log::debug!(
                        "mailbox.fetch skipped for {}: no active session yet (cold boot)",
                        veil_util::hex_short(&target_node_id),
                    );
                    return Err(veil_types::AnonOnionSendError::NoRelays);
                }
            }
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
                relays.retain(|n| {
                    peer_advertised_anonymity_relay(
                        &self.access.dispatcher.crypto.peer_cap_flags,
                        n,
                    )
                });
                self.access
                    .warm_known_relay_directory(&relays, 6, std::time::Duration::from_secs(5))
                    .await;
            }
            // The KEM-key-given direct send: a source-routed onion straight to
            // the known relay (NO ad resolve), authenticated. With `reply` a
            // one-time block rides along so the relay answers over our return
            // circuit (the mailbox FETCH); without it nothing comes back and no
            // reply circuit is built (the ACK).
            self.access
                .send_anonymous_authenticated_direct_with_reply(
                    target_node_id,
                    target_x25519_pk,
                    app_id,
                    endpoint_id,
                    data,
                    self.hop_count,
                    reply,
                )
                .await
                .map_err(|e| {
                    // Every daemon-side FETCH rejection funnels through here
                    // before the coarse AnonOnionSendError→u16 collapse the
                    // client reports as "status 2" — log the real SenderError
                    // so failure bursts are diagnosable.
                    match &e {
                        veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                            ..
                        } => log::debug!(
                            "mailbox.fetch.route_unavailable relay={} err={e:?}",
                            veil_util::hex_short(&target_node_id),
                        ),
                        _ => log::warn!(
                            "mailbox.fetch.send_failed relay={} err={e:?}",
                            veil_util::hex_short(&target_node_id),
                        ),
                    }
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
        relay_kem_valid_until_unix: u64,
    ) -> bool {
        rendezvous_register_publisher_with_kem(
            &self.access.anonymity,
            &rendezvous_node_id,
            auth_cookie,
            validity_window_secs,
            relay_kem_algo,
            relay_kem_pk,
            relay_kem_valid_until_unix,
        )
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
            let mut ads = resolve_fresh_rendezvous_ads(
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
            // The DHT copy of a receiver's ads disappears as soon as it stops
            // republishing them, and a dozing phone stops within minutes — the
            // very recipient the offline mailbox is for. An empty walk is not
            // evidence the relay set moved; the ad we already hold is signed
            // good for 24 hours. See `last_known_valid` for why this is the
            // deposit path's call to make and never the live path's.
            if ads.is_empty() {
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if let Some(stale) = self.resolve_cache.last_known_valid(&receiver_id, now_unix) {
                    self.logger.info(
                        "anonymity.rendezvous.resolve.last_known",
                        format!(
                            "receiver={} no live ad in the DHT; depositing at {} \
                             previously-validated replica(s) still inside their \
                             signed validity",
                            veil_util::hex_short(&receiver_id),
                            stale.len(),
                        ),
                    );
                    ads = stale;
                }
            }
            // Prefer the freshest signed ad before relay dedup. This avoids
            // returning a stale pre-cookie-fix ad just because it was in a
            // lower-numbered slot for the same relay.
            replicas_from_freshest_ads(ads, cap)
        })
    }
}

/// The first eight bytes of a node id, as sixteen lowercase hex characters.
///
/// The same string `builtin::mailbox::hex_short` produces, and the same
/// warning applies: `veil_util::hex_short` is the FOUR-byte form and would
/// quietly halve every id logged here (report24, dead-code table).
pub fn hex_short(node_id: &[u8; 32]) -> String {
    veil_util::bytes_to_hex(&node_id[..8])
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

/// Which builtin seeds the configured [`BuiltinSeedPolicy`] lets this node
/// dial. Pure so the policy can be exercised without standing up a runtime.
///
/// `nothing_configured` is "neither `peers` nor `[[bootstrap_peers]]` is set"
/// — the condition the historical either/or was written against, and the only
/// thing [`Auto`](veil_cfg::BuiltinSeedPolicy::Auto) still consults.
pub fn builtin_seed_contribution(
    policy: veil_cfg::BuiltinSeedPolicy,
    nothing_configured: bool,
    builtin: Vec<veil_cfg::BootstrapPeer>,
) -> Vec<veil_cfg::BootstrapPeer> {
    match policy {
        veil_cfg::BuiltinSeedPolicy::Never => Vec::new(),
        veil_cfg::BuiltinSeedPolicy::Always => builtin,
        veil_cfg::BuiltinSeedPolicy::Auto if nothing_configured => builtin,
        veil_cfg::BuiltinSeedPolicy::Auto => Vec::new(),
    }
}

/// Whether a rendezvous address is worth a dial, given who this node already
/// has.
///
/// The rendezvous names addresses, and a node that has been running for a
/// while very likely already knows some of them — through PEX, through its
/// cache, or because an operator wrote them down. Dialling one of those again
/// does not add a peer: the second connection is a duplicate the far side
/// drops, and this side reports it as `handshake timed out after 10s`, which
/// reads like a network fault and is not one.
///
/// Measured on a live host: it found all three announcing nodes at the
/// rendezvous, was already in session with every one of them, dialled all
/// three anyway, and logged three timeouts.
/// Every address this node already holds a session to.
///
/// Two sources, because one is not enough and finding that out cost a
/// production round-trip. An OUTBOUND session reports the address it dialled,
/// which is the answer. An INBOUND one reports OUR OWN listener --
/// `obfs4-tcp://0.0.0.0:5556`, the same string for every peer that ever
/// connects -- and its `remote_addr` carries the far side's ephemeral source
/// port, not the port it listens on. So an inbound session says nothing about
/// where its peer can be dialled, and seeds, which meet each other inbound,
/// went on re-dialling peers they were already talking to.
///
/// The missing half is identity. A session knows its peer's `node_id`, and the
/// discovered-peer cache maps address to public key -- `dial_and_learn` writes
/// that entry on every success. Deriving the id from the key joins the two.
pub(crate) fn addresses_we_already_hold(
    live: &Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<crate::types::LinkId, crate::types::SessionInfo>,
        >,
    >,
    cache: &Arc<std::sync::Mutex<veil_bootstrap::DiscoveredPeerCache>>,
) -> Vec<String> {
    let sessions: Vec<crate::types::SessionInfo> = lock!(live).values().cloned().collect();
    let mut out: Vec<String> = sessions
        .iter()
        .flat_map(|s| std::iter::once(s.transport.clone()).chain(s.remote_addr.iter().cloned()))
        .collect();

    let held: std::collections::HashSet<[u8; 32]> = sessions
        .iter()
        .filter_map(|s| s.node_id.map(|n| *n.as_bytes()))
        .collect();
    if held.is_empty() {
        return out;
    }
    for peer in lock!(cache).snapshot() {
        if let Ok(id) = veil_cfg::NodeId::from_public_key(peer.algo, &peer.public_key)
            && held.contains(id.as_bytes())
        {
            out.push(peer.transport);
        }
    }
    out
}

pub fn rendezvous_address_is_new(
    known: &[PeerConfigEntry],
    live: &[String],
    transport: &str,
) -> bool {
    // STRICT for the candidate: an address off a meeting point that does not
    // parse as `scheme://host:port` is not dialled blindly. Lenient for what
    // we compare it against, because a session reports its observed address
    // bare.
    let Some(want) = transport
        .split_once("://")
        .and_then(|(_, rest)| rendezvous_authority(rest))
    else {
        return false;
    };
    let in_table = known
        .iter()
        .any(|p| rendezvous_authority(&p.transport).is_some_and(|have| have == want));
    // LIVE SESSIONS TOO, and that is the half that was missing. The peer table
    // is not a record of who we are talking to: a row learned at a rendezvous
    // sits in the autodiscovered range and gets scored out between passes,
    // and then the next pass reads "not known" about a peer this node has an
    // open session with. It dials, the far side dedups the duplicate, and the
    // session that was already working is torn down and rebuilt -- once every
    // pass, for as long as both nodes are up. Measured between two production
    // seeds, which met each other again on every single round.
    let in_session = live
        .iter()
        .any(|t| rendezvous_authority(t).is_some_and(|have| have == want));
    !(in_table || in_session)
}

/// `host:port` from either a full URI or a bare address.
///
/// A peer row carries `scheme://host:port`; a session carries its transport
/// the same way but its observed `remote_addr` bare, and both have to compare
/// against an address from a meeting point.
fn rendezvous_authority(uri: &str) -> Option<String> {
    let rest = uri.split_once("://").map_or(uri, |(_, rest)| rest);
    let authority = rest.split('/').next().unwrap_or(rest);
    (!authority.is_empty()).then(|| authority.to_owned())
}

/// The transport scheme to dial a rendezvous address with.
///
/// A meeting point carries an address and no scheme — the DHT has nowhere to
/// put one, and a relay record is a stranger's, so its scheme is not ours to
/// take. This node has to supply it, from what it knows about the NETWORK:
///
/// 1. the scheme of a peer the operator already named — the operator is
///    saying what this network runs;
/// 2. obfs4-tcp, which is what a veil network runs.
///
/// WHAT THIS NODE LISTENS ON IS NOT EVIDENCE, and using it was the defect.
/// A listener says what this node ACCEPTS; the dial needs what the other end
/// SERVES, and on a client those are chosen by different people for different
/// reasons. The app gives every phone `quic://0.0.0.0:9000` for its own
/// inbound while every seed serves obfs4-tcp on 5556 — so a phone found all
/// three seeds at the rendezvous, rewrote each address to `quic://…:5556`,
/// and timed out against them forever:
///
/// ```text
/// nostr.looked          wss://nos.lol: 3 record(s) at the rendezvous
/// peer.connect.attempt  peer_id=0x92000000 transport=quic://…:5556
/// peer.connect.failure  error=connection timed out after 10s
/// ```
///
/// The rule it replaces read "a network runs one transport, and the one we
/// offer is the one we expect". The first half is true and the second does not
/// follow: a node that offers nothing at all fell through to obfs4-tcp and
/// worked, while a node that offered the wrong thing was confidently wrong —
/// so having a listener was worse than having none.
pub fn rendezvous_dial_scheme(config: &veil_cfg::Config) -> String {
    config
        .peers
        .iter()
        .map(|p| p.transport.as_str())
        .chain(config.bootstrap_peers.iter().map(|p| p.transport.as_str()))
        .find_map(|uri| uri.split_once("://").map(|(scheme, _)| scheme.to_owned()))
        .unwrap_or_else(|| "obfs4-tcp".to_owned())
}

/// How often layer 7 goes back to the rendezvous.
///
/// NOT a nicety. A DHT announcement expires — thirty minutes in most
/// implementations — so a node that announces once at startup is gone from the
/// rendezvous by the afternoon, and the whole layer decays into nothing
/// without a single error anywhere. Measured the hard way: the first version
/// of this task ran once and stopped, and the only reason that was noticed is
/// that `meeting_policy = fallback` never got a second pass in which to say
/// "not needed".
///
/// Fifteen minutes leaves a wide margin under the shortest expiry seen in the
/// wild, and costs a handful of UDP packets.
pub(crate) const RENDEZVOUS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// How many peers one rendezvous may contribute in a run.
///
/// A public index is writable by anyone: without a ceiling, whoever announces
/// most gets to fill this node's peer table. Small on purpose — a way in needs
/// one peer that works, not eight.
pub(crate) const MAX_RENDEZVOUS_PEERS: usize = 4;

/// How many addresses one pass may TRY, successful or not.
///
/// `MAX_RENDEZVOUS_PEERS` counts peers actually met, so an address that fails
/// costs nothing against it -- and every address at a meeting point is one a
/// stranger put there. Two labels across five relays, each answering with a
/// full page of records, is several hundred consecutive dials this node would
/// sit through before the pass ended, which is not an attack on anyone else
/// but is a fine way to keep a node from ever bootstrapping.
///
/// Generous next to the four we keep: a rendezvous full of stale addresses is
/// ordinary, and giving up after four failures would be worse than the problem.
pub(crate) const MAX_RENDEZVOUS_ATTEMPTS: usize = 24;

/// Dial an address nobody vouched for, and write down whoever answered.
///
/// The row goes in with no identity, which is what makes the dial carry no
/// expectation (see `outbound_expects_an_identity`). If the handshake
/// succeeds it proved a public key, a nonce and a node id, and the row is
/// rewritten from that proof before anything durable is said about the peer.
/// If it fails the row goes away again: an address from a public index that
/// does not answer is not a peer, and leaving it behind would have the
/// reconnect scheduler dialling a stranger's socket forever.
pub(crate) async fn dial_and_learn(
    access: &crate::runtime::NodeServices,
    state: &Arc<std::sync::Mutex<crate::state::NodeState>>,
    transport: &str,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) -> std::result::Result<String, String> {
    // CHOSEN AND CLAIMED UNDER ONE LOCK. Reading the table to pick a free slot
    // and then inserting into it under a second lock is a gap two tasks fit
    // through: the Mainline and Nostr passes run concurrently, both saw the
    // same slot free, and the loser then dialled on the winner's row -- writing
    // a proven identity against somebody else's address.
    //
    // The placeholder node id is a hash of the address: unique per address, and
    // not a claim about anybody. It is replaced the moment the handshake says
    // who actually answered.
    let placeholder = {
        let digest = blake3::hash(transport.as_bytes());
        veil_cfg::NodeId::from(*digest.as_bytes())
    };
    let (peer_id, we_minted_the_row) = {
        let mut st = lock_state(state);
        let known: Vec<PeerConfigEntry> = st.peers.values().cloned().collect();
        let slot = rendezvous_slot_claim(&known, transport)
            .ok_or_else(|| "no free rendezvous slot; not learning this peer".to_owned())?;
        match slot {
            // HELD: the row already holds this address -- this same peer,
            // proven on an earlier pass. A placeholder would trade a real
            // identity for a hash of the address and set `bootstrap_only`,
            // which exempts the row from the direction policy; and the failure
            // path below would then delete it, orphaning a connector that may
            // be holding a live session. Dialling the existing row is also
            // strictly better: it carries the peer's key, so the handshake
            // verifies who answers rather than taking whoever does.
            RendezvousSlot::Held(id) => (id, false),
            // FREE, or RECLAIMED from a row that never learned who was there.
            // Both are ours to fill, and a reclaimed one MUST be filled: it
            // still carries the previous tenant's address, so leaving it there
            // sends this dial to a URI nobody asked for and writes whoever
            // answers it down beside the address we meant to call (report21
            // V20-M7b).
            RendezvousSlot::Free(id) | RendezvousSlot::Reclaimed(id) => {
                st.peers.insert(
                    id,
                    PeerConfigEntry {
                        peer_id: id,
                        node_id: placeholder,
                        public_key: String::new(),
                        nonce: String::new(),
                        transport: transport.to_owned(),
                        algo: veil_cfg::SignatureAlgorithm::Ed25519,
                        tls_cert: None,
                        tls_key: None,
                        tls_ca_cert: None,
                        bootstrap_only: true,
                        source: crate::types::PeerSource::Rendezvous,
                    },
                );
                (id, true)
            }
        }
    };

    let session = match access.connect_peer_active(peer_id).await {
        Ok(session) => session,
        Err(e) => {
            let refusal = format!("{e}");
            // "Already yours" is an ANSWER, not a failure. Keeping the row is
            // what makes it stick: `rendezvous_address_is_new` reads the peer
            // table, so the next pass skips this address instead of dialling
            // it again. Without this the larger-node-id side of every pair
            // redials forever -- the only thing that would teach it otherwise
            // is a successful dial, and its dials are all refused as
            // duplicates. Measured: 24 refusals in 54 minutes, and `already_*`
            // never once.
            if refusal.contains(crate::runtime::peer_handshake::DUPLICATE_SESSION) {
                return Err(refusal);
            }
            // Retire only what this call created, AND only if it is still
            // what this call created. The lock that claimed the slot was let
            // go before the dial: the other pass may have taken the same
            // address, completed its handshake and written a proven row into
            // this very id in the meantime, and an unconditional remove then
            // deletes a peer somebody is talking to -- on the strength of a
            // dial that was ours (report21 V20-M7a).
            if we_minted_the_row {
                let mut st = lock_state(state);
                if rendezvous_row_is_our_placeholder(
                    st.peers.get(&peer_id),
                    &placeholder,
                    transport,
                ) {
                    st.peers.remove(&peer_id);
                }
            }
            return Err(refusal);
        }
    };

    // Everything durable about this peer, from what the handshake proved.
    // WHAT THE HANDSHAKE PROVED, not what we would have assumed. Writing
    // Ed25519 down as fact for every peer meant a Falcon or hybrid one was
    // recorded under the wrong algorithm -- and the node id derived from that
    // row is what the direction rule compares, so the wrong algorithm puts the
    // pair back to both sides dialling. A peer whose algorithm this build does
    // not recognise keeps the row's current value rather than being relabelled.
    let proven_algo = proven_algorithm(session.peer_algo);
    let proven = PeerConfigEntry {
        peer_id,
        node_id: session.peer_id,
        public_key: session.peer_public_key.clone(),
        nonce: session.peer_nonce.clone(),
        transport: transport.to_owned(),
        algo: proven_algo,
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        // No longer bootstrap-only: it has an identity now, and the whole
        // point of layer 7 is that the NEXT cold start does not need the DHT.
        bootstrap_only: false,
        source: crate::types::PeerSource::Rendezvous,
    };
    let named = veil_util::hex_str(session.peer_id.as_bytes());
    lock_state(state).peers.insert(peer_id, proven.clone());

    // A LASTING connection, which this dial is not. `connect_peer_active`
    // hands back an `AttachedDebugSession`: it completes the handshake, and
    // closing it is what dropping it means. That is the right shape for
    // proving who is at an address and the wrong one for joining a network --
    // the log said `session.open` and `session.close` eight milliseconds
    // apart, three times, and the node sat at zero sessions having just met
    // every peer it was looking for.
    //
    // The row is a full peer now: the handshake proved the key and the nonce,
    // so the ordinary reconnect loop can own it from here. It claims one slot
    // per node_id, so a peer met at two meeting points -- or met again on the
    // next pass -- still gets exactly one.
    let handles =
        crate::outbound_connector::spawn_outbound_peers(vec![proven.clone()], access, shutdown_tx);
    // Detached on purpose: each loop watches the same shutdown channel and
    // ends with it, and this task has no task-set of its own to park them in.
    drop(handles);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    lock!(access.discovered_peers_cache).upsert(
        veil_cfg::BootstrapPeer {
            transport: proven.transport,
            public_key: proven.public_key,
            nonce: proven.nonce,
            algo: proven.algo,
            tls_cert: None,
            tls_ca_cert: None,
        },
        now,
    );
    Ok(named[..16.min(named.len())].to_owned())
}

/// How many peers one LAN may contribute before this node stops listening to it.
///
/// Anyone on the segment can announce, and an announce is cheap: without a
/// ceiling a single machine could fill this node's peer table with entries of
/// its choosing simply by talking. Smaller than the per-source cap for the
/// other layers because a LAN is a smaller place — a home or office segment
/// with eight veil nodes on it is already unusual.
pub(crate) const MAX_LAN_PEERS: usize = 8;

/// Whether to take a peer heard on the LAN, given who has already been taken.
///
/// Separate from the loop because the bound is the part worth testing, and the
/// bound is the part that was wrong: recording the announcer BEFORE checking
/// the ceiling meant a neighbour rotating keys grew this set forever while
/// none of those peers was ever attached. `taken` is only ever added to here,
/// so a cap enforced here is a cap on its size.
///
/// Returns `false` for our own announce, for one already taken, and for
/// anything past the ceiling.
pub fn admit_lan_peer(
    public_key: &str,
    my_pubkey: &str,
    taken: &std::collections::BTreeMap<String, LanCandidate>,
) -> bool {
    public_key != my_pubkey && !taken.contains_key(public_key) && taken.len() < MAX_LAN_PEERS
}

/// A LAN announce this node acted on: the identity it derived from it, the
/// peer slot it was given, and when.
#[derive(Clone, Debug)]
pub struct LanCandidate {
    pub node_id: [u8; 32],
    pub slot: u32,
    pub admitted: std::time::Instant,
    /// The row this admission wrote, so eviction removes THAT one.
    ///
    /// Reclaiming the slot used to delete the local `seen` entry and nothing
    /// else: the `NodeState` row, the DHT contact and the reconnect task all
    /// stayed. The next eight announces reused the same fixed slots, so an
    /// attacker on the broadcast domain added up to eight more of each every
    /// five minutes, without bound, for the life of the process.
    pub peer_id: crate::types::PeerId,
    /// Stops the reconnect loop this admission spawned. The connector's own
    /// RAII guard releases its per-node-id claim when the task is dropped, so
    /// aborting is what gives the claim back too.
    pub abort: Option<tokio::task::AbortHandle>,
}

/// Take back everything ONE LAN admission created.
///
/// Reclaiming the slot used to delete the local `seen` entry and nothing
/// else, so the `NodeState` row, the DHT contact and the reconnect task all
/// survived. The next eight announces reused the same fixed slots, which is
/// how an attacker on the broadcast domain added up to eight more of each
/// every five minutes, without bound, for the life of the process.
///
/// The row is removed only if it is still THIS candidate's. A `PeerId` is a
/// local slot that outlives whoever occupies it: between the admission and
/// this eviction an endpoint refresh or a rediscovery can put a different
/// peer at the same number, and deleting that one would take out a row that
/// had already been corrected.
pub fn evict_lan_candidate<F: FnMut(&[u8; 32]), G: FnOnce(&[u8; 32])>(
    peers: &mut std::collections::BTreeMap<crate::types::PeerId, PeerConfigEntry>,
    candidate: LanCandidate,
    mut drop_contact: F,
    release_connector: G,
) {
    let ours = peers.get(&candidate.peer_id).is_some_and(|e| {
        e.source == crate::types::PeerSource::Lan && e.node_id.as_bytes() == &candidate.node_id
    });
    if ours {
        peers.remove(&candidate.peer_id);
    }
    // The contact goes either way: it names the node, not the slot, and this
    // candidate is the only reason it was added.
    drop_contact(&candidate.node_id);
    // Dropping the task also drops the connector's RAII guard, which is what
    // gives its per-node-id claim back — LATER, whenever the runtime gets
    // round to the cancellation. This node may re-admit the same peer before
    // then (the announce that triggered this reclaim is usually about to be),
    // and the claim it finds must not be the dying task's: that path only
    // refreshes an existing owner, so the re-admitted peer got no connector at
    // all and every later announce was dropped as already seen
    // (report24 RUNTIME-2). Given back HERE, synchronously; the guard knows
    // not to take a successor's claim with it.
    if let Some(abort) = candidate.abort {
        abort.abort();
    }
    release_connector(&candidate.node_id);
}

/// How long an admitted LAN announce may hold its slot without the peer ever
/// connecting.
pub const LAN_CANDIDATE_GRACE: std::time::Duration = std::time::Duration::from_secs(300);

/// The admitted keys whose slot may be reclaimed.
///
/// The cap used to be spent by ANNOUNCEMENTS. Eight datagrams naming eight
/// distinct keys filled it before a single handshake and nothing ever left,
/// so any machine on the segment could lock this node out of local discovery
/// until it restarted (report20 V20-M2). A slot is held by a peer that
/// CONNECTED; one that has not connected within the grace is a claim rather
/// than a peer, and its slot goes back.
///
/// Connected peers are never reclaimed however old — the cap is on how many
/// LAN neighbours this node takes, and a neighbour it is talking to is one.
pub fn stale_lan_candidates(
    taken: &std::collections::BTreeMap<String, LanCandidate>,
    connected: &std::collections::HashSet<[u8; 32]>,
    grace: std::time::Duration,
    now: std::time::Instant,
) -> Vec<String> {
    taken
        .iter()
        .filter(|(_, c)| {
            !connected.contains(&c.node_id) && now.saturating_duration_since(c.admitted) >= grace
        })
        .map(|(k, _)| k.clone())
        .collect()
}

/// The lowest peer slot no admitted LAN candidate is using.
///
/// Was `seen.len()`, which is the same number only while nothing ever leaves.
/// Once a slot can be reclaimed, the length repeats and a new neighbour
/// overwrites a live one's peer entry.
pub fn free_lan_slot(taken: &std::collections::BTreeMap<String, LanCandidate>) -> Option<u32> {
    let used: std::collections::BTreeSet<u32> = taken.values().map(|c| c.slot).collect();
    (0..MAX_LAN_PEERS as u32).find(|s| !used.contains(s))
}

/// What this node should say about itself on the local network, or `None` when
/// it has nothing a neighbour could dial.
///
/// The listener it picks is the one it would advertise anyway: `advertise`
/// when the operator set it (that field exists precisely because the bind
/// address and the reachable address differ behind a proxy), otherwise
/// `transport`. A listener bound to loopback with no override is skipped — a
/// neighbour that dialled it would reach its own machine, and an announce that
/// can only fail is worse than silence.
/// The address this node would give a stranger, for a meeting point that
/// cannot work it out for itself.
///
/// Layers 6 and 7 never need this: a LAN datagram and a DHT query both arrive
/// from an address, so the host is observed rather than claimed. A relay is
/// neither — it knows the address the record was posted from and does not put
/// it in the record, and taking it from a relay would mean trusting a
/// stranger's server to say where we are. So the node states its own, and can
/// only do that from a listener an operator configured to advertise.
///
/// `None` when there is nothing honest to say: no listener, a port of zero, or
/// a host that is true only from where this node is standing — the wildcard,
/// or loopback. Publishing `0.0.0.0` puts an address at the rendezvous that
/// works for nobody, and the node would look listed while being unreachable.
/// True when a rendezvous named US.
///
/// A meeting point does not know who is asking, so a node that announces
/// itself reads its own record back on the very next pass. Without this it
/// dials its own listener, waits out the full handshake timeout and logs the
/// result as a peer that could not be reached -- which is what layer 8 did on
/// its first live run, once every fifteen minutes, for the whole life of the
/// node.
/// Whether an address a stranger named is somewhere this node may dial.
///
/// A meeting point is an open index: the address in a record is whatever its
/// author put there, and a DHT node can answer with anything at all. Without
/// this, a signed Nostr author or a hostile DHT node could point the dial at
/// `127.0.0.1`, at the RFC 1918 machine next to us, or at a cloud metadata
/// endpoint, and the node would faithfully open a connection there. The
/// handshake fails, so nothing is impersonated -- but which ports answered is
/// itself the answer somebody wanted, and it is our host doing the probing.
///
/// Public sources may name public addresses. A peer on the LAN is reached
/// through layer 6, which observes the address rather than being told it, and
/// an operator who wants a private destination writes it in the config.
pub fn rendezvous_destination_is_dialable(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        // A NAME, not an address. It resolves later and could resolve
        // anywhere, so this layer does not accept one: every meeting point
        // this node uses carries addresses.
        return false;
    };
    // ONE definition of "somebody's inside", shared with the DHT ingress that
    // decides which addresses are worth a query at all. Two copies of this
    // rule is how `::ffff:127.0.0.1` passed one of them (report21 V20-M1a).
    if veil_mainline::endpoint::is_internal(ip) {
        return false;
    }
    // The dial path refuses MORE than the ingress does, and for a different
    // reason: a documentation address is nobody's inside, so probing it harms
    // no one, but dialling one costs a full handshake timeout for an address
    // that by definition names no host.
    match veil_mainline::endpoint::normalize(ip) {
        std::net::IpAddr::V4(v4) => !v4.is_documentation(),
        std::net::IpAddr::V6(v6) => v6.segments()[..2] != [0x2001, 0x0db8],
    }
}

/// Whether this node is the one that should place the call.
///
/// For a pair, exactly one side dials: `we_keep_outbound = ours < theirs`, and
/// the other waits. `outbound_connector` has always honoured it; the rendezvous
/// dial goes straight to `connect_peer_active` and never did, so both ends of
/// every pair called each other at every pass. The larger id's dial is then
/// refused as a duplicate -- and around each refusal the working sessions were
/// observed closing and re-opening.
///
/// Only answerable once the address has an identity. The discovered-peer cache
/// holds `address -> public key` for every peer we have completed a dial with,
/// and a first meeting has no entry: then this says yes, because somebody has
/// to call first and that is how the mapping is learned at all.
pub fn we_should_place_the_call(
    local_node_id: &[u8; 32],
    cache: &std::sync::Arc<std::sync::Mutex<veil_bootstrap::DiscoveredPeerCache>>,
    transport: &str,
) -> bool {
    let Some(want) = transport
        .split_once("://")
        .and_then(|(_, rest)| rendezvous_authority(rest))
    else {
        return false;
    };
    for peer in lock!(cache).snapshot() {
        if rendezvous_authority(&peer.transport).is_none_or(|have| have != want) {
            continue;
        }
        if let Ok(id) = veil_cfg::NodeId::from_public_key(peer.algo, &peer.public_key) {
            return local_node_id.as_slice() < id.as_bytes().as_slice();
        }
    }
    true
}

/// The algorithm to write down for a peer the handshake just proved.
///
/// Everything downstream used to assume Ed25519 and record it as fact, so a
/// Falcon or hybrid peer went into the row and the cache under the wrong name.
/// That is not cosmetic: the node id the direction rule compares is derived
/// from the key AND its algorithm, so a mislabelled peer puts the pair back to
/// both sides dialling each other.
///
/// A wire byte this build does not know falls back to Ed25519 rather than
/// refusing the peer: the handshake still proved a key, the session is real,
/// and dropping it would be a worse answer than an imperfect label. The
/// fallback is here, named, rather than spread as a literal at each use.
fn proven_algorithm(
    from_handshake: Option<veil_cfg::SignatureAlgorithm>,
) -> veil_cfg::SignatureAlgorithm {
    from_handshake.unwrap_or(veil_cfg::SignatureAlgorithm::Ed25519)
}

/// Which peer slot a rendezvous address owns.
///
/// STABLE FOR THE ADDRESS, and that is the whole point. The slot used to be
/// `BASE + taken`, where `taken` counted successful dials in the CURRENT pass
/// and reset every pass: the peer dialled first each round took `BASE + 0` and
/// its `state.peers.insert` overwrote whoever held that slot before. The
/// overwritten peer's connector then found no row for its node_id, exited --
/// `holds_peer_row` is how a connector learns it has been retired -- and took
/// a live session down with it. Two seeds rebuilt their link every few seconds
/// and met each other again at every rendezvous, which is what this looked
/// like from the outside.
///
/// So: an address that already has a row keeps it, and a new address takes the
/// lowest free slot in the window. `None` when the window is full, because
/// refusing to learn one more peer is a great deal better than evicting one we
/// are talking to.
/// Which slot a rendezvous dial gets, and on what terms.
///
/// The three cases are not interchangeable, and reading them as "occupied or
/// not" is what made a reclaimed slot dial the WRONG address (report21
/// V20-M7b): the row was there, so nothing replaced it, so the dial went to
/// the URI the previous tenant had left behind — and on success the identity
/// of whoever answered THAT address was written down beside the transport of
/// the candidate we meant to call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RendezvousSlot {
    /// A row that already holds this address. Dial it as it stands: it may
    /// carry a proven key, and then the handshake verifies who answers rather
    /// than taking whoever does.
    Held(PeerId),
    /// An empty slot in the window.
    Free(PeerId),
    /// Taken from a row that never learned who was there. Its address is not
    /// ours and must be replaced before dialling.
    Reclaimed(PeerId),
}

impl RendezvousSlot {
    /// The slot number, whichever way it was obtained. Production code always
    /// wants the case as well and matches on it; this is for the tests that
    /// only assert WHICH slot.
    #[cfg(test)]
    pub fn peer_id(self) -> PeerId {
        match self {
            Self::Held(id) | Self::Free(id) | Self::Reclaimed(id) => id,
        }
    }
}

/// The slot for `transport`, and how it was obtained.
pub fn rendezvous_slot_claim(known: &[PeerConfigEntry], transport: &str) -> Option<RendezvousSlot> {
    use crate::types::synthetic_peer_id::{RENDEZVOUS_BASE, RENDEZVOUS_WINDOW};
    let want = transport
        .split_once("://")
        .and_then(|(_, rest)| rendezvous_authority(rest))?;

    let in_window = |id: u32| (RENDEZVOUS_BASE..RENDEZVOUS_BASE + RENDEZVOUS_WINDOW).contains(&id);

    if let Some(existing) = known.iter().find(|p| {
        in_window(p.peer_id.get())
            && rendezvous_authority(&p.transport).is_some_and(|have| have == want)
    }) {
        return Some(RendezvousSlot::Held(existing.peer_id));
    }

    let taken: std::collections::HashSet<u32> = known
        .iter()
        .map(|p| p.peer_id.get())
        .filter(|id| in_window(*id))
        .collect();
    if let Some(free) =
        (RENDEZVOUS_BASE..RENDEZVOUS_BASE + RENDEZVOUS_WINDOW).find(|id| !taken.contains(id))
    {
        return Some(RendezvousSlot::Free(PeerId::new(free)));
    }

    // A FULL WINDOW MAY STILL YIELD, but only a row that never learned who was
    // there. A dial refused as a duplicate keeps its row on purpose -- that is
    // what stops the address being dialled again -- and such a row holds a
    // hash of the address and no key. Enough of them, from a rendezvous full
    // of aliases for one host, would otherwise wall the window off for the
    // life of the process and no new peer could ever be learned.
    //
    // A row that HAS an identity is never taken: something completed a
    // handshake with it, and a connector may be holding that session.
    known
        .iter()
        .filter(|p| in_window(p.peer_id.get()) && p.public_key.is_empty())
        .map(|p| p.peer_id)
        .min_by_key(|id| id.get())
        .map(RendezvousSlot::Reclaimed)
}

/// Whether the row in a rendezvous slot is still the placeholder THIS dial put
/// there.
///
/// The lock that claimed the slot is let go before the dial, and the other
/// meeting-point pass may take the same address in that window: it finds the
/// placeholder, dials it, completes a handshake and writes a proven row into
/// the same id. An unconditional rollback then deletes a peer somebody is
/// talking to, on the strength of a dial that was ours (report21 V20-M7a).
///
/// A row is ours only while it carries the address-hash we minted, no key, and
/// the address we meant — the three things a successful pass replaces.
pub fn rendezvous_row_is_our_placeholder(
    row: Option<&PeerConfigEntry>,
    placeholder: &veil_cfg::NodeId,
    transport: &str,
) -> bool {
    row.is_some_and(|p| {
        p.node_id == *placeholder && p.public_key.is_empty() && p.transport == transport
    })
}

pub fn rendezvous_address_is_self(mine: Option<&(String, u16)>, transport: &str) -> bool {
    let Some((host, port)) = mine else {
        return false;
    };
    let Some((_, rest)) = transport.split_once("://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let Some((their_host, their_port)) = authority.rsplit_once(':') else {
        return false;
    };
    their_host.trim_start_matches('[').trim_end_matches(']') == host
        && their_port.parse::<u16>() == Ok(*port)
}

/// The port each listener is ACTUALLY bound on, by its configured transport.
///
/// [`public_address_for`] and [`lan_announce_for`] read the port an operator
/// WROTE DOWN, and there are two ways for that not to be the port in use. A
/// listener configured on port 0 asks the OS to choose, so the config has no
/// port to publish and such a node advertised itself nowhere at all; an
/// ephemeral listener rotates to a fresh port on every interval and the config
/// goes on naming the first one (report20 V20-M3). The state entry carries the
/// address the listener bound and is rewritten on every rebind, so it is the
/// one that can answer.
///
/// Only ACTIVE listeners: an entry that is not bound has no port to speak of,
/// and its stale `local_addr` would be worse than the config.
/// What this node would tell a stranger about itself, AS IT IS NOW:
/// `(announcement, public address)`.
///
/// Read from the listener table on every call, which is the whole point. The
/// discovery tasks used to compute this once, before their loop, and then
/// publish the same port for the life of the process — so a listener that
/// rotated left them advertising a port that closed when its grace ended, and
/// a stranger who found the node at a meeting point could not reach it. The
/// startup case was fixed by reading BOUND ports instead of configured ones;
/// rotation is the same defect one step later (report24 RUNTIME-3).
pub fn current_announcement(
    state: &std::sync::Arc<std::sync::Mutex<crate::state::NodeState>>,
    config: &veil_cfg::Config,
    identity_public_key: &str,
    identity_nonce: &str,
) -> (Option<veil_bootstrap::LanAnnounce>, Option<(String, u16)>) {
    let listens: Vec<crate::types::ListenConfigEntry> = crate::runtime::lock_state(state)
        .listens
        .values()
        .cloned()
        .collect();
    let bound = bound_ports(&listens);
    (
        lan_announce_for(config, identity_public_key, identity_nonce, &bound),
        public_address_for(config, &bound),
    )
}

pub fn bound_ports(listens: &[crate::types::ListenConfigEntry]) -> Vec<(String, u16)> {
    listens
        .iter()
        .filter(|l| l.active)
        .filter_map(|l| {
            let addr = l.local_addr.as_deref()?;
            let authority = addr.split_once("://").map_or(addr, |(_, rest)| rest);
            let authority = authority.split('/').next().unwrap_or(authority);
            let (_, port) = authority.rsplit_once(':')?;
            let port = port.parse::<u16>().ok()?;
            (port != 0).then(|| (l.transport.clone(), port))
        })
        .collect()
}

/// The port to publish for `listener`: what it bound, unless the operator
/// stated an `advertise` address, which is a claim about the outside world and
/// stands as written.
fn published_port(
    listener: &veil_cfg::ListenConfig,
    configured: u16,
    bound: &[(String, u16)],
) -> u16 {
    if listener.advertise.is_some() {
        return configured;
    }
    bound
        .iter()
        .find(|(t, _)| *t == listener.transport)
        .map(|(_, p)| *p)
        .unwrap_or(configured)
}

pub fn public_address_for(
    config: &veil_cfg::Config,
    bound: &[(String, u16)],
) -> Option<(String, u16)> {
    for listener in &config.listen {
        // The SAME gate `build_advertised_transports` applies, and for the same
        // stated reason: "Trusted and Hidden listeners stay invisible on the
        // network -- peers learn about them only through invite-bundles." A
        // meeting point is the most public index there is, so a listener the
        // operator marked unadvertisable must not reach one. Stealth is not
        // even bound at startup, so publishing it would advertise a dead port.
        if !listener.visibility.is_advertisable() {
            continue;
        }
        let uri = listener.advertise.as_deref().unwrap_or(&listener.transport);
        let Some((_, rest)) = uri.split_once("://") else {
            continue;
        };
        let authority = rest.split('/').next().unwrap_or(rest);
        // `[::1]:5556` as well as `1.2.3.4:5556`.
        let (host, port_str) = match authority.rsplit_once(':') {
            Some(split) => split,
            None => continue,
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        let port = published_port(listener, port, bound);
        if port == 0 || host.is_empty() {
            continue;
        }
        // The SAME rule that decides whether a stranger's address is worth
        // dialling decides whether ours is worth publishing. This checked only
        // "unspecified or loopback", so a node whose listener is on
        // `192.168.1.5` posted that to seven public relays: a record no
        // stranger can use, and this network's shape written down where anyone
        // can read it (report21 V20-M3b).
        if let Ok(ip) = host.parse::<std::net::IpAddr>()
            && veil_mainline::endpoint::is_internal(ip)
        {
            continue;
        }
        if host == "localhost" {
            continue;
        }
        return Some((host.to_owned(), port));
    }
    None
}

pub fn lan_announce_for(
    config: &veil_cfg::Config,
    identity_public_key: &str,
    identity_nonce: &str,
    bound: &[(String, u16)],
) -> Option<veil_bootstrap::LanAnnounce> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;

    let public_key: [u8; 32] = b64.decode(identity_public_key).ok()?.try_into().ok()?;
    let pow_nonce: [u8; 4] = b64.decode(identity_nonce).ok()?.try_into().ok()?;

    for listener in &config.listen {
        // See `public_address_for`: an unadvertisable listener is not offered
        // at a meeting point, and a LAN announce is one.
        if !listener.visibility.is_advertisable() {
            continue;
        }
        let uri = listener.advertise.as_deref().unwrap_or(&listener.transport);
        let Some((scheme_str, rest)) = uri.split_once("://") else {
            continue;
        };
        let Some(scheme) = veil_bootstrap::LanScheme::ALL
            .iter()
            .copied()
            .find(|s| s.uri_scheme() == scheme_str)
        else {
            continue;
        };
        // Authority ends at the path, if any: `ws://host:port/veil`.
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host, port_str) = authority.rsplit_once(':')?;
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        let port = published_port(listener, port, bound);
        if port == 0 {
            continue;
        }
        // A loopback bind the operator did not override is not reachable from
        // the wire, and saying otherwise wastes a neighbour's dial.
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if listener.advertise.is_none()
            && host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        {
            continue;
        }
        return Some(veil_bootstrap::LanAnnounce {
            public_key,
            pow_nonce,
            port,
            scheme,
        });
    }
    None
}

/// Every bootstrap peer this node may dial: the operator's `[[bootstrap_peers]]`
/// plus whatever the builtin-seed policy contributes, self dropped and
/// deduplicated by public key (operator-curated entries win the position).
///
/// This is the set the partition watchdog re-dials. It exists because reading
/// `config.bootstrap_peers` alone answers a different question: a node running
/// on builtin seeds has that list EMPTY — the seeds are spliced into a local
/// clone inside `spawn_bootstrap_task` and never reach the config the watchdog
/// sees. Consulting the raw field there left precisely the nodes with no
/// operator list — every stock app install — without partition recovery.
pub fn resolve_bootstrap_candidates(
    config: &veil_cfg::Config,
    my_pubkey: &str,
) -> Vec<veil_cfg::BootstrapPeer> {
    resolve_bootstrap_candidates_from(config, my_pubkey, veil_bootstrap::builtin_seeds())
}

/// [`resolve_bootstrap_candidates`] against an EXPLICIT seed list.
///
/// The list is a build-feature decision — `allow-empty-seeds` makes
/// `builtin_seeds()` empty — and the tests around this are about what happens
/// to a list, not about which list this binary shipped with. Four of them
/// asserted their own premise ("test needs a non-empty builtin seed list") and
/// failed on it under exactly the features CI passes, so the suite was red for
/// a reason that had nothing to do with the behaviour under test.
pub fn resolve_bootstrap_candidates_from(
    config: &veil_cfg::Config,
    my_pubkey: &str,
    seeds: Vec<veil_cfg::BootstrapPeer>,
) -> Vec<veil_cfg::BootstrapPeer> {
    let contributed = builtin_seed_contribution(
        config.global.builtin_seed_policy,
        config.bootstrap_peers.is_empty() && config.peers.is_empty(),
        seeds,
    );
    let mut out = filter_self_seeds(config.bootstrap_peers.clone(), my_pubkey);
    let known: std::collections::HashSet<String> =
        out.iter().map(|p| p.public_key.clone()).collect();
    out.extend(filter_already_known(
        filter_self_seeds(contributed, my_pubkey),
        &known,
    ));
    out
}

/// The domain the DNS seed-discovery fallback should query, or `None` when
/// that fallback must not run at all.
///
/// Two conditions, both required:
///
/// 1. **Nothing else to dial.** Unchanged from the original inline check:
///    DNS discovery is the last fallback, so a node with `peers` or
///    `[[bootstrap_peers]]` (including seeds spliced in by
///    [`resolve_bootstrap_candidates`]) never reaches it.
///
/// 2. **The operator named a domain.** This is the new condition. The old code
///    fell back to [`veil_bootstrap::dns::DEFAULT_BOOTSTRAP_DOMAIN`], which is
///    `veil.example` — inside the `.example` TLD that RFC 6761 §6.5 reserves
///    and guarantees will never resolve in the public DNS. Querying it is not
///    a fallback, it is dead work: several seconds of DoT and DoH against a
///    name that cannot exist, followed by a plain-DNS stage whose only purpose
///    is to fail.
///
/// Condition 2 is what makes the Android abort unreachable in the shipped
/// configuration. The app composes a config with no `[[bootstrap_peers]]` and
/// no `bootstrap_dns_domain`; an identity that sets
/// `builtin_seed_policy = "never"` therefore satisfies condition 1, and the old
/// code walked straight into `discover_seeds_dns_system` →
/// `Resolver::builder_tokio()` → `ndk_context::android_context()` → `SIGABRT`
/// on a tokio worker. (`veil-bootstrap`'s own Android guard closes that door
/// too; this closes the corridor leading to it.)
///
/// Deliberately NOT keyed on [`veil_cfg::BuiltinSeedPolicy::Never`]. `Never` is
/// documented as the off switch for the *compile-time* seed list; a testnet
/// that declines those seeds and names its own `bootstrap_dns_domain` is
/// explicitly asking for that discovery, and suppressing it would break a
/// supported deployment. Nothing is acquired here that the operator did not
/// name, so the refusal stays honest either way.
pub fn dns_seed_discovery_domain(config: &veil_cfg::Config) -> Option<String> {
    if !config.bootstrap_peers.is_empty() || !config.peers.is_empty() {
        return None;
    }
    config.global.bootstrap_dns_domain.clone()
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

    /// A rotation that took must pull the republish forward; one the ring
    /// refused must not.
    ///
    /// The second half is the one worth a test. Announcing after a refusal
    /// publishes a cert around the key the node still holds — harmless-looking,
    /// and it hides the refusal behind a republish that appears to have worked.
    #[tokio::test]
    async fn only_a_rotation_that_took_pulls_the_republish_forward() {
        let keys = veil_e2e::MlKemSeedRing::new(
            1,
            [0x11; veil_e2e::DK_SEED_BYTES],
            [0x11; veil_e2e::EK_BYTES],
        );
        let notify = tokio::sync::Notify::new();
        let overlap = veil_e2e::MLKEM_SEED_MIN_OVERLAP_SECS;

        // A waiter must already be parked: `notify_waiters` wakes whoever is
        // waiting NOW and stores nothing, which is the behaviour the republish
        // loop relies on (it is always parked in its select). The first poll
        // both parks it and shows nothing has fired yet.
        let mut announced = Box::pin(notify.notified());
        assert!(
            futures_lite_ready(&mut announced).is_none(),
            "nothing has rotated yet"
        );

        // Refused: the epoch does not advance.
        let refused = NodeRuntime::rotate_and_announce(
            &keys,
            &notify,
            2_000,
            1,
            [0x22; veil_e2e::DK_SEED_BYTES],
            [0x22; veil_e2e::EK_BYTES],
            overlap,
        );
        assert!(refused.is_err(), "epoch 1 does not advance on epoch 1");
        assert_eq!(keys.current_ek(), [0x11u8; veil_e2e::EK_BYTES]);
        assert!(
            futures_lite_ready(&mut announced).is_none(),
            "a refused rotation must not announce a key that never changed"
        );

        // Accepted: the epoch advances.
        NodeRuntime::rotate_and_announce(
            &keys,
            &notify,
            2_000,
            2,
            [0x33; veil_e2e::DK_SEED_BYTES],
            [0x33; veil_e2e::EK_BYTES],
            overlap,
        )
        .expect("epoch 2 advances");
        assert_eq!(keys.current_ek(), [0x33u8; veil_e2e::EK_BYTES]);
        assert!(
            futures_lite_ready(&mut announced).is_some(),
            "a rotation that took must publish the new key rather than wait out the 6h tick"
        );
    }

    /// Poll a parked future once without awaiting it.
    fn futures_lite_ready<F: std::future::Future<Output = ()> + Unpin>(f: &mut F) -> Option<()> {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        match std::pin::Pin::new(f).poll(&mut cx) {
            std::task::Poll::Ready(()) => Some(()),
            std::task::Poll::Pending => None,
        }
    }

    #[test]
    fn ordinary_retransmit_advances_attempt_without_changing_terminal_content_id() {
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};
        use veil_proto::family::{DeliveryMsg, FrameFamily};
        use veil_proto::header::FrameHeader;

        let envelope = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any([0x21; 32]),
            sender_node_id: [0x22; 32],
            src_app_id: [0x23; 32],
            app_id: [0x24; 32],
            endpoint_id: 9,
            content_id: [0x25; 32],
            created_at: 1,
            ttl_secs: 30,
            payload: vec![1, 2, 3],
            trace_id: 0,
            require_ack: true,
        };
        let body = ForwardPayload {
            next_hop_node_id: [0x26; 32],
            envelope,
            relay_hops: 0,
            delivery_attempt: Some(1),
            traffic_class: None,
        }
        .encode();
        let mut header = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
        header.body_len = body.len() as u32;
        let frame = veil_proto::codec::encode_frame(&header, &body);

        let retried = prepare_ack_retransmit_frame(&frame, [0x27; 32], 2).unwrap();
        let retried = ForwardPayload::decode(&retried[veil_proto::HEADER_SIZE..]).unwrap();
        assert_eq!(retried.next_hop_node_id, [0x27; 32]);
        assert_eq!(retried.envelope.content_id, [0x25; 32]);
        assert_eq!(retried.delivery_attempt, Some(2));
        assert!(prepare_ack_retransmit_frame(&frame, [0x27; 32], 256).is_none());
    }

    #[test]
    fn chunk_retransmit_refreshes_only_carrier_id_and_next_hop() {
        use veil_proto::delivery::{ChunkedEnvelopePayload, DeliveryEnvelope, ForwardPayload};
        use veil_proto::family::{DeliveryMsg, FrameFamily};
        use veil_proto::header::FrameHeader;

        let chunk = ChunkedEnvelopePayload {
            transfer_id: [0x11; 16],
            chunk_index: 2,
            chunk_count: 4,
            total_size: 9,
            orig_content_id: [0x22; 32],
            require_ack: true,
            data: vec![7, 8, 9],
        };
        let envelope = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any([0x33; 32]),
            sender_node_id: [0x44; 32],
            src_app_id: [0x55; 32],
            app_id: [0x66; 32],
            endpoint_id: 7,
            content_id: [0x77; 32],
            created_at: 1,
            ttl_secs: 30,
            payload: chunk.encode(),
            trace_id: 9,
            require_ack: false,
        };
        let body = ForwardPayload {
            next_hop_node_id: [0x88; 32],
            envelope,
            relay_hops: 0,
            delivery_attempt: None,
            traffic_class: None,
        }
        .encode();
        let mut header = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
        header.body_len = body.len() as u32;
        let frame = veil_proto::codec::encode_frame(&header, &body);

        let first = prepare_ack_retransmit_frame(&frame, [0x99; 32], 2).unwrap();
        let second = prepare_ack_retransmit_frame(&frame, [0xAA; 32], 2).unwrap();
        let first = ForwardPayload::decode(&first[veil_proto::header::HEADER_SIZE..]).unwrap();
        let second = ForwardPayload::decode(&second[veil_proto::header::HEADER_SIZE..]).unwrap();
        assert_eq!(first.next_hop_node_id, [0x99; 32]);
        assert_eq!(second.next_hop_node_id, [0xAA; 32]);
        assert_ne!(first.envelope.content_id, [0x77; 32]);
        assert_ne!(second.envelope.content_id, [0x77; 32]);
        assert_ne!(first.envelope.content_id, second.envelope.content_id);
        assert_eq!(
            ChunkedEnvelopePayload::decode(&first.envelope.payload).unwrap(),
            chunk
        );
        assert_eq!(
            ChunkedEnvelopePayload::decode(&second.envelope.payload).unwrap(),
            chunk
        );
    }

    #[test]
    fn whole_batch_retry_fills_loss_once_and_leaves_no_phantom_transfer() {
        use veil_dispatcher::envelope_chunks::{AddChunkResult, EnvelopeChunkReassembler};
        use veil_proto::delivery::{ChunkedEnvelopePayload, DeliveryEnvelope, ForwardPayload};
        use veil_proto::family::{DeliveryMsg, FrameFamily};
        use veil_proto::header::FrameHeader;

        let transfer_id = [0xB1; 16];
        let original_id = [0xB2; 32];
        let make_frame = |index: u32| {
            let chunk = ChunkedEnvelopePayload {
                transfer_id,
                chunk_index: index,
                chunk_count: 4,
                total_size: 8,
                orig_content_id: original_id,
                require_ack: true,
                data: vec![index as u8; 2],
            };
            let envelope = DeliveryEnvelope {
                recipient: veil_proto::recipient::Recipient::any([0xB3; 32]),
                sender_node_id: [0xB4; 32],
                src_app_id: [0xB5; 32],
                app_id: [0xB6; 32],
                endpoint_id: 1,
                content_id: [index as u8 + 1; 32],
                created_at: 1,
                ttl_secs: 30,
                payload: chunk.encode(),
                trace_id: 0,
                require_ack: false,
            };
            let body = ForwardPayload {
                next_hop_node_id: [0xB7; 32],
                envelope,
                relay_hops: 0,
                delivery_attempt: None,
                traffic_class: None,
            }
            .encode();
            let mut header =
                FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
            header.body_len = body.len() as u32;
            veil_proto::codec::encode_frame(&header, &body)
        };
        let frames: Vec<_> = (0..4).map(make_frame).collect();
        let mut reassembler = EnvelopeChunkReassembler::new();

        // First attempt arrives reordered and loses index 2 after the relay;
        // 3,0,1 remain buffered.
        for index in [3usize, 0, 1] {
            let fwd = ForwardPayload::decode(&frames[index][veil_proto::HEADER_SIZE..]).unwrap();
            let chunk = ChunkedEnvelopePayload::decode(&fwd.envelope.payload).unwrap();
            assert!(matches!(
                reassembler.add(&fwd.envelope, fwd.envelope.sender_node_id, chunk, 100),
                AddChunkResult::Pending
            ));
        }

        let mut completed = 0;
        let mut replayed_tail = 0;
        for (index, frame) in frames.iter().enumerate() {
            let retried = prepare_ack_retransmit_frame(frame, [0xC1; 32], 2).unwrap();
            let fwd = ForwardPayload::decode(&retried[veil_proto::HEADER_SIZE..]).unwrap();
            assert_ne!(fwd.envelope.content_id, [index as u8 + 1; 32]);
            let chunk = ChunkedEnvelopePayload::decode(&fwd.envelope.payload).unwrap();
            match reassembler.add(&fwd.envelope, fwd.envelope.sender_node_id, chunk, 101) {
                AddChunkResult::Complete(envelope) => {
                    completed += 1;
                    assert_eq!(envelope.content_id, original_id);
                    assert_eq!(envelope.payload, vec![0, 0, 1, 1, 2, 2, 3, 3]);
                }
                AddChunkResult::CompletedReplay(id) => {
                    replayed_tail += 1;
                    assert_eq!(id, original_id);
                }
                AddChunkResult::Pending | AddChunkResult::Rejected("duplicate chunk") => {}
                other => panic!("unexpected retry outcome: {other:?}"),
            }
        }
        assert_eq!(completed, 1);
        assert_eq!(replayed_tail, 1);
        assert_eq!(reassembler.transfer_count(), 0);
        assert_eq!(reassembler.buffered_bytes(), 0);
    }

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

        rendezvous_register_publisher_with_kem(&state, &relay, cookie, 3600, 1, kem.clone(), 0);
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
        rendezvous_register_publisher_with_kem(&state, &relay, cookie, 3600, 1, kem.clone(), 0);

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

        let out = replicas_from_freshest_ads(vec![old_generation.clone(), current], 8);
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

    // ── builtin-seed policy: alternative entry points ────────────────────
    //
    // The seeds are the only entry points a stock binary knows. When they are
    // blocked the operator's answer is to name other hosts — but naming them
    // used to switch the seeds OFF, so the node swapped one single point of
    // failure for another. These pin the policy that lets it hold both.

    fn row(source: crate::types::PeerSource, node: u8, transport: &str) -> PeerConfigEntry {
        PeerConfigEntry {
            peer_id: PeerId::new(7),
            node_id: veil_cfg::NodeId::from([node; 32]),
            public_key: String::new(),
            nonce: String::new(),
            transport: transport.to_owned(),
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            bootstrap_only: false,
            source,
        }
    }

    fn listener(uri: &str, advertise: Option<&str>) -> veil_cfg::ListenConfig {
        veil_cfg::ListenConfig {
            id: crate::types::ListenId::new(1),
            transport: uri.to_owned(),
            advertise: advertise.map(str::to_owned),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            relay: None,
            ..Default::default()
        }
    }

    /// A 32-byte key and 4-byte nonce, base64, as the identity carries them.
    fn identity_b64() -> (String, String) {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        (b64.encode([7u8; 32]), b64.encode([1u8, 2, 3, 4]))
    }

    fn announce_for_listeners(
        listeners: Vec<veil_cfg::ListenConfig>,
    ) -> Option<veil_bootstrap::LanAnnounce> {
        let (key, nonce) = identity_b64();
        let mut c = veil_cfg::Config::default();
        c.listen = listeners;
        lan_announce_for(&c, &key, &nonce, &[])
    }

    fn address_for_listeners(uris: &[(&str, Option<&str>)]) -> Option<(String, u16)> {
        let mut c = veil_cfg::Config::default();
        c.listen = uris.iter().map(|(u, a)| listener(u, *a)).collect();
        public_address_for(&c, &[])
    }

    #[test]
    fn exactly_one_side_of_a_pair_places_the_call() {
        use veil_bootstrap::DiscoveredPeerCache;
        use veil_cfg::{NodeId, SignatureAlgorithm};

        // A pair dials one way: `ours < theirs`. `outbound_connector` has
        // always honoured that; the rendezvous dial went straight to
        // `connect_peer_active` and never did, so both ends called each other
        // at every pass. Measured on a production seed with the largest id:
        // 24 dials in 54 minutes, every one refused as a duplicate.
        let key = "fyU1fAlyHVNMat6NZBJ+KBU/aeJhCP+OBsomlgJ1Cjo=";
        let theirs = NodeId::from_public_key(SignatureAlgorithm::Ed25519, key).expect("valid");
        let addr = "obfs4-tcp://198.51.100.7:5556";

        let mut c = DiscoveredPeerCache::in_memory();
        c.upsert(
            veil_cfg::BootstrapPeer {
                transport: addr.to_owned(),
                public_key: key.to_owned(),
                nonce: "AOCZRA==".to_owned(),
                algo: SignatureAlgorithm::Ed25519,
                tls_cert: None,
                tls_ca_cert: None,
            },
            1_700_000_000,
        );
        let cache = Arc::new(std::sync::Mutex::new(c));

        let mut smaller = *theirs.as_bytes();
        smaller[0] = smaller[0].wrapping_sub(1);
        let mut larger = *theirs.as_bytes();
        larger[0] = larger[0].wrapping_add(1);

        assert!(
            we_should_place_the_call(&smaller, &cache, addr),
            "the smaller id must call, or nobody does"
        );
        assert!(
            !we_should_place_the_call(&larger, &cache, addr),
            "the larger id called anyway; its dial is refused as a duplicate \
             and the working session goes down around the refusal"
        );

        // A first meeting has no mapping, and somebody has to call or the
        // mapping is never learned at all.
        let empty = Arc::new(std::sync::Mutex::new(DiscoveredPeerCache::in_memory()));
        assert!(we_should_place_the_call(&larger, &empty, addr));
        // An address the cache knows nothing about is a first meeting too.
        assert!(we_should_place_the_call(
            &larger,
            &cache,
            "obfs4-tcp://203.0.113.9:5556"
        ));
        // Nothing dialable, nothing to decide.
        assert!(!we_should_place_the_call(
            &smaller,
            &cache,
            "no-scheme-here"
        ));
    }

    #[test]
    fn a_refused_duplicate_is_an_answer_and_keeps_its_row() {
        // The producer and the reader of this refusal live in different files,
        // and the reader matches on the text. Pin them together, or a reworded
        // message turns "you already have this peer" back into "retry next
        // pass" -- which is the loop that was measured.
        let produced = include_str!("peer_handshake.rs");
        assert!(
            produced.contains("{DUPLICATE_SESSION} to node"),
            "the refusal no longer carries the shared marker"
        );
        let reader = production_source(include_str!("service_tasks.rs"));
        assert!(
            reader.contains("refusal.contains(crate::runtime::peer_handshake::DUPLICATE_SESSION)"),
            "the rendezvous dial no longer recognises the refusal"
        );
        // And the row survives it: removing it is what made the next pass
        // dial the same peer again.
        let at = reader
            .find("let refusal = format!(\"{e}\");")
            .expect("the failure arm is gone; this guard is stale");
        let arm = &reader[at..];
        let recognise = arm
            .find("DUPLICATE_SESSION")
            .expect("the failure arm no longer recognises a duplicate");
        let remove = arm
            .find("peers.remove(&peer_id)")
            .expect("the failure arm no longer removes anything; guard is stale");
        assert!(
            recognise < remove,
            "the row is removed before the duplicate case is recognised, so the \
             next pass dials the same peer again"
        );
    }

    /// The file WITHOUT its test module.
    ///
    /// A guard that greps its own file finds its own assertion string and
    /// passes no matter what the production code does. That is not a
    /// hypothetical: the first version of the algorithm guard below did
    /// exactly this, and the break-check that should have reddened stayed
    /// green.
    /// The slot alone, for the assertions that only care WHICH one.
    fn rendezvous_slot_for(known: &[PeerConfigEntry], transport: &str) -> Option<PeerId> {
        rendezvous_slot_claim(known, transport).map(RendezvousSlot::peer_id)
    }

    fn production_source(file: &str) -> &str {
        file.split("#[cfg(test)]").next().unwrap_or(file)
    }

    /// report20 V18-M4: an entry that can never be published takes no slot.
    ///
    /// The slots are bounded and the publish tick signs what is in them, so an
    /// entry the signer refuses costs a slot a working publisher could have
    /// had — silently, because the refusal lands later, on a tick, in a log
    /// line nobody reads, while the registration answered "registered".
    #[test]
    fn an_entry_the_signer_would_refuse_never_takes_a_slot() {
        use veil_anonymity::rendezvous::{
            MAX_PUSH_ENVELOPE_LEN, MAX_RENDEZVOUS_KEM_PK_LEN, MAX_VALIDITY_WINDOW_SECS,
            MAX_WAKE_HMAC_ENVELOPE_LEN,
        };
        let base = || veil_anonymity::rendezvous::RendezvousPublisherEntry {
            rendezvous_node_id: [3; 32],
            auth_cookie: [3; 16],
            validity_window_secs: 3600,
            push_envelope: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            rendezvous_kem_valid_until_unix: 0,
            ephemeral_ad_identity: None,
        };

        // Vacuity first: the ordinary entry is admitted, or every refusal
        // below is passing on a function that refuses everything.
        let mut entries = Vec::new();
        assert!(
            insert_publisher_entry(&mut entries, base()),
            "a publishable entry was refused"
        );
        assert_eq!(entries.len(), 1);

        let unpublishable: Vec<(&str, veil_anonymity::rendezvous::RendezvousPublisherEntry)> = vec![
            ("a window of zero is expired the moment it is signed", {
                let mut e = base();
                e.validity_window_secs = 0;
                e
            }),
            ("a window past the signer's cap", {
                let mut e = base();
                e.validity_window_secs = MAX_VALIDITY_WINDOW_SECS + 1;
                e
            }),
            ("a push envelope past the cap", {
                let mut e = base();
                e.push_envelope = vec![0u8; MAX_PUSH_ENVELOPE_LEN + 1];
                e
            }),
            ("a wake envelope past the cap", {
                let mut e = base();
                e.wake_hmac_envelope = vec![0u8; MAX_WAKE_HMAC_ENVELOPE_LEN + 1];
                e
            }),
            ("a relay key past the cap", {
                let mut e = base();
                e.rendezvous_kem_algo = 1;
                e.rendezvous_kem_pk = vec![0u8; MAX_RENDEZVOUS_KEM_PK_LEN + 1];
                e
            }),
            ("an algorithm named with no key behind it", {
                let mut e = base();
                e.rendezvous_kem_algo = 1;
                e
            }),
        ];

        for (why, entry) in unpublishable {
            // A DIFFERENT (relay, cookie) each time, so a refusal cannot be
            // mistaken for the replace path.
            let mut entry = entry;
            entry.rendezvous_node_id = [9; 32];
            let mut fresh = Vec::new();
            assert!(
                !insert_publisher_entry(&mut fresh, entry),
                "{why}: it was registered anyway"
            );
            assert!(fresh.is_empty(), "{why}: it took a slot anyway");
        }

        // And the clock-dependent one, which the admission does not judge
        // because it has no clock: a relay stamp already in the past makes
        // every tick refuse the ad.
        let mut stale = base();
        stale.rendezvous_kem_algo = 1;
        stale.rendezvous_kem_pk = vec![7u8; 32];
        stale.rendezvous_kem_valid_until_unix = 1_000;
        assert!(
            publisher_entry_is_publishable(&stale, 2_000).is_err(),
            "a relay key whose stamp has passed was called publishable"
        );
        assert!(
            publisher_entry_is_publishable(&stale, 0).is_ok(),
            "with no clock offered, the stamp is not judged"
        );
        assert!(
            publisher_entry_is_publishable(&stale, 500).is_ok(),
            "a stamp still in the future is fine"
        );
    }

    /// report21 V18-L1: every registration goes through the one admission.
    ///
    /// `NodeRuntime::register_rendezvous_publisher_with_push` kept its own copy
    /// of "replace or push", so it kept none of what the shared helper had been
    /// taught: it pushed past the slot bound (an entry past it is cloned on
    /// every publish tick and never signed), and its replace overwrote the KEM
    /// key with the empty one it registers with — the erasure the helper exists
    /// to prevent, arriving through a different door.
    #[test]
    fn the_runtime_registration_uses_the_bounded_admission() {
        let src = include_str!("../runtime/mod.rs");
        let f = src
            .split("pub fn register_rendezvous_publisher_with_push")
            .nth(1)
            .and_then(|t| t.split("\n    ///").next())
            .expect("the registration");
        assert!(
            f.contains("insert_publisher_entry(&mut entries, entry)"),
            "the registration keeps its own admission again, so the slot bound \
             and the KEM-preservation rule do not apply to it"
        );
        assert!(
            !f.contains("entries.push(entry)"),
            "an entry is pushed past the slot bound: it is cloned on every \
             publish tick and never signed"
        );

        // And setting a relay key moves its expiry with it, or a fresh key is
        // advertised under the lifetime of the one it replaced.
        let setter = src
            .split("pub fn set_rendezvous_relay_kem")
            .nth(1)
            .and_then(|t| t.split("\n    ///").next())
            .expect("the relay-key setter");
        assert!(
            setter.contains("entry.rendezvous_kem_valid_until_unix = 0;"),
            "a rotated relay key keeps the previous key's expiry"
        );
    }

    /// report20 V18-M13: a refused publisher slot must stop the relay from
    /// being counted as one we are reachable through.
    ///
    /// `insert_publisher_entry` returns whether the entry actually took a
    /// slot, and the re-pick loop threw that answer away: the relay went into
    /// `registered`, `current` could become a relay carrying NO ad, and the
    /// node then sat at a meeting point no sender was ever told about. There
    /// is no seam to call this loop through — it wants a live session
    /// registry, a DHT and an outbox — so the guard is on the source: the
    /// answer has to be read.
    #[test]
    fn the_repick_loop_reads_the_publisher_slot_answer() {
        let src = production_source(include_str!("service_tasks.rs"));
        // The definition itself matches the same shape; only CALLS count.
        let calls = src.matches("rendezvous_register_publisher(\n").count()
            - src.matches("fn rendezvous_register_publisher(\n").count();
        assert!(
            calls >= 1,
            "the re-pick loop no longer registers a publisher at all; this \
             guard is now vacuous and has to be re-aimed"
        );
        assert_eq!(
            src.matches("if !rendezvous_register_publisher(\n").count(),
            calls,
            "a call to rendezvous_register_publisher ignores its answer: a \
             refused slot means no ad, and the relay must not be counted as \
             one this node is reachable through"
        );
    }

    #[test]
    fn a_peer_is_recorded_under_the_algorithm_it_proved() {
        use veil_cfg::SignatureAlgorithm;
        // Ed25519 was written down as fact for every peer met at a meeting
        // point. The node id the direction rule compares derives from the key
        // and its algorithm, so a mislabelled Falcon peer puts the pair back to
        // both ends dialling each other.
        for proved in [SignatureAlgorithm::Ed25519, SignatureAlgorithm::Falcon512] {
            assert_eq!(
                proven_algorithm(Some(proved)),
                proved,
                "the handshake proved {proved:?} and the row said otherwise"
            );
        }
        // An algorithm this build cannot name still yields a session; the row
        // takes the historical default rather than the peer being dropped.
        assert_eq!(proven_algorithm(None), SignatureAlgorithm::Ed25519);

        // And the value actually travels: handshake -> session -> row.
        let hs = include_str!("peer_handshake.rs");
        assert!(
            hs.contains("pub algo: Option<veil_cfg::SignatureAlgorithm>"),
            "the handshake no longer carries the proved algorithm"
        );
        assert!(
            hs.contains("peer_algo: remote_identity.algo"),
            "the session no longer receives the proved algorithm"
        );
        let here = production_source(include_str!("service_tasks.rs"));
        assert!(
            here.contains("proven_algorithm(session.peer_algo)"),
            "the row no longer asks what was proved"
        );
    }

    /// A bootstrap dial that could not ask for contacts must SAY so.
    ///
    /// A rendezvous peer is dialled for exactly one reason: to be asked for
    /// contacts, and then broken. The ask is spawned behind a wait for the
    /// session outbox, so a session that ends first takes the ask with it —
    /// no contacts, no peers, and the node then reports itself connected with
    /// zero peers for the rest of the process, which reads exactly like having
    /// no network at all.
    ///
    /// Measured on a fresh identity with nothing configured: three seeds
    /// dialled, three sessions opened and closed inside the same millisecond,
    /// and not one `bootstrap.find_node_done` line — the burst was skipped and
    /// nothing recorded that it had been.
    #[test]
    fn a_bootstrap_burst_that_never_ran_leaves_a_trace() {
        let src = production_source(include_str!("../outbound_connector.rs"));
        assert!(
            src.contains("bootstrap.find_node_skipped"),
            "a bootstrap dial that lost its session before it could ask for \
             contacts is silent again, and silence there is indistinguishable \
             from a node that simply has no peers"
        );
        let at = src
            .find("bootstrap.find_node_skipped")
            .expect("checked above");

        // And it has to be REACHABLE. A line behind `if false` reads exactly
        // like a line behind the real condition, and the first version of this
        // test could not tell them apart: it asked whether the string was in
        // the file, which is existence, not a decision.
        let condition = src[..at]
            .rmatch_indices("if ")
            .map(|(i, _)| src[i..].lines().next().unwrap_or_default())
            .next()
            .expect("no condition governs the skip");
        assert!(
            condition.contains("registered"),
            "the skip is governed by `{}` rather than by whether the session \
             ever registered, so it cannot fire for the case it exists for",
            condition.trim()
        );

        // The skip has to END the task. Falling through to `find_node` on a
        // session that is gone logs `find_node_done contacts_received=0`,
        // which says the peer answered with nothing — a different and wrong
        // story about the same failure.
        let after = &src[at..];
        let ret = after.find("return;").unwrap_or(usize::MAX);
        let ask = after.find("querier.find_node").unwrap_or(usize::MAX);
        assert!(
            ret < ask,
            "the skipped burst falls through and asks anyway, so an ask that \
             could not happen is reported as a peer that answered with nothing"
        );
    }

    /// `session.close` says only THAT a session ended, never why or for how
    /// long, and it is written by our own teardown after `run()` returns — so
    /// a far end that hung up and an orderly local wind-down produce the same
    /// line. The lifetime is what separates them, and separating them is the
    /// whole diagnosis for a bootstrap dial that taught us nothing.
    #[test]
    fn a_session_says_how_long_it_lived() {
        let src = production_source(include_str!("../outbound_connector.rs"));
        assert!(
            src.contains("\"session.ended\""),
            "the session lifetime is unrecorded again"
        );
        assert!(
            src.contains("lived_ms="),
            "session.ended no longer carries the one field it exists for"
        );
    }

    /// report21 V20-M7a: a failed dial retires ITS OWN placeholder and
    /// nothing else.
    ///
    /// The lock that claims the slot is let go before the dial. The other
    /// meeting-point pass can take the same address in that window, complete
    /// a handshake and write a proven row into the same id — and the rollback
    /// removed the row by id regardless, deleting a peer somebody is talking
    /// to on the strength of a dial that was ours.
    #[test]
    fn a_failed_dial_retires_only_the_row_it_minted() {
        let transport = "obfs4-tcp://198.51.100.7:5556";
        let placeholder = veil_cfg::NodeId::from(*blake3::hash(transport.as_bytes()).as_bytes());
        let mine = PeerConfigEntry {
            peer_id: PeerId::new(0x9200_0000),
            node_id: placeholder,
            public_key: String::new(),
            nonce: String::new(),
            transport: transport.to_owned(),
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            bootstrap_only: true,
            source: crate::types::PeerSource::Rendezvous,
        };

        assert!(
            rendezvous_row_is_our_placeholder(Some(&mine), &placeholder, transport),
            "vacuity: the row this dial minted must be retirable, or a failed \
             dial leaves a slot claimed forever"
        );

        // The other pass got there first and proved who is at that address.
        let mut proven = mine.clone();
        proven.node_id = veil_cfg::NodeId::from([0xAB; 32]);
        proven.public_key = "their-key".to_owned();
        proven.bootstrap_only = false;
        assert!(
            !rendezvous_row_is_our_placeholder(Some(&proven), &placeholder, transport),
            "a proven row written by the other pass was deleted by our failure"
        );

        // A key alone is enough: a row that learned an identity is not ours.
        let mut keyed = mine.clone();
        keyed.public_key = "their-key".to_owned();
        assert!(!rendezvous_row_is_our_placeholder(
            Some(&keyed),
            &placeholder,
            transport
        ));

        // The slot was reclaimed for a DIFFERENT address while we waited.
        let mut elsewhere = mine.clone();
        elsewhere.transport = "obfs4-tcp://203.12.31.146:5556".to_owned();
        elsewhere.node_id =
            veil_cfg::NodeId::from(*blake3::hash(elsewhere.transport.as_bytes()).as_bytes());
        assert!(
            !rendezvous_row_is_our_placeholder(Some(&elsewhere), &placeholder, transport),
            "another pass's claim on this slot was retired by our failure"
        );

        // And a slot already empty has nothing to retire.
        assert!(!rendezvous_row_is_our_placeholder(
            None,
            &placeholder,
            transport
        ));
    }

    #[test]
    fn a_rendezvous_address_keeps_its_slot_across_passes() {
        use crate::types::synthetic_peer_id::{RENDEZVOUS_BASE, RENDEZVOUS_WINDOW};

        fn rz(id: u32, transport: &str) -> PeerConfigEntry {
            PeerConfigEntry {
                peer_id: PeerId::new(id),
                node_id: veil_cfg::NodeId::from([id as u8; 32]),
                public_key: "k".to_owned(),
                nonce: "n".to_owned(),
                transport: transport.to_owned(),
                algo: veil_cfg::SignatureAlgorithm::Ed25519,
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                bootstrap_only: false,
                source: crate::types::PeerSource::Rendezvous,
            }
        }

        // THE defect. The slot was `BASE + taken`, and `taken` restarted every
        // pass: whoever was dialled first took `BASE + 0` and overwrote the
        // row of whoever held it. The overwritten peer's connector then found
        // no row for its node_id, exited, and dropped a live session -- two
        // seeds rebuilt their link every few seconds because of it.
        let a = "obfs4-tcp://198.51.100.7:5556";
        let b = "obfs4-tcp://198.51.100.8:5556";
        let first = rendezvous_slot_for(&[], a).expect("an empty table has room");
        let known = vec![rz(first.get(), a)];
        assert_eq!(
            rendezvous_slot_for(&known, a),
            Some(first),
            "the same address took a different slot on a later pass; the row it \
             overwrites belongs to a peer whose session then dies"
        );
        assert_ne!(
            rendezvous_slot_for(&known, b),
            Some(first),
            "a second address was handed the slot the first one is using"
        );

        // The scheme is ours to choose and must not decide identity.
        assert_eq!(
            rendezvous_slot_for(&known, "tcp://198.51.100.7:5556"),
            Some(first)
        );
        // A neighbour that merely looks similar is a different peer.
        for near in [
            "obfs4-tcp://198.51.100.70:5556",
            "obfs4-tcp://198.51.100.7:55560",
        ] {
            assert_ne!(
                rendezvous_slot_for(&known, near),
                Some(first),
                "{near} was given the slot of 198.51.100.7:5556"
            );
        }

        // A row OUTSIDE the window belongs to another allocator and must not
        // be reused, however well its address matches. (That it also does not
        // occupy a slot is true by construction rather than by this check --
        // it cannot fall inside the range being scanned.)
        let foreign = vec![rz(0xD100_0000, a)];
        let fresh = rendezvous_slot_for(&foreign, a).expect("room");
        assert!(
            (RENDEZVOUS_BASE..RENDEZVOUS_BASE + RENDEZVOUS_WINDOW).contains(&fresh.get()),
            "allocated outside the rendezvous window"
        );

        // A full window REFUSES rather than evicting a peer we may be talking
        // to -- the whole failure being fixed here is an overwrite.
        let full: Vec<PeerConfigEntry> = (0..RENDEZVOUS_WINDOW)
            .map(|i| {
                rz(
                    RENDEZVOUS_BASE + i,
                    &format!("obfs4-tcp://198.51.100.7:{}", 6000 + i),
                )
            })
            .collect();
        assert_eq!(
            rendezvous_slot_for(&full, "obfs4-tcp://203.0.113.9:5556"),
            None,
            "a full window handed out a slot that is in use"
        );
        // ...but an address already in a full window still finds its own row.
        assert_eq!(
            rendezvous_slot_for(&full, "obfs4-tcp://198.51.100.7:6000"),
            Some(PeerId::new(RENDEZVOUS_BASE))
        );

        // A full window of rows that never learned an identity is a different
        // matter: those are refused duplicates, kept only so the address is not
        // dialled again. Enough aliases for one host would otherwise wall the
        // window off for the life of the process, so the lowest one yields.
        let tombstones: Vec<PeerConfigEntry> = (0..RENDEZVOUS_WINDOW)
            .map(|i| {
                let mut r = rz(
                    RENDEZVOUS_BASE + i,
                    &format!("obfs4-tcp://198.51.100.7:{}", 6000 + i),
                );
                r.public_key = String::new();
                r
            })
            .collect();
        assert_eq!(
            rendezvous_slot_for(&tombstones, "obfs4-tcp://203.0.113.9:5556"),
            Some(PeerId::new(RENDEZVOUS_BASE)),
            "a window full of identity-less rows refused a new peer forever"
        );
        // A single row WITH an identity is never the one taken: something
        // completed a handshake with it and may be holding that session.
        let mut mixed = tombstones.clone();
        mixed[0] = rz(RENDEZVOUS_BASE, "obfs4-tcp://198.51.100.7:6000");
        assert_eq!(
            rendezvous_slot_for(&mixed, "obfs4-tcp://203.0.113.9:5556"),
            Some(PeerId::new(RENDEZVOUS_BASE + 1)),
            "a row that had proved an identity was reclaimed"
        );

        // Something unparseable gets nothing rather than slot zero.
        assert_eq!(rendezvous_slot_for(&[], "no-scheme-here"), None);

        // AND THE CALLER HAS TO KNOW WHICH OF THE THREE IT GOT. The number
        // alone reads a reclaimed slot as an occupied one, so the row keeps
        // the previous tenant's address, the dial goes to a URI nobody asked
        // for, and whoever answers THAT is written down beside the address we
        // meant to call (report21 V20-M7b).
        assert_eq!(
            rendezvous_slot_claim(&known, a),
            Some(RendezvousSlot::Held(first)),
            "a row already holding this address must be dialled as it stands"
        );
        assert!(
            matches!(
                rendezvous_slot_claim(&known, b),
                Some(RendezvousSlot::Free(_))
            ),
            "a new address in a window with room takes a free slot"
        );
        assert_eq!(
            rendezvous_slot_claim(&tombstones, "obfs4-tcp://203.0.113.9:5556"),
            Some(RendezvousSlot::Reclaimed(PeerId::new(RENDEZVOUS_BASE))),
            "a slot taken from an identity-less row is indistinguishable from \
             one that already held this address"
        );
        assert_eq!(
            rendezvous_slot_claim(&full, "obfs4-tcp://203.0.113.9:5556"),
            None
        );
    }

    #[test]
    fn an_address_a_stranger_named_is_not_dialled_into_this_network() {
        // A meeting point is an open index. The address in a record is
        // whatever its author wrote, and a DHT node answers with whatever it
        // likes, so without this a stranger could aim this host's dial at
        // loopback, at the machine next to it, or at a cloud metadata
        // endpoint. The handshake fails either way -- but which ports answered
        // is the answer they were after, and our host did the probing.
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.54",
            "172.16.0.1",
            "169.254.169.254", // the cloud metadata address
            "100.64.0.1",      // carrier NAT
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "203.0.113.9", // documentation range
            "::1",
            "[fe80::1]",
            "[fc00::1]",
            "veil.example.com", // a NAME resolves later, and could resolve anywhere
            // The SAME addresses written in the other notation. A v4 address
            // wearing a v6 coat is a v4 address, and none of the v6 rules look
            // at the octets it carries — so every one of the refusals above
            // could be had simply by spelling it this way (report21 V20-M1a).
            "[::ffff:127.0.0.1]",
            "[::ffff:10.1.2.3]",
            "[::ffff:192.168.1.54]",
            "[::ffff:169.254.169.254]",
            "[::ffff:100.64.0.1]",
            "[::ffff:0.0.0.0]",
            "[::ffff:224.0.0.1]",
            // ::a.b.c.d, the deprecated compatible form, carries the same
            // address without the ffff to key off.
            "[::127.0.0.1]",
            "[::10.1.2.3]",
            // Documentation and NAT64: neither is a host on this internet.
            "[2001:db8::1]",
            "[64:ff9b::7f00:1]",
        ] {
            assert!(
                !rendezvous_destination_is_dialable(private),
                "{private} was accepted from a public meeting point"
            );
        }

        // ...and a real public address still is, or the layer finds nobody.
        for public in [
            "8.8.8.8",
            "203.12.31.146",
            "1.1.1.1",
            "[2001:4860:4860::8888]",
            // A mapped PUBLIC address is still public: the normalisation must
            // not refuse everything it touches.
            "[::ffff:8.8.8.8]",
            "[::ffff:203.12.31.146]",
        ] {
            assert!(
                rendezvous_destination_is_dialable(public),
                "{public} is a public address and was refused"
            );
        }
    }

    #[test]
    fn a_node_does_not_dial_its_own_announcement() {
        // Found live, on layer 8's first real run: the node announced itself,
        // read its own record back on the same pass, dialled its own listener
        // and sat out the full ten-second handshake timeout -- then logged the
        // result as a peer that could not be reached. Every fifteen minutes,
        // for as long as the node runs.
        let me = ("203.0.113.9".to_owned(), 5556);
        assert!(rendezvous_address_is_self(
            Some(&me),
            "obfs4://203.0.113.9:5556"
        ));
        // The scheme is ours to choose, so it must not decide this.
        assert!(rendezvous_address_is_self(
            Some(&me),
            "tcp://203.0.113.9:5556"
        ));
        assert!(rendezvous_address_is_self(
            Some(&me),
            "ws://203.0.113.9:5556/veil"
        ));

        // A different port on the same host is a different node -- two nodes
        // behind one address is an ordinary way to run them.
        assert!(!rendezvous_address_is_self(
            Some(&me),
            "obfs4://203.0.113.9:5557"
        ));
        assert!(!rendezvous_address_is_self(
            Some(&me),
            "obfs4://203.0.113.8:5556"
        ));
        // A host that merely CONTAINS ours, or is contained by it, is not
        // ours -- in both directions, because a prefix test reads as correct
        // and is wrong on one side each way. `.90` and `.9` are neighbours on
        // a real subnet, and mistaking one for this node makes it invisible.
        for near in [
            "obfs4://203.0.113.99:5556",
            "obfs4://1203.0.113.9:5556",
            "obfs4://203.0.113.9:55560",
        ] {
            assert!(
                !rendezvous_address_is_self(Some(&me), near),
                "{near} was mistaken for this node and skipped"
            );
        }
        let long = ("203.0.113.90".to_owned(), 5556);
        assert!(
            !rendezvous_address_is_self(Some(&long), "obfs4://203.0.113.9:5556"),
            "a neighbour whose address is a prefix of ours was skipped as us"
        );
        assert!(
            !rendezvous_address_is_self(Some(&me), "obfs4://203.0.113.90:5556"),
            "a neighbour whose address extends ours was skipped as us"
        );

        let v6 = ("2001:db8::1".to_owned(), 5556);
        assert!(rendezvous_address_is_self(
            Some(&v6),
            "obfs4://[2001:db8::1]:5556"
        ));

        // A node with no address of its own recognises nothing, rather than
        // everything: this must never become a filter that skips real peers.
        for any in [
            "obfs4://203.0.113.9:5556",
            "obfs4://198.51.100.1:5556",
            "nonsense",
        ] {
            assert!(!rendezvous_address_is_self(None, any));
        }
    }

    fn listener_seen_as(uri: &str, visibility: veil_cfg::Visibility) -> veil_cfg::ListenConfig {
        let mut l = listener(uri, None);
        l.visibility = visibility;
        l
    }

    #[test]
    fn a_listener_the_operator_hid_is_not_offered_at_a_meeting_point() {
        use veil_cfg::Visibility;
        // `build_advertised_transports` states the contract: "Trusted and
        // Hidden listeners stay invisible on the network -- peers learn about
        // them only through invite-bundles." A meeting point is the most public
        // index there is. Stealth is not even bound at startup, so publishing
        // it would advertise a port that answers nobody.
        let (key, nonce) = identity_b64();
        for hidden in [Visibility::Trusted, Visibility::Hidden, Visibility::Stealth] {
            let mut c = veil_cfg::Config::default();
            c.listen = vec![listener_seen_as(
                "obfs4-tcp://203.0.113.9:5556",
                hidden.clone(),
            )];
            assert_eq!(
                public_address_for(&c, &[]),
                None,
                "a {hidden:?} listener was offered as this node's public address"
            );
            assert!(
                lan_announce_for(&c, &key, &nonce, &[]).is_none(),
                "a {hidden:?} listener was announced on the local network"
            );
        }

        // Public still works, or the gate would silence every layer.
        let mut c = veil_cfg::Config::default();
        c.listen = vec![listener_seen_as(
            "obfs4-tcp://203.0.113.9:5556",
            Visibility::Public,
        )];
        assert_eq!(
            public_address_for(&c, &[]),
            Some(("203.0.113.9".to_owned(), 5556))
        );
        assert!(lan_announce_for(&c, &key, &nonce, &[]).is_some());

        // A hidden listener does not veto a public one standing behind it.
        let mut c = veil_cfg::Config::default();
        c.listen = vec![
            listener_seen_as("obfs4-tcp://198.51.100.1:5556", Visibility::Hidden),
            listener_seen_as("obfs4-tcp://203.0.113.9:5557", Visibility::Public),
        ];
        assert_eq!(
            public_address_for(&c, &[]),
            Some(("203.0.113.9".to_owned(), 5557)),
            "the hidden listener hid the public one behind it"
        );
    }

    #[test]
    fn a_node_never_publishes_an_address_that_is_true_only_where_it_stands() {
        // Layers 6 and 7 observe the host from the packet. A relay does not
        // tell us ours and must not be asked to, so this is the one place the
        // node claims its own address -- and a claim of `0.0.0.0` would list
        // it at a rendezvous while being unreachable from every one of them,
        // which reads in the log exactly like a node that is listed and fine.
        for bad in [
            "obfs4://0.0.0.0:5556",
            "obfs4://127.0.0.1:5556",
            "obfs4://localhost:5556",
            "obfs4://[::]:5556",
            "obfs4://[::1]:5556",
            "obfs4://1.2.3.4:0",
            "obfs4://:5556",
            "not-a-uri",
        ] {
            assert_eq!(
                address_for_listeners(&[(bad, None)]),
                None,
                "{bad} was offered to strangers as this node's address"
            );
        }

        assert_eq!(
            address_for_listeners(&[("obfs4://203.0.113.9:5556", None)]),
            Some(("203.0.113.9".to_owned(), 5556)),
            "a listener with a real address was not usable"
        );
        // `advertise` wins: the bind address is where the socket is, the
        // advertised one is where the world can reach it, and behind NAT they
        // are not the same string.
        assert_eq!(
            address_for_listeners(&[("obfs4://0.0.0.0:5556", Some("obfs4://203.0.113.9:443"))]),
            Some(("203.0.113.9".to_owned(), 443)),
            "the bind address was published instead of the advertised one"
        );
        // An unusable listener does not veto a usable one behind it -- and
        // once per REASON it can be unusable, because "skip" and "give up" are
        // one keyword apart and each branch has its own.
        for first in [
            "obfs4://0.0.0.0:5556",
            "obfs4://127.0.0.1:5556",
            "obfs4://203.0.113.7:0",
            "obfs4://:5556",
            "obfs4://203.0.113.7:not-a-port",
            "no-scheme-here",
        ] {
            assert_eq!(
                address_for_listeners(&[(first, None), ("obfs4://203.0.113.9:5556", None)]),
                Some(("203.0.113.9".to_owned(), 5556)),
                "a listener of {first} hid the usable one after it"
            );
        }
        // Paths and IPv6 brackets both survive the split.
        assert_eq!(
            address_for_listeners(&[("ws://203.0.113.9:8080/veil", None)]),
            Some(("203.0.113.9".to_owned(), 8080))
        );
        assert_eq!(
            address_for_listeners(&[("obfs4://[2001:db8::1]:5556", None)]),
            Some(("2001:db8::1".to_owned(), 5556))
        );
    }

    /// A hundred rounds of announce-and-evict must leave nothing behind.
    ///
    /// The cap counted SLOTS, and reclaiming one deleted only the local
    /// bookkeeping. The row, the DHT contact and the reconnect task the
    /// admission had created all stayed, and the next eight announces reused
    /// the same fixed slots — so an attacker on the broadcast domain added up
    /// to eight more of each every five minutes, without bound, for the life
    /// of the process (report22 V-02).
    #[test]
    fn a_hundred_lan_rounds_leave_no_rows_or_contacts() {
        use crate::types::PeerId;
        let mut peers: std::collections::BTreeMap<PeerId, PeerConfigEntry> = Default::default();
        let mut contacts: std::collections::HashSet<[u8; 32]> = Default::default();
        // Every eviction gives the connector claim back too, synchronously —
        // the abort alone gives it back at some later poll, and a re-admission
        // before then finds the slot held by a task that is dying
        // (report24 RUNTIME-2).
        let mut released: Vec<[u8; 32]> = Vec::new();

        for round in 0..100u32 {
            let mut admitted = Vec::new();
            for slot in 0..MAX_LAN_PEERS as u32 {
                let node_id = [(round as u8).wrapping_add((slot as u8).wrapping_mul(37)); 32];
                let peer_id = PeerId::new(0x9000_0000u32.wrapping_add(slot));
                let mut entry = lan_entry(node_id);
                entry.peer_id = peer_id;
                peers.insert(peer_id, entry);
                contacts.insert(node_id);
                admitted.push(LanCandidate {
                    node_id,
                    slot,
                    admitted: std::time::Instant::now(),
                    peer_id,
                    abort: None,
                });
            }
            assert_eq!(
                peers.len(),
                MAX_LAN_PEERS,
                "round {round}: the admissions themselves are already over the cap"
            );
            for candidate in admitted {
                evict_lan_candidate(
                    &mut peers,
                    candidate,
                    |id| {
                        contacts.remove(id);
                    },
                    |id| {
                        released.push(*id);
                    },
                );
            }
            assert!(
                peers.is_empty(),
                "round {round}: {} row(s) survived their eviction",
                peers.len()
            );
            assert_eq!(
                released.len(),
                MAX_LAN_PEERS,
                "round {round}: {} of the evicted connector claims were left \
                 for the aborted task to give back",
                released.len(),
            );
            released.clear();
            assert!(
                contacts.is_empty(),
                "round {round}: {} contact(s) survived their eviction",
                contacts.len()
            );
        }
    }

    /// The slot is local and gets reused, so eviction must check the OCCUPANT.
    #[test]
    fn eviction_leaves_a_row_that_is_no_longer_ours() {
        use crate::types::PeerId;
        let peer_id = PeerId::new(0x9000_0000);
        let mine = [7u8; 32];
        let someone_else = [9u8; 32];

        let mut peers: std::collections::BTreeMap<PeerId, PeerConfigEntry> = Default::default();
        let mut entry = lan_entry(someone_else);
        entry.peer_id = peer_id;
        peers.insert(peer_id, entry);

        let mut dropped = Vec::new();
        evict_lan_candidate(
            &mut peers,
            LanCandidate {
                node_id: mine,
                slot: 0,
                admitted: std::time::Instant::now(),
                peer_id,
                abort: None,
            },
            |id| dropped.push(*id),
            |_| {},
        );
        assert!(
            peers.contains_key(&peer_id),
            "a stale eviction deleted the row that had already replaced it"
        );
        assert_eq!(
            dropped,
            vec![mine],
            "the contact removed must be the evicted candidate's own"
        );

        // Vacuity: the same shape where the row IS ours does get removed, or
        // the assertion above would hold over a function that removes nothing.
        let mut ours = lan_entry(mine);
        ours.peer_id = peer_id;
        peers.insert(peer_id, ours);
        evict_lan_candidate(
            &mut peers,
            LanCandidate {
                node_id: mine,
                slot: 0,
                admitted: std::time::Instant::now(),
                peer_id,
                abort: None,
            },
            |_| {},
            |_| {},
        );
        assert!(peers.is_empty());
    }

    /// A row a LAN admission would write, with only the fields these rules read.
    fn lan_entry(node_id: [u8; 32]) -> PeerConfigEntry {
        let hex = veil_util::hex_str(&node_id);
        PeerConfigEntry {
            peer_id: crate::types::PeerId::new(0),
            node_id: <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex).unwrap(),
            public_key: String::new(),
            nonce: String::new(),
            transport: String::new(),
            algo: Default::default(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            bootstrap_only: true,
            source: crate::types::PeerSource::Lan,
        }
    }

    /// A candidate with no history: `admit_lan_peer` only counts and dedups.
    fn lan_slot(slot: u32) -> LanCandidate {
        LanCandidate {
            node_id: [slot as u8; 32],
            slot,
            admitted: std::time::Instant::now(),
            peer_id: crate::types::PeerId::new(0),
            abort: None,
        }
    }

    /// report21 V20-M3b: what this node publishes about itself is a public
    /// address, written so a stranger can read it back.
    ///
    /// Two halves. The helper refused only "unspecified or loopback", so a
    /// node whose listener sits on `192.168.1.5` posted that to seven public
    /// relays — a record nobody can use, and this network's shape written down
    /// where anyone can read it. And the helper strips the brackets from a v6
    /// literal, so `{host}:{port}` produced `2001:db8::1:5556`, whose last
    /// colon belongs to the address: every receiver split it in the wrong
    /// place.
    #[test]
    fn what_we_publish_about_ourselves_is_public_and_unambiguous() {
        let listener = |uri: &str| veil_cfg::Config {
            listen: vec![veil_cfg::ListenConfig {
                transport: uri.to_owned(),
                ..Default::default()
            }],
            ..Default::default()
        };

        for inside in [
            "obfs4://192.168.1.5:5556",
            "obfs4://10.0.0.4:5556",
            "obfs4://172.16.9.9:5556",
            "obfs4://169.254.169.254:5556",
            "obfs4://100.64.0.1:5556",
            "obfs4://[fe80::1]:5556",
            "obfs4://[fc00::1]:5556",
            "obfs4://[::ffff:192.168.1.5]:5556",
            "obfs4://localhost:5556",
        ] {
            assert_eq!(
                public_address_for(&listener(inside), &[]),
                None,
                "{inside} would have been published to the public relays"
            );
        }

        // Vacuity: a real public listener is still published, or the node
        // never announces itself anywhere.
        assert_eq!(
            public_address_for(&listener("obfs4://203.12.31.146:5556"), &[]),
            Some(("203.12.31.146".to_owned(), 5556))
        );

        // The helper hands back a BARE v6 host, which is why the publisher has
        // to put the brackets back rather than interpolating.
        let (host, port) = public_address_for(&listener("obfs4://[2001:4860::1]:5556"), &[])
            .expect("a public v6 listener is publishable");
        assert_eq!(host, "2001:4860::1", "premise: the brackets are stripped");
        let published = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => std::net::SocketAddr::new(ip, port).to_string(),
            Err(_) => format!("{host}:{port}"),
        };
        assert_eq!(
            published, "[2001:4860::1]:5556",
            "the published record is ambiguous: its last colon is part of the \
             address, so a receiver splits it in the wrong place"
        );
        // And a receiver reading it back finds the address that was meant.
        let (h, p) = published.rsplit_once(':').expect("a record splits");
        assert_eq!(p, "5556");
        assert!(rendezvous_destination_is_dialable(h), "unreadable by us");
    }

    /// report20 V20-M3: what gets published is the port the listener BOUND.
    ///
    /// Both publishers read the config. A listener configured on port 0 asks
    /// the OS to choose, so there was no port in the config to publish and the
    /// node advertised itself nowhere; an ephemeral listener rotates and the
    /// config goes on naming the port it started on, so every meeting point
    /// held a dead one.
    #[test]
    fn the_port_we_publish_is_the_port_we_bound() {
        let mut c = veil_cfg::Config::default();
        c.listen = vec![veil_cfg::ListenConfig {
            transport: "obfs4://203.0.113.7:0".to_owned(),
            ..Default::default()
        }];
        assert_eq!(
            public_address_for(&c, &[]),
            None,
            "premise: with nothing bound there is no port to publish"
        );

        let bound = vec![("obfs4://203.0.113.7:0".to_owned(), 41337u16)];
        assert_eq!(
            public_address_for(&c, &bound),
            Some(("203.0.113.7".to_owned(), 41337)),
            "an OS-chosen port was never published, so the node advertised \
             itself at no meeting point at all"
        );

        // A rotated listener: the config still names the first port.
        c.listen[0].transport = "obfs4://203.0.113.7:5556".to_owned();
        let rotated = vec![("obfs4://203.0.113.7:5556".to_owned(), 47001u16)];
        assert_eq!(
            public_address_for(&c, &rotated),
            Some(("203.0.113.7".to_owned(), 47001)),
            "the config port was published over the one the listener rotated to"
        );

        // An operator's `advertise` is a claim about the outside world — a
        // published port behind a proxy has nothing to do with the bound one.
        c.listen[0].advertise = Some("obfs4://example.test:443".to_owned());
        assert_eq!(
            public_address_for(&c, &rotated),
            Some(("example.test".to_owned(), 443)),
            "a bound port overrode the address the operator stated"
        );
    }

    /// What is published follows the listener, pass by pass.
    ///
    /// `bound_ports` reading the listener table instead of the config fixed the
    /// startup case — an OS-chosen port was published as zero. Rotation is the
    /// same question later: the discovery tasks computed the announcement once,
    /// before their loop, so a listener that took a new port left them naming
    /// the old one for the life of the process, and it closes when the old
    /// listener's grace ends (report24 RUNTIME-3).
    #[test]
    fn the_announcement_follows_a_listener_that_rotates() {
        use std::sync::{Arc, Mutex};

        let mut c = veil_cfg::Config::default();
        c.listen = vec![veil_cfg::ListenConfig {
            transport: "obfs4-tcp://203.0.113.7:0".to_owned(),
            ..Default::default()
        }];
        let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0x11u8; 32]);
        let nonce =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8, 1, 2, 3]);

        let listen = |addr: &str| crate::types::ListenConfigEntry {
            listen_id: crate::types::ListenId::new(1),
            listener_handle: None,
            transport: "obfs4-tcp://203.0.113.7:0".to_owned(),
            advertise: None,
            relay: None,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            psk_file: None,
            visibility: veil_cfg::Visibility::Public,
            allowlist_node_ids: vec![],
            group_label: None,
            ephemeral: None,
            on_demand: None,
            local_addr: Some(addr.to_owned()),
            active: true,
        };

        let state = Arc::new(Mutex::new(crate::state::NodeState::new(
            veil_cfg::NodeId::from([0xAAu8; 32]),
            crate::types::NodeRole::Core,
            std::path::PathBuf::from("/nonexistent/veil.toml"),
            true,
            std::time::Instant::now(),
            false,
            None,
            vec![],
            vec![listen("obfs4-tcp://203.0.113.7:41337")],
        )));

        let (announce, address) = current_announcement(&state, &c, &key, &nonce);
        assert_eq!(
            address,
            Some(("203.0.113.7".to_owned(), 41337)),
            "premise: the bound port is what is published"
        );
        assert_eq!(announce.map(|a| a.port), Some(41337));

        // The listener rotates: same entry, new bound address.
        {
            let mut st = crate::runtime::lock_state(&state);
            for entry in st.listens.values_mut() {
                entry.local_addr = Some("obfs4-tcp://203.0.113.7:47001".to_owned());
            }
        }

        let (announce, address) = current_announcement(&state, &c, &key, &nonce);
        assert_eq!(
            address,
            Some(("203.0.113.7".to_owned(), 47001)),
            "the address still names the port the listener left behind"
        );
        assert_eq!(
            announce.map(|a| a.port),
            Some(47001),
            "the LAN announcement still names the port the listener left behind"
        );
    }

    /// The short id in a log line is SIXTEEN characters, in both places that
    /// write one.
    ///
    /// Two identical implementations stood here and in `builtin::mailbox`,
    /// each formatting a byte at a time. They are one call now — and the
    /// obvious shared helper is the wrong one: `veil_util::hex_short` takes
    /// FOUR bytes, so reaching for it by name would have halved every id in
    /// these logs without a single test noticing (report24, dead-code table).
    #[test]
    fn the_short_id_is_sixteen_characters_in_both_writers() {
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8;
        }
        let here = hex_short(&id);
        assert_eq!(here, "0001020304050607", "the short id changed shape");
        assert_eq!(here.len(), 16);
        assert_eq!(
            here,
            crate::builtin::mailbox::hex_short(&id),
            "the two log writers no longer print the same id",
        );
        assert_ne!(
            here,
            veil_util::hex_short(&id),
            "the four-byte helper was substituted for the eight-byte one",
        );
    }

    /// And the bound ports come only from listeners that are actually bound.
    #[test]
    fn only_a_bound_listener_offers_a_port() {
        let entry =
            |transport: &str, addr: Option<&str>, active: bool| crate::types::ListenConfigEntry {
                listen_id: crate::types::ListenId::new(1),
                listener_handle: None,
                transport: transport.to_owned(),
                advertise: None,
                relay: None,
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                psk_file: None,
                visibility: veil_cfg::Visibility::Public,
                allowlist_node_ids: vec![],
                group_label: None,
                ephemeral: None,
                on_demand: None,
                local_addr: addr.map(str::to_owned),
                active,
            };
        let listens = vec![
            entry("obfs4://0.0.0.0:0", Some("obfs4://0.0.0.0:41337"), true),
            // Not bound: its address is whatever it was last time, and that is
            // worse than the config.
            entry("tcp://0.0.0.0:0", Some("tcp://0.0.0.0:5000"), false),
            // Bound but with no address recorded, and a port of zero says
            // nothing.
            entry("ws://0.0.0.0:0", None, true),
            entry("wss://0.0.0.0:0", Some("wss://0.0.0.0:0"), true),
        ];
        assert_eq!(
            bound_ports(&listens),
            vec![("obfs4://0.0.0.0:0".to_owned(), 41337u16)],
            "a listener that is not bound, or has no address, offered a port"
        );
    }

    #[test]
    fn a_talkative_neighbour_cannot_grow_this_nodes_memory_without_bound() {
        // The defect this closes was mine: the announcer was recorded BEFORE
        // the ceiling was checked, so somebody rotating keys on the segment
        // grew the set forever while none of those peers was ever attached.
        // The set is what the cap has to bound, not the attach count.
        let mut taken: std::collections::BTreeMap<String, LanCandidate> =
            std::collections::BTreeMap::new();
        for i in 0..1000 {
            let key = format!("neighbour-{i}");
            if admit_lan_peer(&key, "ME", &taken) {
                let slot = free_lan_slot(&taken).expect("a slot the admit just allowed");
                taken.insert(key, lan_slot(slot));
            }
        }
        assert_eq!(
            taken.len(),
            MAX_LAN_PEERS,
            "the set a LAN can grow is not bounded by the cap"
        );
    }

    /// report20 V20-M2: eight announces must not close local discovery for
    /// the rest of the run.
    ///
    /// The cap counted ANNOUNCEMENTS, and an announcement costs a datagram.
    /// Anybody on the segment could send eight naming eight keys, fill every
    /// slot before a handshake, and the real neighbour that announced ninth
    /// was ignored until the node restarted.
    #[test]
    fn announces_that_never_connect_give_their_slots_back() {
        let t0 = std::time::Instant::now();
        let mut taken: std::collections::BTreeMap<String, LanCandidate> =
            std::collections::BTreeMap::new();
        for i in 0..MAX_LAN_PEERS as u32 {
            let key = format!("flood-{i}");
            assert!(admit_lan_peer(&key, "ME", &taken));
            taken.insert(
                key,
                LanCandidate {
                    node_id: [i as u8; 32],
                    slot: free_lan_slot(&taken).expect("a free slot below the cap"),
                    admitted: t0,
                    peer_id: crate::types::PeerId::new(0),
                    abort: None,
                },
            );
        }
        assert!(
            !admit_lan_peer("the-real-neighbour", "ME", &taken),
            "premise: the cap is full, so a real neighbour is refused"
        );

        // Nothing connected. One grace later every slot is a claim, not a peer.
        let connected = std::collections::HashSet::new();
        let stale = stale_lan_candidates(
            &taken,
            &connected,
            LAN_CANDIDATE_GRACE,
            t0 + LAN_CANDIDATE_GRACE,
        );
        assert_eq!(
            stale.len(),
            MAX_LAN_PEERS,
            "a flood that never connected still holds the cap: local \
             discovery stays closed for the life of the process"
        );
        for key in stale {
            taken.remove(&key);
        }
        assert!(
            admit_lan_peer("the-real-neighbour", "ME", &taken),
            "the reclaimed slots did not let a real neighbour in"
        );

        // Before the grace nothing is reclaimed — a slot is not taken away
        // from an announce that simply has not finished connecting yet.
        let mut fresh: std::collections::BTreeMap<String, LanCandidate> =
            std::collections::BTreeMap::new();
        fresh.insert(
            "dialling".to_owned(),
            LanCandidate {
                node_id: [42; 32],
                slot: 0,
                admitted: t0,
                peer_id: crate::types::PeerId::new(0),
                abort: None,
            },
        );
        assert!(
            stale_lan_candidates(
                &fresh,
                &connected,
                LAN_CANDIDATE_GRACE,
                t0 + LAN_CANDIDATE_GRACE - std::time::Duration::from_secs(1),
            )
            .is_empty(),
            "a slot was taken from an announce still inside its grace"
        );
    }

    /// And a CONNECTED neighbour keeps its slot however long it holds it.
    /// The cap is on how many LAN peers this node takes; one it is talking to
    /// is one of them, and reclaiming its slot would hand the peer table to
    /// whoever announces next.
    #[test]
    fn a_connected_neighbour_never_loses_its_slot() {
        let t0 = std::time::Instant::now();
        let mut taken: std::collections::BTreeMap<String, LanCandidate> =
            std::collections::BTreeMap::new();
        taken.insert(
            "live".to_owned(),
            LanCandidate {
                node_id: [1; 32],
                slot: 0,
                admitted: t0,
                peer_id: crate::types::PeerId::new(0),
                abort: None,
            },
        );
        taken.insert(
            "silent".to_owned(),
            LanCandidate {
                node_id: [2; 32],
                slot: 1,
                admitted: t0,
                peer_id: crate::types::PeerId::new(0),
                abort: None,
            },
        );
        let connected: std::collections::HashSet<[u8; 32]> = [[1u8; 32]].into_iter().collect();
        assert_eq!(
            stale_lan_candidates(
                &taken,
                &connected,
                LAN_CANDIDATE_GRACE,
                t0 + LAN_CANDIDATE_GRACE * 100,
            ),
            vec!["silent".to_owned()],
            "the reclaim does not separate a peer we are talking to from one \
             that never answered"
        );
    }

    /// A reclaimed slot must not be handed out twice.
    ///
    /// The peer id was `seen.len()`, which equals the free slot only while
    /// nothing ever leaves. With reclamation the length repeats, and the same
    /// peer id would overwrite a live neighbour's entry in the peer table.
    #[test]
    fn a_reclaimed_slot_is_reused_without_colliding_with_a_live_one() {
        let t0 = std::time::Instant::now();
        let mut taken: std::collections::BTreeMap<String, LanCandidate> =
            std::collections::BTreeMap::new();
        for (i, key) in ["a", "b", "c"].iter().enumerate() {
            taken.insert(
                (*key).to_owned(),
                LanCandidate {
                    node_id: [i as u8; 32],
                    slot: i as u32,
                    admitted: t0,
                    peer_id: crate::types::PeerId::new(0),
                    abort: None,
                },
            );
        }
        taken.remove("b"); // slot 1 goes back
        assert_eq!(
            free_lan_slot(&taken),
            Some(1),
            "the free slot is not the reclaimed one"
        );
        taken.insert(
            "d".to_owned(),
            LanCandidate {
                node_id: [9; 32],
                slot: 1,
                admitted: t0,
                peer_id: crate::types::PeerId::new(0),
                abort: None,
            },
        );
        let slots: std::collections::BTreeSet<u32> = taken.values().map(|c| c.slot).collect();
        assert_eq!(slots.len(), taken.len(), "two neighbours share a peer id");
        // And a full ledger offers nothing.
        let mut full: std::collections::BTreeMap<String, LanCandidate> =
            std::collections::BTreeMap::new();
        for i in 0..MAX_LAN_PEERS as u32 {
            full.insert(
                format!("n{i}"),
                LanCandidate {
                    node_id: [i as u8; 32],
                    slot: i,
                    admitted: t0,
                    peer_id: crate::types::PeerId::new(0),
                    abort: None,
                },
            );
        }
        assert_eq!(
            free_lan_slot(&full),
            None,
            "a slot past the cap was offered"
        );
    }

    #[test]
    fn we_do_not_take_ourselves_or_the_same_neighbour_twice() {
        let mut taken: std::collections::BTreeMap<String, LanCandidate> =
            std::collections::BTreeMap::new();
        assert!(
            !admit_lan_peer("ME", "ME", &taken),
            "a node took its own announce"
        );
        assert!(admit_lan_peer("THEM", "ME", &taken));
        taken.insert("THEM".to_owned(), lan_slot(0));
        assert!(
            !admit_lan_peer("THEM", "ME", &taken),
            "the same neighbour was taken twice, which spawns a second connector"
        );
        // Vacuity: with the ceiling not yet reached, a NEW key is still taken —
        // otherwise the two assertions above would pass on a function that
        // refuses everything.
        assert!(admit_lan_peer("SOMEBODY-ELSE", "ME", &taken));
    }

    #[test]
    fn an_inbound_peer_is_recognised_by_identity_not_by_address() {
        // The half the first attempt missed. An inbound session reports OUR
        // listener as its transport, so address comparison alone learns
        // nothing from it -- and seeds meet each other inbound. The join is
        // the peer's node_id, which the session knows, against the
        // discovered-peer cache, which maps address to public key.
        use veil_bootstrap::DiscoveredPeerCache;
        use veil_cfg::{NodeId, SignatureAlgorithm};

        // A real key, so the id derives the way production derives it.
        let key = "fyU1fAlyHVNMat6NZBJ+KBU/aeJhCP+OBsomlgJ1Cjo=";
        let their_id =
            NodeId::from_public_key(SignatureAlgorithm::Ed25519, key).expect("a valid ed25519 key");

        let mut cache = DiscoveredPeerCache::in_memory();
        cache.upsert(
            veil_cfg::BootstrapPeer {
                transport: "obfs4-tcp://198.51.100.7:5556".to_owned(),
                public_key: key.to_owned(),
                nonce: "AOCZRA==".to_owned(),
                algo: SignatureAlgorithm::Ed25519,
                tls_cert: None,
                tls_ca_cert: None,
            },
            1_700_000_000,
        );
        // A second entry, for a peer we are NOT talking to. Everything below
        // that says "still dialled" is about this one.
        cache.upsert(
            veil_cfg::BootstrapPeer {
                transport: "obfs4-tcp://198.51.100.9:5556".to_owned(),
                public_key: "VVxxLVptuXZ/qFV94aPP1daiz6ZYg2yf1JLbc1VHXhQ=".to_owned(),
                nonce: "AdW8kw==".to_owned(),
                algo: SignatureAlgorithm::Ed25519,
                tls_cert: None,
                tls_ca_cert: None,
            },
            1_700_000_000,
        );

        // The session as an INBOUND one actually looks: our own listener, and
        // no useful address anywhere in it.
        let inbound = crate::types::SessionInfo {
            link_id: crate::types::LinkId::new(1),
            node_id: Some(their_id),
            nonce: None,
            matched_peer_id: None,
            source: crate::types::SessionSource::Inbound(crate::types::ListenId::new(2)),
            listener_handle: None,
            state: crate::types::SessionState::Active,
            transport: "obfs4-tcp://0.0.0.0:5556".to_owned(),
            remote_addr: None,
            description: String::new(),
        };
        let mut live = std::collections::BTreeMap::new();
        live.insert(inbound.link_id, inbound);
        let live = Arc::new(std::sync::Mutex::new(live));
        let cache = Arc::new(std::sync::Mutex::new(cache));

        let held = addresses_we_already_hold(&live, &cache);
        assert!(
            !rendezvous_address_is_new(&[], &held, "obfs4-tcp://198.51.100.7:5556"),
            "a peer we hold an INBOUND session with was dialled again; that is \
             the churn between two seeds, once per rendezvous pass"
        );

        // A cached address whose peer we are NOT in session with is still
        // dialled, or the cache would silence the layer for everybody it has
        // ever met. It has to be IN THE CACHE for this to test anything --
        // an address the cache never heard of proves nothing about the join.
        assert!(
            rendezvous_address_is_new(&[], &held, "obfs4-tcp://198.51.100.9:5556"),
            "an address we merely have in cache stopped being dialled"
        );

        // With no sessions at all the cache contributes nothing.
        let empty = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        assert!(rendezvous_address_is_new(
            &[],
            &addresses_we_already_hold(&empty, &cache),
            "obfs4-tcp://198.51.100.7:5556"
        ));
    }

    #[test]
    fn a_peer_we_are_talking_to_is_not_dialled_again_when_its_row_is_gone() {
        // The peer TABLE is not the record of who we are talking to. A row
        // learned at a rendezvous lives in the autodiscovered range and gets
        // scored out between passes, so the next pass read "not known" about a
        // peer with an open session, dialled it, and the far side dedupped the
        // duplicate -- tearing down the session that was already working.
        // Two production seeds met each other again on every single round.
        let known: Vec<PeerConfigEntry> = vec![];
        let live = vec!["obfs4-tcp://198.51.100.7:5556".to_owned()];
        assert!(
            !rendezvous_address_is_new(&known, &live, "obfs4-tcp://198.51.100.7:5556"),
            "an address this node holds a session to was dialled again"
        );

        // The observed remote address is bare, and it has to compare too.
        let bare = vec!["198.51.100.7:5556".to_owned()];
        assert!(
            !rendezvous_address_is_new(&known, &bare, "obfs4-tcp://198.51.100.7:5556"),
            "the address a session actually came from did not count as ours"
        );

        // ...and this must not become a filter that silences the layer: a
        // different port, a different host, and an empty session list all
        // still dial.
        assert!(rendezvous_address_is_new(
            &known,
            &live,
            "obfs4-tcp://198.51.100.7:5557"
        ));
        assert!(rendezvous_address_is_new(
            &known,
            &live,
            "obfs4-tcp://203.0.113.9:5556"
        ));
        assert!(rendezvous_address_is_new(
            &known,
            &[],
            "obfs4-tcp://198.51.100.7:5556"
        ));
        // An address that merely CONTAINS ours, or is contained by it, is not
        // ours -- both directions, because a containment test reads as right
        // and is wrong on one side each way.
        for near in [
            "obfs4-tcp://198.51.100.70:5556",
            "obfs4-tcp://198.51.100.7:55560",
            "obfs4-tcp://8.198.51.100.7:5556",
        ] {
            let held = vec![near.to_owned()];
            assert!(
                rendezvous_address_is_new(&known, &held, "obfs4-tcp://198.51.100.7:5556"),
                "a session to {near} was mistaken for one to 198.51.100.7:5556"
            );
        }
        let held = vec!["obfs4-tcp://198.51.100.7:5556".to_owned()];
        assert!(
            rendezvous_address_is_new(&known, &held, "obfs4-tcp://198.51.100.7:55560"),
            "a session to :5556 was mistaken for one to :55560"
        );
    }

    #[test]
    fn an_address_this_node_already_has_is_not_dialled_again() {
        // Measured, not imagined: a live host found all three announcing nodes
        // at the rendezvous, was already in session with every one of them
        // through PEX, dialled all three anyway, and logged three
        // "handshake timed out after 10s" — which reads like a network fault
        // and was a duplicate connection the far side dropped.
        let known = vec![
            row(
                crate::types::PeerSource::Exchanged,
                0xAA,
                "obfs4-tcp://198.51.100.7:5556",
            ),
            row(
                crate::types::PeerSource::Configured,
                0xBB,
                "tcp://198.51.100.8:5556",
            ),
        ];
        assert!(
            !rendezvous_address_is_new(&known, &[], "obfs4-tcp://198.51.100.7:5556"),
            "an address already held was treated as new"
        );
        // The AUTHORITY decides, not the whole URI: the same host reached over
        // a different transport is the same machine, and a second session to
        // it is the same duplicate.
        assert!(
            !rendezvous_address_is_new(&known, &[], "tcp://198.51.100.7:5556"),
            "the same host under another scheme was treated as new"
        );
        // A different port is a different node, and a genuinely new address is
        // still worth a dial — or the guard would silence the whole layer.
        assert!(rendezvous_address_is_new(
            &known,
            &[],
            "obfs4-tcp://198.51.100.7:5557"
        ));
        assert!(rendezvous_address_is_new(
            &known,
            &[],
            "obfs4-tcp://203.0.113.9:5556"
        ));
        assert!(
            rendezvous_address_is_new(&[], &[], "obfs4-tcp://203.0.113.9:5556"),
            "a node with no peers must dial what it finds"
        );
        // Something unparseable is not dialled rather than dialled blindly.
        assert!(!rendezvous_address_is_new(&known, &[], "no-scheme-here"));
    }

    #[test]
    fn a_node_with_no_listener_still_knows_how_to_dial_what_it_found() {
        // The defect this closes was measured on a live host: it found three
        // addresses at the rendezvous and dialled none of them, because the
        // dial was gated on having something to ANNOUNCE. A client listens for
        // nobody -- that is the ordinary shape, not an edge case -- so the
        // gate made layer 7 useless to exactly the nodes it is for.
        let bare = veil_cfg::Config::default();
        assert_eq!(
            rendezvous_dial_scheme(&bare),
            "obfs4-tcp",
            "a node with nothing at all must still have a scheme to dial with"
        );

        // What the operator already named wins over the default: a network
        // running plain tcp must not be dialled with obfs4.
        let mut named = veil_cfg::Config::default();
        named.bootstrap_peers.push(veil_cfg::BootstrapPeer {
            transport: "tcp://198.51.100.4:5556".to_owned(),
            public_key: "K".to_owned(),
            nonce: "N".to_owned(),
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        });
        assert_eq!(rendezvous_dial_scheme(&named), "tcp");
    }

    /// WHAT THIS NODE LISTENS ON MUST NOT DECIDE HOW IT DIALS.
    ///
    /// It used to, and it won over everything else — including a transport
    /// the operator had named. A listener says what this node ACCEPTS; the
    /// dial needs what the other end SERVES, and on a client those are chosen
    /// by different people. The app gives every phone `quic://0.0.0.0:9000`
    /// for its own inbound while every seed serves obfs4-tcp on 5556, so a
    /// phone found all three seeds at the rendezvous, rewrote each address to
    /// `quic://…:5556` and timed out against them forever. Measured on a
    /// device: `nostr.looked … 3 record(s)`, then `peer.connect.attempt
    /// transport=quic://…:5556`, then `connection timed out after 10s`, on a
    /// loop.
    ///
    /// A node that offered NOTHING fell through to obfs4-tcp and worked, so
    /// having a listener was strictly worse than having none.
    #[test]
    fn a_quic_listener_does_not_make_this_node_dial_quic() {
        // The exact shape the app composes for a phone: a QUIC listener of
        // its own, and no peer anybody named.
        let mut phone = veil_cfg::Config::default();
        phone.listen.push(veil_cfg::ListenConfig {
            transport: "quic://0.0.0.0:9000".to_owned(),
            ..Default::default()
        });
        assert_eq!(
            rendezvous_dial_scheme(&phone),
            "obfs4-tcp",
            "a phone rewrote every seed address to its own listener's scheme \
             and timed out against all of them"
        );

        // And the operator's own answer still wins over the default, which is
        // the case the local listener used to override.
        let mut named = phone.clone();
        named.bootstrap_peers.push(veil_cfg::BootstrapPeer {
            transport: "tcp://198.51.100.4:5556".to_owned(),
            public_key: "K".to_owned(),
            nonce: "N".to_owned(),
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        });
        assert_eq!(
            rendezvous_dial_scheme(&named),
            "tcp",
            "a network the operator said runs plain tcp was dialled otherwise"
        );
    }

    #[test]
    fn each_layer_runs_exactly_when_its_meeting_point_is_named() {
        // One setting decides both layers now, and the mapping is the whole of
        // it: a config that names one point must not start the other.
        use veil_cfg::{MeetingPoint as P, MeetingPoints as M, MeetingPointsPreset as Pre};

        let all = M::default();
        for point in P::ALL {
            assert!(all.includes(*point), "`all` does not run {point:?}");
        }

        let off = M::Preset(Pre::Off);
        for point in P::ALL {
            assert!(!off.includes(*point), "`off` runs {point:?}");
        }

        // Named subsets, walked over every point so a third one added later
        // has to be decided rather than inherited.
        for point in P::ALL {
            let only = M::Only(vec![*point]);
            for other in P::ALL {
                assert_eq!(
                    only.includes(*other),
                    other == point,
                    "naming {point:?} alone got {other:?} wrong"
                );
            }
        }
    }

    #[test]
    fn what_we_tell_the_lan_is_a_listener_a_neighbour_could_actually_dial() {
        let a = announce_for_listeners(vec![listener("obfs4-tcp://0.0.0.0:5556", None)])
            .expect("a bound listener should be announceable");
        assert_eq!(a.port, 5556);
        assert_eq!(a.scheme, veil_bootstrap::LanScheme::Obfs4Tcp);

        // A path after the authority is not part of the port.
        let ws = announce_for_listeners(vec![listener("ws://192.168.1.5:7001/veil", None)])
            .expect("a ws listener should be announceable");
        assert_eq!(ws.port, 7001);
        assert_eq!(ws.scheme, veil_bootstrap::LanScheme::Ws);
    }

    #[test]
    fn a_loopback_listener_is_not_offered_to_the_wire() {
        // A neighbour dialling 127.0.0.1 reaches its own machine. Announcing
        // it costs somebody else a failed dial and tells them nothing.
        assert!(
            announce_for_listeners(vec![listener("tcp://127.0.0.1:5556", None)]).is_none(),
            "a loopback-only listener was announced"
        );
        // Unless the operator said otherwise: `advertise` exists for exactly
        // the case where the bind address and the reachable one differ.
        let a = announce_for_listeners(vec![listener(
            "tcp://127.0.0.1:5556",
            Some("tcp://192.168.1.5:443"),
        )])
        .expect("an advertised address should win over the bind address");
        assert_eq!(a.port, 443, "the advertised port was ignored");
    }

    #[test]
    fn a_node_with_nothing_dialable_says_nothing() {
        assert!(announce_for_listeners(Vec::new()).is_none(), "no listeners");
        assert!(
            announce_for_listeners(vec![listener("memory://whatever:1", None)]).is_none(),
            "a transport the wire format cannot name was announced anyway"
        );
        assert!(
            announce_for_listeners(vec![listener("tcp://0.0.0.0:0", None)]).is_none(),
            "port 0 is what the kernel assigns, not what a neighbour dials"
        );
        // A bad identity is not announceable either, and must not panic.
        let mut c = veil_cfg::Config::default();
        c.listen = vec![listener("tcp://0.0.0.0:5556", None)];
        assert!(lan_announce_for(&c, "not base64!!", "AE1JRw==", &[]).is_none());
        assert!(
            lan_announce_for(&c, "c2hvcnQ=", "AE1JRw==", &[]).is_none(),
            "a key of the wrong length"
        );
    }

    #[test]
    fn the_first_dialable_listener_wins_and_the_undialable_ones_are_skipped() {
        // Order matters: a node whose first listener is loopback must still
        // announce its second, or a common config (localhost admin + public
        // transport) announces nothing at all.
        let a = announce_for_listeners(vec![
            listener("tcp://127.0.0.1:9999", None),
            listener("memory://x:1", None),
            listener("obfs4-tcp://0.0.0.0:5556", None),
        ])
        .expect("the third listener should have been reached");
        assert_eq!(a.port, 5556);
    }

    fn config_with(
        bootstrap: Vec<BootstrapPeer>,
        policy: veil_cfg::BuiltinSeedPolicy,
    ) -> veil_cfg::Config {
        let mut c = veil_cfg::Config::default();
        c.bootstrap_peers = bootstrap;
        c.global.builtin_seed_policy = policy;
        c
    }

    #[test]
    fn auto_keeps_the_historical_either_or() {
        let builtin = vec![peer("SEED1"), peer("SEED2")];
        // Nothing configured → seeds contribute.
        assert_eq!(
            builtin_seed_contribution(veil_cfg::BuiltinSeedPolicy::Auto, true, builtin.clone())
                .len(),
            2,
        );
        // Something configured → seeds stay out, exactly as before.
        assert!(
            builtin_seed_contribution(veil_cfg::BuiltinSeedPolicy::Auto, false, builtin).is_empty(),
        );
    }

    #[test]
    fn always_contributes_alongside_a_configured_alternative() {
        let builtin = vec![peer("SEED1"), peer("SEED2")];
        // The point of the knob: seeds contribute even though the operator
        // has named their own entry points.
        assert_eq!(
            builtin_seed_contribution(veil_cfg::BuiltinSeedPolicy::Always, false, builtin).len(),
            2,
        );
    }

    #[test]
    fn never_is_an_off_switch_that_does_not_depend_on_build_features() {
        let builtin = vec![peer("SEED1")];
        assert!(
            builtin_seed_contribution(veil_cfg::BuiltinSeedPolicy::Never, true, builtin).is_empty(),
        );
    }

    // ── DNS seed-discovery gate ──────────────────────────────────────────
    //
    // The crash these pin: an identity that declined the shared seeds boots
    // with `builtin_seed_policy = "never"`, no `peers` and no
    // `[[bootstrap_peers]]`. The runtime used to answer that by querying
    // `veil.example` — a domain RFC 6761 guarantees cannot resolve — which
    // ran the DoT and DoH stages for nothing and then entered
    // `discover_seeds_dns_system`. On Android that constructor calls
    // `ndk_context::android_context()`, whose `expect` fires on a tokio
    // worker; with `panic = "abort"` the whole process takes SIGABRT
    // ("android context was not initialized") 12-90 s after boot.

    /// The exact shipped shape of the defect: seeds refused, no peers, no
    /// bootstrap peers, no DNS domain. Nothing must be spawned. Weakening the
    /// gate back to the `unwrap_or(DEFAULT_BOOTSTRAP_DOMAIN)` default makes
    /// this return `Some("veil.example")` and go red.
    #[test]
    fn refusing_seeds_with_no_peers_does_not_start_dns_discovery() {
        let cfg = config_with(Vec::new(), veil_cfg::BuiltinSeedPolicy::Never);
        assert!(cfg.peers.is_empty(), "fixture must have no peers");
        assert!(
            cfg.global.bootstrap_dns_domain.is_none(),
            "fixture must not name a DNS domain — that is the shipped config"
        );
        assert_eq!(
            dns_seed_discovery_domain(&cfg),
            None,
            "a node with nothing to dial and no configured bootstrap DNS \
             domain must NOT run seed discovery: the only domain available is \
             the RFC 6761-reserved placeholder, and reaching the system-DNS \
             stage aborts the process on Android"
        );
    }

    /// Same for the default policy — the gate is about the missing domain, not
    /// about the refusal, so a stock node with an empty candidate set is
    /// covered too.
    #[test]
    fn no_domain_means_no_dns_discovery_under_any_policy() {
        for policy in [
            veil_cfg::BuiltinSeedPolicy::Never,
            veil_cfg::BuiltinSeedPolicy::Auto,
            veil_cfg::BuiltinSeedPolicy::Always,
        ] {
            let cfg = config_with(Vec::new(), policy);
            assert_eq!(
                dns_seed_discovery_domain(&cfg),
                None,
                "policy {policy} must not reach DNS discovery without a domain"
            );
        }
    }

    /// The gate must not cost a deployment that genuinely uses DNS discovery:
    /// naming a domain still arms it, including under `Never` (declining the
    /// compile-time seeds is not declining your own operator's domain).
    #[test]
    fn a_configured_domain_still_arms_dns_discovery() {
        let mut cfg = config_with(Vec::new(), veil_cfg::BuiltinSeedPolicy::Never);
        cfg.global.bootstrap_dns_domain = Some("seeds.testnet.invalid".to_owned());
        assert_eq!(
            dns_seed_discovery_domain(&cfg),
            Some("seeds.testnet.invalid".to_owned()),
            "an operator who named a bootstrap DNS domain must still get \
             discovery — the gate targets the placeholder, not the feature"
        );
    }

    /// Condition 1 preserved: DNS discovery stays the LAST fallback.
    #[test]
    fn dns_discovery_stays_last_behind_configured_entry_points() {
        let mut cfg = config_with(vec![peer("ALT")], veil_cfg::BuiltinSeedPolicy::Never);
        cfg.global.bootstrap_dns_domain = Some("seeds.testnet.invalid".to_owned());
        assert_eq!(
            dns_seed_discovery_domain(&cfg),
            None,
            "a node with bootstrap_peers has something to dial; DNS discovery \
             is the last fallback and must not run"
        );
    }

    /// A seed list these tests own.
    ///
    /// NOT `veil_bootstrap::builtin_seeds()`: that is empty under
    /// `allow-empty-seeds`, which is one of the features CI builds with — so
    /// every test below asserted its own premise and failed on it there, red
    /// for a reason unrelated to what it was checking. What these tests are
    /// about is what resolution does to a list.
    fn seed_fixture() -> Vec<veil_cfg::BootstrapPeer> {
        vec![peer("SEED-A"), peer("SEED-B"), peer("SEED-C")]
    }

    #[test]
    fn a_configured_alternative_no_longer_disables_the_builtin_seeds() {
        // The defect this closes: `bootstrap_peers` REPLACED the builtin list,
        // so one non-seed entry point silently cost the node every seed.
        let seeds = seed_fixture();
        let cfg = config_with(vec![peer("ALT")], veil_cfg::BuiltinSeedPolicy::Always);
        let resolved = resolve_bootstrap_candidates_from(&cfg, "ME", seeds.clone());

        assert_eq!(
            resolved.len(),
            seeds.len() + 1,
            "expected the alternative AND every builtin seed",
        );
        assert!(resolved.iter().any(|p| p.public_key == "ALT"));
        for s in &seeds {
            assert!(
                resolved.iter().any(|p| p.public_key == s.public_key),
                "builtin seed {} was dropped by the configured alternative",
                s.public_key,
            );
        }
    }

    #[test]
    fn a_seed_only_node_has_a_non_empty_watchdog_retry_set() {
        // The defect this closes: the partition watchdog early-returned on
        // `config.bootstrap_peers.is_empty()`, which is the state of every
        // stock install — the seeds live in a local clone it never sees. Those
        // nodes got no partition recovery at all.
        let cfg = config_with(Vec::new(), veil_cfg::BuiltinSeedPolicy::Auto);
        assert!(
            cfg.bootstrap_peers.is_empty(),
            "precondition: the raw field the watchdog used to read is empty",
        );
        assert!(
            !resolve_bootstrap_candidates_from(&cfg, "ME", seed_fixture()).is_empty(),
            "watchdog would have nothing to re-dial for a seed-only node",
        );
    }

    #[test]
    fn resolve_dedups_a_peer_that_is_both_configured_and_builtin() {
        let seeds = seed_fixture();
        // Pin the first builtin seed in `bootstrap_peers` too — the operator
        // curating a host that is also a seed must not double-dial it.
        let cfg = config_with(vec![seeds[0].clone()], veil_cfg::BuiltinSeedPolicy::Always);
        let resolved = resolve_bootstrap_candidates_from(&cfg, "ME", seeds.clone());

        assert_eq!(resolved.len(), seeds.len(), "duplicate was dialed twice");
        let occurrences = resolved
            .iter()
            .filter(|p| p.public_key == seeds[0].public_key)
            .count();
        assert_eq!(occurrences, 1);
    }

    #[test]
    fn resolving_twice_is_a_fixed_point() {
        // `spawn_bootstrap_task` splices the resolved set back into a config
        // clone and recurses while `resolved.len() > configured.len()`. If
        // resolution were not idempotent that recursion would never bottom
        // out — the node would blow its stack at startup instead of dialing
        // anyone. Checked for both policies that contribute anything.
        for policy in [
            veil_cfg::BuiltinSeedPolicy::Always,
            veil_cfg::BuiltinSeedPolicy::Auto,
        ] {
            let cfg = config_with(vec![peer("ALT")], policy);
            let once = resolve_bootstrap_candidates_from(&cfg, "ME", seed_fixture());
            let mut next = cfg.clone();
            next.bootstrap_peers = once.clone();
            let twice = resolve_bootstrap_candidates_from(&next, "ME", seed_fixture());
            assert_eq!(
                twice.len(),
                once.len(),
                "policy={policy}: resolution is not a fixed point, \
                 spawn_bootstrap_task would recurse forever",
            );
        }
    }

    #[test]
    fn resolve_drops_our_own_key_from_both_sources() {
        let seeds = seed_fixture();
        // A seed host bootstrapping itself: its own key appears in the builtin
        // list, and must not be dialed from either source.
        let me = seeds[0].public_key.clone();
        let cfg = config_with(vec![peer("ALT")], veil_cfg::BuiltinSeedPolicy::Always);
        let resolved = resolve_bootstrap_candidates_from(&cfg, &me, seeds.clone());
        assert!(resolved.iter().all(|p| p.public_key != me));
    }

    // ── deterministic rendezvous cookie + relay anchor ────────────────────

    /// report17 V17-M6: an accepted registration must own a slot that is
    /// actually published.
    ///
    /// The registry was an unbounded `Vec` while the maintenance tick signed
    /// only the first `MAX_RENDEZVOUS_AD_SLOTS` of it. Every registration past
    /// that was answered with success and never published: the caller believed
    /// its mailbox was discoverable while nothing signed an ad for it, and the
    /// entry stayed in memory to be cloned on every tick — one `Vec` grown by
    /// anything that can reach the IPC socket.
    #[test]
    fn the_publisher_registry_is_no_larger_than_what_gets_published() {
        use veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS;
        let slots = MAX_RENDEZVOUS_AD_SLOTS as usize;
        let mut entries = Vec::new();

        let entry = |n: u8| veil_anonymity::rendezvous::RendezvousPublisherEntry {
            rendezvous_node_id: [n; 32],
            auth_cookie: [n; 16],
            validity_window_secs: 3600,
            push_envelope: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            rendezvous_kem_valid_until_unix: 0,
            ephemeral_ad_identity: None,
        };

        for n in 0..slots as u8 {
            assert!(
                insert_publisher_entry(&mut entries, entry(n)),
                "registration {n} was refused inside the slot count"
            );
        }
        assert_eq!(entries.len(), slots, "premise: the slots are full");

        assert!(
            !insert_publisher_entry(&mut entries, entry(0xEE)),
            "a registration past the publishable slots was accepted: it will \
             never be signed, and the caller was told its mailbox is live"
        );
        assert_eq!(entries.len(), slots, "the refused entry was kept anyway");

        // A REPLACEMENT still fits — it takes a slot already accounted for.
        // The built-in recipient task re-registers the same (relay, cookie) on
        // every tick, so refusing this would break a working publisher.
        assert!(
            insert_publisher_entry(&mut entries, entry(0)),
            "re-registering an existing (relay, cookie) was refused, which \
             breaks the publisher that already holds that slot"
        );
        assert_eq!(entries.len(), slots);
    }

    /// And a replacement keeps the KEM key the app registered.
    ///
    /// The built-in task re-registers KEM-LESS on its tick; a full overwrite
    /// drops the deposit target and senders can no longer leave offline mail.
    #[test]
    fn a_kemless_re_registration_keeps_the_key_the_app_supplied() {
        let mut entries = Vec::new();
        let base =
            |kem: Vec<u8>, until: u64| veil_anonymity::rendezvous::RendezvousPublisherEntry {
                rendezvous_node_id: [7; 32],
                auth_cookie: [7; 16],
                validity_window_secs: 3600,
                push_envelope: Vec::new(),
                wake_hmac_envelope: Vec::new(),
                rendezvous_kem_algo: if kem.is_empty() { 0 } else { 1 },
                rendezvous_kem_pk: kem,
                rendezvous_kem_valid_until_unix: until,
                ephemeral_ad_identity: None,
            };

        assert!(insert_publisher_entry(
            &mut entries,
            base(vec![9; 32], 1_700_000_000)
        ));
        assert!(insert_publisher_entry(&mut entries, base(Vec::new(), 0)));

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].rendezvous_kem_pk,
            vec![9; 32],
            "the KEM was dropped"
        );
        assert_eq!(
            entries[0].rendezvous_kem_valid_until_unix, 1_700_000_000,
            "the KEM survived but its expiry did not, so the ad stops being \
             clipped to it (V17-M1)"
        );
    }

    /// But a re-registration that brings its OWN key ROTATES.
    ///
    /// The inheritance above is for the KEM-less tick only. When the app hands
    /// in a new key it also hands in that key's expiry, and the two belong
    /// together: keeping the old key while adopting the new key's lifetime
    /// re-published a rotated-out key for another full window, and no sender
    /// ever saw the new one (report20 V18-M2).
    #[test]
    fn a_rotated_kem_key_replaces_the_one_it_supersedes() {
        let mut entries = Vec::new();
        let base =
            |kem: Vec<u8>, until: u64| veil_anonymity::rendezvous::RendezvousPublisherEntry {
                rendezvous_node_id: [7; 32],
                auth_cookie: [7; 16],
                validity_window_secs: 3600,
                push_envelope: Vec::new(),
                wake_hmac_envelope: Vec::new(),
                rendezvous_kem_algo: if kem.is_empty() { 0 } else { 1 },
                rendezvous_kem_pk: kem,
                rendezvous_kem_valid_until_unix: until,
                ephemeral_ad_identity: None,
            };

        assert!(insert_publisher_entry(
            &mut entries,
            base(vec![9; 32], 1_700_000_000)
        ));
        assert!(insert_publisher_entry(
            &mut entries,
            base(vec![4; 32], 1_800_000_000)
        ));

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].rendezvous_kem_pk,
            vec![4; 32],
            "the rotation was discarded: senders keep sealing to the key the \
             receiver replaced"
        );
        assert_eq!(
            entries[0].rendezvous_kem_valid_until_unix, 1_800_000_000,
            "the rotated-in key kept the old expiry"
        );
        assert!(
            !(entries[0].rendezvous_kem_pk == vec![9; 32]
                && entries[0].rendezvous_kem_valid_until_unix == 1_800_000_000),
            "the SUPERSEDED key is advertised under the NEW key's lifetime — \
             it stays sealable for a window it was retired before"
        );
    }

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

    /// The refresh-ahead set must never contain us.
    ///
    /// Asserted through the CACHE, not through the predicate: what matters is
    /// that the background refresher gets no candidate, and that a real peer
    /// still does. A predicate-only test would pass just as happily if the
    /// call site had the arms the wrong way round.
    #[test]
    fn resolving_our_own_ad_does_not_subscribe_us_to_refresh_ahead() {
        let me = [1u8; 32];
        let peer = [2u8; 32];
        let cache = Arc::new(super::super::anonymity_state::RendezvousResolveCache::new());
        let window = std::time::Duration::from_secs(300);
        let margin = std::time::Duration::from_secs(6);

        super::note_send_target(&cache, me, me);
        assert!(
            cache.refresh_candidates(window, margin).is_empty(),
            "self-resolve enrolled us; the refresher would re-walk our own 8 ad \
             slots once per TTL forever"
        );

        super::note_send_target(&cache, peer, me);
        assert_eq!(
            cache.refresh_candidates(window, margin),
            vec![peer],
            "a genuine send target must still be kept warm — the whole point of \
             the proactive set"
        );
    }
}
