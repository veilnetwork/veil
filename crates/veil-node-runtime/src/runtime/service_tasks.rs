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
                    let refreshed = super::rendezvous_resolver::resolve_fresh_rendezvous_ads(
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
mod tests;
