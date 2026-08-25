//! Mailbox built-in app service.
//!
//! Receives `MailboxPutPayload` from senders over the veil app-message
//! channel, stores the blob in the local [`veil_mailbox::Mailbox`]
//! and (when an envelope is provided) fires a push-wake trigger.
//!
//! ## Why fire-and-forget
//!
//! Sender does not get an explicit reply — the wire is a single
//! datagram (no MailboxPutAck out). This keeps the protocol
//! single-frame and avoids stream / correlation-id machinery. Sender
//! relies on:
//!
//! **Multi-replica fan-out** (K=3) — at least one replica likely
//! stores even if one rejects (quota / rate-limit).
//! **Peer-sync (P4)** — eventual delivery guarantee independent of
//! any single put landing.
//!
//! Failures (decode error, mailbox storage error, rejected by quota)
//! are logged at WARN; sender does not learn unless it observes
//! receiver-side eventual non-delivery.
//!
//! ## Auth model
//!
//! **Deposit is open by default, not unauthenticated by design.** A PUT may
//! carry a capability token, and `MailboxConfig::require_capability_token`
//! makes one mandatory — tokenless puts are then rejected with
//! `CapabilityRequired`. The relay ships with that gate off (senders are not
//! all propagating tokens yet), so on a default relay anyone can deposit; a
//! relay that turns it on accepts deposits only from holders of a token its
//! receiver minted.
//!
//! Independent of the token, every deposit is bounded by the per-receiver
//! quota and the 60/min rate limit at the storage layer, and the per-sender
//! byte quota is keyed on the AUTHENTICATED session source rather than the
//! wire-supplied `sender_id`.
//!
//! The receiver's `node_id` in the payload is taken at face value;
//! storage records (sender, content_id, blob) and on-fetch the
//! receiver decrypts end-to-end (relay never sees plaintext).
//!
//! ## Push trigger hook
//!
//! On `Stored` outcome with a non-empty `push_envelope`, the service
//! sends `(receiver_id, envelope)` over the same `mpsc::UnboundedSender<PushTrigger>`
//! the IPC bridge uses (P3a). A single push task drains both.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use veil_app::AppMessage;
use veil_mailbox::{
    MAILBOX_ACK_ENDPOINT_CAPACITY, MAILBOX_ACK_ENDPOINT_ID, MAILBOX_APP_ID,
    MAILBOX_FETCH_ENDPOINT_CAPACITY, MAILBOX_FETCH_ENDPOINT_ID, MAILBOX_FETCH_REPLY_MAX_BYTES,
    MAILBOX_PUT_ENDPOINT_CAPACITY, MAILBOX_PUT_ENDPOINT_ID, MAILBOX_SLICE_ENDPOINT_CAPACITY,
    MAILBOX_SLICE_ENDPOINT_ID, Mailbox,
};
use veil_proto::{
    MAILBOX_PUT_CHUNK_DATA_BYTES, MAX_MAILBOX_FETCH_ENTRIES, MAX_MAILBOX_PUT_CHUNKS,
    MailboxBlobWire, MailboxFetchRespPayload, MailboxPutChunkPayload, MailboxPutPayload,
};
use veil_types::AnonOnionSender;

use super::host::{BuiltinAppHost, BuiltinEndpoint, ServiceContext, ServiceSpec};

/// Trigger sent over the mpsc to the push-dispatch task. Mirrors
/// the type used by `MailboxIpcBridge` in `service_tasks.rs` — both
/// the IPC bridge and the built-in app service feed the same task.
pub struct PushTrigger {
    /// Receiver whose envelope is being unsealed and dispatched.
    pub receiver_id: [u8; 32],
    /// Sealed envelope bytes. Caller must have ensured non-empty
    /// before sending.
    pub envelope: Vec<u8>,
    /// Content id of the stored mailbox blob — bound into the wake-HMAC so a
    /// forged/replayed wake for a different message fails the receiver's verify.
    pub content_id: [u8; 32],
    /// Optional sealed `WakeHmacKey` envelope (Epic 489.10). When present the
    /// relay unseals it and mints an authenticated wake payload; `None`/empty
    /// falls back to the legacy wake-only push.
    pub wake_hmac_envelope: Option<Vec<u8>>,
}

/// Sends the in-network deposit WAKE: a tiny empty datagram to the receiver's
/// `(MAILBOX_APP_ID, MAILBOX_WAKE_ENDPOINT_ID)` over its LIVE direct session
/// with this relay (see the constant's doc in veil-mailbox). Returns whether a
/// frame was actually queued (false = no live session / debounced). Injected
/// as a closure so this module needs no `SessionTxRegistry` dependency; the
/// runtime builds it where the registry lives.
pub type MailboxWakeSender = Arc<dyn Fn(&[u8; 32]) -> bool + Send + Sync>;

/// bound the push-trigger channel.
/// Pre-fix the channel was `unbounded_channel`; an attacker spamming
/// `MailboxPut` faster than the push-dispatch task drains would cause
/// unbounded queue growth (RAM DoS). At ~80-100 push triggers/sec
/// healthy steady-state, 512-deep buffer absorbs ~5 seconds of burst.
/// On overflow `try_send` returns `Full(...)` and the trigger is
/// dropped with a warn-level log (the mailbox-stored blob is still
/// accessible via fetch — push is a wake hint, not a data delivery
/// channel, so dropping a trigger only delays notification, does not lose
/// the message itself).
pub const PUSH_TRIGGER_QUEUE_CAP: usize = 512;

/// Max concurrent in-flight deposit reassemblies (global RAM bound). Each holds
/// ≤ `MAX_MAILBOX_PUT_CHUNKS` × the chunk size ≈ 60 KB, so the worst case is
/// ~7.5 MB — and stale ones are evicted, so steady-state is far lower.
const MAX_INFLIGHT_PUT_REASSEMBLIES: usize = 128;

/// A partially-received deposit that has made no PROGRESS for this long is
/// evicted. A real deposit's chunks all arrive within a few seconds, so this
/// never drops honest traffic.
const PUT_REASSEMBLY_STALE: Duration = Duration::from_secs(30);

/// Hard ceiling on a reassembly's life, measured from when its first chunk
/// arrived and NOT renewable by anything.
///
/// The idle timer alone was renewable: re-sending a chunk already held pushed
/// `last_activity` forward without adding a single byte, so 128 slots could be
/// held open forever by replaying the first chunk of each every 29 seconds —
/// and every honest deposit was refused for as long as the attacker cared to
/// keep it up (audit V-02). A deadline that no incoming packet can move puts
/// an end to that regardless of what arrives.
///
/// Generous next to the seconds an honest deposit takes, so it only ever fires
/// on something that was never going to complete.
const PUT_REASSEMBLY_MAX_LIFETIME: Duration = Duration::from_secs(120);

struct PutReassembly {
    chunk_total: u16,
    chunks: Vec<Option<Vec<u8>>>,
    received: u16,
    /// Last time a chunk we did not already hold arrived. A duplicate does not
    /// move this — replaying is not progress.
    last_progress: Instant,
    /// When the first chunk arrived. Never updated.
    created: Instant,
}

/// Reassembles chunked network deposits ([`MailboxPutChunkPayload`]) keyed by the
/// deposit's `content_id`. Anonymous deposits carry no authenticated source, so
/// the key is the random per-message `content_id` (also the dedup key); bounds
/// (max in-flight + stale-evict) keep a hostile depositor from exhausting memory.
/// The assembled bytes are the depositor's encoded [`MailboxPutPayload`] — the
/// E2E crypto is untouched, this only un-fragments the transport.
#[derive(Default)]
pub struct PutChunkReassembler {
    inflight: HashMap<[u8; 32], PutReassembly>,
}

impl PutChunkReassembler {
    /// Accept one chunk; returns the assembled `MailboxPutPayload` bytes when the
    /// deposit is complete, else `None`. Malformed / out-of-range / capacity-
    /// exceeding chunks are dropped (`None`), fail-safe.
    pub fn accept(&mut self, c: MailboxPutChunkPayload, now: Instant) -> Option<Vec<u8>> {
        if c.chunk_total == 0 || c.chunk_total > MAX_MAILBOX_PUT_CHUNKS {
            return None;
        }
        if c.chunk_index >= c.chunk_total {
            return None;
        }
        // Independently of the decoder's cap: this is the code that ALLOCATES,
        // and `MAX_MAILBOX_PUT_CHUNKS` only bounds the chunk count. Without a
        // byte cap here, 128 concurrent reassemblies x 256 chunks is bounded by
        // the frame size (16 MiB), not by the ~60 KB the doc-comment claims —
        // and a deposit needs no authentication to send.
        if c.chunk_data.len() > MAILBOX_PUT_CHUNK_DATA_BYTES {
            return None;
        }
        // Drop partial deposits before doing anything else (memory bound): the
        // ones that have stopped making progress, AND the ones that have simply
        // been here too long. The second condition is the one that cannot be
        // gamed — no arriving packet moves `created`.
        self.inflight.retain(|_, r| {
            now.duration_since(r.last_progress) < PUT_REASSEMBLY_STALE
                && now.duration_since(r.created) < PUT_REASSEMBLY_MAX_LIFETIME
        });

        // A conflicting chunk_total for an existing key = corruption / an injected
        // chunk under a guessed content_id → restart that reassembly.
        if self
            .inflight
            .get(&c.content_id)
            .is_some_and(|r| r.chunk_total != c.chunk_total)
        {
            self.inflight.remove(&c.content_id);
        }
        // Full, and this is a NEW key: make room rather than turn it away.
        //
        // Refusing was the old policy, on the reasoning that an in-progress
        // honest deposit should never be sacrificed. But the sacrifice happened
        // anyway — to whoever arrived second — and an attacker holding all 128
        // slots turned "never evict" into "never accept anyone else". Something
        // has to give; the question is only what.
        //
        // The least-advanced reassembly gives. An attacker's slots hold one
        // chunk each because sending more would complete them; an honest
        // deposit part-way through holds many. Ties break on age, so the oldest
        // of the equally-stalled goes first. The evicted depositor's outbox
        // retries, which is the same cost the refused one used to pay.
        if !self.inflight.contains_key(&c.content_id)
            && self.inflight.len() >= MAX_INFLIGHT_PUT_REASSEMBLIES
        {
            // `?` on purpose: an empty table cannot be over the cap, so this
            // never fires — but returning beats inserting past the bound.
            let victim = *self
                .inflight
                .iter()
                .min_by_key(|(_, r)| (r.received, r.created))
                .map(|(k, _)| k)?;
            self.inflight.remove(&victim);
        }

        let complete = {
            let r = self
                .inflight
                .entry(c.content_id)
                .or_insert_with(|| PutReassembly {
                    chunk_total: c.chunk_total,
                    chunks: vec![None; c.chunk_total as usize],
                    received: 0,
                    last_progress: now,
                    created: now,
                });
            let idx = c.chunk_index as usize;
            if r.chunks[idx].is_none() {
                r.received += 1;
                r.chunks[idx] = Some(c.chunk_data);
                // ONLY here. Re-sending a chunk we already hold used to push the
                // idle timer forward too, which is what let one attacker keep a
                // slot alive indefinitely by replaying its first chunk.
                r.last_progress = now;
            } // duplicate index (relay redundancy / retry) → idempotent no-op
            r.received == r.chunk_total
        };

        if complete {
            let r = self.inflight.remove(&c.content_id)?;
            let mut out = Vec::new();
            for chunk in r.chunks {
                out.extend_from_slice(&chunk.unwrap_or_default());
            }
            Some(out)
        } else {
            None
        }
    }
}

/// Spawn the mailbox built-in app service on `host`. Idempotent at
/// the program level — calling twice would panic at registry-bind
/// time on the duplicate `(MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)`.
///
/// `mailbox` is the shared storage handle. `push_trigger_tx` is the
/// channel the configured push dispatcher consumes from; pass `None`
/// to disable push triggering (e.g. relay running without anonymity X25519
/// secret — without a key it can't unseal envelopes anyway).
///
/// `reply_sender` is the anonymous-reply egress used to answer network FETCH
/// requests over their one-time reply path. Pass `None` to run PUT-only (a
/// relay with no anon sender can still store, just not serve fetches).
pub fn spawn_mailbox_app_service(
    host: &mut BuiltinAppHost,
    ctx: ServiceContext,
    mailbox: Arc<Mailbox>,
    push_trigger_tx: Option<tokio::sync::mpsc::Sender<PushTrigger>>,
    reply_sender: Option<Arc<dyn AnonOnionSender>>,
    // In-network deposit wake toward the receiver's live session (None =
    // feature off, e.g. tests / a node with no session registry).
    wake_sender: Option<MailboxWakeSender>,
) {
    let spec = ServiceSpec {
        name: "veil.mailbox.v1",
        app_id: MAILBOX_APP_ID,
        endpoints: vec![
            BuiltinEndpoint {
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                capacity: MAILBOX_PUT_ENDPOINT_CAPACITY,
            },
            BuiltinEndpoint {
                endpoint_id: MAILBOX_FETCH_ENDPOINT_ID,
                capacity: MAILBOX_FETCH_ENDPOINT_CAPACITY,
            },
            BuiltinEndpoint {
                endpoint_id: MAILBOX_ACK_ENDPOINT_ID,
                capacity: MAILBOX_ACK_ENDPOINT_CAPACITY,
            },
            BuiltinEndpoint {
                endpoint_id: MAILBOX_SLICE_ENDPOINT_ID,
                capacity: MAILBOX_SLICE_ENDPOINT_CAPACITY,
            },
        ],
    };
    host.spawn(ctx, spec, move |mut ctx, mut rxs| async move {
        // Receivers are in spec.endpoints order: [PUT, FETCH, ACK, SLICE].
        let mut put_rx = rxs.remove(0);
        let mut fetch_rx = rxs.remove(0);
        let mut ack_rx = rxs.remove(0);
        let mut slice_rx = rxs.remove(0);
        // Per-service deposit reassembler — the task is single-threaded, so the
        // `&mut` needs no lock. State stays local to this service instance.
        let mut reassembler = PutChunkReassembler::default();
        loop {
            tokio::select! {
                Some(msg) = put_rx.recv() => {
                    handle_put_message(
                        &mailbox,
                        push_trigger_tx.as_ref(),
                        wake_sender.as_ref(),
                        &mut reassembler,
                        msg,
                    );
                }
                Some(msg) = fetch_rx.recv() => {
                    handle_fetch_message(&mailbox, reply_sender.as_ref(), msg).await;
                }
                Some(msg) = ack_rx.recv() => {
                    handle_ack_message(&mailbox, msg);
                }
                Some(msg) = slice_rx.recv() => {
                    handle_slice_message(&mailbox, reply_sender.as_ref(), msg).await;
                }
                _ = ctx.shutdown.changed() => {
                    log::info!("veil-mailbox: app service stopping");
                    break;
                }
                else => {
                    // recv returned None — registry dropped the senders
                    // (shouldn't happen during normal operation; means
                    // the host is being torn down).
                    log::info!("veil-mailbox: PUT/FETCH endpoint closed");
                    break;
                }
            }
        }
    });
}

/// Minimum interval between two `MAILBOX_WAKE` events published for the SAME
/// sender. Mirrors the relay-side `WAKE_DEBOUNCE` in `service_tasks.rs`.
///
/// The relay-side debounce is per RECEIVER and lives inside the
/// `mailbox.enabled` block, so it constrains only a well-behaved relay's own
/// fan-out. It does nothing here: the wake endpoint is bound on every node,
/// and any session peer — relay or not — can send an empty datagram to it.
/// Each one used to publish an event, and each event makes the client app
/// drain its mailbox: radio up, battery down, at whatever rate the peer likes.
pub const WAKE_RECV_DEBOUNCE: Duration = Duration::from_secs(2);

/// Cap on distinct senders tracked by [`WakeDebounce`]. Reached only under a
/// Sybil-ish fan of session peers; the map is compacted before it grows past
/// this, so the listener's memory is bounded by construction.
const MAX_WAKE_RECV_DEBOUNCE_ENTRIES: usize = 1024;

/// Per-sender receive-side wake debounce.
///
/// Keyed by sender rather than kept as one global timestamp on purpose: a
/// single global gate would let ONE noisy peer suppress a real relay's wake,
/// turning a battery fix into a delivery-latency bug.
pub struct WakeDebounce {
    last: HashMap<[u8; 32], Instant>,
}

impl WakeDebounce {
    pub fn new() -> Self {
        Self {
            last: HashMap::new(),
        }
    }

    /// `true` when a wake from `src` may be published now; records the time if
    /// so. A suppressed wake costs nothing but latency — the app's own poll
    /// schedule still drains the mailbox.
    pub fn admit(&mut self, src: &[u8; 32], now: Instant) -> bool {
        if self
            .last
            .get(src)
            .is_some_and(|t| now.duration_since(*t) < WAKE_RECV_DEBOUNCE)
        {
            return false;
        }
        if self.last.len() >= MAX_WAKE_RECV_DEBOUNCE_ENTRIES {
            self.last
                .retain(|_, t| now.duration_since(*t) < WAKE_RECV_DEBOUNCE);
            // Compaction alone is not a bound: a fan of distinct senders
            // arriving inside one window leaves every entry fresh and nothing
            // to retain away. Evict the oldest so the cap holds unconditionally
            // — the evicted sender simply gets one un-debounced wake later.
            if self.last.len() >= MAX_WAKE_RECV_DEBOUNCE_ENTRIES
                && let Some(oldest) = self.last.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k)
            {
                self.last.remove(&oldest);
            }
        }
        self.last.insert(*src, now);
        true
    }
}

impl Default for WakeDebounce {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle one datagram that landed on the wake endpoint. Returns whether a
/// `MAILBOX_WAKE` event was published.
///
/// Split out of the select! loop so the debounce can be exercised at the point
/// where the event is actually published, not merely next to it.
pub fn handle_wake_message(
    msg: AppMessage,
    debounce: &mut WakeDebounce,
    now: Instant,
    event_bus: &veil_ipc::EventBus,
) -> bool {
    let AppMessage::Deliver { src_node_id, .. } = msg else {
        return false;
    };
    if !debounce.admit(&src_node_id, now) {
        log::trace!(
            "veil-mailbox: deposit wake from {} debounced",
            hex_short(&src_node_id),
        );
        return false;
    }
    log::debug!(
        "veil-mailbox: deposit wake from relay {} — publishing event",
        hex_short(&src_node_id),
    );
    event_bus.publish(veil_proto::EventPayload {
        kind: veil_proto::event_kind::MAILBOX_WAKE,
        payload: Vec::new(),
    });
    true
}

/// Spawn the receiver-side WAKE listener: binds
/// `(MAILBOX_APP_ID, MAILBOX_WAKE_ENDPOINT_ID)` and, for every datagram that
/// lands there, publishes a `MAILBOX_WAKE` event on the daemon event bus so
/// the client app drains its mailbox promptly (the payload is ignored — the
/// wake is a pure hint). Runs on EVERY node (not just mailbox relays): any
/// node may be a mailbox RECEIVER.
///
/// Because it is bound unconditionally, the sender is any directly-connected
/// session peer — not necessarily a relay holding a deposit for us. Wakes are
/// therefore debounced per sender ([`WAKE_RECV_DEBOUNCE`]) so a peer cannot
/// keep the client's radio awake by repeating an empty datagram.
pub fn spawn_mailbox_wake_listener(
    host: &mut BuiltinAppHost,
    ctx: ServiceContext,
    event_bus: Arc<veil_ipc::EventBus>,
) {
    use veil_mailbox::{MAILBOX_WAKE_ENDPOINT_CAPACITY, MAILBOX_WAKE_ENDPOINT_ID};
    let spec = ServiceSpec {
        name: "veil.mailbox.wake.v1",
        app_id: MAILBOX_APP_ID,
        endpoints: vec![BuiltinEndpoint {
            endpoint_id: MAILBOX_WAKE_ENDPOINT_ID,
            capacity: MAILBOX_WAKE_ENDPOINT_CAPACITY,
        }],
    };
    host.spawn(ctx, spec, move |mut ctx, mut rxs| async move {
        let mut wake_rx = rxs.remove(0);
        let mut debounce = WakeDebounce::new();
        loop {
            tokio::select! {
                Some(msg) = wake_rx.recv() => {
                    handle_wake_message(msg, &mut debounce, Instant::now(), &event_bus);
                }
                _ = ctx.shutdown.changed() => {
                    log::info!("veil-mailbox: wake listener stopping");
                    break;
                }
                else => break,
            }
        }
    });
}

/// Per-blob wire header inside a `MailboxFetchRespPayload` entry:
/// sender_id + content_id + deposited_at + blob_len.
const PER_BLOB_WIRE_HDR: usize = 32 + 32 + 8 + 4;

/// Bytes one FETCH reply may carry. The reply rides a SINGLE signed
/// AuthDeliver capped at `MAX_AUTH_DELIVER_MSG_BYTES` (~6 KB, fragmented);
/// leave margin for the AuthDeliver framing (sig + node_id + fields) + the
/// resp count. A blob whose wire cost exceeds this can NEVER be fetched —
/// both the FETCH packer and the PUT gate key off this same number.
fn fetch_reply_budget() -> usize {
    veil_proto::MAX_AUTH_DELIVER_MSG_BYTES
        .saturating_sub(512)
        .min(MAILBOX_FETCH_REPLY_MAX_BYTES)
}

/// Handle one incoming app message addressed to the FETCH endpoint.
///
/// The requester is AUTHENTICATED — the onion delivery cryptographically
/// verified its identity, so `src_node_id` IS the receiver. We gather THAT
/// receiver's stored blobs and reply over the one-time reply path (`reply_id`).
/// No cookie: the verified identity is the authorization (a shared secret would
/// only be a weaker, leakable substitute for the cryptographic proof we already
/// have here). Bounded so the reply fits the anonymous reply path; the receiver
/// re-fetches after acking to drain more.
pub async fn handle_fetch_message(
    mailbox: &Mailbox,
    reply_sender: Option<&Arc<dyn AnonOnionSender>>,
    msg: AppMessage,
) {
    let (src_node_id, provenance, sender_device_id, reply_id, request) = match msg {
        AppMessage::Deliver {
            src_node_id,
            provenance,
            sender_device_id,
            reply_id,
            data,
            ..
        } => {
            // The request body. It was empty on every client that predates the
            // field and this handler never read it, so reading it now is
            // additive in both directions — and `decode` never fails, because
            // refusing a fetch over a hint would strand somebody's mail
            // (report14 X14-M4).
            let request = veil_mailbox::MailboxFetchRequest::decode(&data);
            (src_node_id, provenance, sender_device_id, reply_id, request)
        }
        other => {
            log::debug!("veil-mailbox: ignoring non-Deliver on FETCH endpoint: {other:?}");
            return;
        }
    };
    // The doc above says the requester is authenticated. ASK, rather than
    // assume it from the shape of the message (X/V-01): `src_node_id` is the
    // key this whole handler reads a mailbox by, so serving one that was never
    // verified hands a stranger someone else's mail. A zero id (the
    // anonymous-send marker) and a missing reply path are still refused —
    // there would be no receiver to key on and nowhere to send the answer.
    if !provenance.is_authenticated() {
        log::debug!(
            "veil-mailbox: FETCH dropped (src {} is {provenance:?}, not an authenticated identity)",
            hex_short(&src_node_id),
        );
        return;
    }
    if src_node_id == [0u8; 32] || reply_id == 0 {
        log::debug!("veil-mailbox: FETCH dropped (unauthenticated src or no reply path)");
        return;
    }
    let Some(sender) = reply_sender else {
        log::debug!("veil-mailbox: FETCH dropped — no reply egress configured");
        return;
    };
    let mut blobs = match mailbox.fetch_skipping(src_node_id, &request.skip) {
        Ok(b) => b,
        Err(e) => {
            log::warn!(
                "veil-mailbox: FETCH store error (recv={}): {e}",
                hex_short(&src_node_id),
            );
            return;
        }
    };
    // The mailbox key is the AUTHENTICATED FETCHER id — and every device of a
    // family authenticates as the shared IDENTITY, so a box keyed by a
    // device's own id was never fetched by anyone: deposits landed and sat
    // until TTL, a live black hole. The `sig_key_idx` subkey that verified
    // THIS request names the exact signing device, and that proof IS the
    // authorization to drain that device's box (same standard as the identity
    // box: the verified id, nothing claimed). Identity box first, device box
    // behind it, one shared reply budget — no wire change, so an old client
    // drains its device box the moment the relay serves it.
    if let Some(dev) = sender_device_id
        && dev != src_node_id
        && dev != [0u8; 32]
    {
        match mailbox.fetch_skipping(dev, &request.skip) {
            Ok(dev_blobs) => {
                if !dev_blobs.is_empty() {
                    log::debug!(
                        "veil-mailbox: FETCH recv={} also drains device box {} ({} blob(s))",
                        hex_short(&src_node_id),
                        hex_short(&dev),
                        dev_blobs.len(),
                    );
                }
                blobs.extend(dev_blobs);
                blobs.sort_by_key(|b| b.deposited_at);
                // Oldest-first ACROSS the two boxes, not per-box: the
                // reply budget packs from the front, so "identity box
                // first" starves the device box for as long as the
                // identity backlog alone can fill a reply — measured
                // live: 133 device blobs announced, none served, while
                // 74 identity blobs took the whole budget every round.
            }
            Err(e) => log::warn!(
                "veil-mailbox: FETCH device-box store error (recv={} dev={}): {e}",
                hex_short(&src_node_id),
                hex_short(&dev),
            ),
        }
    }
    // Bound the reply so the whole encoded MailboxFetchRespPayload fits in ONE
    // signed AuthDeliver (see [fetch_reply_budget]). Oldest-first; the receiver
    // re-fetches to drain the rest (FETCH is non-destructive, deduped
    // receiver-side by content_id).
    //
    // A blob that ALONE exceeds the budget is ANNOUNCED rather than sent: the
    // entry rides with an empty blob, and the receiver collects it a window at
    // a time from the SLICE endpoint. It must not be emitted whole — that made
    // send_reply fail PayloadTooLarge on EVERY fetch, and since the queue is
    // oldest-first the oversized blob stayed at its head, wedging that
    // receiver's mailbox and starving everything behind it (observed in
    // production).
    //
    // It was purged instead, for a while, and that was the wrong end of the
    // problem: what a blob weighs is not the sender's to choose. One ML-KEM
    // envelope per recipient DEVICE means the weight follows the identity, and
    // past a few devices NO message of any size fits a reply. Purging made a
    // multi-device identity undeliverable to by design.
    //
    // A receiver that predates the SLICE endpoint sees an entry with no bytes
    // and skips it — the same outcome the purge produced, minus the deletion.
    let reply_budget = fetch_reply_budget();
    let mut total = 0usize;
    let mut wire: Vec<MailboxBlobWire> = Vec::new();
    for b in blobs {
        if wire.len() >= MAX_MAILBOX_FETCH_ENTRIES {
            break;
        }
        let cost = b.blob.len() + PER_BLOB_WIRE_HDR;
        if cost > reply_budget {
            // Announce it: header only, no bytes. The receiver asks the SLICE
            // endpoint for the rest and acks it like any other blob.
            if total + PER_BLOB_WIRE_HDR > reply_budget {
                break; // no room even for the announcement this round
            }
            total += PER_BLOB_WIRE_HDR;
            log::debug!(
                "veil-mailbox: announcing oversized blob (recv={} cid={} {}B > \
                 fetch budget {reply_budget}B) — the receiver will slice it",
                hex_short(&src_node_id),
                hex_short(&b.content_id),
                b.blob.len(),
            );
            wire.push(MailboxBlobWire {
                sender_id: b.sender_id,
                content_id: b.content_id,
                deposited_at: b.deposited_at,
                blob: Vec::new(),
            });
            continue;
        }
        if total + cost > reply_budget {
            break; // deliverable, just not THIS round — a later fetch gets it
        }
        total += cost;
        wire.push(MailboxBlobWire {
            sender_id: b.sender_id,
            content_id: b.content_id,
            deposited_at: b.deposited_at,
            blob: b.blob,
        });
    }
    let n = wire.len();
    let resp = MailboxFetchRespPayload { blobs: wire }.encode();
    match sender.send_reply(reply_id, &resp, MAILBOX_APP_ID).await {
        Ok(()) => log::debug!(
            "veil-mailbox: FETCH replied {n} blob(s) to recv={}",
            hex_short(&src_node_id),
        ),
        Err(e) => log::warn!(
            "veil-mailbox: FETCH reply failed (recv={}): {e:?}",
            hex_short(&src_node_id),
        ),
    }
}

/// Handle one incoming app message addressed to the SLICE endpoint.
///
/// The half of the mailbox that the reply budget used to make impossible. A
/// blob carries one ML-KEM envelope per recipient DEVICE, so its size follows
/// the identity rather than the message: past a few devices nothing of any size
/// rides a single FETCH reply, and the deposit — chunked, up to a megabyte —
/// was never the constraint. Here the receiver asks for one window at a time,
/// each request its own onion round trip with its own one-time reply path.
///
/// Same authorization as FETCH and ACK, and it has to be: the onion delivery
/// verified the requester, so `src_node_id` IS the receiver, and the store is
/// keyed on `(receiver, content_id)`. A caller can only ever read its own mail,
/// and an unauthenticated or reply-less request is refused rather than served.
///
/// A blob this relay does not hold answers `total_len = 0` — an answer, not
/// silence, so the receiver stops instead of walking offsets forever.
pub async fn handle_slice_message(
    mailbox: &Mailbox,
    reply_sender: Option<&Arc<dyn AnonOnionSender>>,
    msg: AppMessage,
) {
    let (src_node_id, provenance, sender_device_id, reply_id, data) = match msg {
        AppMessage::Deliver {
            src_node_id,
            provenance,
            sender_device_id,
            reply_id,
            data,
            ..
        } => (src_node_id, provenance, sender_device_id, reply_id, data),
        other => {
            log::debug!("veil-mailbox: ignoring non-Deliver on SLICE endpoint: {other:?}");
            return;
        }
    };
    if !provenance.is_authenticated() {
        log::debug!(
            "veil-mailbox: SLICE dropped (src {} is {provenance:?}, not an authenticated identity)",
            hex_short(&src_node_id),
        );
        return;
    }
    if src_node_id == [0u8; 32] || reply_id == 0 {
        log::debug!("veil-mailbox: SLICE dropped (unauthenticated src or no reply path)");
        return;
    }
    let Some(sender) = reply_sender else {
        log::debug!("veil-mailbox: SLICE dropped — no reply egress configured");
        return;
    };
    let req = match veil_proto::ipc::MailboxSliceReqPayload::decode(&data) {
        Ok(r) => r,
        Err(e) => {
            log::debug!(
                "veil-mailbox: SLICE dropped (malformed request from {}): {e}",
                hex_short(&src_node_id),
            );
            return;
        }
    };
    // What one reply may carry, minus this payload's own header — the same
    // budget the FETCH packer works to, so a slice can never be the thing that
    // cannot be delivered.
    let window =
        fetch_reply_budget().saturating_sub(veil_proto::ipc::MailboxSlicePayload::HEADER_SIZE);
    // FETCH announces device-box blobs alongside identity-box ones, so the
    // slice lookup must cover the same two boxes — an oversized blob that can
    // be announced but never sliced would put the client in a request loop
    // that no retry ends. Identity box first; the verified signer device's
    // box only behind it, under the same authorization as the extra fetch.
    let mut sliced = mailbox.slice(src_node_id, req.content_id, req.offset, window);
    if matches!(sliced, Ok(None))
        && let Some(dev) = sender_device_id
        && dev != src_node_id
        && dev != [0u8; 32]
    {
        sliced = mailbox.slice(dev, req.content_id, req.offset, window);
    }
    let resp = match sliced {
        Ok(Some((total_len, bytes))) => veil_proto::ipc::MailboxSlicePayload {
            content_id: req.content_id,
            offset: req.offset,
            total_len,
            bytes,
        },
        Ok(None) => veil_proto::ipc::MailboxSlicePayload {
            content_id: req.content_id,
            offset: req.offset,
            total_len: 0,
            bytes: Vec::new(),
        },
        Err(e) => {
            log::warn!(
                "veil-mailbox: SLICE store error (recv={} cid={}): {e}",
                hex_short(&src_node_id),
                hex_short(&req.content_id),
            );
            return;
        }
    };
    let n = resp.bytes.len();
    let total = resp.total_len;
    match sender
        .send_reply(reply_id, &resp.encode(), MAILBOX_APP_ID)
        .await
    {
        Ok(()) => log::debug!(
            "veil-mailbox: SLICE replied {n}B at {} of {total}B to recv={} cid={}",
            req.offset,
            hex_short(&src_node_id),
            hex_short(&req.content_id),
        ),
        Err(e) => log::warn!(
            "veil-mailbox: SLICE reply failed (recv={}): {e:?}",
            hex_short(&src_node_id),
        ),
    }
}

/// Handle one incoming app message addressed to the ACK endpoint.
///
/// Same auth model as FETCH: the onion delivery cryptographically verified the
/// requester, so `src_node_id` IS the receiver — it can only drop its OWN
/// blobs. Payload = the 32-byte `content_id` to drop (fire-and-forget, no
/// reply). Without this endpoint an already-processed blob was re-served on
/// every fetch until its 7-day TTL — pure wasted onion bandwidth, and a
/// permanently-undecryptable deposit kept the receiver's drain loop at max
/// cadence the whole time. All paths fail-safe: malformed/unauthenticated
/// requests are logged + discarded.
pub fn handle_ack_message(mailbox: &Mailbox, msg: AppMessage) {
    let (src_node_id, provenance, sender_device_id, data) = match msg {
        AppMessage::Deliver {
            src_node_id,
            provenance,
            sender_device_id,
            data,
            ..
        } => (src_node_id, provenance, sender_device_id, data),
        other => {
            log::debug!("veil-mailbox: ignoring non-Deliver on ACK endpoint: {other:?}");
            return;
        }
    };
    // Unauthenticated acks could drop OTHER receivers' mail — reject, exactly
    // like FETCH, and on the same evidence: what the node knows about
    // `src_node_id`, not merely that it is non-zero (X/V-01).
    if !provenance.is_authenticated() {
        log::debug!(
            "veil-mailbox: ACK dropped (src {} is {provenance:?}, not an authenticated identity)",
            hex_short(&src_node_id),
        );
        return;
    }
    if src_node_id == [0u8; 32] {
        log::debug!("veil-mailbox: ACK dropped (unauthenticated src)");
        return;
    }
    let Ok(content_id) = <[u8; 32]>::try_from(&data[..]) else {
        log::debug!(
            "veil-mailbox: ACK dropped (payload len {} != 32, recv={})",
            data.len(),
            hex_short(&src_node_id),
        );
        return;
    };
    match mailbox.ack(src_node_id, content_id) {
        Ok(removed) => log::debug!(
            "veil-mailbox: ACK recv={} content={} removed={removed}",
            hex_short(&src_node_id),
            hex_short(&content_id),
        ),
        Err(e) => log::warn!(
            "veil-mailbox: ACK store error (recv={}): {e}",
            hex_short(&src_node_id),
        ),
    }
    // FETCH serves the verified signer's device box alongside the identity
    // box, so the ack must reach both: a deposit duplicated into the two
    // boxes that dies in only one is re-served on every later fetch — the
    // exact re-serve loop this endpoint exists to end. Same authorization as
    // the extra fetch: the `sig_key_idx` subkey that verified this request IS
    // the device, so it can only ever drop that device's own mail.
    if let Some(dev) = sender_device_id
        && dev != src_node_id
        && dev != [0u8; 32]
    {
        match mailbox.ack(dev, content_id) {
            Ok(removed) => log::debug!(
                "veil-mailbox: ACK device box dev={} content={} removed={removed}",
                hex_short(&dev),
                hex_short(&content_id),
            ),
            Err(e) => log::warn!(
                "veil-mailbox: ACK device-box store error (dev={}): {e}",
                hex_short(&dev),
            ),
        }
    }
}

/// Handle one incoming app message addressed to the PUT endpoint.
/// All code paths are fail-safe: a malformed payload, a storage
/// error, or a rejected put is logged and discarded without
/// propagating up.
pub fn handle_put_message(
    mailbox: &Mailbox,
    push_trigger_tx: Option<&tokio::sync::mpsc::Sender<PushTrigger>>,
    wake_sender: Option<&MailboxWakeSender>,
    reassembler: &mut PutChunkReassembler,
    msg: AppMessage,
) {
    let (src_node_id, data) = match msg {
        AppMessage::Deliver {
            src_node_id, data, ..
        } => (src_node_id, data),
        // The other AppMessage variants (StreamOpen / StreamData /
        // RtData / etc.) shouldn't address the PUT endpoint — we use
        // datagram delivery only. Drop with a debug log.
        other => {
            log::debug!("veil-mailbox: ignoring non-Deliver AppMessage on PUT endpoint: {other:?}",);
            return;
        }
    };

    // A deposit arrives as one or more chunks (the full MailboxPutPayload often
    // exceeds the single-cell anonymous-send budget). Reassemble by content_id;
    // only proceed once the whole payload is recovered.
    let chunk = match MailboxPutChunkPayload::decode(&data) {
        Ok(c) => c,
        Err(e) => {
            log::warn!(
                "veil-mailbox: PUT chunk decode failed (src={}): {e}",
                hex_short(&src_node_id),
            );
            return;
        }
    };
    // Kept across the move into `accept`: the reassembly key must match the id
    // the assembled payload claims for itself (checked below).
    let chunk_content_id = chunk.content_id;
    let assembled = match reassembler.accept(chunk, Instant::now()) {
        Some(bytes) => bytes,
        None => return, // incomplete (or dropped) — await the remaining chunks
    };

    let req = match MailboxPutPayload::decode(&assembled) {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                "veil-mailbox: PUT decode failed after reassembly (src={}): {e}",
                hex_short(&src_node_id),
            );
            return;
        }
    };
    // The deposit is keyed for reassembly by the CHUNK's content_id, but stored,
    // deduped and ACKed by the id inside the assembled payload. Nothing tied the
    // two together, so a depositor could reassemble under one id and have the
    // relay file the blob under another — and deposits are sender-anonymous, so
    // there is no identity to hold responsible for the discrepancy.
    //
    // That splits the relay's view of one message in two: dedup and ACK act on
    // an id the reassembly never saw. Reject rather than pick a side; an honest
    // depositor writes the same value in both places, because it only ever has
    // one.
    if req.content_id != chunk_content_id {
        log::warn!(
            "veil-mailbox: PUT rejected (chunk cid={} != payload cid={}, src={})",
            hex_short(&chunk_content_id),
            hex_short(&req.content_id),
            hex_short(&src_node_id),
        );
        return;
    }

    // Soft-warn if the envelope blob in the payload claims a different
    // sender than the OVL1 session source. We don't reject — a node
    // running multiple identities could legitimately spoof its own
    // sender_id field — but log so the operator can spot funny traffic.
    if req.sender_id != src_node_id && req.sender_id != [0u8; 32] {
        log::debug!(
            "veil-mailbox: PUT sender_id ({}) differs from session source ({})",
            hex_short(&req.sender_id),
            hex_short(&src_node_id),
        );
    }

    // NO SIZE GATE HERE ANY MORE, and its removal is the point of the SLICE
    // endpoint. It rejected any deposit larger than one FETCH reply, which was
    // right while a reply was the only way out of the store — an unfetchable
    // blob wedged its receiver's queue head. But a blob's weight is not the
    // sender's to choose: it carries one ML-KEM envelope per recipient DEVICE,
    // so it grows with the identity, and past a few devices the gate refused
    // EVERY message to that identity. What is stored is bounded by the store's
    // own MAX_BLOB_BYTES; what a reply may carry is now a separate question,
    // answered a window at a time.

    let envelope_for_push = req.push_envelope.clone();
    // NOTE (489.10 slice 4.4): `req.wake_hmac_envelope` IS now forwarded onto the
    // `PushTrigger` below (alongside `req.content_id`). The push-dispatch task
    // unseals it with the relay's X25519 sk and mints an authenticated wake
    // payload; `None`/empty falls back to the legacy wake-only push.
    let wake_hmac_envelope_for_push = req.wake_hmac_envelope.clone();
    // route through `put_with_capability` so
    // the relay's `MailboxConfig::require_capability_token` policy gate
    // is honored. Token bytes (if any) come from the new optional
    // trailer on the wire. When the policy is `false` (default) and no
    // token is present, this entry-point delegates to the legacy `put`
    // path unchanged.
    //
    // SECURITY (audit 2026-05-29, A6 — per-sender quota integrity): use
    // the AUTHENTICATED OVL1 session source (`src_node_id`) as the
    // mailbox `sender` argument, NOT the wire-supplied `req.sender_id`.
    // The mailbox keys its per-sender byte quota (TABLE_SENDER_BYTES) on
    // this value AND persists it for eviction-time counter bookkeeping.
    // Keying on the spoofable `req.sender_id` let an attacker (a) rotate
    // their claimed sender_id to evade their own quota slice, or (b) set
    // it to a victim's id to exhaust the victim's slice.  `src_node_id` is
    // cryptographically bound by the session handshake, so neither is
    // possible.  Note: `req.sender_id` is a documented UNAUTHENTICATED
    // hint — the receiver must never trust it; the real sender identity
    // is conveyed inside the opaque E2E `blob`.  Surfacing the truthful
    // authenticated source as the stored hint is strictly safer.
    let outcome = match mailbox.put_with_capability(
        req.receiver_id,
        req.content_id,
        src_node_id,
        req.blob,
        req.capability_token.as_deref(),
    ) {
        Ok(o) => o,
        Err(e) => {
            log::warn!(
                "veil-mailbox: PUT mailbox.put error (recv={}): {e}",
                hex_short(&req.receiver_id),
            );
            return;
        }
    };

    use veil_mailbox::PutOutcome;
    match outcome {
        PutOutcome::Stored { evicted } => {
            log::debug!(
                "veil-mailbox: PUT stored (recv={} cid={} evicted={evicted})",
                hex_short(&req.receiver_id),
                hex_short(&req.content_id),
            );
            // In-network wake: if the receiver has a LIVE direct session with
            // this relay, tell it mail just landed so it drains NOW instead of
            // on its poll back-off. Best-effort + relay-debounced inside the
            // closure; independent of the (FCM/APNs) push envelope below —
            // most deposits carry no envelope at all.
            if let Some(wake) = wake_sender
                && wake(&req.receiver_id)
            {
                log::debug!(
                    "veil-mailbox: deposit wake sent (recv={})",
                    hex_short(&req.receiver_id),
                );
            }
            // Push trigger only when a) we have a tx and b) sender
            // supplied a non-empty envelope.
            if let Some(tx) = push_trigger_tx
                && let Some(env) = envelope_for_push.filter(|e| !e.is_empty())
            {
                // audit: bounded `try_send` — drop on
                // overflow rather than block the IPC handler.
                if tx
                    .try_send(PushTrigger {
                        receiver_id: req.receiver_id,
                        envelope: env,
                        content_id: req.content_id,
                        wake_hmac_envelope: wake_hmac_envelope_for_push,
                    })
                    .is_err()
                {
                    log::warn!(
                        "veil-mailbox: push-trigger queue full — dropping trigger \
                             for receiver={} (push is wake-hint only; blob fetched via Fetch)",
                        hex_short(&req.receiver_id),
                    );
                }
            }
        }
        PutOutcome::Duplicate => {
            log::debug!(
                "veil-mailbox: PUT duplicate cid={} — no-op",
                hex_short(&req.content_id),
            );
        }
        PutOutcome::QuotaPerReceiverExceeded {
            current_bytes,
            cap_bytes,
        } => {
            log::warn!(
                "veil-mailbox: PUT rejected (recv={} per-receiver quota: {current_bytes}/{cap_bytes})",
                hex_short(&req.receiver_id),
            );
        }
        PutOutcome::QuotaGlobalExceeded {
            blob_size,
            cap_bytes,
        } => {
            log::warn!(
                "veil-mailbox: PUT rejected (global quota: blob_size={blob_size} cap={cap_bytes})",
            );
        }
        PutOutcome::RateLimited => {
            log::warn!(
                "veil-mailbox: PUT rate-limited (recv={})",
                hex_short(&req.receiver_id),
            );
        }
        // capability-policy rejections. Logged
        // at info level — a probing client with no token (or a stale token)
        // is the expected fail mode for the policy's purpose. Operators
        // bump to DEBUG only if digging into a specific deployment
        // misconfiguration.
        PutOutcome::CapabilityRequired => {
            log::info!(
                "veil-mailbox: PUT rejected — capability token required (recv={})",
                hex_short(&req.receiver_id),
            );
        }
        PutOutcome::CapabilityInvalid => {
            log::info!(
                "veil-mailbox: PUT rejected — capability token invalid (recv={})",
                hex_short(&req.receiver_id),
            );
        }
        // per-sender quota miss. Same INFO
        // level as capability rejections — a high-rate sender is more
        // likely an over-eager legitimate client than an attack.
        PutOutcome::QuotaPerSenderExceeded {
            current_bytes,
            cap_bytes,
        } => {
            // audit cycle-6: log the AUTHENTICATED OVL1 session source
            // (`src_node_id`) — the value the per-sender quota is actually
            // keyed on — NOT the wire-supplied, spoofable `req.sender_id`.
            // Logging the latter let an attacker who exhausts their own quota
            // set `req.sender_id` to a victim's id and forge the audit trail.
            log::info!(
                "veil-mailbox: PUT rejected — per-sender quota exceeded \
                 (sender={} current={current_bytes} cap={cap_bytes})",
                hex_short(&src_node_id),
            );
        }
    }
}

pub fn hex_short(node_id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in node_id.iter().take(8) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_app::AppEndpointRegistry;
    use veil_app::registry::SenderProvenance;

    fn fresh_mailbox() -> (Arc<Mailbox>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let mb = Mailbox::open(tmp.path(), veil_mailbox::MailboxConfig::default()).unwrap();
        (Arc::new(mb), tmp)
    }

    /// A whole deposit wrapped as a SINGLE PUT chunk (these test payloads are
    /// small enough to fit one). The relay reassembles by content_id before
    /// decoding the inner MailboxPutPayload.
    fn mk_payload(
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        sender_id: [u8; 32],
        blob: Vec<u8>,
        envelope: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let inner = MailboxPutPayload {
            receiver_id,
            content_id,
            sender_id,
            blob,
            push_envelope: envelope,
            capability_token: None,
            wake_hmac_envelope: None,
        }
        .encode();
        mk_chunks(content_id, &inner)
            .pop()
            .expect("mk_payload is only used where the deposit fits one chunk")
    }

    /// Split an encoded `MailboxPutPayload` the way a real depositor does.
    ///
    /// `MAILBOX_PUT_CHUNK_DATA_BYTES` is the protocol, not a suggestion — the
    /// decoder enforces it, so a test helper that stuffs a whole multi-KB
    /// payload into one chunk gets rejected at the door and every assertion
    /// downstream of that rejection passes for the wrong reason.
    fn mk_chunks(content_id: [u8; 32], inner: &[u8]) -> Vec<Vec<u8>> {
        let total = inner.len().div_ceil(MAILBOX_PUT_CHUNK_DATA_BYTES).max(1);
        (0..total)
            .map(|i| {
                let start = i * MAILBOX_PUT_CHUNK_DATA_BYTES;
                let end = ((i + 1) * MAILBOX_PUT_CHUNK_DATA_BYTES).min(inner.len());
                MailboxPutChunkPayload {
                    content_id,
                    chunk_index: i as u16,
                    chunk_total: total as u16,
                    chunk_data: inner[start..end].to_vec(),
                }
                .encode()
            })
            .collect()
    }

    /// The encoded `MailboxPutPayload` bytes, unchunked — for tests that need
    /// to split a deposit across several chunks themselves.
    fn mk_inner(
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        sender_id: [u8; 32],
        blob: Vec<u8>,
    ) -> Vec<u8> {
        MailboxPutPayload {
            receiver_id,
            content_id,
            sender_id,
            blob,
            push_envelope: None,
            capability_token: None,
            wake_hmac_envelope: None,
        }
        .encode()
    }

    /// A Deliver addressed to the WAKE endpoint, as the dispatcher would form
    /// it for an inbound empty datagram from a session peer.
    fn wake_deliver(src_node_id: [u8; 32]) -> AppMessage {
        AppMessage::Deliver {
            src_node_id,
            provenance: SenderProvenance::Signed,
            sender_device_id: None,
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: veil_mailbox::MAILBOX_WAKE_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
            reply_id: 0,
        }
    }

    /// The wake endpoint is bound on EVERY node, whether or not the mailbox is
    /// enabled, so its sender is any session peer — not necessarily a relay
    /// holding a deposit. The relay-side 2 s debounce is per RECEIVER and lives
    /// inside the `mailbox.enabled` block, so it does not constrain this side
    /// at all: every inbound datagram used to publish a MAILBOX_WAKE, and every
    /// MAILBOX_WAKE makes the client app drain its mailbox.
    ///
    /// Asserts on the published events, not on the predicate, so the debounce
    /// has to be wired into the path that actually publishes.
    #[test]
    fn wake_listener_debounces_per_sender() {
        let bus = veil_ipc::EventBus::new();
        let mut rx = bus.subscribe();
        let mut deb = WakeDebounce::new();
        let t0 = Instant::now();
        let noisy = [0x01u8; 32];
        let relay = [0x02u8; 32];

        assert!(
            handle_wake_message(wake_deliver(noisy), &mut deb, t0, &bus),
            "the first wake from a peer must always go through",
        );
        // A burst from the SAME peer inside the window publishes nothing more.
        for i in 1..50u64 {
            assert!(
                !handle_wake_message(
                    wake_deliver(noisy),
                    &mut deb,
                    t0 + Duration::from_millis(i * 10),
                    &bus,
                ),
                "wake #{i} from the same peer inside the window must be dropped",
            );
        }
        // ... but a DIFFERENT peer is not collateral damage: a per-sender gate,
        // not one global timestamp, or a noisy peer would mute the real relay.
        assert!(
            handle_wake_message(
                wake_deliver(relay),
                &mut deb,
                t0 + Duration::from_millis(10),
                &bus,
            ),
            "a different sender must not be suppressed by the noisy one",
        );
        // Once the window elapses the same peer is admitted again.
        assert!(
            handle_wake_message(wake_deliver(noisy), &mut deb, t0 + WAKE_RECV_DEBOUNCE, &bus),
            "the debounce must reopen after WAKE_RECV_DEBOUNCE",
        );

        let mut published = 0usize;
        while let Ok(ev) = rx.try_recv() {
            assert_eq!(ev.kind, veil_proto::event_kind::MAILBOX_WAKE);
            published += 1;
        }
        assert_eq!(
            published, 3,
            "52 inbound wake datagrams must publish exactly 3 events",
        );
    }

    /// Non-Deliver traffic on the endpoint must never publish, and must not
    /// consume a debounce slot either.
    #[test]
    fn wake_listener_ignores_non_deliver() {
        let bus = veil_ipc::EventBus::new();
        let mut deb = WakeDebounce::new();
        let t0 = Instant::now();
        assert!(!handle_wake_message(
            AppMessage::DeliveryFailed {
                content_id: [0u8; 32]
            },
            &mut deb,
            t0,
            &bus,
        ));
        assert!(
            deb.last.is_empty(),
            "a non-Deliver must not occupy a debounce slot",
        );
    }

    /// The tracking map is bounded even when every tracked sender is fresh —
    /// the case plain TTL compaction cannot handle.
    #[test]
    fn wake_debounce_map_is_bounded_under_a_sender_fan() {
        let mut deb = WakeDebounce::new();
        let t0 = Instant::now();
        for i in 0..(MAX_WAKE_RECV_DEBOUNCE_ENTRIES as u64 * 3) {
            let mut src = [0u8; 32];
            src[..8].copy_from_slice(&i.to_le_bytes());
            // All inside one debounce window: nothing is ever stale.
            deb.admit(&src, t0 + Duration::from_millis(i % 1000));
        }
        assert!(
            deb.last.len() <= MAX_WAKE_RECV_DEBOUNCE_ENTRIES,
            "debounce map grew to {} entries, cap is {MAX_WAKE_RECV_DEBOUNCE_ENTRIES}",
            deb.last.len(),
        );
    }

    /// A Deliver addressed to the ACK endpoint, as the dispatcher would form it.
    fn ack_deliver(src_node_id: [u8; 32], data: Vec<u8>) -> AppMessage {
        AppMessage::Deliver {
            src_node_id,
            provenance: SenderProvenance::Signed,
            sender_device_id: None,
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_ACK_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(data),
            reply_id: 0,
        }
    }

    #[test]
    fn ack_endpoint_drops_own_blob_only() {
        let (mb, _tmp) = fresh_mailbox();
        let recv_a = [0xA1u8; 32];
        let recv_b = [0xB1u8; 32];
        let cid = [0xC1u8; 32];
        mb.put(recv_a, cid, [3u8; 32], vec![1, 2, 3]).unwrap();
        mb.put(recv_b, cid, [3u8; 32], vec![4, 5, 6]).unwrap();

        // Receiver A acks its blob — only A's copy is dropped.
        handle_ack_message(&mb, ack_deliver(recv_a, cid.to_vec()));
        assert!(
            mb.fetch(recv_a).unwrap().is_empty(),
            "A's blob must be acked away"
        );
        assert_eq!(
            mb.fetch(recv_b).unwrap().len(),
            1,
            "B's blob must survive A's ack"
        );
    }

    #[test]
    fn ack_endpoint_rejects_unauthenticated_and_malformed() {
        let (mb, _tmp) = fresh_mailbox();
        let recv = [0xA2u8; 32];
        let cid = [0xC2u8; 32];
        mb.put(recv, cid, [3u8; 32], vec![9]).unwrap();

        // Unauthenticated (anonymous-send marker src == 0) must not drop mail.
        handle_ack_message(&mb, ack_deliver([0u8; 32], cid.to_vec()));
        assert_eq!(mb.fetch(recv).unwrap().len(), 1);

        // Malformed payload (wrong length) is ignored without panicking.
        handle_ack_message(&mb, ack_deliver(recv, vec![1, 2, 3]));
        assert_eq!(mb.fetch(recv).unwrap().len(), 1);

        // Ack of an unknown content id is a harmless no-op.
        handle_ack_message(&mb, ack_deliver(recv, [0xEEu8; 32].to_vec()));
        assert_eq!(mb.fetch(recv).unwrap().len(), 1);
    }

    #[test]
    fn put_chunk_reassembler_multi_chunk_round_trip() {
        let mut ra = PutChunkReassembler::default();
        let now = Instant::now();
        let cid = [0x42u8; 32];
        // Split an 800-byte payload into 4 chunks of 200; assemble = original.
        let full: Vec<u8> = (0..800).map(|i| (i % 251) as u8).collect();
        let chunks: Vec<&[u8]> = full.chunks(200).collect();
        let total = chunks.len() as u16;
        // Feed out of order; only the last completes.
        let order = [2usize, 0, 3, 1];
        let mut assembled = None;
        for (k, &i) in order.iter().enumerate() {
            let out = ra.accept(
                MailboxPutChunkPayload {
                    content_id: cid,
                    chunk_index: i as u16,
                    chunk_total: total,
                    chunk_data: chunks[i].to_vec(),
                },
                now,
            );
            if k + 1 < order.len() {
                assert!(out.is_none(), "must not complete before all chunks");
            } else {
                assembled = out;
            }
        }
        assert_eq!(
            assembled.unwrap(),
            full,
            "reassembled bytes must equal the original"
        );
    }

    #[test]
    fn put_chunk_reassembler_evicts_stale_and_rejects_bad_input() {
        let mut ra = PutChunkReassembler::default();
        let t0 = Instant::now();
        let cid = [1u8; 32];
        // out-of-range index / zero total are dropped.
        assert!(
            ra.accept(
                MailboxPutChunkPayload {
                    content_id: cid,
                    chunk_index: 3,
                    chunk_total: 2,
                    chunk_data: vec![0]
                },
                t0,
            )
            .is_none()
        );
        assert!(
            ra.accept(
                MailboxPutChunkPayload {
                    content_id: cid,
                    chunk_index: 0,
                    chunk_total: 0,
                    chunk_data: vec![0]
                },
                t0,
            )
            .is_none()
        );
        // a partial deposit (1 of 2) then a long idle gap → the next chunk for a
        // DIFFERENT deposit triggers stale eviction; the partial never completes.
        assert!(
            ra.accept(
                MailboxPutChunkPayload {
                    content_id: cid,
                    chunk_index: 0,
                    chunk_total: 2,
                    chunk_data: vec![9]
                },
                t0,
            )
            .is_none()
        );
        let later = t0 + PUT_REASSEMBLY_STALE + Duration::from_secs(1);
        let _ = ra.accept(
            MailboxPutChunkPayload {
                content_id: [2u8; 32],
                chunk_index: 0,
                chunk_total: 1,
                chunk_data: vec![7],
            },
            later,
        );
        // The stale partial was evicted: sending its 2nd chunk now starts fresh
        // (chunk 1 alone, with chunk 0 gone) → still incomplete, no panic.
        assert!(
            ra.accept(
                MailboxPutChunkPayload {
                    content_id: cid,
                    chunk_index: 1,
                    chunk_total: 2,
                    chunk_data: vec![8]
                },
                later,
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn t1_4_p5b_app_service_stores_put_blob() {
        let (mailbox, _tmp) = fresh_mailbox();
        let mut host = BuiltinAppHost::new();
        let registry = Arc::new(AppEndpointRegistry::new());
        let ctx = host.make_context([0u8; 32], Arc::clone(&registry));
        spawn_mailbox_app_service(&mut host, ctx, Arc::clone(&mailbox), None, None, None);

        // Send a Deliver to MAILBOX_APP_ID + MAILBOX_PUT_ENDPOINT_ID.
        let recv = [11u8; 32];
        let cid = [22u8; 32];
        let payload = mk_payload(recv, cid, [33u8; 32], b"opaque".to_vec(), None);
        let sender = registry
            .get_sender(MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)
            .expect("mailbox endpoint registered");
        sender
            .try_send(AppMessage::Deliver {
                src_node_id: [33u8; 32],
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(payload),
                reply_id: 0,
            })
            .expect("send to PUT");

        // Allow service task to consume.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Verify mailbox now has the blob.
        let stored = mailbox.fetch(recv).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].content_id, cid);
        assert_eq!(stored[0].blob, b"opaque");
        host.shutdown().await;
    }

    #[tokio::test]
    async fn app_service_fires_in_network_wake_on_stored() {
        let (mailbox, _tmp) = fresh_mailbox();
        let mut host = BuiltinAppHost::new();
        let registry = Arc::new(AppEndpointRegistry::new());
        let ctx = host.make_context([0u8; 32], Arc::clone(&registry));
        // Counting wake sender — the runtime's real closure sends a session
        // frame; here we only assert the hook fires with the right receiver.
        let woken: Arc<std::sync::Mutex<Vec<[u8; 32]>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let woken_in = Arc::clone(&woken);
        let wake: MailboxWakeSender = Arc::new(move |r| {
            woken_in.lock().unwrap().push(*r);
            true
        });
        spawn_mailbox_app_service(&mut host, ctx, Arc::clone(&mailbox), None, None, Some(wake));

        let recv = [11u8; 32];
        // NO push envelope: the wake must fire regardless (most deposits carry
        // no FCM/APNs envelope at all).
        let payload = mk_payload(recv, [22u8; 32], [33u8; 32], b"x".to_vec(), None);
        let sender = registry
            .get_sender(MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)
            .unwrap();
        sender
            .try_send(AppMessage::Deliver {
                src_node_id: [33u8; 32],
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(payload),
                reply_id: 0,
            })
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(woken.lock().unwrap().as_slice(), &[recv]);
        // A DUPLICATE deposit must not wake again (only Stored does).
        let dup = mk_payload(recv, [22u8; 32], [33u8; 32], b"x".to_vec(), None);
        let sender2 = registry
            .get_sender(MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)
            .unwrap();
        sender2
            .try_send(AppMessage::Deliver {
                src_node_id: [33u8; 32],
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(dup),
                reply_id: 0,
            })
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(woken.lock().unwrap().len(), 1, "duplicate must not re-wake");
        host.shutdown().await;
    }

    #[tokio::test]
    async fn wake_listener_publishes_mailbox_wake_event() {
        let mut host = BuiltinAppHost::new();
        let registry = Arc::new(AppEndpointRegistry::new());
        let ctx = host.make_context([0u8; 32], Arc::clone(&registry));
        let bus = Arc::new(veil_ipc::EventBus::new());
        let mut events = bus.subscribe();
        spawn_mailbox_wake_listener(&mut host, ctx, Arc::clone(&bus));

        let sender = registry
            .get_sender(MAILBOX_APP_ID, veil_mailbox::MAILBOX_WAKE_ENDPOINT_ID)
            .expect("wake endpoint registered");
        sender
            .try_send(AppMessage::Deliver {
                src_node_id: [44u8; 32],
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: veil_mailbox::MAILBOX_WAKE_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
                reply_id: 0,
            })
            .unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .expect("event timeout")
            .expect("event");
        assert_eq!(ev.kind, veil_proto::event_kind::MAILBOX_WAKE);
        assert!(ev.payload.is_empty());
        host.shutdown().await;
    }

    #[tokio::test]
    async fn t1_4_p5b_app_service_fires_push_trigger_on_stored_with_envelope() {
        let (mailbox, _tmp) = fresh_mailbox();
        let mut host = BuiltinAppHost::new();
        let registry = Arc::new(AppEndpointRegistry::new());
        let ctx = host.make_context([0u8; 32], Arc::clone(&registry));
        let (push_tx, mut push_rx) =
            tokio::sync::mpsc::channel::<PushTrigger>(PUSH_TRIGGER_QUEUE_CAP);
        spawn_mailbox_app_service(
            &mut host,
            ctx,
            Arc::clone(&mailbox),
            Some(push_tx),
            None,
            None,
        );

        let recv = [11u8; 32];
        let envelope = vec![0xEE; 60];
        let payload = mk_payload(
            recv,
            [22u8; 32],
            [33u8; 32],
            b"x".to_vec(),
            Some(envelope.clone()),
        );
        let sender = registry
            .get_sender(MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)
            .unwrap();
        sender
            .try_send(AppMessage::Deliver {
                src_node_id: [33u8; 32],
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(payload),
                reply_id: 0,
            })
            .unwrap();

        // Push trigger should arrive within a few ms.
        let trigger = tokio::time::timeout(std::time::Duration::from_secs(1), push_rx.recv())
            .await
            .expect("trigger timeout")
            .expect("channel closed");
        assert_eq!(trigger.receiver_id, recv);
        assert_eq!(trigger.envelope, envelope);
        host.shutdown().await;
    }

    #[tokio::test]
    async fn t1_4_p5b_app_service_does_not_fire_push_when_envelope_absent() {
        let (mailbox, _tmp) = fresh_mailbox();
        let mut host = BuiltinAppHost::new();
        let registry = Arc::new(AppEndpointRegistry::new());
        let ctx = host.make_context([0u8; 32], Arc::clone(&registry));
        let (push_tx, mut push_rx) =
            tokio::sync::mpsc::channel::<PushTrigger>(PUSH_TRIGGER_QUEUE_CAP);
        spawn_mailbox_app_service(
            &mut host,
            ctx,
            Arc::clone(&mailbox),
            Some(push_tx),
            None,
            None,
        );

        let payload = mk_payload(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            b"no-envelope".to_vec(),
            None,
        );
        let sender = registry
            .get_sender(MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)
            .unwrap();
        sender
            .try_send(AppMessage::Deliver {
                src_node_id: [3u8; 32],
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(payload),
                reply_id: 0,
            })
            .unwrap();
        // Wait for the put to complete.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Push channel must NOT have a trigger.
        assert!(
            push_rx.try_recv().is_err(),
            "push trigger fired even though envelope was None",
        );
        host.shutdown().await;
    }

    #[tokio::test]
    async fn t1_4_p5b_app_service_drops_malformed_payload_without_panic() {
        let (mailbox, _tmp) = fresh_mailbox();
        let mut host = BuiltinAppHost::new();
        let registry = Arc::new(AppEndpointRegistry::new());
        let ctx = host.make_context([0u8; 32], Arc::clone(&registry));
        spawn_mailbox_app_service(&mut host, ctx, Arc::clone(&mailbox), None, None, None);

        let sender = registry
            .get_sender(MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)
            .unwrap();
        // Truncated payload — must be dropped without crashing the service.
        sender
            .try_send(AppMessage::Deliver {
                src_node_id: [3u8; 32],
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(vec![0u8; 10]), // way too short for header
                reply_id: 0,
            })
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Service still alive — second Deliver succeeds.
        let valid = mk_payload([7u8; 32], [8u8; 32], [9u8; 32], b"ok".to_vec(), None);
        sender
            .try_send(AppMessage::Deliver {
                src_node_id: [9u8; 32],
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(valid),
                reply_id: 0,
            })
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stored = mailbox.fetch([7u8; 32]).unwrap();
        assert_eq!(stored.len(), 1);
        host.shutdown().await;
    }

    #[tokio::test]
    async fn t1_4_p5b_app_service_ignores_non_deliver_messages() {
        // Send AppMessage::DeliveryStage (which shouldn't address PUT
        // endpoint in normal flow) — service must drop and stay alive.
        let (mailbox, _tmp) = fresh_mailbox();
        let mut host = BuiltinAppHost::new();
        let registry = Arc::new(AppEndpointRegistry::new());
        let ctx = host.make_context([0u8; 32], Arc::clone(&registry));
        spawn_mailbox_app_service(&mut host, ctx, Arc::clone(&mailbox), None, None, None);

        let sender = registry
            .get_sender(MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)
            .unwrap();
        sender
            .try_send(AppMessage::DeliveryStage {
                content_id: [0u8; 32],
                stage: 0,
            })
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Service still alive — valid follow-up succeeds.
        let valid = mk_payload([1u8; 32], [2u8; 32], [3u8; 32], b"after".to_vec(), None);
        sender
            .try_send(AppMessage::Deliver {
                src_node_id: [3u8; 32],
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(valid),
                reply_id: 0,
            })
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stored = mailbox.fetch([1u8; 32]).unwrap();
        assert_eq!(stored.len(), 1);
        host.shutdown().await;
    }

    // ── FETCH endpoint ──────────────────────────────────────────────────────

    /// Captures `send_reply` calls; every other AnonOnionSender method is
    /// unreachable on the FETCH path and panics if hit.
    type CapturedReplies = std::sync::Arc<std::sync::Mutex<Vec<(u64, Vec<u8>, [u8; 32])>>>;

    struct MockReplySender {
        captured: CapturedReplies,
    }

    type AnonFut<'a> = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    >;

    impl veil_types::AnonOnionSender for MockReplySender {
        fn send_reply<'a>(
            &'a self,
            reply_id: u64,
            data: &'a [u8],
            src_app_id: [u8; 32],
        ) -> AnonFut<'a> {
            self.captured
                .lock()
                .unwrap()
                .push((reply_id, data.to_vec(), src_app_id));
            Box::pin(async { Ok(()) })
        }
        fn send_authenticated<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: &'a [u8],
        ) -> AnonFut<'a> {
            unimplemented!()
        }
        fn send_authenticated_with_reply<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: &'a [u8],
            _: [u8; 32],
            _: u32,
        ) -> AnonFut<'a> {
            unimplemented!()
        }
        fn send_authenticated_direct_with_reply<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: &'a [u8],
            _: Option<([u8; 32], u32)>,
        ) -> AnonFut<'a> {
            Box::pin(async { Ok(()) })
        }
        fn register_onion_service<'a>(&'a self, _: usize) -> AnonFut<'a> {
            unimplemented!()
        }
        fn register_rendezvous_publisher(
            &self,
            _: [u8; 32],
            _: [u8; 16],
            _: u64,
            _: u8,
            _: Vec<u8>,
        ) {
            unimplemented!()
        }
        fn send_to_onion_service<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: &'a [u8],
            _: usize,
        ) -> AnonFut<'a> {
            unimplemented!()
        }
        fn send_to_onion_service_anonymous<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: [u8; 32],
            _: &'a [u8],
            _: usize,
        ) -> AnonFut<'a> {
            unimplemented!()
        }
        fn send_anonymous_direct<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: [u8; 32],
            _: &'a [u8],
            _: usize,
        ) -> AnonFut<'a> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn network_fetch_replies_with_authenticated_receivers_blobs() {
        let (mailbox, _tmp) = fresh_mailbox();
        // Deposit a blob for the receiver that will authenticate as src_node_id.
        let recv = [0x77u8; 32];
        mailbox
            .put(recv, [0xC1; 32], [0xAA; 32], b"sealed-blob".to_vec())
            .unwrap();
        // A different receiver's blob must NOT leak into recv's fetch.
        mailbox
            .put([0x99; 32], [0xC2; 32], [0xBB; 32], b"other".to_vec())
            .unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });

        // Authenticated delivery: src_node_id == recv, non-zero reply_id.
        let msg = AppMessage::Deliver {
            src_node_id: recv,
            provenance: SenderProvenance::Signed,
            sender_device_id: None,
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_FETCH_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
            reply_id: 99,
        };
        handle_fetch_message(&mailbox, Some(&sender), msg).await;

        let cap = captured.lock().unwrap();
        assert_eq!(cap.len(), 1, "exactly one reply");
        let (rid, data, src_app) = &cap[0];
        assert_eq!(*rid, 99, "replies over the inbound reply_id");
        assert_eq!(*src_app, MAILBOX_APP_ID, "reply owned by the mailbox app");
        let resp = veil_proto::MailboxFetchRespPayload::decode(data).unwrap();
        assert_eq!(resp.blobs.len(), 1, "only the receiver's own blob");
        assert_eq!(resp.blobs[0].content_id, [0xC1; 32]);
        assert_eq!(resp.blobs[0].blob, b"sealed-blob");
    }

    #[tokio::test]
    async fn network_fetch_drops_unauthenticated_or_no_reply_path() {
        let (mailbox, _tmp) = fresh_mailbox();
        mailbox
            .put([0x77; 32], [0xC1; 32], [0xAA; 32], b"x".to_vec())
            .unwrap();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });
        // Anonymous source (src_node_id == 0): no verified receiver → drop.
        let anon = AppMessage::Deliver {
            src_node_id: [0u8; 32],
            provenance: SenderProvenance::Claimed,
            sender_device_id: None,
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_FETCH_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
            reply_id: 5,
        };
        handle_fetch_message(&mailbox, Some(&sender), anon).await;
        // No reply path (reply_id == 0): nowhere to answer → drop.
        let noreply = AppMessage::Deliver {
            src_node_id: [0x77u8; 32],
            provenance: SenderProvenance::Signed,
            sender_device_id: None,
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_FETCH_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
            reply_id: 0,
        };
        handle_fetch_message(&mailbox, Some(&sender), noreply).await;
        assert!(
            captured.lock().unwrap().is_empty(),
            "no reply for either drop case"
        );
    }

    /// X/V-01 at a consumer: FETCH keys a mailbox by `src_node_id`, so it must
    /// refuse a request whose sender was never verified — even one that is
    /// otherwise perfectly well-formed (non-zero id, valid reply path). The
    /// two pre-existing shape checks (`src != 0`, `reply_id != 0`) both pass
    /// here; only the provenance decides, which is the point.
    #[tokio::test]
    async fn network_fetch_refuses_a_well_formed_but_unauthenticated_requester() {
        let (mailbox, _tmp) = fresh_mailbox();
        let victim = [0x77u8; 32];
        mailbox
            .put(victim, [0xC1; 32], [0xAA; 32], b"victims-mail".to_vec())
            .unwrap();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });

        let spoofed = AppMessage::Deliver {
            src_node_id: victim,
            provenance: SenderProvenance::Claimed,
            sender_device_id: None,
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_FETCH_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
            reply_id: 42,
        };
        handle_fetch_message(&mailbox, Some(&sender), spoofed).await;
        assert!(
            captured.lock().unwrap().is_empty(),
            "an unverified requester must not be handed the victim's mail",
        );
    }

    /// Same for ACK, which can DELETE mail: an unverified sender naming the
    /// victim must not be able to drop the victim's blobs.
    #[test]
    fn network_ack_refuses_a_well_formed_but_unauthenticated_requester() {
        let (mailbox, _tmp) = fresh_mailbox();
        let victim = [0x77u8; 32];
        let content_id = [0xC1u8; 32];
        mailbox
            .put(victim, content_id, [0xAA; 32], b"victims-mail".to_vec())
            .unwrap();

        handle_ack_message(
            &mailbox,
            AppMessage::Deliver {
                src_node_id: victim,
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_ACK_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(content_id.to_vec()),
                reply_id: 0,
            },
        );
        assert_eq!(
            mailbox.fetch(victim).unwrap().len(),
            1,
            "an unverified ACK must not drop the victim's mail",
        );

        // The verified form of the very same request DOES drop it — otherwise
        // "ACK never works" would pass the assertion above.
        handle_ack_message(
            &mailbox,
            AppMessage::Deliver {
                src_node_id: victim,
                provenance: SenderProvenance::Signed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_ACK_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(content_id.to_vec()),
                reply_id: 0,
            },
        );
        assert!(
            mailbox.fetch(victim).unwrap().is_empty(),
            "a verified ACK must still drop the blob",
        );
    }

    /// A family device authenticates FETCH as the shared IDENTITY, so mail
    /// deposited under its own DEVICE id was never fetched by anyone — a live
    /// black hole. The verified signer device on the request is the
    /// authorization to drain that box too, in the SAME reply: identity box
    /// first, device box behind it.
    #[tokio::test]
    async fn network_fetch_drains_the_verified_devices_box_alongside_the_identitys() {
        let (mailbox, _tmp) = fresh_mailbox();
        let identity = [0x11u8; 32];
        let device = [0xD1u8; 32];
        mailbox
            .put(identity, [0xC1; 32], [0xAA; 32], b"for-identity".to_vec())
            .unwrap();
        mailbox
            .put(device, [0xC2; 32], [0xAA; 32], b"for-device".to_vec())
            .unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });
        let msg = AppMessage::Deliver {
            src_node_id: identity,
            provenance: SenderProvenance::Signed,
            sender_device_id: Some(device),
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_FETCH_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
            reply_id: 13,
        };
        handle_fetch_message(&mailbox, Some(&sender), msg).await;

        let cap = captured.lock().unwrap();
        assert_eq!(cap.len(), 1, "one reply carries both boxes");
        let resp = veil_proto::MailboxFetchRespPayload::decode(&cap[0].1).unwrap();
        assert_eq!(resp.blobs.len(), 2, "identity box + device box");
        assert_eq!(resp.blobs[0].blob, b"for-identity", "identity box first");
        assert_eq!(
            resp.blobs[1].blob, b"for-device",
            "the device box rides the SAME reply",
        );
    }

    /// The reply budget packs from the front, so ordering IS delivery policy:
    /// a device-box blob older than the identity backlog must not wait behind
    /// it. Measured live before the merge-sort: 133 device blobs announced,
    /// zero served — 74 identity blobs took the whole budget every round.
    #[tokio::test]
    async fn network_fetch_serves_boxes_oldest_first_not_identity_first() {
        let tmp = tempfile::tempdir().unwrap();
        let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1_000));
        let c2 = std::sync::Arc::clone(&clock);
        let mailbox = Arc::new(
            Mailbox::open_with_clock(
                tmp.path(),
                veil_mailbox::MailboxConfig::default(),
                move || c2.load(std::sync::atomic::Ordering::SeqCst),
            )
            .unwrap(),
        );
        let identity = [0x11u8; 32];
        let device = [0xD1u8; 32];
        // Device blob deposited FIRST (older)…
        mailbox
            .put(device, [0xC1; 32], [0xAA; 32], b"older-device".to_vec())
            .unwrap();
        clock.store(2_000, std::sync::atomic::Ordering::SeqCst);
        // …identity blob a wall-clock second later.
        mailbox
            .put(identity, [0xC2; 32], [0xAA; 32], b"newer-identity".to_vec())
            .unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });
        let msg = AppMessage::Deliver {
            src_node_id: identity,
            provenance: SenderProvenance::Signed,
            sender_device_id: Some(device),
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_FETCH_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
            reply_id: 55,
        };
        handle_fetch_message(&mailbox, Some(&sender), msg).await;

        let cap = captured.lock().unwrap();
        let resp = veil_proto::MailboxFetchRespPayload::decode(&cap[0].1).unwrap();
        assert_eq!(resp.blobs.len(), 2);
        assert_eq!(
            resp.blobs[0].blob, b"older-device",
            "the older device-box blob is served first",
        );
        assert_eq!(resp.blobs[1].blob, b"newer-identity");
    }

    /// An oversized blob in a DEVICE box: FETCH announces it, so SLICE must
    /// find it too — a blob that can be announced but never sliced puts the
    /// client in a request loop no retry ends. Same two-box lookup, same
    /// authorization: only the verified signer device reaches its own box.
    #[tokio::test]
    async fn network_slice_reads_the_verified_devices_box() {
        let (mailbox, _tmp) = fresh_mailbox();
        let identity = [0x11u8; 32];
        let device = [0xD1u8; 32];
        let cid = [0xC7u8; 32];
        let body = vec![0xB7u8; 9000];
        mailbox.put(device, cid, [0xAA; 32], body.clone()).unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });
        let req = veil_proto::ipc::MailboxSliceReqPayload {
            content_id: cid,
            offset: 0,
        };
        let msg = AppMessage::Deliver {
            src_node_id: identity,
            provenance: SenderProvenance::Signed,
            sender_device_id: Some(device),
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_SLICE_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(req.encode()),
            reply_id: 34,
        };
        handle_slice_message(&mailbox, Some(&sender), msg).await;

        // Scoped, not `drop`ped: the guard must be structurally dead before
        // the second `.await` below, and a plain `drop()` leaves it alive as
        // far as the await-holding-lock check is concerned.
        {
            let cap = captured.lock().unwrap();
            assert_eq!(cap.len(), 1);
            let resp = veil_proto::ipc::MailboxSlicePayload::decode(&cap[0].1).unwrap();
            assert_eq!(
                resp.total_len as usize,
                body.len(),
                "the device-box blob answers"
            );
            assert!(!resp.bytes.is_empty());
            assert_eq!(&body[..resp.bytes.len()], &resp.bytes[..]);
        }

        // And WITHOUT the verified device the same request finds nothing —
        // the box stays invisible to a fetcher the signature does not name.
        captured.lock().unwrap().clear();
        let req2 = veil_proto::ipc::MailboxSliceReqPayload {
            content_id: cid,
            offset: 0,
        };
        let msg2 = AppMessage::Deliver {
            src_node_id: identity,
            provenance: SenderProvenance::Signed,
            sender_device_id: None,
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_SLICE_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(req2.encode()),
            reply_id: 35,
        };
        handle_slice_message(&mailbox, Some(&sender), msg2).await;
        let cap = captured.lock().unwrap();
        assert_eq!(cap.len(), 1);
        let resp2 = veil_proto::ipc::MailboxSlicePayload::decode(&cap[0].1).unwrap();
        assert_eq!(
            resp2.total_len, 0,
            "no verified device, no device-box slice"
        );
        assert!(resp2.bytes.is_empty());
    }

    /// Without a verified signer device the old contract holds exactly: a
    /// fetch reads ONLY the box keyed by the authenticated fetcher id. `Some`
    /// is minted solely by the signature-verified delivery path, so nothing a
    /// non-family fetcher sends can name someone else's device box.
    #[tokio::test]
    async fn network_fetch_without_a_verified_device_leaves_device_boxes_alone() {
        let (mailbox, _tmp) = fresh_mailbox();
        let identity = [0x11u8; 32];
        let device = [0xD1u8; 32];
        mailbox
            .put(device, [0xC2; 32], [0xAA; 32], b"for-device".to_vec())
            .unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });
        let msg = AppMessage::Deliver {
            src_node_id: identity,
            provenance: SenderProvenance::Signed,
            sender_device_id: None,
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_FETCH_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
            reply_id: 21,
        };
        handle_fetch_message(&mailbox, Some(&sender), msg).await;

        let cap = captured.lock().unwrap();
        assert_eq!(cap.len(), 1, "the empty identity box still answers");
        let resp = veil_proto::MailboxFetchRespPayload::decode(&cap[0].1).unwrap();
        assert!(
            resp.blobs.is_empty(),
            "no verified device ⇒ no device box in the reply",
        );
        assert_eq!(
            mailbox.fetch(device).unwrap().len(),
            1,
            "the device box is untouched",
        );
    }

    /// A deposit duplicated into BOTH the identity box and the signer's
    /// device box must die in both on one ack — a surviving copy is re-served
    /// on every later fetch, the exact loop the ACK endpoint exists to end.
    #[test]
    fn network_ack_from_a_family_device_clears_both_boxes() {
        let (mailbox, _tmp) = fresh_mailbox();
        let identity = [0x11u8; 32];
        let device = [0xD1u8; 32];
        let cid = [0xC7u8; 32];
        mailbox
            .put(identity, cid, [0xAA; 32], b"copy-i".to_vec())
            .unwrap();
        mailbox
            .put(device, cid, [0xAA; 32], b"copy-d".to_vec())
            .unwrap();

        handle_ack_message(
            &mailbox,
            AppMessage::Deliver {
                src_node_id: identity,
                provenance: SenderProvenance::Signed,
                sender_device_id: Some(device),
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_ACK_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(cid.to_vec()),
                reply_id: 0,
            },
        );
        assert!(
            mailbox.fetch(identity).unwrap().is_empty(),
            "the identity-box copy dies",
        );
        assert!(
            mailbox.fetch(device).unwrap().is_empty(),
            "the device-box copy dies in the same ack",
        );
    }

    #[tokio::test]
    async fn network_fetch_announces_oversized_head_blob_and_serves_next() {
        let (mailbox, _tmp) = fresh_mailbox();
        let recv = [0x77u8; 32];
        // A deposit that ALONE exceeds the reply budget. It cannot ride a reply
        // whole — under the old "always emit at least one" rule it failed
        // PayloadTooLarge every time and wedged the queue head forever — and it
        // must not be deleted either: what a blob weighs is not the sender's to
        // choose, since it carries one envelope per recipient DEVICE.
        let oversized = vec![0xEE; fetch_reply_budget()];
        mailbox
            .put(recv, [0xC1; 32], [0xAA; 32], oversized)
            .unwrap();
        // A perfectly deliverable blob behind it.
        mailbox
            .put(recv, [0xC2; 32], [0xAA; 32], b"deliverable".to_vec())
            .unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });
        let msg = AppMessage::Deliver {
            src_node_id: recv,
            provenance: SenderProvenance::Signed,
            sender_device_id: None,
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_FETCH_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
            reply_id: 7,
        };
        handle_fetch_message(&mailbox, Some(&sender), msg).await;

        let cap = captured.lock().unwrap();
        assert_eq!(cap.len(), 1, "exactly one reply");
        let resp = veil_proto::MailboxFetchRespPayload::decode(&cap[0].1).unwrap();
        assert_eq!(resp.blobs.len(), 2, "the oversized one is announced too");
        let announced = resp
            .blobs
            .iter()
            .find(|b| b.content_id == [0xC1; 32])
            .expect("the oversized blob is named in the reply");
        assert!(
            announced.blob.is_empty(),
            "announced with no bytes — the receiver comes back for them",
        );
        let served = resp
            .blobs
            .iter()
            .find(|b| b.content_id == [0xC2; 32])
            .expect("the deliverable blob still rides");
        assert_eq!(served.blob, b"deliverable");
        // And the reply still fits what one reply may carry.
        assert!(cap[0].1.len() <= fetch_reply_budget());
        // The announced blob is STILL THERE. Deleting it is how a receiver ends
        // up waiting forever for mail the relay threw away.
        let left = mailbox.fetch(recv).unwrap();
        assert_eq!(left.len(), 2, "nothing was purged");
    }

    #[tokio::test]
    async fn slice_endpoint_serves_a_blob_no_reply_could_carry() {
        let (mailbox, _tmp) = fresh_mailbox();
        let recv = [0x66u8; 32];
        let cid = [0xD1u8; 32];
        // Three replies' worth: the walk has to take several rounds, which is
        // the case a single-round implementation would pass by accident.
        let payload: Vec<u8> = (0..fetch_reply_budget() * 3)
            .map(|i| (i % 251) as u8)
            .collect();
        mailbox.put(recv, cid, [0xAA; 32], payload.clone()).unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });
        let mut got: Vec<u8> = Vec::new();
        let mut offset = 0u32;
        for round in 0..16 {
            let req = veil_proto::ipc::MailboxSliceReqPayload {
                content_id: cid,
                offset,
            }
            .encode();
            handle_slice_message(
                &mailbox,
                Some(&sender),
                AppMessage::Deliver {
                    src_node_id: recv,
                    provenance: SenderProvenance::Signed,
                    sender_device_id: None,
                    src_app_id: [0u8; 32],
                    app_id: MAILBOX_APP_ID,
                    endpoint_id: MAILBOX_SLICE_ENDPOINT_ID,
                    data: veil_bufpool::pooled_shared_from_vec(req),
                    reply_id: 9,
                },
            )
            .await;
            let reply = {
                let cap = captured.lock().unwrap();
                assert_eq!(cap.len(), round + 1, "one reply per request");
                cap[round].1.clone()
            };
            assert!(
                reply.len() <= fetch_reply_budget(),
                "a slice reply must itself fit one reply",
            );
            let slice = veil_proto::ipc::MailboxSlicePayload::decode(&reply).unwrap();
            assert_eq!(slice.total_len as usize, payload.len());
            if slice.bytes.is_empty() {
                break;
            }
            offset += slice.bytes.len() as u32;
            got.extend_from_slice(&slice.bytes);
            if got.len() >= payload.len() {
                break;
            }
        }
        assert_eq!(got, payload, "the windows reassemble to the deposit");
    }

    #[tokio::test]
    async fn slice_endpoint_refuses_to_read_another_receivers_mail() {
        let (mailbox, _tmp) = fresh_mailbox();
        let owner = [0x11u8; 32];
        let cid = [0xD2u8; 32];
        mailbox
            .put(owner, cid, [0xAA; 32], vec![0x5A; 4096])
            .unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });
        // A DIFFERENT authenticated node naming the content id it wants.
        handle_slice_message(
            &mailbox,
            Some(&sender),
            AppMessage::Deliver {
                src_node_id: [0x99u8; 32],
                provenance: SenderProvenance::Signed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_SLICE_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(
                    veil_proto::ipc::MailboxSliceReqPayload {
                        content_id: cid,
                        offset: 0,
                    }
                    .encode(),
                ),
                reply_id: 9,
            },
        )
        .await;
        let cap = captured.lock().unwrap();
        assert_eq!(cap.len(), 1, "it is answered, not ignored");
        let slice = veil_proto::ipc::MailboxSlicePayload::decode(&cap[0].1).unwrap();
        assert_eq!(slice.total_len, 0, "and the answer is: nothing here");
        assert!(slice.bytes.is_empty());
    }

    #[tokio::test]
    async fn slice_endpoint_refuses_an_unauthenticated_request() {
        let (mailbox, _tmp) = fresh_mailbox();
        let recv = [0x22u8; 32];
        let cid = [0xD3u8; 32];
        mailbox
            .put(recv, cid, [0xAA; 32], vec![0x5A; 4096])
            .unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });
        handle_slice_message(
            &mailbox,
            Some(&sender),
            AppMessage::Deliver {
                src_node_id: recv,
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_SLICE_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(
                    veil_proto::ipc::MailboxSliceReqPayload {
                        content_id: cid,
                        offset: 0,
                    }
                    .encode(),
                ),
                reply_id: 9,
            },
        )
        .await;
        assert!(
            captured.lock().unwrap().is_empty(),
            "an unverified claim gets no bytes and no answer",
        );
    }

    #[test]
    fn a_replayed_chunk_cannot_hold_a_reassembly_slot_open() {
        // 128 slots, and re-sending a chunk already held used to push the idle
        // timer forward. An attacker filled every slot with a first-of-N chunk
        // and replayed them every 29 seconds; honest deposits were refused for
        // as long as they cared to keep it up, and the capability check never
        // ran because it only happens after full reassembly (audit V-02).
        let mut ra = PutChunkReassembler::default();
        let t0 = Instant::now();

        fn first_of_two(id: u8) -> MailboxPutChunkPayload {
            MailboxPutChunkPayload {
                content_id: [id; 32],
                chunk_index: 0,
                chunk_total: 2,
                chunk_data: vec![0xAA; 16],
            }
        }

        // Fill every slot with a deposit that will never be finished.
        for id in 0..MAX_INFLIGHT_PUT_REASSEMBLIES {
            assert!(ra.accept(first_of_two(id as u8), t0).is_none());
        }
        assert_eq!(ra.inflight.len(), MAX_INFLIGHT_PUT_REASSEMBLIES);

        // 1. A NEW deposit still gets in, by displacing the least-advanced
        //    squatter rather than being turned away.
        let honest = [0xEE; 32];
        assert!(
            ra.accept(
                MailboxPutChunkPayload {
                    content_id: honest,
                    chunk_index: 0,
                    chunk_total: 2,
                    chunk_data: vec![0xBB; 16],
                },
                t0,
            )
            .is_none(),
            "first of two chunks — not complete yet"
        );
        assert!(
            ra.inflight.contains_key(&honest),
            "a full table must not lock every newcomer out"
        );
        assert_eq!(
            ra.inflight.len(),
            MAX_INFLIGHT_PUT_REASSEMBLIES,
            "still bounded — one in, one out"
        );

        // ...and it completes normally.
        let assembled = ra.accept(
            MailboxPutChunkPayload {
                content_id: honest,
                chunk_index: 1,
                chunk_total: 2,
                chunk_data: vec![0xCC; 16],
            },
            t0,
        );
        assert!(assembled.is_some(), "the honest deposit must reassemble");

        // 2. Replaying a chunk we already hold is not progress, so it cannot
        //    carry accumulated state across the idle window. Re-sending it can
        //    only ever start a fresh reassembly — never preserve the old one's
        //    chunks — which is what stops an attacker from banking progress and
        //    what keeps their slots the least-advanced, hence first evicted.
        let mut ra = PutChunkReassembler::default();
        let squatter = [0x11; 32];
        assert!(ra.accept(first_of_two(0x11), t0).is_none());
        // A replay half-way through the idle window. Under the old rule this
        // pushed the timer to here and chunk 0 survived to meet chunk 1 below.
        assert!(
            ra.accept(first_of_two(0x11), t0 + PUT_REASSEMBLY_STALE / 2)
                .is_none()
        );

        let past_idle = t0 + PUT_REASSEMBLY_STALE + Duration::from_secs(1);
        let finishing = MailboxPutChunkPayload {
            content_id: squatter,
            chunk_index: 1,
            chunk_total: 2,
            chunk_data: vec![0xAA; 16],
        };
        assert!(
            ra.accept(finishing, past_idle).is_none(),
            "chunk 0 was replayed, not re-sent as progress, so it must have \
             aged out — the deposit cannot complete off a banked chunk"
        );

        // 3. Even a deposit that keeps making REAL progress cannot outlive the
        //    hard deadline — nothing arriving can move `created`.
        let mut ra = PutChunkReassembler::default();
        let slow = [0x33; 32];
        assert!(
            ra.accept(
                MailboxPutChunkPayload {
                    content_id: slow,
                    chunk_index: 0,
                    chunk_total: 200,
                    chunk_data: vec![0xDD; 16],
                },
                t0,
            )
            .is_none()
        );
        // A genuinely new chunk every 10s keeps the idle timer alive — and
        // stays inside the hard deadline, so the entry is never re-created and
        // `created` really is t0 when the deadline is checked below.
        for i in 1..11u16 {
            let t = t0 + Duration::from_secs(10 * i as u64);
            ra.accept(
                MailboxPutChunkPayload {
                    content_id: slow,
                    chunk_index: i,
                    chunk_total: 200,
                    chunk_data: vec![0xDD; 16],
                },
                t,
            );
        }
        let past_lifetime = t0 + PUT_REASSEMBLY_MAX_LIFETIME + Duration::from_secs(1);
        ra.accept(first_of_two(0x44), past_lifetime);
        assert!(
            !ra.inflight.contains_key(&slow),
            "the hard deadline must fire even on a reassembly still progressing"
        );
    }

    #[test]
    fn put_chunk_bytes_are_capped_and_the_two_content_ids_must_agree() {
        let (mb, _tmp) = fresh_mailbox();
        let recv = [0x77u8; 32];
        let cid = [0x88u8; 32];

        // 1. An oversized chunk never reaches the reassembler's allocation.
        //    MAX_MAILBOX_PUT_CHUNKS bounds the chunk COUNT; without a byte cap
        //    128 concurrent reassemblies x 256 chunks is bounded by the frame
        //    size (16 MiB), not the ~60 KB the design assumes — from deposits
        //    that need no authentication to send.
        let mut ra = PutChunkReassembler::default();
        let fat = MailboxPutChunkPayload {
            content_id: cid,
            chunk_index: 0,
            chunk_total: 1,
            chunk_data: vec![0xEE; MAILBOX_PUT_CHUNK_DATA_BYTES + 1],
        };
        assert!(
            MailboxPutChunkPayload::decode(&fat.encode()).is_err(),
            "the decoder must refuse a chunk past the per-chunk cap"
        );
        assert!(
            ra.accept(fat, Instant::now()).is_none(),
            "the reassembler allocates, so it must refuse it independently"
        );

        // 2. The reassembly key and the id the payload claims must be the same
        //    value. Nothing tied them together, so a deposit could reassemble
        //    under one id and be stored, deduped and ACKed under another — and
        //    deposits are sender-anonymous, so no identity answers for it.
        let inner = mk_inner(recv, [0x99u8; 32], [0x33u8; 32], b"mismatched".to_vec());
        for chunk in mk_chunks(cid, &inner) {
            handle_put_message(
                &mb,
                None,
                None,
                &mut ra,
                AppMessage::Deliver {
                    src_node_id: [0x33u8; 32],
                    provenance: SenderProvenance::Claimed,
                    sender_device_id: None,
                    src_app_id: [0u8; 32],
                    app_id: MAILBOX_APP_ID,
                    endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                    data: veil_bufpool::pooled_shared_from_vec(chunk),
                    reply_id: 0,
                },
            );
        }
        assert!(
            mb.fetch(recv).unwrap().is_empty(),
            "a deposit whose two content_ids disagree must not be stored"
        );

        // 3. Control: the same deposit with both ids equal DOES land, so the
        //    check above is rejecting the mismatch and not the shape.
        let agreed = mk_inner(recv, cid, [0x33u8; 32], b"agreed".to_vec());
        for chunk in mk_chunks(cid, &agreed) {
            handle_put_message(
                &mb,
                None,
                None,
                &mut ra,
                AppMessage::Deliver {
                    src_node_id: [0x33u8; 32],
                    provenance: SenderProvenance::Claimed,
                    sender_device_id: None,
                    src_app_id: [0u8; 32],
                    app_id: MAILBOX_APP_ID,
                    endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                    data: veil_bufpool::pooled_shared_from_vec(chunk),
                    reply_id: 0,
                },
            );
        }
        let stored = mb.fetch(recv).unwrap();
        assert_eq!(stored.len(), 1, "the agreeing deposit must land");
        assert_eq!(stored[0].blob, b"agreed");
    }

    #[test]
    fn put_endpoint_stores_a_blob_no_single_reply_could_carry() {
        let (mb, _tmp) = fresh_mailbox();
        let recv = [0x55u8; 32];
        let mut ra = PutChunkReassembler::default();
        // Blob big enough that blob + per-entry wire header exceeds one FETCH
        // reply. It used to be refused at the door as "permanently
        // unfetchable", which for a multi-device identity meant refusing every
        // message: a blob carries one ML-KEM envelope per recipient DEVICE, so
        // its weight follows the identity and no size the app could pick was
        // small enough. It is stored now and served in windows.
        //
        // A ~5.6 KB blob does not fit one chunk, and must not be made to: the
        // decoder caps chunk_data at 240 B, so a single oversized chunk would
        // be rejected there and the deposit path below would never run.
        let inner = mk_inner(
            recv,
            [0xC9; 32],
            [0x33; 32],
            vec![0xEE; fetch_reply_budget()],
        );
        for chunk in mk_chunks([0xC9; 32], &inner) {
            handle_put_message(
                &mb,
                None,
                None,
                &mut ra,
                AppMessage::Deliver {
                    src_node_id: [0x33u8; 32],
                    provenance: SenderProvenance::Claimed,
                    sender_device_id: None,
                    src_app_id: [0u8; 32],
                    app_id: MAILBOX_APP_ID,
                    endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                    data: veil_bufpool::pooled_shared_from_vec(chunk),
                    reply_id: 0,
                },
            );
        }
        let stored = mb.fetch(recv).unwrap();
        assert_eq!(stored.len(), 1, "the oversized deposit is kept");
        assert_eq!(stored[0].blob.len(), fetch_reply_budget());
        // And it can be read back out, which is what makes keeping it honest.
        let (total, window) = mb
            .slice(recv, [0xC9; 32], 0, 1024)
            .unwrap()
            .expect("stored, therefore sliceable");
        assert_eq!(total as usize, fetch_reply_budget());
        assert_eq!(window.len(), 1024);

        // Control: a normal-sized deposit through the same path still lands.
        let ok = mk_payload(recv, [0xCA; 32], [0x33; 32], b"fits".to_vec(), None);
        handle_put_message(
            &mb,
            None,
            None,
            &mut ra,
            AppMessage::Deliver {
                src_node_id: [0x33u8; 32],
                provenance: SenderProvenance::Claimed,
                sender_device_id: None,
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(ok),
                reply_id: 0,
            },
        );
        let both = mb.fetch(recv).unwrap();
        assert_eq!(
            both.len(),
            2,
            "normal deposit still stored, beside the big one"
        );
        assert!(both.iter().any(|b| b.blob == b"fits"));
    }
}
