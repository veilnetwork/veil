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
//! **No auth on put.** Anyone can deposit. Per-receiver quota
//! and 60/min rate limit at the storage layer gate abuse.
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
    MAILBOX_PUT_ENDPOINT_CAPACITY, MAILBOX_PUT_ENDPOINT_ID, Mailbox,
};
use veil_proto::{
    MAX_MAILBOX_FETCH_ENTRIES, MAX_MAILBOX_PUT_CHUNKS, MailboxBlobWire, MailboxFetchRespPayload,
    MailboxPutChunkPayload, MailboxPutPayload,
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

/// A partially-received deposit idle longer than this is evicted, so a hostile
/// depositor cannot pin relay memory with half-sent deposits. A real deposit's
/// chunks all arrive within a few seconds, so this never drops honest traffic.
const PUT_REASSEMBLY_STALE: Duration = Duration::from_secs(30);

struct PutReassembly {
    chunk_total: u16,
    chunks: Vec<Option<Vec<u8>>>,
    received: u16,
    last_activity: Instant,
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
        // Drop idle partial deposits before doing anything else (memory bound).
        self.inflight
            .retain(|_, r| now.duration_since(r.last_activity) < PUT_REASSEMBLY_STALE);

        // A conflicting chunk_total for an existing key = corruption / an injected
        // chunk under a guessed content_id → restart that reassembly.
        if self
            .inflight
            .get(&c.content_id)
            .is_some_and(|r| r.chunk_total != c.chunk_total)
        {
            self.inflight.remove(&c.content_id);
        }
        // Refuse a NEW key when full — never evict an in-progress honest deposit
        // (they complete in seconds; the depositor's outbox retries on drop).
        if !self.inflight.contains_key(&c.content_id)
            && self.inflight.len() >= MAX_INFLIGHT_PUT_REASSEMBLIES
        {
            return None;
        }

        let complete = {
            let r = self
                .inflight
                .entry(c.content_id)
                .or_insert_with(|| PutReassembly {
                    chunk_total: c.chunk_total,
                    chunks: vec![None; c.chunk_total as usize],
                    received: 0,
                    last_activity: now,
                });
            r.last_activity = now;
            let idx = c.chunk_index as usize;
            if r.chunks[idx].is_none() {
                r.received += 1;
                r.chunks[idx] = Some(c.chunk_data);
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
        ],
    };
    host.spawn(ctx, spec, move |mut ctx, mut rxs| async move {
        // Receivers are in spec.endpoints order: [PUT, FETCH, ACK].
        let mut put_rx = rxs.remove(0);
        let mut fetch_rx = rxs.remove(0);
        let mut ack_rx = rxs.remove(0);
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

/// Spawn the receiver-side WAKE listener: binds
/// `(MAILBOX_APP_ID, MAILBOX_WAKE_ENDPOINT_ID)` and, for every datagram that
/// lands there, publishes a `MAILBOX_WAKE` event on the daemon event bus so
/// the client app drains its mailbox promptly (the payload is ignored — the
/// wake is a pure hint). Runs on EVERY node (not just mailbox relays): any
/// node may be a mailbox RECEIVER. The sender is a directly-connected session
/// peer; a spoofed/spammy wake can only cause a bounded early drain (the app
/// debounces), never data loss — same threat class as any live inbound frame.
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
        loop {
            tokio::select! {
                Some(msg) = wake_rx.recv() => {
                    if let AppMessage::Deliver { src_node_id, .. } = msg {
                        log::debug!(
                            "veil-mailbox: deposit wake from relay {} — publishing event",
                            hex_short(&src_node_id),
                        );
                        event_bus.publish(veil_proto::EventPayload {
                            kind: veil_proto::event_kind::MAILBOX_WAKE,
                            payload: Vec::new(),
                        });
                    }
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
    let (src_node_id, reply_id) = match msg {
        AppMessage::Deliver {
            src_node_id,
            reply_id,
            ..
        } => (src_node_id, reply_id),
        other => {
            log::debug!("veil-mailbox: ignoring non-Deliver on FETCH endpoint: {other:?}");
            return;
        }
    };
    // An UNAUTHENTICATED request (src_node_id == 0, the anonymous-send marker)
    // or one with no reply path can't be served: we'd have no verified receiver
    // to key the mailbox on, and nowhere to send the answer.
    if src_node_id == [0u8; 32] || reply_id == 0 {
        log::debug!("veil-mailbox: FETCH dropped (unauthenticated src or no reply path)");
        return;
    }
    let Some(sender) = reply_sender else {
        log::debug!("veil-mailbox: FETCH dropped — no reply egress configured");
        return;
    };
    let blobs = match mailbox.fetch(src_node_id) {
        Ok(b) => b,
        Err(e) => {
            log::warn!(
                "veil-mailbox: FETCH store error (recv={}): {e}",
                hex_short(&src_node_id),
            );
            return;
        }
    };
    // Bound the reply so the whole encoded MailboxFetchRespPayload fits in ONE
    // signed AuthDeliver (see [fetch_reply_budget]). Oldest-first; the receiver
    // re-fetches to drain the rest (FETCH is non-destructive, deduped
    // receiver-side by content_id).
    //
    // A blob that ALONE exceeds the budget can never be served: emitting it
    // (the old "always emit at least one" progress rule) made send_reply fail
    // PayloadTooLarge on EVERY fetch, and since the queue is oldest-first the
    // oversized blob stayed at its head — permanently wedging that receiver's
    // mailbox and starving every deliverable blob behind it (observed in
    // production). Purge such blobs instead: undeliverable-by-protocol mail is
    // dead mail (the PUT gate now rejects new ones at the door; this clears
    // any already stored).
    let reply_budget = fetch_reply_budget();
    let mut total = 0usize;
    let mut wire: Vec<MailboxBlobWire> = Vec::new();
    for b in blobs {
        if wire.len() >= MAX_MAILBOX_FETCH_ENTRIES {
            break;
        }
        let cost = b.blob.len() + PER_BLOB_WIRE_HDR;
        if cost > reply_budget {
            match mailbox.ack(src_node_id, b.content_id) {
                Ok(removed) => log::warn!(
                    "veil-mailbox: purged oversized blob (recv={} cid={} {}B > \
                     fetch budget {reply_budget}B, removed={removed}) — it could \
                     never ride a FETCH reply",
                    hex_short(&src_node_id),
                    hex_short(&b.content_id),
                    b.blob.len(),
                ),
                Err(e) => log::warn!(
                    "veil-mailbox: failed to purge oversized blob (recv={} cid={}): {e}",
                    hex_short(&src_node_id),
                    hex_short(&b.content_id),
                ),
            }
            continue; // the NEXT blob may well fit — keep packing
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
    let (src_node_id, data) = match msg {
        AppMessage::Deliver {
            src_node_id, data, ..
        } => (src_node_id, data),
        other => {
            log::debug!("veil-mailbox: ignoring non-Deliver on ACK endpoint: {other:?}");
            return;
        }
    };
    // Unauthenticated (src == 0 = anonymous-send marker) acks could drop OTHER
    // receivers' mail — reject, exactly like FETCH.
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

    // Reject a deposit whose blob could never be FETCHED back out: PUT accepts
    // chunked payloads far past the reply cap (MAX_MAILBOX_BLOB_BYTES = 1 MB vs
    // ~5.6 KB deliverable), so without this gate an oversized deposit was
    // stored, then wedged its receiver's queue head forever (send_reply
    // PayloadTooLarge on every drain). Fail it loudly at the door instead.
    {
        let cost = req.blob.len() + PER_BLOB_WIRE_HDR;
        let budget = fetch_reply_budget();
        if cost > budget {
            log::warn!(
                "veil-mailbox: PUT rejected (recv={} cid={} blob {}B + hdr > \
                 fetch budget {budget}B — would be permanently unfetchable)",
                hex_short(&req.receiver_id),
                hex_short(&req.content_id),
                req.blob.len(),
            );
            return;
        }
    }

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
        MailboxPutChunkPayload {
            content_id,
            chunk_index: 0,
            chunk_total: 1,
            chunk_data: inner,
        }
        .encode()
    }

    /// A Deliver addressed to the ACK endpoint, as the dispatcher would form it.
    fn ack_deliver(src_node_id: [u8; 32], data: Vec<u8>) -> AppMessage {
        AppMessage::Deliver {
            src_node_id,
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
    struct MockReplySender {
        captured: std::sync::Arc<std::sync::Mutex<Vec<(u64, Vec<u8>, [u8; 32])>>>,
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
            _: [u8; 32],
            _: u32,
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

    #[tokio::test]
    async fn network_fetch_purges_oversized_head_blob_and_serves_next() {
        let (mailbox, _tmp) = fresh_mailbox();
        let recv = [0x77u8; 32];
        // Pre-existing oversized deposit (stored via the raw store API, as by a
        // relay predating the PUT gate): ALONE it exceeds the reply budget, so
        // under the old "always emit at least one" rule it rode every reply,
        // failed PayloadTooLarge each time, and wedged the queue head forever.
        let oversized = vec![0xEE; fetch_reply_budget()];
        mailbox
            .put(recv, [0xC1; 32], [0xAA; 32], oversized)
            .unwrap();
        // A perfectly deliverable blob stuck BEHIND it.
        mailbox
            .put(recv, [0xC2; 32], [0xAA; 32], b"deliverable".to_vec())
            .unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender: Arc<dyn veil_types::AnonOnionSender> = Arc::new(MockReplySender {
            captured: std::sync::Arc::clone(&captured),
        });
        let msg = AppMessage::Deliver {
            src_node_id: recv,
            src_app_id: [0u8; 32],
            app_id: MAILBOX_APP_ID,
            endpoint_id: MAILBOX_FETCH_ENDPOINT_ID,
            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
            reply_id: 7,
        };
        handle_fetch_message(&mailbox, Some(&sender), msg).await;

        // The reply carries ONLY the deliverable blob and fits the budget.
        let cap = captured.lock().unwrap();
        assert_eq!(cap.len(), 1, "exactly one reply");
        let resp = veil_proto::MailboxFetchRespPayload::decode(&cap[0].1).unwrap();
        assert_eq!(resp.blobs.len(), 1);
        assert_eq!(resp.blobs[0].content_id, [0xC2; 32]);
        // The oversized blob is PURGED from the store, not merely skipped —
        // otherwise it stays at the queue head as a permanent tombstone.
        let left = mailbox.fetch(recv).unwrap();
        assert_eq!(left.len(), 1, "oversized blob gone from the store");
        assert_eq!(left[0].content_id, [0xC2; 32]);
    }

    #[test]
    fn put_endpoint_rejects_unfetchable_oversized_blob() {
        let (mb, _tmp) = fresh_mailbox();
        let recv = [0x55u8; 32];
        let mut ra = PutChunkReassembler::default();
        // Blob big enough that blob + per-entry wire header exceeds one FETCH
        // reply — storing it would make it permanently unfetchable.
        let payload = mk_payload(
            recv,
            [0xC9; 32],
            [0x33; 32],
            vec![0xEE; fetch_reply_budget()],
            None,
        );
        handle_put_message(
            &mb,
            None,
            None,
            &mut ra,
            AppMessage::Deliver {
                src_node_id: [0x33u8; 32],
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(payload),
                reply_id: 0,
            },
        );
        assert!(
            mb.fetch(recv).unwrap().is_empty(),
            "unfetchable deposit must be rejected at the door"
        );

        // Control: a normal-sized deposit through the same path still lands.
        let ok = mk_payload(recv, [0xCA; 32], [0x33; 32], b"fits".to_vec(), None);
        handle_put_message(
            &mb,
            None,
            None,
            &mut ra,
            AppMessage::Deliver {
                src_node_id: [0x33u8; 32],
                src_app_id: [0u8; 32],
                app_id: MAILBOX_APP_ID,
                endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
                data: veil_bufpool::pooled_shared_from_vec(ok),
                reply_id: 0,
            },
        );
        assert_eq!(
            mb.fetch(recv).unwrap().len(),
            1,
            "normal deposit still stored"
        );
    }
}
