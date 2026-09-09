//! The three doors the app knocks on, and what the node says back.
//!
//! Every one of these is an implementation of a `veil_ipc` trait, and that
//! is the whole boundary: the IPC server decodes a `LocalAppMsg`, calls one
//! of these, and the answer goes back over the socket. Nothing here spawns a
//! task, holds a loop or owns a lifetime — each is a thin adaptor over state
//! the runtime already keeps behind an `Arc`.
//!
//!  * [`RendezvousPushEnvelopeForwarder`] — `SetPushEnvelope`: the app hands
//!    up a sealed push envelope, and it is written into the publisher entry
//!    in place, without a round trip through `NodeRuntime`.
//!  * [`MailboxIpcBridge`] — deposit, fetch, ack: the offline-mail surface.
//!  * [`OutboxIpcBridge`] — the send side's durable queue.
//!
//! They live together because they are the same KIND of thing, not because
//! they share state — they share none. What that buys is a place to look
//! when the question is "what can an app actually ask this node to do", and
//! an answer that is three hundred lines rather than ten thousand.
//!
//! Moved verbatim out of `service_tasks.rs` (report24 RUNTIME-3). Behaviour
//! is unchanged.

use std::sync::Arc;

use veil_proto::{EventPayload, event_kind};
use veil_util::lock;

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
    pub(crate) fn new(
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
    pub(crate) fn new(
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
    pub(crate) fn new(outbox: Arc<veil_mailbox::Outbox>) -> Self {
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
