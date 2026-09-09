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

#[cfg(test)]
mod tests {
    use super::*;
    use veil_ipc::{MailboxBackend, PushEnvelopeSink};

    // Nothing exercised these three when they were a region in the middle of
    // ten thousand lines, and every property below is one their own comments
    // already claim. The comments are not the guard; these are.

    fn entry(
        node: [u8; 32],
        cookie: [u8; 16],
    ) -> veil_anonymity::rendezvous::RendezvousPublisherEntry {
        veil_anonymity::rendezvous::RendezvousPublisherEntry {
            rendezvous_node_id: node,
            auth_cookie: cookie,
            validity_window_secs: 1800,
            push_envelope: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            rendezvous_kem_valid_until_unix: 0,
            ephemeral_ad_identity: None,
        }
    }

    fn forwarder(
        rows: Vec<veil_anonymity::rendezvous::RendezvousPublisherEntry>,
    ) -> (
        RendezvousPushEnvelopeForwarder,
        Arc<std::sync::Mutex<Vec<veil_anonymity::rendezvous::RendezvousPublisherEntry>>>,
    ) {
        let entries = Arc::new(std::sync::Mutex::new(rows));
        (
            RendezvousPushEnvelopeForwarder::new(Arc::clone(&entries)),
            entries,
        )
    }

    /// The cookie is the authorisation, not decoration.
    ///
    /// Both halves of the pair have to match. Matching on the node id alone
    /// would let anyone who can read a published ad — the node id is IN it —
    /// replace the push envelope of a receiver they are not, and every wake
    /// for that receiver would then be sealed to the wrong operator's key.
    #[test]
    fn a_push_envelope_lands_only_on_the_row_that_matches_both_halves() {
        let mine = [1u8; 32];
        let cookie = [9u8; 16];
        let (fwd, entries) = forwarder(vec![entry(mine, cookie), entry([2u8; 32], [8u8; 16])]);

        assert!(
            fwd.set_rendezvous_push_envelope(mine, cookie, b"sealed".to_vec()),
            "the row that matches both halves was not found"
        );
        assert_eq!(lock!(entries)[0].push_envelope, b"sealed".to_vec());
        assert!(
            lock!(entries)[1].push_envelope.is_empty(),
            "the envelope landed on somebody else's row as well"
        );

        assert!(
            !fwd.set_rendezvous_push_envelope(mine, [7u8; 16], b"forged".to_vec()),
            "the right node id with the WRONG cookie was accepted"
        );
        assert!(
            !fwd.set_rendezvous_push_envelope([3u8; 32], cookie, b"forged".to_vec()),
            "the right cookie against the WRONG node id was accepted"
        );
        assert_eq!(
            lock!(entries)[0].push_envelope,
            b"sealed".to_vec(),
            "a refused call still overwrote the envelope"
        );
    }

    /// The two setters write two different fields.
    ///
    /// They are near-identical methods next to each other, which is the shape
    /// a copy-paste crosses silently: the wake-HMAC key would be stored where
    /// the push token belongs, the relay would sign wake payloads with
    /// something the receiver cannot verify, and every push would be dropped
    /// by the receiver's own authentication as forged.
    #[test]
    fn the_wake_hmac_setter_does_not_write_the_push_envelope() {
        let node = [4u8; 32];
        let cookie = [5u8; 16];
        let (fwd, entries) = forwarder(vec![entry(node, cookie)]);

        assert!(fwd.set_rendezvous_wake_hmac_envelope(node, cookie, b"wake-key".to_vec()));
        assert_eq!(lock!(entries)[0].wake_hmac_envelope, b"wake-key".to_vec());
        assert!(
            lock!(entries)[0].push_envelope.is_empty(),
            "the wake-HMAC setter wrote the push envelope"
        );

        assert!(fwd.set_rendezvous_push_envelope(node, cookie, b"push-token".to_vec()));
        assert_eq!(lock!(entries)[0].push_envelope, b"push-token".to_vec());
        assert_eq!(
            lock!(entries)[0].wake_hmac_envelope,
            b"wake-key".to_vec(),
            "the push setter overwrote the wake-HMAC envelope"
        );
    }

    struct MailboxFixture {
        bridge: MailboxIpcBridge,
        _dir: tempfile::TempDir,
        _rx: tokio::sync::mpsc::Receiver<PushTrigger>,
    }

    fn mailbox_bridge(registered: Option<([u8; 32], [u8; 16])>) -> MailboxFixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let mailbox = Arc::new(
            veil_mailbox::Mailbox::open(dir.path(), veil_mailbox::MailboxConfig::default())
                .expect("mailbox"),
        );
        let registry = registered.map(|(receiver, cookie)| {
            let mut reg = veil_anonymity::mailbox_cookie_registry::MailboxCookieRegistry::new(16);
            reg.register(receiver, cookie, 1_700_000_000);
            Arc::new(std::sync::RwLock::new(reg))
        });
        let (tx, rx) = tokio::sync::mpsc::channel::<PushTrigger>(4);
        MailboxFixture {
            bridge: MailboxIpcBridge::new(mailbox, registry, tx, None),
            _dir: dir,
            _rx: rx,
        }
    }

    fn deposit(fixture: &MailboxFixture, receiver: [u8; 32], content: [u8; 32]) {
        // Deposited underneath the bridge on purpose: what is under test is
        // the fetch/ack authorisation, not the deposit policy.
        fixture
            .bridge
            .mailbox
            .put(receiver, content, [7u8; 32], b"ciphertext".to_vec())
            .expect("deposit");
    }

    /// A wrong cookie must be indistinguishable from an empty mailbox.
    ///
    /// `Some(empty)` rather than an error or a refusal is the whole point: an
    /// answer that told the two apart would turn the fetch call into an oracle
    /// for "does this receiver have mail waiting here", which is exactly the
    /// metadata a relay exists not to leak. And it must not DRAIN — a probe
    /// that emptied the mailbox would be a denial of service with no cookie
    /// at all.
    #[test]
    fn a_wrong_fetch_cookie_reads_as_an_empty_mailbox_and_takes_nothing() {
        let receiver = [1u8; 32];
        let cookie = [2u8; 16];
        let f = mailbox_bridge(Some((receiver, cookie)));
        deposit(&f, receiver, [3u8; 32]);

        assert_eq!(
            f.bridge.fetch(receiver, [0xEEu8; 16]).map(|b| b.len()),
            Some(0),
            "a wrong cookie answered something other than an empty mailbox"
        );

        let got = f.bridge.fetch(receiver, cookie).expect("authorised fetch");
        assert_eq!(
            got.len(),
            1,
            "the wrong-cookie probe drained the mailbox it was refused"
        );
    }

    /// The same for ack, where the damage is deletion rather than disclosure.
    #[test]
    fn a_wrong_ack_cookie_removes_nothing() {
        let receiver = [1u8; 32];
        let cookie = [2u8; 16];
        let content = [3u8; 32];
        let f = mailbox_bridge(Some((receiver, cookie)));
        deposit(&f, receiver, content);

        assert_eq!(
            f.bridge.ack(receiver, content, [0xEEu8; 16]),
            Some(false),
            "a wrong cookie was allowed to ack"
        );
        assert_eq!(
            f.bridge.fetch(receiver, cookie).map(|b| b.len()),
            Some(1),
            "the refused ack removed the blob anyway"
        );
        assert_eq!(
            f.bridge.ack(receiver, content, cookie),
            Some(true),
            "the authorised ack did not remove it"
        );
    }

    /// A node that is not a mailbox relay authorises nobody.
    ///
    /// `None` for the registry is the state of every node that never opted in,
    /// and the fail-open reading of it — "no registry, no check" — would make
    /// every such node serve any cookie presented to it.
    #[test]
    fn without_a_cookie_registry_no_fetch_is_authorised() {
        let receiver = [1u8; 32];
        let f = mailbox_bridge(None);
        deposit(&f, receiver, [3u8; 32]);

        assert_eq!(
            f.bridge.fetch(receiver, [2u8; 16]).map(|b| b.len()),
            Some(0),
            "a node with no cookie registry served a fetch"
        );
        assert_eq!(
            f.bridge.ack(receiver, [3u8; 32], [2u8; 16]),
            Some(false),
            "a node with no cookie registry allowed an ack"
        );
    }
}
