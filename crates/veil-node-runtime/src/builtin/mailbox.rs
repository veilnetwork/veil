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

use std::sync::Arc;

use veil_app::AppMessage;
use veil_mailbox::{
    MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_CAPACITY, MAILBOX_PUT_ENDPOINT_ID, Mailbox,
};
use veil_proto::MailboxPutPayload;

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

/// Spawn the mailbox built-in app service on `host`. Idempotent at
/// the program level — calling twice would panic at registry-bind
/// time on the duplicate `(MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)`.
///
/// `mailbox` is the shared storage handle. `push_trigger_tx` is the
/// channel the configured push dispatcher consumes from; pass `None`
/// to disable push triggering (e.g. relay running without anonymity X25519
/// secret — without a key it can't unseal envelopes anyway).
pub fn spawn_mailbox_app_service(
    host: &mut BuiltinAppHost,
    ctx: ServiceContext,
    mailbox: Arc<Mailbox>,
    push_trigger_tx: Option<tokio::sync::mpsc::Sender<PushTrigger>>,
) {
    let spec = ServiceSpec {
        name: "veil.mailbox.v1",
        app_id: MAILBOX_APP_ID,
        endpoints: vec![BuiltinEndpoint {
            endpoint_id: MAILBOX_PUT_ENDPOINT_ID,
            capacity: MAILBOX_PUT_ENDPOINT_CAPACITY,
        }],
    };
    host.spawn(ctx, spec, move |mut ctx, mut rxs| async move {
        let mut put_rx = rxs.remove(0);
        loop {
            tokio::select! {
                Some(msg) = put_rx.recv() => {
                    handle_put_message(&mailbox, push_trigger_tx.as_ref(), msg);
                }
                _ = ctx.shutdown.changed() => {
                    log::info!("veil-mailbox: app service stopping");
                    break;
                }
                else => {
                    // recv returned None — registry dropped the sender
                    // (shouldn't happen during normal operation; means
                    // the host is being torn down).
                    log::info!("veil-mailbox: PUT endpoint closed");
                    break;
                }
            }
        }
    });
}

/// Handle one incoming app message addressed to the PUT endpoint.
/// All code paths are fail-safe: a malformed payload, a storage
/// error, or a rejected put is logged and discarded without
/// propagating up.
pub fn handle_put_message(
    mailbox: &Mailbox,
    push_trigger_tx: Option<&tokio::sync::mpsc::Sender<PushTrigger>>,
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

    let req = match MailboxPutPayload::decode(&data) {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                "veil-mailbox: PUT decode failed (src={}): {e}",
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

    fn mk_payload(
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        sender_id: [u8; 32],
        blob: Vec<u8>,
        envelope: Option<Vec<u8>>,
    ) -> Vec<u8> {
        MailboxPutPayload {
            receiver_id,
            content_id,
            sender_id,
            blob,
            push_envelope: envelope,
            capability_token: None,
            wake_hmac_envelope: None,
        }
        .encode()
    }

    #[tokio::test]
    async fn t1_4_p5b_app_service_stores_put_blob() {
        let (mailbox, _tmp) = fresh_mailbox();
        let mut host = BuiltinAppHost::new();
        let registry = Arc::new(AppEndpointRegistry::new());
        let ctx = host.make_context([0u8; 32], Arc::clone(&registry));
        spawn_mailbox_app_service(&mut host, ctx, Arc::clone(&mailbox), None);

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
    async fn t1_4_p5b_app_service_fires_push_trigger_on_stored_with_envelope() {
        let (mailbox, _tmp) = fresh_mailbox();
        let mut host = BuiltinAppHost::new();
        let registry = Arc::new(AppEndpointRegistry::new());
        let ctx = host.make_context([0u8; 32], Arc::clone(&registry));
        let (push_tx, mut push_rx) =
            tokio::sync::mpsc::channel::<PushTrigger>(PUSH_TRIGGER_QUEUE_CAP);
        spawn_mailbox_app_service(&mut host, ctx, Arc::clone(&mailbox), Some(push_tx));

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
        spawn_mailbox_app_service(&mut host, ctx, Arc::clone(&mailbox), Some(push_tx));

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
        spawn_mailbox_app_service(&mut host, ctx, Arc::clone(&mailbox), None);

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
        spawn_mailbox_app_service(&mut host, ctx, Arc::clone(&mailbox), None);

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
}
