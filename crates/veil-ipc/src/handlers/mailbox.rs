//! Mailbox handlers (`MailboxPut` / `MailboxFetch` / `MailboxAck`).
//!
//! Mailbox = offline store-and-forward for а receiver that's currently
//! offline.  Apps deposit encrypted blobs through `MailboxPut`; the
//! recipient's app pulls them through `MailboxFetch` и acknowledges
//! receipt through `MailboxAck`.  The backend (если wired) enforces
//! per-receiver и global byte / blob quotas plus rate limits;
//! authentication on fetch / ack is done через `auth_cookie` verified
//! against rendezvous-publisher entries.  Когда no backend is wired,
//! `MailboxPut` returns `NotMailboxRelay` и `MailboxFetch` / `MailboxAck`
//! return empty / `false` respectively (feature off gracefully).

use std::sync::Arc;

use veil_proto::{
    FrameFamily, LocalAppMsg, MAX_MAILBOX_FETCH_ENTRIES, MailboxAckPayload, MailboxBlobWire,
    MailboxFetchPayload, MailboxFetchRespPayload, MailboxPutOkPayload, MailboxPutPayload,
    MailboxPutStatus,
};

use crate::frame_io::write_frame_wh;
use crate::server::IpcClientState;
use crate::transport::IpcWriteHalf;
use crate::{MailboxBackend, MailboxPutOutcome};

pub(crate) async fn handle_mailbox_put(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    mailbox_backend: Option<&Arc<dyn MailboxBackend>>,
) -> std::io::Result<()> {
    // App deposits an encrypted blob for an offline receiver.  No auth
    // cookie at this layer — the per-receiver quota + rate limit gate
    // the call.  Drop malformed silently.
    let Ok(req) = MailboxPutPayload::decode(body) else {
        return Ok(());
    };
    // audit cycle-6 (A9): per-client PUT rate-limit BEFORE touching the backend,
    // so a local process cannot spam MailboxPut (across rotating receiver_ids)
    // and drive the backend mutex + quota-scan path. Reply RateLimited rather
    // than silently dropping — PUT carries no presence-probe oracle (unlike
    // fetch's auth_cookie), so a clear back-off signal is safe and useful.
    if !client_state.allow_put() {
        let reply = MailboxPutOkPayload {
            status: MailboxPutStatus::RateLimited,
            evicted: 0,
        };
        return write_frame_wh(
            wh,
            FrameFamily::LocalApp as u8,
            LocalAppMsg::MailboxPutOk as u16,
            &reply.encode(),
        )
        .await;
    }
    let (status, evicted) = match mailbox_backend.and_then(|b| {
        b.put(
            req.receiver_id,
            req.content_id,
            req.sender_id,
            req.blob,
            req.push_envelope,
            // audit U14: forward the capability token so the backend can honor
            // the relay's require_capability_token policy (was dropped here).
            req.capability_token,
            // Epic 489.10 slice 4.4: forward the sealed wake-HMAC envelope so the
            // backend can mint an authenticated wake payload on the push it fires.
            req.wake_hmac_envelope,
        )
    }) {
        Some(MailboxPutOutcome::Stored { evicted }) => (MailboxPutStatus::Stored, evicted),
        Some(MailboxPutOutcome::Duplicate) => (MailboxPutStatus::Duplicate, 0),
        Some(MailboxPutOutcome::QuotaPerReceiverExceeded) => {
            (MailboxPutStatus::QuotaPerReceiverExceeded, 0)
        }
        Some(MailboxPutOutcome::QuotaGlobalExceeded) => (MailboxPutStatus::QuotaGlobalExceeded, 0),
        Some(MailboxPutOutcome::RateLimited) => (MailboxPutStatus::RateLimited, 0),
        Some(MailboxPutOutcome::CapabilityRequired) => (MailboxPutStatus::CapabilityRequired, 0),
        Some(MailboxPutOutcome::CapabilityInvalid) => (MailboxPutStatus::CapabilityInvalid, 0),
        Some(MailboxPutOutcome::QuotaPerSenderExceeded) => {
            (MailboxPutStatus::QuotaPerSenderExceeded, 0)
        }
        None => (MailboxPutStatus::NotMailboxRelay, 0),
    };
    let reply = MailboxPutOkPayload { status, evicted };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::MailboxPutOk as u16,
        &reply.encode(),
    )
    .await
}

pub(crate) async fn handle_mailbox_fetch(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    mailbox_backend: Option<&Arc<dyn MailboxBackend>>,
) -> std::io::Result<()> {
    // Recipient's app pulls all pending blobs.  `auth_cookie` is verified
    // by the backend against rendezvous-publisher entries.  Mismatch /
    // no-mailbox → empty list (no distinction, so cookie isn't а probing
    // oracle).  Cap entries returned per IPC frame; caller can re-fetch
    // if the cap is hit (acks make subsequent fetches return the next
    // batch).
    if !client_state.allow_query() {
        return Ok(());
    }
    let Ok(req) = MailboxFetchPayload::decode(body) else {
        return Ok(());
    };
    let blobs_raw = mailbox_backend
        .and_then(|b| b.fetch(req.receiver_id, req.auth_cookie))
        .unwrap_or_default();
    let blobs: Vec<MailboxBlobWire> = blobs_raw
        .into_iter()
        .take(MAX_MAILBOX_FETCH_ENTRIES)
        .map(|b| MailboxBlobWire {
            sender_id: b.sender_id,
            content_id: b.content_id,
            deposited_at: b.deposited_at,
            blob: b.blob,
        })
        .collect();
    let reply = MailboxFetchRespPayload { blobs };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::MailboxFetchResp as u16,
        &reply.encode(),
    )
    .await
}

pub(crate) async fn handle_mailbox_ack(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    mailbox_backend: Option<&Arc<dyn MailboxBackend>>,
) -> std::io::Result<()> {
    // Recipient's app confirms end-to-end receipt.  Backend verifies
    // `auth_cookie`; mismatch returns false (a no-op from the caller's
    // perspective).
    let Ok(req) = MailboxAckPayload::decode(body) else {
        return Ok(());
    };
    let removed = mailbox_backend
        .and_then(|b| b.ack(req.receiver_id, req.content_id, req.auth_cookie))
        .unwrap_or(false);
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::MailboxAckOk as u16,
        &[removed as u8],
    )
    .await
}
