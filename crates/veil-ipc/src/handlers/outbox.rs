//! Outbox handlers (`OutboxPut` / `OutboxFindMissing` / `OutboxAck`).
//!
//! Outbox = sender-side peer-sync store.  When sending a message the
//! app records it here for opportunistic retransmission whenever the
//! receiver comes online and a peer-sync exchange happens.  `OutboxPut`
//! stores a fresh entry, `OutboxFindMissing` answers a peer-sync request
//! (peer sends a Bloom filter of what they have; the daemon's outbox
//! returns entries the peer is missing), and `OutboxAck` drops an entry
//! after the receiver confirms direct receipt.
//!
//! Without a wired backend, `OutboxPut` returns `false` (stored=false),
//! `OutboxFindMissing` returns an empty list, and `OutboxAck` returns
//! `false` (feature off gracefully).

use std::sync::Arc;

use veil_proto::{
    FrameFamily, LocalAppMsg, MAX_OUTBOX_FIND_MISSING_ENTRIES, OutboxAckPayload, OutboxEntryWire,
    OutboxFindMissingPayload, OutboxFindMissingRespPayload, OutboxPutPayload,
};

use crate::OutboxBackend;
use crate::frame_io::write_frame_wh;
use crate::server::IpcClientState;
use crate::transport::IpcWriteHalf;

pub(crate) async fn handle_outbox_put(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    outbox_backend: Option<&Arc<dyn OutboxBackend>>,
) -> std::io::Result<()> {
    let Ok(req) = OutboxPutPayload::decode(body) else {
        return Ok(());
    };
    // audit cycle-7 (MED): per-client PUT rate-limit BEFORE touching the backend,
    // mirroring handle_mailbox_put (cycle-6 A9). OutboxPut was the one local-IPC
    // PUT path lacking this gate, so a buggy/malicious local app could spam it
    // (across rotating receiver/content ids) and drive the backend mutex.
    // OutboxPutOk carries only a stored bool, so a rate-limited PUT replies
    // stored=false (a clear "didn't store — back off" signal) rather than
    // silently dropping. Shares the per-client PUT token bucket with MailboxPut
    // (allow_put), the intended per-client PUT budget.
    if !client_state.allow_put() {
        return write_frame_wh(
            wh,
            FrameFamily::LocalApp as u8,
            LocalAppMsg::OutboxPutOk as u16,
            &[0u8], // stored = false
        )
        .await;
    }
    let stored = outbox_backend
        .map(|b| b.put(req.receiver_id, req.content_id, req.blob))
        .unwrap_or(false);
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::OutboxPutOk as u16,
        &[stored as u8],
    )
    .await
}

pub(crate) async fn handle_outbox_find_missing(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    outbox_backend: Option<&Arc<dyn OutboxBackend>>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    let Ok(req) = OutboxFindMissingPayload::decode(body) else {
        return Ok(());
    };
    let entries_raw = outbox_backend
        .and_then(|b| b.find_missing(req.receiver_id, req.since, req.bloom))
        .unwrap_or_default();
    let entries: Vec<OutboxEntryWire> = entries_raw
        .into_iter()
        .take(MAX_OUTBOX_FIND_MISSING_ENTRIES)
        .map(|e| OutboxEntryWire {
            content_id: e.content_id,
            deposited_at: e.deposited_at,
            blob: e.blob,
        })
        .collect();
    let reply = OutboxFindMissingRespPayload { entries };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::OutboxFindMissingResp as u16,
        &reply.encode(),
    )
    .await
}

pub(crate) async fn handle_outbox_ack(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    outbox_backend: Option<&Arc<dyn OutboxBackend>>,
) -> std::io::Result<()> {
    // Idempotent — receiver confirms direct end-to-end ack, sender drops
    // the entry.
    let Ok(req) = OutboxAckPayload::decode(body) else {
        return Ok(());
    };
    let removed = outbox_backend
        .map(|b| b.ack(req.receiver_id, req.content_id))
        .unwrap_or(false);
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::OutboxAckOk as u16,
        &[removed as u8],
    )
    .await
}
