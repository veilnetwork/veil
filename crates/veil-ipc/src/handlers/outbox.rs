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
use crate::OutboxEntryOut;
use crate::frame_io::write_frame_wh;
use crate::server::IpcClientState;
use crate::transport::IpcWriteHalf;

/// Cumulative-byte budget for a single `OutboxFindMissing` response (audit
/// cycle-10). Mirror of mailbox's `MAX_MAILBOX_FETCH_BYTES`: kept well under the
/// IPC frame body cap `MAX_FRAME_BODY` (16 MiB) with room for per-entry framing.
const MAX_OUTBOX_FIND_MISSING_BYTES: usize = 12 * 1024 * 1024;

/// Select a prefix of `raw` bounded by BOTH `max_entries` and `max_bytes`
/// (audit cycle-10). The structural twin of mailbox's `select_bounded_fetch_blobs`:
/// the entry-count cap alone (`MAX_OUTBOX_FIND_MISSING_ENTRIES` × `MAX_MAILBOX_BLOB_BYTES`
/// = 256 MiB) overran the 16 MiB frame body cap, so a receiver with >16 MiB of
/// accumulated outbox entries got an unparseable frame on every peer-sync and
/// could never synchronize. The first entry is ALWAYS emitted (a real blob is
/// ≤ `MAX_MAILBOX_BLOB_BYTES` = 1 MiB, far under the budget) so the receiver
/// always makes progress, acks the batch, then re-syncs the rest.
fn select_bounded_outbox_entries(
    raw: Vec<OutboxEntryOut>,
    max_entries: usize,
    max_bytes: usize,
) -> Vec<OutboxEntryWire> {
    let mut total_bytes = 0usize;
    raw.into_iter()
        .take(max_entries)
        .take_while(|e| {
            if total_bytes == 0 {
                total_bytes = e.blob.len();
                return true; // always emit at least one (guarantees progress)
            }
            if total_bytes + e.blob.len() > max_bytes {
                return false; // stop before the frame body would exceed the cap
            }
            total_bytes += e.blob.len();
            true
        })
        .map(|e| OutboxEntryWire {
            content_id: e.content_id,
            deposited_at: e.deposited_at,
            blob: e.blob,
        })
        .collect()
}

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
    // Bound by BOTH entry count AND cumulative bytes: the count cap alone could
    // produce a >16 MiB frame the receiver cannot parse, wedging peer-sync
    // forever (audit cycle-10, mirror of the mailbox fetch fix).
    let entries = select_bounded_outbox_entries(
        entries_raw,
        MAX_OUTBOX_FIND_MISSING_ENTRIES,
        MAX_OUTBOX_FIND_MISSING_BYTES,
    );
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
    client_state: &mut IpcClientState,
    outbox_backend: Option<&Arc<dyn OutboxBackend>>,
) -> std::io::Result<()> {
    // Idempotent — receiver confirms direct end-to-end ack, sender drops
    // the entry.
    // audit cycle-8: per-client rate-limit, symmetric with the sibling
    // `handle_mailbox_ack` / `handle_outbox_put` / `handle_outbox_find_missing`
    // gates. `OutboxBackend::ack` is a lookup-and-remove store mutation under
    // the outbox lock, so an ungated local process could spam OUTBOX_ACK frames
    // to pin the lock / amplify CPU. On limit, reply the same no-op
    // `removed=false` a miss yields (not a distinguishable oracle).
    if !client_state.allow_query() {
        return write_frame_wh(
            wh,
            FrameFamily::LocalApp as u8,
            LocalAppMsg::OutboxAckOk as u16,
            &[0u8],
        )
        .await;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: usize) -> OutboxEntryOut {
        OutboxEntryOut {
            content_id: [0u8; 32],
            deposited_at: 0,
            blob: vec![0u8; n],
        }
    }

    #[test]
    fn find_missing_bounded_by_bytes_stays_under_budget_and_makes_progress() {
        // 20×1 MiB entries, 12 MiB budget → take a prefix that fits, never empty,
        // never the whole set (CRIT: previously a ~256 MiB frame, unparseable by
        // the peer's MAX_FRAME_BODY=16 MiB decoder, wedging peer-sync forever).
        let raw: Vec<_> = (0..20).map(|_| entry(1024 * 1024)).collect();
        let out = select_bounded_outbox_entries(raw, 256, 12 * 1024 * 1024);
        let total: usize = out.iter().map(|e| e.blob.len()).sum();
        assert!(!out.is_empty(), "must make progress");
        assert!(out.len() < 20, "bounded prefix, not the whole backlog");
        assert!(
            total <= 12 * 1024 * 1024,
            "cumulative bytes stay within the budget, got {total}"
        );
    }

    #[test]
    fn find_missing_first_entry_always_returned_even_if_over_budget() {
        // Progress guarantee: the first entry is emitted even if it alone exceeds
        // the budget (real blobs are ≤ MAX_MAILBOX_BLOB_BYTES so this never bites,
        // but it prevents a permanently-wedged peer-sync).
        let out = select_bounded_outbox_entries(vec![entry(2_000_000)], 256, 1_000_000);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn find_missing_entry_count_cap_still_enforced() {
        let raw: Vec<_> = (0..500).map(|_| entry(1)).collect();
        let out = select_bounded_outbox_entries(raw, 256, 12 * 1024 * 1024);
        assert_eq!(out.len(), 256, "entry-count cap holds when blobs are tiny");
    }
}
