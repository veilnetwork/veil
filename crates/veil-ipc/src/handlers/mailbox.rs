//! Mailbox handlers (`MailboxPut` / `MailboxFetch` / `MailboxAck`).
//!
//! Mailbox = offline store-and-forward for a receiver that's currently
//! offline.  Apps deposit encrypted blobs through `MailboxPut`; the
//! recipient's app pulls them through `MailboxFetch` and acknowledges
//! receipt through `MailboxAck`.  The backend (if wired) enforces
//! per-receiver and global byte / blob quotas plus rate limits;
//! authentication on fetch / ack is done through `auth_cookie` verified
//! against rendezvous-publisher entries.  When no backend is wired,
//! `MailboxPut` returns `NotMailboxRelay` and `MailboxFetch` / `MailboxAck`
//! return empty / `false` respectively (feature off gracefully).

use std::sync::Arc;

use veil_proto::{
    FrameFamily, LocalAppMsg, MAX_MAILBOX_FETCH_ENTRIES, MailboxAckPayload, MailboxBlobWire,
    MailboxFetchPayload, MailboxFetchRespPayload, MailboxPutOkPayload, MailboxPutPayload,
    MailboxPutStatus,
};

use veil_proto::ipc::{
    MailboxCryptoStatus, MailboxOpenPayload, MailboxOpenResultPayload, MailboxSealPayload,
    MailboxSealResultPayload,
};

use crate::frame_io::write_frame_wh;
use crate::server::IpcClientState;
use crate::{MailboxBlobOut, MailboxCryptoSink, MailboxOpenOutcome, MailboxSealOutcome};

/// Cumulative-byte budget for a single `MailboxFetch` response (audit cycle-9).
/// Kept well under the IPC frame body cap `MAX_FRAME_BODY` (16 MiB) with room
/// for per-blob framing overhead.
const MAX_MAILBOX_FETCH_BYTES: usize = 12 * 1024 * 1024;

/// Select a prefix of `raw` (already oldest-first from the backend) bounded by
/// BOTH `max_entries` and `max_bytes` (audit cycle-9). Entry-count alone
/// (`MAX_MAILBOX_FETCH_ENTRIES` × `MAX_BLOB_BYTES` = 256 MiB) overran the
/// 16 MiB frame body cap, so a receiver with >16 MiB of accumulated blobs got
/// an unparseable frame on every fetch and could never ack out (ack needs a
/// content_id only a successful fetch reveals). The first blob is ALWAYS
/// emitted (a real blob is ≤ `MAX_BLOB_BYTES` = 1 MiB, far under the budget) so
/// the receiver always makes progress, acks the batch, then re-fetches the rest.
fn select_bounded_fetch_blobs(
    raw: Vec<MailboxBlobOut>,
    max_entries: usize,
    max_bytes: usize,
) -> Vec<MailboxBlobWire> {
    let mut total_bytes = 0usize;
    raw.into_iter()
        .take(max_entries)
        .take_while(|b| {
            if total_bytes == 0 {
                total_bytes = b.blob.len();
                return true; // always emit at least one (guarantees progress)
            }
            if total_bytes + b.blob.len() > max_bytes {
                return false; // stop before the frame body would exceed the cap
            }
            total_bytes += b.blob.len();
            true
        })
        .map(|b| MailboxBlobWire {
            sender_id: b.sender_id,
            content_id: b.content_id,
            deposited_at: b.deposited_at,
            blob: b.blob,
        })
        .collect()
}
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
    // no-mailbox → empty list (no distinction, so cookie isn't a probing
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
    let blobs = select_bounded_fetch_blobs(
        blobs_raw,
        MAX_MAILBOX_FETCH_ENTRIES,
        MAX_MAILBOX_FETCH_BYTES,
    );
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
    client_state: &mut IpcClientState,
    mailbox_backend: Option<&Arc<dyn MailboxBackend>>,
) -> std::io::Result<()> {
    // Recipient's app confirms end-to-end receipt.  Backend verifies
    // `auth_cookie`; mismatch returns false (a no-op from the caller's
    // perspective).
    // Per-client rate-limit (shared read-query bucket, symmetric with
    // `handle_mailbox_fetch`): ack hits the backend's auth-cookie verify +
    // store mutation, so a local process must not be able to spam it. On
    // limit, reply the same no-op `removed=false` a cookie mismatch yields, so
    // the rate-limit is not a distinguishable oracle.
    if !client_state.allow_query() {
        return write_frame_wh(
            wh,
            FrameFamily::LocalApp as u8,
            LocalAppMsg::MailboxAckOk as u16,
            &[0u8],
        )
        .await;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(n: usize) -> MailboxBlobOut {
        MailboxBlobOut {
            sender_id: [0u8; 32],
            content_id: [0u8; 32],
            deposited_at: 0,
            blob: vec![0u8; n],
        }
    }

    #[test]
    fn fetch_bounded_by_bytes_stays_under_budget_and_makes_progress() {
        // 20×1 MiB blobs, 12 MiB budget → take a prefix that fits, never empty,
        // never the whole set (CRIT: previously 256 MiB frame, unparseable).
        let raw: Vec<_> = (0..20).map(|_| blob(1024 * 1024)).collect();
        let out = select_bounded_fetch_blobs(raw, 256, 12 * 1024 * 1024);
        let total: usize = out.iter().map(|b| b.blob.len()).sum();
        assert!(!out.is_empty(), "must make progress");
        assert!(out.len() < 20, "bounded prefix, not the whole backlog");
        assert!(
            total <= 12 * 1024 * 1024,
            "cumulative bytes stay within the budget, got {total}"
        );
    }

    #[test]
    fn fetch_first_blob_always_returned_even_if_over_budget() {
        // Progress guarantee: the first blob is emitted even if it alone exceeds
        // the budget (real blobs are ≤ MAX_BLOB_BYTES so this never bites, but it
        // prevents a permanently-wedged mailbox).
        let out = select_bounded_fetch_blobs(vec![blob(2_000_000)], 256, 1_000_000);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn fetch_entry_count_cap_still_enforced() {
        let raw: Vec<_> = (0..500).map(|_| blob(1)).collect();
        let out = select_bounded_fetch_blobs(raw, 256, 12 * 1024 * 1024);
        assert_eq!(out.len(), 256, "entry-count cap holds when blobs are tiny");
    }
}

// ── Offline seal/open (node-side E2E crypto, distinct from the relay
//    Put/Fetch/Ack above) ─────────────────────────────────────────────────────

/// `LocalAppMsg::MailboxSeal`: app asks the node to seal `data` for a recipient
/// into an offline-mailbox blob (the node holds the sovereign identity + does
/// the DHT cert resolution). Replies `MailboxSealOk`. Malformed bodies are
/// dropped silently; a missing sink (feature off) replies `Failed`.
pub(crate) async fn handle_mailbox_seal(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    mailbox_crypto_sink: Option<&Arc<dyn MailboxCryptoSink>>,
) -> std::io::Result<()> {
    let Ok(req) = MailboxSealPayload::decode(body) else {
        return Ok(());
    };
    let reply = match mailbox_crypto_sink {
        Some(sink) => {
            match sink
                .seal_blob(req.recipient_node_id, req.app_id, req.endpoint_id, req.data)
                .await
            {
                MailboxSealOutcome::Ok(blob) => MailboxSealResultPayload {
                    status: MailboxCryptoStatus::Ok,
                    blob,
                },
                MailboxSealOutcome::NoIdentity => MailboxSealResultPayload {
                    status: MailboxCryptoStatus::NoIdentity,
                    blob: Vec::new(),
                },
                MailboxSealOutcome::PeerUnresolved => MailboxSealResultPayload {
                    status: MailboxCryptoStatus::PeerUnresolved,
                    blob: Vec::new(),
                },
                MailboxSealOutcome::Failed => MailboxSealResultPayload {
                    status: MailboxCryptoStatus::Failed,
                    blob: Vec::new(),
                },
            }
        }
        None => MailboxSealResultPayload {
            status: MailboxCryptoStatus::Failed,
            blob: Vec::new(),
        },
    };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::MailboxSealOk as u16,
        &reply.encode(),
    )
    .await
}

/// `LocalAppMsg::MailboxOpen`: app asks the node to open + verify a fetched
/// mailbox blob (decrypt under our dk_seed, verify the sender's auth-deliver
/// signature). Replies `MailboxOpenOk` with the verified routing target +
/// plaintext, or a non-`Ok` status.
pub(crate) async fn handle_mailbox_open(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    mailbox_crypto_sink: Option<&Arc<dyn MailboxCryptoSink>>,
) -> std::io::Result<()> {
    let Ok(req) = MailboxOpenPayload::decode(body) else {
        return Ok(());
    };
    let reply = match mailbox_crypto_sink {
        Some(sink) => match sink.open_blob(req.blob, req.our_cert_version).await {
            MailboxOpenOutcome::Ok {
                sender_node_id,
                app_id,
                endpoint_id,
                data,
            } => MailboxOpenResultPayload {
                status: MailboxCryptoStatus::Ok,
                sender_node_id,
                app_id,
                endpoint_id,
                data,
            },
            MailboxOpenOutcome::NoIdentity => MailboxOpenResultPayload {
                status: MailboxCryptoStatus::NoIdentity,
                sender_node_id: [0u8; 32],
                app_id: [0u8; 32],
                endpoint_id: 0,
                data: Vec::new(),
            },
            MailboxOpenOutcome::PeerUnresolved => MailboxOpenResultPayload {
                status: MailboxCryptoStatus::PeerUnresolved,
                sender_node_id: [0u8; 32],
                app_id: [0u8; 32],
                endpoint_id: 0,
                data: Vec::new(),
            },
            MailboxOpenOutcome::Failed => MailboxOpenResultPayload {
                status: MailboxCryptoStatus::Failed,
                sender_node_id: [0u8; 32],
                app_id: [0u8; 32],
                endpoint_id: 0,
                data: Vec::new(),
            },
        },
        None => MailboxOpenResultPayload {
            status: MailboxCryptoStatus::Failed,
            sender_node_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            data: Vec::new(),
        },
    };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::MailboxOpenOk as u16,
        &reply.encode(),
    )
    .await
}
