//! Low-level frame I/O helpers for IPC transport.
//!
//! Three small async functions read and write `OVL1`-framed IPC payloads on
//! top of `crate::transport::{IpcReadHalf, IpcWriteHalf, IpcStream}`, plus a
//! sync encoder that builds a complete pooled frame buffer for queueing
//! before flushing.
//!
//! Pooled-buffer rationale: the daemon → chat-node delivery path runs at
//! ~200 frames/sec × 60 KiB encrypted payloads.  Reusing buffers from
//! `veil_bufpool::global()` eliminates the dominant `Vec` allocation that
//! previously fed both jemalloc dirty-page retention and the bounded delivery
//! channel; without pooling, default-decay jemalloc holds ~100-200 MiB RSS
//! that the process never reclaims.

use crate::transport::{IpcReadHalf, IpcStream, IpcWriteHalf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use veil_proto::{FrameFamily, FrameHeader, codec};

/// Build a complete IPC OVL1 frame (`LocalApp` family) from a `msg_type` and
/// `body` bytes, allocating from the global buffer pool.
///
/// Debug-asserts that `body.len() <= u32::MAX`; release builds saturate to
/// `u32::MAX` because callers don't have a fallible signature, but this
/// case is unreachable in practice — `MAX_FRAME_BODY` is 16 MiB.
pub(crate) fn encode_ipc_frame(msg_type: u16, body: &[u8]) -> veil_bufpool::PooledShared {
    debug_assert!(
        body.len() <= u32::MAX as usize,
        "encode_ipc_frame body {} > u32::MAX — caller must enforce MAX_FRAME_BODY first",
        body.len(),
    );
    let mut hdr = FrameHeader::new(FrameFamily::LocalApp as u8, msg_type);
    hdr.body_len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let hdr_bytes = codec::encode_header(&hdr);
    let total = hdr_bytes.len() + body.len();
    let mut p = veil_bufpool::global().acquire(total);
    p.as_vec_mut().extend_from_slice(&hdr_bytes);
    p.as_vec_mut().extend_from_slice(body);
    p.into_shared()
}

/// Hard upper-bound on the time a frame body can wait after header
/// successful read. Without deadline, a local IPC client can declare a body of
/// up to 16 MiB and never push it — pinning RSS until the connection drops.
/// At 256 clients × 16 MiB this is up to 4 GiB of pinned buffers.
///
/// 30 seconds is generous even for legacy slow disks / fuse FS on the
/// app side, and still bounds the worst-case memory exposure to
/// `256 clients × 16 MiB × 30 s` of windowed risk.
pub(crate) const BODY_READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Read one framed message from `rh`.
///
/// Acquires the body buffer from the global pool — see module docs for the
/// jemalloc-retention rationale.  `decode_header` already rejects bodies
/// larger than `MAX_FRAME_BODY`, so the acquisition is bounded in bytes.
/// **Body read** is also bounded in time by [`BODY_READ_DEADLINE`]: after
/// successful header, the client must finish pushing body within 30 s
/// or the read returns `TimedOut`. Closes the local-IPC memory-DoS
/// vector where a stuck client kept a 16-MiB buffer pinned indefinitely.
pub(crate) async fn read_frame(
    rh: &mut IpcReadHalf,
) -> std::io::Result<(FrameHeader, veil_bufpool::Pooled)> {
    let mut hdr_buf = [0u8; veil_proto::HEADER_SIZE];
    rh.read_exact(&mut hdr_buf).await?;
    let header = codec::decode_header(&hdr_buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let body_len = header.body_len as usize;
    // audit V-07: the per-frame cap bounds ONE reader; nothing bounded the sum.
    // 256 authenticated clients each declaring 16 MiB is ~4 GiB of buffers
    // allocated and zeroed BEFORE a single body byte arrives, held for the
    // whole 30-second read window. The permit is held across the allocation
    // and the read, and released when this function returns — which is exactly
    // the window the 4 GiB came from.
    let _budget = body_budget::acquire(body_len).await?;
    let mut body = veil_bufpool::global().acquire(body_len);
    body.as_vec_mut().resize(body_len, 0);
    if body_len > 0 {
        match tokio::time::timeout(BODY_READ_DEADLINE, rh.read_exact(&mut body[..])).await {
            Ok(io_result) => io_result?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "frame body read timeout after {}s (header announced {} body bytes)",
                        BODY_READ_DEADLINE.as_secs(),
                        body_len,
                    ),
                ));
            }
        };
    }
    Ok((header, body))
}

/// Process-wide ceiling on frame-body bytes being read at once (audit V-07).
///
/// ## Why a byte budget and not a smaller connection cap
///
/// The connection cap counts CLIENTS; memory is spent in BYTES, and the two
/// stopped tracking each other the moment one client could declare 16 MiB.
/// Lowering the client cap enough to bound memory would have refused
/// legitimate clients that only ever send 5 KiB chunks. A byte budget charges
/// each reader for what it actually asks for: thousands of small frames pass
/// untouched, and a flood of maximum-size declarations queues instead of
/// allocating.
///
/// Charged BEFORE the buffer exists, because the allocation is the cost —
/// `resize(body_len, 0)` touches every page, so an unread 16 MiB body is
/// 16 MiB of resident memory, not a lazy reservation.
pub(crate) mod body_budget {
    use std::sync::Arc;
    use tokio::sync::{OwnedSemaphorePermit, Semaphore};

    /// Total bytes that may be in flight across all frame-body reads.
    ///
    /// 128 MiB: eight simultaneous maximum-size frames, or tens of thousands
    /// of ordinary ones. Real traffic is chunks in the low tens of KiB, so
    /// this is far above legitimate use and 1/32 of the old worst case.
    pub(crate) const MAX_INFLIGHT_BODY_BYTES: usize = 128 * 1024 * 1024;

    /// How long a reader waits for budget before giving up.
    ///
    /// Waiting is correct — the frames ahead are being read, not idling — but
    /// not forever: a caller stuck behind a saturated budget should learn that
    /// rather than hang, and its connection dropping returns its own charge.
    pub(crate) const ACQUIRE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    fn semaphore() -> &'static Arc<Semaphore> {
        static SEM: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
        SEM.get_or_init(|| Arc::new(Semaphore::new(MAX_INFLIGHT_BODY_BYTES)))
    }

    /// Charge `bytes` against the global budget for as long as the returned
    /// permit lives. A zero-length body is free — there is nothing to allocate.
    pub(crate) async fn acquire(bytes: usize) -> std::io::Result<Option<OwnedSemaphorePermit>> {
        if bytes == 0 {
            return Ok(None);
        }
        // `decode_header` already refuses bodies above MAX_FRAME_BODY, so this
        // cannot ask for more than the budget holds — but assert it rather than
        // assume, because a request larger than the total would wait out the
        // timeout every time instead of failing for the right reason.
        let want = u32::try_from(bytes.min(MAX_INFLIGHT_BODY_BYTES)).unwrap_or(u32::MAX);
        match tokio::time::timeout(
            ACQUIRE_TIMEOUT,
            Arc::clone(semaphore()).acquire_many_owned(want),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(Some(permit)),
            Ok(Err(_)) => Ok(None), // semaphore closed: never happens, don't fail the read
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!(
                    "frame body of {bytes} B waited {}s for the global \
                     {MAX_INFLIGHT_BODY_BYTES} B read budget",
                    ACQUIRE_TIMEOUT.as_secs(),
                ),
            )),
        }
    }

    /// Bytes currently free. Test-facing: the invariant worth checking is that
    /// the budget comes BACK, and a leak is invisible from the outside.
    #[cfg(test)]
    pub(crate) fn available() -> usize {
        semaphore().available_permits()
    }
}

/// Encode and write a framed message to a split write half.
pub(crate) async fn write_frame_wh(
    wh: &mut IpcWriteHalf,
    family: u8,
    msg_type: u16,
    body: &[u8],
) -> std::io::Result<()> {
    write_frame_wh_id(wh, family, msg_type, 0, body).await
}

/// Reply variant of [`write_frame_wh`]: echoes the request's
/// `FrameHeader.request_id` so an id-stamping client can correlate the reply
/// exactly (out-of-order safe). `request_id == 0` keeps the legacy
/// positional-FIFO wire bytes.
pub(crate) async fn write_frame_wh_id(
    wh: &mut IpcWriteHalf,
    family: u8,
    msg_type: u16,
    request_id: u32,
    body: &[u8],
) -> std::io::Result<()> {
    let mut hdr = FrameHeader::new(family, msg_type);
    hdr.request_id = request_id;
    hdr.body_len = u32::try_from(body.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame body too large")
    })?;
    let hdr_buf = codec::encode_header(&hdr);
    wh.write_all(&hdr_buf).await?;
    if !body.is_empty() {
        wh.write_all(body).await?;
    }
    Ok(())
}

/// Encode a complete `LocalApp` reply frame (header + body) into one buffer,
/// echoing `request_id` — for handler tasks spawned off the connection loop,
/// which hand finished frames back to the loop's reply channel instead of
/// writing to the socket themselves.
pub(crate) fn encode_reply_frame_id(msg_type: u16, request_id: u32, body: &[u8]) -> Vec<u8> {
    debug_assert!(
        body.len() <= u32::MAX as usize,
        "encode_reply_frame_id body {} > u32::MAX — caller must enforce MAX_FRAME_BODY first",
        body.len(),
    );
    let mut hdr = FrameHeader::new(FrameFamily::LocalApp as u8, msg_type);
    hdr.request_id = request_id;
    hdr.body_len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let hdr_buf = codec::encode_header(&hdr);
    let mut frame = Vec::with_capacity(hdr_buf.len() + body.len());
    frame.extend_from_slice(&hdr_buf);
    frame.extend_from_slice(body);
    frame
}

/// Encode and write a framed message to a non-split `IpcStream`.
pub(crate) async fn write_frame_stream(
    stream: &mut IpcStream,
    family: u8,
    msg_type: u16,
    body: &[u8],
) -> std::io::Result<()> {
    let mut hdr = FrameHeader::new(family, msg_type);
    hdr.body_len = u32::try_from(body.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame body too large")
    })?;
    let hdr_buf = codec::encode_header(&hdr);
    stream.write_all(&hdr_buf).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    Ok(())
}

#[cfg(test)]
mod body_budget_tests {
    use super::body_budget::{self, MAX_INFLIGHT_BODY_BYTES};

    /// The budget is ONE counter for the whole process, and
    /// `a_waiting_reader_proceeds_once_the_budget_frees` takes all of it on
    /// purpose. Run beside it, any other test here reads `available() == 0`
    /// and measures its neighbour instead of itself — the charge test
    /// underflowed `before - 1024` and panicked with "subtract with overflow",
    /// which reads like a budget bug and is not one. Every test that touches
    /// the budget takes this first.
    static BUDGET: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Audit V-07. The per-frame cap bounds one reader; nothing bounded the
    /// sum, so 256 clients each declaring 16 MiB was ~4 GiB allocated and
    /// zeroed before a single body byte arrived.
    #[tokio::test]
    async fn a_body_is_charged_against_the_global_budget() {
        let _serialised = BUDGET.lock().await;
        let before = body_budget::available();
        let held = body_budget::acquire(1024).await.expect("acquire");
        assert_eq!(
            body_budget::available(),
            before - 1024,
            "the reader must be charged for what it declared, before allocating"
        );
        drop(held);
        assert_eq!(
            body_budget::available(),
            before,
            "the charge must come back — a budget that only counts down wedges \
             every reader after enough frames"
        );
    }

    /// An empty body allocates nothing and must not be charged, or a stream of
    /// zero-length frames would exhaust a budget it never spends.
    #[tokio::test]
    async fn an_empty_body_costs_nothing() {
        let _serialised = BUDGET.lock().await;
        let before = body_budget::available();
        let held = body_budget::acquire(0).await.expect("acquire");
        assert!(held.is_none());
        assert_eq!(body_budget::available(), before);
    }

    /// The budget is a QUEUE, not a refusal: a reader that has to wait gets
    /// its turn as soon as the frame ahead of it lands. This is the property
    /// that keeps ordinary traffic working while a flood is in progress.
    #[tokio::test]
    async fn a_waiting_reader_proceeds_once_the_budget_frees() {
        let _serialised = BUDGET.lock().await;
        let hog = body_budget::acquire(MAX_INFLIGHT_BODY_BYTES)
            .await
            .expect("acquire the whole budget");
        assert_eq!(body_budget::available(), 0);

        let waiter = tokio::spawn(async { body_budget::acquire(4096).await.map(|p| p.is_some()) });
        // Still parked while the budget is held.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "a reader must WAIT, not be refused");

        drop(hog);
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("the waiter must be released promptly")
            .expect("join")
            .expect("acquire");
        assert!(got);
    }
}
