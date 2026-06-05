//! Low-level frame I/O helpers for IPC transport.
//!
//! Three small async functions read и write `OVL1`-framed IPC payloads on
//! top of `crate::transport::{IpcReadHalf, IpcWriteHalf, IpcStream}`, plus а
//! sync encoder that builds а complete pooled frame buffer for queueing
//! before flushing.
//!
//! Pooled-buffer rationale: the daemon → chat-node delivery path runs at
//! ~200 frames/sec × 60 KiB encrypted payloads.  Reusing buffers from
//! `veil_bufpool::global()` eliminates the dominant `Vec` allocation that
//! previously fed both jemalloc dirty-page retention и the bounded delivery
//! channel; without pooling, default-decay jemalloc holds ~100-200 MiB RSS
//! that the process never reclaims.

use crate::transport::{IpcReadHalf, IpcStream, IpcWriteHalf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use veil_proto::{FrameFamily, FrameHeader, codec};

/// Build а complete IPC OVL1 frame (`LocalApp` family) from а `msg_type` и
/// `body` bytes, allocating from the global buffer pool.
///
/// Debug-asserts that `body.len() <= u32::MAX`; release builds saturate to
/// `u32::MAX` because callers don't have а fallible signature, but this
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

/// Hard upper-bound on the time а frame body может ждать после header
/// successful read. Без deadline, а local IPC client может объявить body
/// до 16 MiB and never push it — pinning RSS until the connection drops.
/// At 256 clients × 16 MiB this is up to 4 GiB of pinned buffers.
///
/// 30 seconds is generous даже для legacy slow disks / fuse FS на the
/// app side, и still bounds the worst-case memory exposure к
/// `256 clients × 16 MiB × 30 s` of windowed risk.
pub(crate) const BODY_READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Read one framed message from `rh`.
///
/// Acquires the body buffer from the global pool — see module docs for the
/// jemalloc-retention rationale.  `decode_header` already rejects bodies
/// larger than `MAX_FRAME_BODY`, so the acquisition is bounded в bytes.
/// **Body read** is also bounded в time by [`BODY_READ_DEADLINE`]: после
/// successful header, the client must finish pushing body within 30 s
/// or the read returns `TimedOut`. Closes the local-IPC memory-DoS
/// vector where а stuck client kept а 16-MiB buffer pinned indefinitely.
pub(crate) async fn read_frame(
    rh: &mut IpcReadHalf,
) -> std::io::Result<(FrameHeader, veil_bufpool::Pooled)> {
    let mut hdr_buf = [0u8; veil_proto::HEADER_SIZE];
    rh.read_exact(&mut hdr_buf).await?;
    let header = codec::decode_header(&hdr_buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let body_len = header.body_len as usize;
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

/// Encode и write а framed message to а split write half.
pub(crate) async fn write_frame_wh(
    wh: &mut IpcWriteHalf,
    family: u8,
    msg_type: u16,
    body: &[u8],
) -> std::io::Result<()> {
    let mut hdr = FrameHeader::new(family, msg_type);
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

/// Encode и write а framed message to а non-split `IpcStream`.
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
