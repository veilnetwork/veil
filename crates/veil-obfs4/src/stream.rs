//! Async-stream wrapper that applies obfs4 framing to a raw `AsyncRead +
//! AsyncWrite` transport.  Sits between session-layer (which sends
//! plaintext OVL1 bytes) and raw TCP (which sees obfs4 ciphertext only).
//!
//! Usage (sketch — real callers use [`tokio::net::TcpStream`]):
//!
//! ```ignore
//! use veil_obfs4::{NodeIdMacKey, obfs4_client_connect, obfs4_server_accept};
//! use tokio::net::TcpStream;
//!
//! let psk = NodeIdMacKey([0x42; 32]);
//!
//! // Client side: connect, then upgrade to obfs4-wrapped stream.
//! let tcp = TcpStream::connect("server.example:9000").await?;
//! let mut stream = obfs4_client_connect(tcp, &psk).await?;
//! // `stream` is AsyncRead + AsyncWrite, speaks OVL1 plaintext.
//!
//! // Server side:
//! let listener = tokio::net::TcpListener::bind(addr).await?;
//! let (tcp, _) = listener.accept().await?;
//! let mut stream = obfs4_server_accept(tcp, &psk).await?;
//! ```

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    ClientHandshake, FrameError, HANDSHAKE_MAX_BYTES, HANDSHAKE_MIN_BYTES, HandshakeError,
    InboundStream, NodeIdMacKey, OutboundStream, ServerHandshake,
    elligator2::REPRESENTATIVE_LEN,
    ntor::{MAC_LEN, TWEAK_LEN},
};

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("I/O error during handshake: {0}")]
    Io(#[from] io::Error),

    #[error("obfs4 handshake error: {0}")]
    Handshake(#[from] HandshakeError),
}

fn frame_to_io(e: FrameError) -> io::Error {
    match e {
        FrameError::TooShort(_) => io::Error::new(io::ErrorKind::UnexpectedEof, e),
        FrameError::OversizedFrame(_) => io::Error::new(io::ErrorKind::InvalidData, e),
        FrameError::CounterOverflow => io::Error::other(e),
        _ => io::Error::new(io::ErrorKind::InvalidData, e),
    }
}

// ── Upgrade helpers ──────────────────────────────────────────────────────────

/// Read a single obfs4 handshake message (length-prefix-aware) from the
/// underlying stream and return the bytes.  Caps at `HANDSHAKE_MAX_BYTES`.
async fn read_handshake_message<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, UpgradeError> {
    // Handshake message has variable padding 0..=128 bytes, but a
    // valid message is bounded by HANDSHAKE_MAX_BYTES.  We don't know
    // the exact length until parsed — so read up to the max and hand the
    // fully-buffered slice to the parser.  Read in chunks; stop when
    // we have enough to verify (parser will complain on excess trailing
    // bytes, but we'd never read past HANDSHAKE_MAX_BYTES).
    let mut buf = Vec::with_capacity(HANDSHAKE_MAX_BYTES);
    let mut chunk = [0u8; 64];
    while buf.len() < HANDSHAKE_MAX_BYTES {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        // Try parsing with current buffer; if `TooShort`, keep reading. Once we
        // have the declared total we accept.
        if buf.len() >= HANDSHAKE_MIN_BYTES {
            // Peek at declared pad_len to determine total length.
            // (No timestamp field on the wire since C-01.)
            let pad_len_offset = REPRESENTATIVE_LEN + TWEAK_LEN + MAC_LEN;
            if buf.len() > pad_len_offset {
                let pad_len = buf[pad_len_offset] as usize;
                let total = pad_len_offset + 1 + pad_len;
                if buf.len() >= total {
                    // No-pipeline invariant: obfs4 is strictly request/response
                    // up to and including this handshake flight — the peer sends
                    // NO post-handshake data until both handshakes complete, so a
                    // single read never carries bytes past `total`. `truncate`
                    // therefore only ever drops zero bytes. If a future framing
                    // ever pipelines data into the handshake segment, those bytes
                    // would be silently lost here; assert loudly in debug builds
                    // so that change is caught rather than corrupting the stream.
                    debug_assert_eq!(
                        buf.len(),
                        total,
                        "obfs4 handshake read over-read past the message — peer \
                         pipelined post-handshake data; truncate would drop it"
                    );
                    buf.truncate(total);
                    return Ok(buf);
                }
            }
        }
    }
    if buf.len() < HANDSHAKE_MIN_BYTES {
        return Err(UpgradeError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "stream closed before handshake completed",
        )));
    }
    Ok(buf)
}

/// Perform the obfs4 client handshake on the supplied raw stream and
/// return an `Obfs4Stream` ready for OVL1 plaintext I/O.  V1-default
/// wrapper — for Phase 2 kill-switch use `obfs4_client_connect_variant`.
pub async fn obfs4_client_connect<S>(
    stream: S,
    psk: &NodeIdMacKey,
) -> Result<Obfs4Stream<S>, UpgradeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    obfs4_client_connect_variant(stream, psk, super::wire_variant::WireFormatVariant::V1).await
}

/// Variant-aware obfs4 client handshake.  Caller picks the variant
/// (V1 / V2); if the server doesn't accept that variant, the read
/// of the server response times out / returns EOF, which surfaces as
/// `UpgradeError::Io` — caller (transport layer) treats it as a
/// silent-drop signal and may retry with a fallback variant.
pub async fn obfs4_client_connect_variant<S>(
    mut stream: S,
    psk: &NodeIdMacKey,
    variant: super::wire_variant::WireFormatVariant,
) -> Result<Obfs4Stream<S>, UpgradeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (state, wire) = ClientHandshake::start_variant(psk, variant)?;
    stream.write_all(&wire).await?;
    stream.flush().await?;

    let server_msg = read_handshake_message(&mut stream).await?;
    let out = state.complete(&server_msg)?;
    Ok(Obfs4Stream::new(
        stream,
        OutboundStream::new(out.dk_c_to_s),
        InboundStream::new(out.dk_s_to_c),
    ))
}

/// Perform the obfs4 server handshake on the supplied raw stream and
/// return an `Obfs4Stream`.  Returns `Err` on bad PSK / tampered
/// message; caller treats it as a silent-drop signal (closes the
/// connection without sending anything).
///
/// V1-only wrapper.  For Phase 2 kill-switch multi-variant accept,
/// use `obfs4_server_accept_multi`.
pub async fn obfs4_server_accept<S>(
    stream: S,
    psk: &NodeIdMacKey,
) -> Result<Obfs4Stream<S>, UpgradeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (s, _variant) =
        obfs4_server_accept_multi(stream, psk, &[super::wire_variant::WireFormatVariant::V1])
            .await?;
    Ok(s)
}

/// Phase 2 multi-variant server accept.  Tries each variant in
/// `accept_variants` order on the client's first frame; first MAC
/// that verifies wins.  Returns the stream + the matched variant so
/// the caller can log/metric which wire format the client used.
///
/// Operator wires this from `[transport] obfs4_accept_variants` config.
/// Default `&[V1]` preserves pre-Phase-2 behavior bit-for-bit.
pub async fn obfs4_server_accept_multi<S>(
    mut stream: S,
    psk: &NodeIdMacKey,
    accept_variants: &[super::wire_variant::WireFormatVariant],
) -> Result<(Obfs4Stream<S>, super::wire_variant::WireFormatVariant), UpgradeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client_msg = read_handshake_message(&mut stream).await?;
    let (out, matched, wire) =
        ServerHandshake::accept_full_multi(&client_msg, psk, accept_variants)?;
    stream.write_all(&wire).await?;
    stream.flush().await?;
    Ok((
        Obfs4Stream::new(
            stream,
            OutboundStream::new(out.dk_s_to_c),
            InboundStream::new(out.dk_c_to_s),
        ),
        matched,
    ))
}

// ── Obfs4Stream ──────────────────────────────────────────────────────────────

/// Internal write state.
enum WriteState {
    /// No frame pending — ready to accept new bytes.
    Idle,
    /// Currently writing an outbound frame to the underlying stream.
    Writing { frame: Vec<u8>, offset: usize },
}

/// Internal read state.
enum ReadState {
    /// Reading the 2-byte length prefix of the next inbound frame.
    Length { buf: [u8; 2], filled: usize },
    /// Reading the body of the current frame.  `total` includes the
    /// (already-consumed) 2-byte length prefix.
    Body { wire: Vec<u8>, total: usize },
    /// Plaintext ready to deliver to caller.
    Plaintext { plaintext: Vec<u8>, offset: usize },
}

pin_project! {
    /// Wraps a raw `AsyncRead + AsyncWrite` transport with obfs4 framing.
    /// Implements `AsyncRead + AsyncWrite` so session-layer can use it
    /// transparently in place of a raw TCP stream.
    pub struct Obfs4Stream<S> {
        #[pin]
        inner: S,
        outbound: OutboundStream,
        inbound: InboundStream,
        write_state: WriteState,
        read_state: ReadState,
    }
}

impl<S> Obfs4Stream<S> {
    fn new(inner: S, outbound: OutboundStream, inbound: InboundStream) -> Self {
        Self {
            inner,
            outbound,
            inbound,
            write_state: WriteState::Idle,
            read_state: ReadState::Length {
                buf: [0u8; 2],
                filled: 0,
            },
        }
    }

    /// Consume the wrapper and return the underlying stream.  Useful
    /// for test cleanup; do NOT call mid-stream — any buffered
    /// plaintext or ciphertext is lost.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

// ── AsyncWrite ──────────────────────────────────────────────────────

impl<S: AsyncWrite + Unpin> AsyncWrite for Obfs4Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        // First, drain any in-flight frame.
        loop {
            match this.write_state {
                WriteState::Idle => break,
                WriteState::Writing { frame, offset } => {
                    let pending = &frame[*offset..];
                    match this.inner.as_mut().poll_write(cx, pending) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "obfs4 underlying write returned 0",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            *offset += n;
                            if *offset >= frame.len() {
                                *this.write_state = WriteState::Idle;
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
        // State is Idle — wrap user bytes into a frame and queue it.
        //
        // Audit batch 2026-05-24 phase H: fragment large writes to fit
        // the obfs4 16 KiB ciphertext cap (`MAX_FRAME_CIPHERTEXT_BYTES`).
        // `wrap_next` enforces the cap on body ciphertext; a single
        // OVL1 frame can legitimately reach `MAX_FRAME_BODY = 16 MiB`
        // (e.g. DHT `owned_push` with 14 records ≈ 62 KiB), so the
        // transport layer is responsible for chunking.  Without this,
        // every oversized push tore down the session ("session.writer.
        // write_error frame ciphertext length 63121 exceeds cap
        // 16384") and tx_registry churn cycled the whole cluster: every
        // host saw 0-session windows every few minutes pre-fix even
        // with chaos-ban stopped.
        //
        // Take only the next `MAX_PLAINTEXT_PER_FRAME` bytes; the
        // AsyncWrite contract permits returning a short count, so the
        // caller will re-poll with the remainder.
        let chunk_len = buf.len().min(crate::MAX_PLAINTEXT_PER_FRAME);
        let chunk = &buf[..chunk_len];
        let frame = this.outbound.wrap_next(chunk).map_err(frame_to_io)?;
        *this.write_state = WriteState::Writing { frame, offset: 0 };
        // Optimistically try writing the new frame; either way report
        // chunk_len consumed since those bytes are committed to our
        // pipeline.
        if let WriteState::Writing { frame, offset } = this.write_state {
            match this.inner.as_mut().poll_write(cx, &frame[*offset..]) {
                Poll::Ready(Ok(n)) => {
                    *offset += n;
                    if *offset >= frame.len() {
                        *this.write_state = WriteState::Idle;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {} // bytes still committed; flush will retry
            }
        }
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        // Drain pending frame.
        loop {
            match this.write_state {
                WriteState::Idle => break,
                WriteState::Writing { frame, offset } => {
                    let pending = &frame[*offset..];
                    match this.inner.as_mut().poll_write(cx, pending) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "obfs4 underlying write returned 0",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            *offset += n;
                            if *offset >= frame.len() {
                                *this.write_state = WriteState::Idle;
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
        this.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush, then shutdown underlying.
        ready!(self.as_mut().poll_flush(cx))?;
        let this = self.project();
        this.inner.poll_shutdown(cx)
    }
}

// ── AsyncRead ───────────────────────────────────────────────────────

impl<S: AsyncRead + Unpin> AsyncRead for Obfs4Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        loop {
            match this.read_state {
                ReadState::Plaintext { plaintext, offset } => {
                    let available = &plaintext[*offset..];
                    if available.is_empty() {
                        // Reset to begin reading next frame.
                        *this.read_state = ReadState::Length {
                            buf: [0u8; 2],
                            filled: 0,
                        };
                        continue;
                    }
                    let n = available.len().min(out.remaining());
                    out.put_slice(&available[..n]);
                    *offset += n;
                    return Poll::Ready(Ok(()));
                }
                ReadState::Length { buf, filled } => {
                    // Need 2 bytes for the length prefix.
                    let mut tmp = ReadBuf::new(&mut buf[*filled..]);
                    match this.inner.as_mut().poll_read(cx, &mut tmp) {
                        Poll::Ready(Ok(())) => {
                            let read_n = tmp.filled().len();
                            if read_n == 0 {
                                // EOF mid-prefix.  Surface as Ok(()) with
                                // out untouched ⇒ caller sees EOF.
                                return Poll::Ready(Ok(()));
                            }
                            *filled += read_n;
                            if *filled < 2 {
                                continue;
                            }
                            // Have full prefix.  Peek next-frame length.
                            let prefix = *buf;
                            // peek_frame_len reads from a slice starting with
                            // the prefix; build a dummy buf containing
                            // just the prefix.
                            let body_len =
                                this.inbound.peek_frame_len(&prefix).map_err(frame_to_io)?;
                            let total = 2 + body_len;
                            if total > crate::MAX_FRAME_CIPHERTEXT_BYTES + 2 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "obfs4: frame length exceeds cap",
                                )));
                            }
                            let mut wire = Vec::with_capacity(total);
                            wire.extend_from_slice(&prefix);
                            *this.read_state = ReadState::Body { wire, total };
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ReadState::Body { wire, total } => {
                    // Read body bytes to fill wire.
                    let needed = *total - wire.len();
                    if needed == 0 {
                        // Decrypt.
                        let (_, plaintext) = this.inbound.unwrap_next(wire).map_err(frame_to_io)?;
                        *this.read_state = ReadState::Plaintext {
                            plaintext,
                            offset: 0,
                        };
                        continue;
                    }
                    let mut chunk = vec![0u8; needed];
                    let mut tmp = ReadBuf::new(&mut chunk);
                    match this.inner.as_mut().poll_read(cx, &mut tmp) {
                        Poll::Ready(Ok(())) => {
                            let read_n = tmp.filled().len();
                            if read_n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "obfs4: EOF mid-frame",
                                )));
                            }
                            wire.extend_from_slice(&chunk[..read_n]);
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

// ── Re-exports required ntor constants (for read_handshake_message) ──

// Make ntor constants visible at our internal use site.  ntor.rs already
// declares them `pub` so this is a path re-export, not a new definition.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn test_psk() -> NodeIdMacKey {
        NodeIdMacKey([0x42; 32])
    }

    /// End-to-end: bind a duplex pair, run client handshake on one
    /// half and server handshake on the other, then push bytes through.
    #[tokio::test]
    async fn handshake_then_roundtrip_bytes() {
        let (client_raw, server_raw) = duplex(64 * 1024);

        let psk_a = test_psk();
        let psk_b = test_psk();
        let client_fut = obfs4_client_connect(client_raw, &psk_a);
        let server_fut = obfs4_server_accept(server_raw, &psk_b);

        let (client, server) = tokio::join!(client_fut, server_fut);
        let mut client = client.expect("client handshake ok");
        let mut server = server.expect("server handshake ok");

        // Bidirectional traffic.
        client.write_all(b"hello server").await.unwrap();
        client.flush().await.unwrap();

        let mut buf = vec![0u8; 12];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello server");

        server.write_all(b"hi client").await.unwrap();
        server.flush().await.unwrap();

        let mut buf2 = vec![0u8; 9];
        client.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"hi client");
    }

    #[tokio::test]
    async fn multiple_writes_decode_correctly() {
        let (client_raw, server_raw) = duplex(64 * 1024);
        let psk = test_psk();
        let (client, server) = tokio::join!(
            obfs4_client_connect(client_raw, &psk),
            obfs4_server_accept(server_raw, &psk),
        );
        let mut client = client.unwrap();
        let mut server = server.unwrap();

        // 50 frames of increasing size, each round-trip.
        for i in 1..=50 {
            let payload = vec![i as u8; i as usize];
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();

            let mut buf = vec![0u8; i as usize];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, payload);
        }
    }

    #[tokio::test]
    async fn wrong_psk_handshake_fails() {
        let (client_raw, server_raw) = duplex(64 * 1024);
        let server_psk = NodeIdMacKey([0x42; 32]);
        let wrong_psk = NodeIdMacKey([0xAB; 32]);

        let client_fut = obfs4_client_connect(client_raw, &wrong_psk);
        let server_fut = obfs4_server_accept(server_raw, &server_psk);

        let (client_res, server_res) = tokio::join!(client_fut, server_fut);

        // Server rejects the bad MAC.
        match server_res {
            Ok(_) => panic!("server should NOT accept bad MAC"),
            Err(UpgradeError::Handshake(HandshakeError::ClientMacMismatch)) => {}
            Err(other) => panic!("expected ClientMacMismatch, got {other:?}"),
        }

        // Client could fail with various errors depending on timing
        // (EOF when server drops, AuthMismatch if server happens to
        // respond before drop).  Just confirm it's an error.
        assert!(client_res.is_err());
    }

    /// Wire-level capture: writes a payload containing the OVL1 magic;
    /// the wire bytes between the two halves MUST NOT contain it.
    #[tokio::test]
    async fn no_ovl1_magic_on_wire() {
        let (mut client_raw, server_raw) = duplex(64 * 1024);
        let psk = test_psk();

        // Spawn server-side handshake on a separate task so it
        // actually progresses while we manually drive the client.
        let psk_clone = psk.clone();
        let server_task =
            tokio::spawn(async move { obfs4_server_accept(server_raw, &psk_clone).await });

        // Client side: handshake manually so we can intercept bytes.
        let (state, c_hs_wire) = ClientHandshake::start(&psk).unwrap();
        client_raw.write_all(&c_hs_wire).await.unwrap();
        client_raw.flush().await.unwrap();

        let mut s_hs = vec![0u8; HANDSHAKE_MAX_BYTES];
        let n = client_raw.read(&mut s_hs).await.unwrap();
        s_hs.truncate(n);
        let out = state.complete(&s_hs).unwrap();
        let mut outbound = OutboundStream::new(out.dk_c_to_s);

        // Wrap a payload containing the OVL1 magic plaintext.
        let payload = b"OVL1\x01\x00\x00\x00body...";
        let frame = outbound.wrap_next(payload).unwrap();

        for buf in [&c_hs_wire[..], &s_hs[..], &frame[..]] {
            for window in buf.windows(4) {
                assert_ne!(window, b"OVL1", "OVL1 magic leaked on wire");
            }
        }

        // Await server task so it doesn't leak past test end.
        let _ = server_task.await;
    }
}
