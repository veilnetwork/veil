//! Bidirectional veil stream wrapping a raw IPC stream connection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use veilcore::proto::{LocalAppMsg, StreamClosePayload, StreamDataPayload};

use crate::client::{SharedWriter, StreamEvent, encode_frame};

/// Maximum application bytes packed into one `STREAM_DATA` frame.
///
/// A single `write()` larger than this is split across multiple bounded frames
/// (`AsyncWrite::poll_write` is allowed to accept fewer bytes than offered, and
/// `write_all` loops). Kept well below the IPC `DEFAULT_MAX_FRAME_BODY` (1 MiB)
/// so the receiver never rejects a stream frame for being oversized, and so a
/// single huge user write cannot force a multi-megabyte frame allocation.
const MAX_STREAM_CHUNK: usize = 256 * 1024;

const WRITER_CLOSED: &str = "veil IPC writer task closed";

/// Bidirectional stream between two veil endpoints.
///
/// Obtained [`AppHandle::open_stream`]. Implements [`AsyncRead`] and
/// [`AsyncWrite`]; dropping it sends a `STREAM_CLOSE` frame to the peer.
pub struct VeilStream {
    stream_id: u32,
    writer: SharedWriter,
    /// Incoming data/close events from the reader task.  Bounded к
    /// `STREAM_EVENT_QUEUE_CAP`; а slow consumer что fills the queue
    /// has its stream silently closed (visible через `recv()` → None
    /// → EOF), preventing unbounded SDK-side memory growth.
    rx: mpsc::Receiver<StreamEvent>,
    /// Backpressure-aware sender for the `AsyncWrite` poll paths. Wraps a
    /// clone of the writer channel; `poll_reserve` registers the task waker
    /// when the channel is full (no busy-spin).
    tx: PollSender<Vec<u8>>,
    /// Leftover bytes from the last partial read.
    read_buf: Vec<u8>,
    /// Set when a StreamClose event has been received.
    read_closed: bool,
    /// Set once `poll_shutdown` has enqueued the STREAM_CLOSE frame, so a
    /// repeated `poll_shutdown` is a no-op instead of sending a second close.
    shutdown_sent: bool,
}

impl VeilStream {
    pub(crate) fn new(
        stream_id: u32,
        writer: SharedWriter,
        rx: mpsc::Receiver<StreamEvent>,
    ) -> Self {
        let tx = writer.poll_sender();
        Self {
            stream_id,
            writer,
            rx,
            tx,
            read_buf: Vec::new(),
            read_closed: false,
            shutdown_sent: false,
        }
    }

    /// Returns the numeric stream ID assigned by the node.
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Send raw bytes over the stream.
    pub async fn send_data(&self, data: &[u8]) -> io::Result<()> {
        let payload = StreamDataPayload {
            stream_id: self.stream_id,
            data: data.to_vec(),
        };
        self.writer
            .write_frame(LocalAppMsg::StreamData as u16, &payload.encode())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "veil writer closed"))
    }

    /// Send a STREAM_CLOSE and mark write side closed.
    pub async fn close_write(&self) -> io::Result<()> {
        let payload = StreamClosePayload {
            stream_id: self.stream_id,
        };
        self.writer
            .write_frame(LocalAppMsg::StreamClose as u16, &payload.encode())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "veil writer closed"))
    }
}

impl AsyncRead for VeilStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        if self.read_closed {
            return Poll::Ready(Ok(())); // EOF
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(StreamEvent::Data(data))) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(StreamEvent::Close)) | Poll::Ready(None) => {
                self.read_closed = true;
                Poll::Ready(Ok(())) // EOF
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for VeilStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Reserve a channel slot first. `PollSender` registers the task waker
        // with the bounded IPC writer channel, so when the writer task frees
        // capacity this task is woken exactly once — no `wake_by_ref` busy-spin
        // under backpressure.
        match self.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                // Chunk: cap each frame's payload so a single large `write()`
                // is split across multiple bounded STREAM_DATA frames the
                // receiver accepts, instead of one oversized frame it rejects.
                let chunk_len = buf.len().min(MAX_STREAM_CHUNK);
                let payload = StreamDataPayload {
                    stream_id: self.stream_id,
                    data: buf[..chunk_len].to_vec(),
                };
                let frame = encode_frame(LocalAppMsg::StreamData as u16, &payload.encode());
                self.tx
                    .send_item(frame)
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, WRITER_CLOSED))?;
                Poll::Ready(Ok(chunk_len))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                WRITER_CLOSED,
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        match self.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let payload = StreamClosePayload {
                    stream_id: self.stream_id,
                };
                let frame = encode_frame(LocalAppMsg::StreamClose as u16, &payload.encode());
                self.tx
                    .send_item(frame)
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, WRITER_CLOSED))?;
                self.shutdown_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                WRITER_CLOSED,
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for VeilStream {
    fn drop(&mut self) {
        // `tokio::spawn` from `Drop` panics when no Tokio runtime is in
        // TLS — common when the host app drops the stream from a non-
        // tokio context (sync FFI shutdown, Flutter `NativeFinalizer`
        // panic-handler cleanup, signal handlers). Without this guard
        // dropping a stream from a foreign thread crashes the host
        // process. Same pattern as `AppHandle::Drop` / `AppSender::Drop`.
        //
        // Degradation when we skip: no STREAM_CLOSE notification; the
        // daemon GCs the stream after its keepalive timeout (~30 s).
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let stream_id = self.stream_id;
        let writer = self.writer.clone();
        tokio::spawn(async move {
            let payload = StreamClosePayload { stream_id };
            let _ = writer
                .write_frame(LocalAppMsg::StreamClose as u16, &payload.encode())
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::SharedWriter;
    use tokio::io::AsyncWriteExt;

    /// Audit M3: a single large `write()` must be split into multiple frames,
    /// each carrying at most `MAX_STREAM_CHUNK` application bytes, so the
    /// receiver never sees an oversized STREAM_DATA frame (which it would
    /// reject) and no single huge frame is allocated.
    #[tokio::test]
    async fn poll_write_chunks_large_writes_m3() {
        use veil_proto::header::HEADER_SIZE;
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        let writer = SharedWriter::new(tx);
        let (_ev_tx, ev_rx) = mpsc::channel::<StreamEvent>(8);
        let mut stream = VeilStream::new(7, writer, ev_rx);

        // Two full chunks + a remainder → exactly 3 bounded frames.
        let payload_len = MAX_STREAM_CHUNK * 2 + 1024;
        let payload = vec![0xABu8; payload_len];
        stream.write_all(&payload).await.expect("write_all");

        let mut frames = 0usize;
        let mut total_data = 0usize;
        while let Ok(frame) = rx.try_recv() {
            assert!(frame.len() > HEADER_SIZE, "frame must carry a body");
            let body = &frame[HEADER_SIZE..];
            let pl = StreamDataPayload::decode(body).expect("decode StreamData");
            assert_eq!(pl.stream_id, 7);
            assert!(
                pl.data.len() <= MAX_STREAM_CHUNK,
                "chunk {} exceeds MAX_STREAM_CHUNK {}",
                pl.data.len(),
                MAX_STREAM_CHUNK
            );
            total_data += pl.data.len();
            frames += 1;
        }
        assert_eq!(total_data, payload_len, "all bytes delivered across frames");
        assert_eq!(frames, 3, "large write split into 3 bounded frames");
    }
}
