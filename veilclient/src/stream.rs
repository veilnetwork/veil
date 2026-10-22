//! Bidirectional veil stream wrapping a raw IPC stream connection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use veilcore::proto::{LocalAppMsg, StreamClosePayload, StreamDataPayload, StreamWindowPayload};

use crate::client::{SharedWriter, StreamEvent, encode_frame};

/// Maximum application bytes packed into one `STREAM_DATA` frame.
///
/// A single `write()` larger than this is split across multiple bounded frames
/// (`AsyncWrite::poll_write` is allowed to accept fewer bytes than offered, and
/// `write_all` loops). The daemon schedules remote stream frames in its local
/// background lane. Keep each body below the endpoint's active-primary 4 KiB
/// wire budget: a whole frame cannot be preempted once committed to the ordered
/// connection. This is a sender limit; older peers may still send larger frames.
const MAX_STREAM_CHUNK: usize = 2 * 1024;

/// Negotiated app→node admission credit, independent of incoming stream data.
/// The IPC reader refunds it without awaiting a file consumer.
pub(crate) struct StreamWriteCredit(std::sync::Mutex<WriteCreditState>);
struct WriteCreditState {
    bytes: usize,
    closed: bool,
    wakers: Vec<std::task::Waker>,
}
impl StreamWriteCredit {
    pub(crate) fn new() -> Self {
        Self(std::sync::Mutex::new(WriteCreditState {
            bytes: veilcore::proto::ipc::IPC_STREAM_WRITE_WINDOW as usize,
            closed: false,
            wakers: Vec::new(),
        }))
    }
    pub(crate) fn refund(&self, n: u32) {
        let wakers = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            state.bytes = state
                .bytes
                .saturating_add(n as usize)
                .min(veilcore::proto::ipc::IPC_STREAM_WRITE_WINDOW as usize);
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }
    pub(crate) fn close(&self) {
        let wakers = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            state.closed = true;
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

fn poll_stream_write(
    id: u32,
    tx: &mut PollSender<crate::client::IpcWriterFrame>,
    credit: Option<&StreamWriteCredit>,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>> {
    if buf.is_empty() {
        return Poll::Ready(Ok(0));
    }
    let overhead = veilcore::proto::ipc::IPC_STREAM_WRITE_OVERHEAD as usize;
    let mut state = credit.map(|credit| credit.0.lock().unwrap_or_else(|e| e.into_inner()));
    let mut n = buf.len().min(MAX_STREAM_CHUNK);
    if let Some(state) = state.as_mut() {
        if state.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                // A peer/reader close retires only this stream's credit. The
                // shared IPC writer can still serve other streams. Preserve
                // the existing FFI closed-handle classification as well.
                "veil stream already closed",
            )));
        }
        if state.bytes <= overhead {
            if !state.wakers.iter().any(|w| w.will_wake(cx.waker())) {
                state.wakers.push(cx.waker().clone());
            }
            return Poll::Pending;
        }
        n = n.min(state.bytes - overhead);
    }
    // Reserve the IPC slot while holding the short credit lock: concurrent
    // send_data callers cannot spend the same credit. Neither operation awaits.
    match tx.poll_reserve(cx) {
        Poll::Ready(Ok(())) => {
            let payload = StreamDataPayload {
                stream_id: id,
                data: buf[..n].to_vec(),
            };
            tx.send_item(encode_frame(LocalAppMsg::StreamData as u16, &payload.encode()).into())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, WRITER_CLOSED))?;
            if let Some(state) = state.as_mut() {
                state.bytes -= n + overhead;
            }
            Poll::Ready(Ok(n))
        }
        Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            WRITER_CLOSED,
        ))),
        Poll::Pending => Poll::Pending,
    }
}

const WRITER_CLOSED: &str = "veil IPC writer task closed";

/// Bidirectional stream between two veil endpoints.
///
/// Obtained [`AppHandle::open_stream`]. Implements [`AsyncRead`] and
/// [`AsyncWrite`]; dropping it sends a `STREAM_CLOSE` frame to the peer.
pub struct VeilStream {
    stream_id: u32,
    writer: SharedWriter,
    write_credit: Option<std::sync::Arc<StreamWriteCredit>>,
    /// Incoming data/close events from the reader task.  Bounded to
    /// `STREAM_EVENT_QUEUE_CAP`; a slow consumer that fills the queue
    /// has its stream silently closed (visible through `recv()` → None
    /// → EOF), preventing unbounded SDK-side memory growth.
    rx: mpsc::Receiver<StreamEvent>,
    /// Backpressure-aware sender for the `AsyncWrite` poll paths. Wraps a
    /// clone of the writer channel; `poll_reserve` registers the task waker
    /// when the channel is full (no busy-spin).
    tx: PollSender<crate::client::IpcWriterFrame>,
    /// Leftover bytes from the last partial read.
    read_buf: Vec<u8>,
    /// Set when a StreamClose event has been received.
    read_closed: bool,
    /// Set once `poll_shutdown` has enqueued the STREAM_CLOSE frame, so a
    /// repeated `poll_shutdown` is a no-op instead of sending a second close.
    shutdown_sent: bool,
    /// Bytes consumed by the app but not yet credited back to the daemon as
    /// STREAM_WINDOW (diff-audit H5). The daemon debits the A→B flow-control
    /// window per data frame and only refills it on an inbound STREAM_WINDOW
    /// from this acceptor SDK; without crediting, a transfer past the initial
    /// window gets force-closed mid-stream. Accumulated so a momentarily-full
    /// IPC channel never drops a credit — `credit_window` retries next read.
    pending_window: u32,
    /// Only the ACCEPTOR (B) credits: the flow-control window is A→B
    /// (opener→acceptor) only, and the daemon honours STREAM_WINDOW solely from
    /// the acceptor. An opener crediting on its B→A reads would emit ignored
    /// frames, so suppress it there.
    is_acceptor: bool,
}

impl VeilStream {
    /// Opener-side stream (A). Does NOT credit STREAM_WINDOW (see `is_acceptor`).
    pub(crate) fn new(
        stream_id: u32,
        writer: SharedWriter,
        rx: mpsc::Receiver<StreamEvent>,
    ) -> Self {
        Self::with_role(stream_id, writer, rx, false)
    }

    /// Acceptor-side stream (B). Credits STREAM_WINDOW as the app drains data so
    /// the daemon refills the A→B window (diff-audit H5).
    pub(crate) fn new_acceptor(
        stream_id: u32,
        writer: SharedWriter,
        rx: mpsc::Receiver<StreamEvent>,
    ) -> Self {
        Self::with_role(stream_id, writer, rx, true)
    }

    fn with_role(
        stream_id: u32,
        writer: SharedWriter,
        rx: mpsc::Receiver<StreamEvent>,
        is_acceptor: bool,
    ) -> Self {
        let tx = writer.poll_sender();
        let write_credit = writer.register_stream_credit(stream_id);
        Self {
            stream_id,
            writer,
            write_credit,
            rx,
            tx,
            read_buf: Vec::new(),
            read_closed: false,
            shutdown_sent: false,
            pending_window: 0,
            is_acceptor,
        }
    }

    /// Credit `n` consumed bytes back to the daemon's A→B flow-control window
    /// (diff-audit H5). Acceptor-only (the daemon ignores opener credits).
    /// Best-effort non-blocking send from the sync poll_read path: on a full
    /// channel the amount stays pending and is retried on the next read, so
    /// credits are never lost (only briefly delayed).
    fn credit_window(&mut self, n: usize) {
        if n == 0 || !self.is_acceptor {
            return;
        }
        self.pending_window = self.pending_window.saturating_add(n as u32);
        let payload = StreamWindowPayload {
            stream_id: self.stream_id,
            increment: self.pending_window,
        };
        if self
            .writer
            .try_send_frame(LocalAppMsg::StreamWindow as u16, &payload.encode())
        {
            self.pending_window = 0;
        }
    }

    /// Returns the numeric stream ID assigned by the node.
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Send raw bytes over the stream.
    pub async fn send_data(&self, data: &[u8]) -> io::Result<()> {
        let mut tx = self.writer.poll_sender();
        let mut remaining = data;
        while !remaining.is_empty() {
            let n = std::future::poll_fn(|cx| {
                poll_stream_write(
                    self.stream_id,
                    &mut tx,
                    self.write_credit.as_deref(),
                    cx,
                    remaining,
                )
            })
            .await?;
            remaining = &remaining[n..];
        }
        Ok(())
    }

    /// Send a STREAM_CLOSE and mark write side closed.
    pub async fn close_write(&self) -> io::Result<()> {
        let payload = StreamClosePayload {
            stream_id: self.stream_id,
        };
        self.writer
            .write_frame(LocalAppMsg::StreamClose as u16, &payload.encode())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "veil writer closed"))?;
        if let Some(credit) = &self.write_credit {
            credit.close();
        }
        Ok(())
    }
}

impl AsyncRead for VeilStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        // Drain only ready frames. The FFI caller otherwise crosses into a new
        // Dart worker for every 2-KiB IPC frame even with a full receive queue.
        // Cap work per poll, including empty frames from an untrusted peer.
        for _ in 0..64 {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
            }
            if buf.remaining() == 0 || self.read_closed {
                break;
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(StreamEvent::Data(data))) => {
                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        self.read_buf.extend_from_slice(&data[n..]);
                    }
                }
                Poll::Ready(Some(StreamEvent::Close)) | Poll::Ready(None) => {
                    self.read_closed = true;
                    break;
                }
                Poll::Pending => {
                    let n = buf.filled().len() - before;
                    self.credit_window(n);
                    return if n > 0 {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
        let n = buf.filled().len() - before;
        self.credit_window(n);
        if n > 0 || self.read_closed {
            Poll::Ready(Ok(()))
        } else {
            // Empty DATA is not EOF. Bound a continuously ready producer, and
            // retry on the next poll without waiting for a new channel event.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

impl AsyncWrite for VeilStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let credit = self.write_credit.clone();
        poll_stream_write(self.stream_id, &mut self.tx, credit.as_deref(), cx, buf)
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
                    .send_item(frame.into())
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, WRITER_CLOSED))?;
                self.shutdown_sent = true;
                if let Some(credit) = &self.write_credit {
                    credit.close();
                }
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
        if let Some(credit) = &self.write_credit {
            self.writer.unregister_stream_credit(self.stream_id, credit);
        }
        if self.shutdown_sent {
            return;
        }
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
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn read_drains_queued_frames_without_waiting_for_more_bytes() {
        let (tx, mut ipc) = mpsc::channel::<crate::client::IpcWriterFrame>(8);
        let writer = SharedWriter::new(tx);
        let (events, rx) = mpsc::channel(64);
        let mut stream = VeilStream::new_acceptor(7, writer, rx);
        let expected: Vec<_> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        for chunk in expected.chunks(2048) {
            events
                .send(StreamEvent::Data(chunk.to_vec()))
                .await
                .unwrap();
        }
        let mut bytes = vec![0; 64 * 1024];
        let n = stream.read(&mut bytes).await.unwrap();
        assert_eq!(
            n,
            expected.len(),
            "queued IPC frames must share one FFI read"
        );
        assert_eq!(bytes, expected);
        let frame = ipc.recv().await.unwrap();
        let credit = StreamWindowPayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap();
        assert_eq!(credit.increment as usize, n);
        assert!(
            ipc.try_recv().is_err(),
            "credit is coalesced with this read"
        );
        events.send(StreamEvent::Data(vec![9; 17])).await.unwrap();
        // The producer remains live and has not supplied another full buffer.
        let n = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.read(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&bytes[..n], &[9; 17]);
        events.send(StreamEvent::Close).await.unwrap();
        assert_eq!(stream.read(&mut bytes).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn coalesced_reads_preserve_partial_frames_empty_data_and_eof() {
        let (tx, _ipc) = mpsc::channel::<crate::client::IpcWriterFrame>(8);
        let writer = SharedWriter::new(tx);
        let (events, rx) = mpsc::channel(128);
        let mut stream = VeilStream::new(7, writer, rx);
        // More empty frames than the per-poll fairness budget. They must
        // neither manufacture EOF nor strand a consumer with data queued.
        for _ in 0..80 {
            events.send(StreamEvent::Data(Vec::new())).await.unwrap();
        }
        let expected: Vec<_> = (0..100_003).map(|i| (i % 251) as u8).collect();
        events
            .send(StreamEvent::Data(expected[..70_000].to_vec()))
            .await
            .unwrap();
        events
            .send(StreamEvent::Data(expected[70_000..].to_vec()))
            .await
            .unwrap();
        events.send(StreamEvent::Close).await.unwrap();
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        let mut actual = Vec::new();
        let mut buf = [0; 4097];
        loop {
            let n = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            if n == 0 {
                break;
            }
            actual.extend_from_slice(&buf[..n]);
        }
        assert_eq!(
            actual, expected,
            "partial reads must not lose or duplicate bytes"
        );
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn bounded_stream_frames_preserve_bytes_and_one_close_under_backpressure() {
        use veil_proto::{codec::decode_header, header::HEADER_SIZE};
        let (tx, mut rx) = mpsc::channel::<crate::client::IpcWriterFrame>(2);
        let writer = SharedWriter::new(tx);
        let (_ev_tx, ev_rx) = mpsc::channel::<StreamEvent>(8);
        let mut stream = VeilStream::new(7, writer, ev_rx);
        let payload: Vec<_> = (0..128 * 1024 + 19).map(|n| (n % 251) as u8).collect();
        let read = tokio::spawn(async move {
            let mut bytes = Vec::new();
            let mut closed = false;
            while let Some(frame) = rx.recv().await {
                let header = decode_header(&frame).unwrap();
                let body = &frame[HEADER_SIZE..];
                if header.msg_type == LocalAppMsg::StreamClose as u16 {
                    assert!(!closed, "shutdown and drop must not duplicate close");
                    assert_eq!(StreamClosePayload::decode(body).unwrap().stream_id, 7);
                    closed = true;
                } else {
                    assert!(!closed, "close overtook data");
                    assert_eq!(header.msg_type, LocalAppMsg::StreamData as u16);
                    let data = StreamDataPayload::decode(body).unwrap();
                    assert_eq!(data.stream_id, 7);
                    // Independent of MAX_STREAM_CHUNK: restoring the old 256
                    // KiB producer must fail the latency-granularity contract.
                    assert!(data.data.len() <= 2048, "oversized committed stream body");
                    bytes.extend(data.data);
                }
                tokio::task::yield_now().await;
            }
            assert!(closed);
            bytes
        });
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        assert_eq!(
            read.await.unwrap(),
            payload,
            "loss, duplication or reordering"
        );
    }

    /// Audit M3: a single large `write()` must be split into multiple frames,
    /// each carrying at most `MAX_STREAM_CHUNK` application bytes, so the
    /// receiver never sees an oversized STREAM_DATA frame (which it would
    /// reject) and no single huge frame is allocated.
    #[tokio::test]
    async fn poll_write_chunks_large_writes_m3() {
        use veil_proto::header::HEADER_SIZE;
        let (tx, mut rx) = mpsc::channel::<crate::client::IpcWriterFrame>(64);
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
    #[tokio::test]
    async fn closing_source_credit_wakes_a_blocked_sdk_writer() {
        let (tx, mut frames) = mpsc::channel::<crate::client::IpcWriterFrame>(64);
        let writer = SharedWriter::new(tx).with_stream_credit(true);
        let (_events, rx) = mpsc::channel(8);
        let mut stream = VeilStream::new(7, writer.clone(), rx);
        let write = tokio::spawn(async move { stream.write_all(&vec![1; 64 * 1024]).await });
        // All four initial source writes can reach IPC, but their payload plus
        // per-frame allocation cost consumes exactly the initial 8 KiB credit.
        let mut charged = 0;
        while charged < veilcore::proto::ipc::IPC_STREAM_WRITE_WINDOW as usize {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), frames.recv())
                .await
                .unwrap()
                .unwrap();
            let data = StreamDataPayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap();
            charged += data.data.len() + veilcore::proto::ipc::IPC_STREAM_WRITE_OVERHEAD as usize;
        }
        assert!(!write.is_finished());
        writer.close_stream_credit(7);
        let error = tokio::time::timeout(std::time::Duration::from_millis(250), write)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "veil stream already closed");
        // A retired stream must not be diagnosed as a failed IPC connection.
        // Prove that a second stream can still write through this writer.
        let (_other_events, other_rx) = mpsc::channel(8);
        let mut other = VeilStream::new(8, writer, other_rx);
        other.write_all(b"still live").await.unwrap();
        // Dropping the first VeilStream also enqueues its normal close.
        let frame = loop {
            let frame = frames.recv().await.unwrap();
            if veil_proto::codec::decode_header(&frame).unwrap().msg_type
                == LocalAppMsg::StreamData as u16
            {
                break frame;
            }
        };
        let data = StreamDataPayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap();
        assert_eq!(data.stream_id, 8);
        assert_eq!(data.data, b"still live");
    }

    #[tokio::test]
    async fn ipc_writer_exit_is_distinct_from_stream_credit_close() {
        let (tx, frames) = mpsc::channel::<crate::client::IpcWriterFrame>(8);
        let writer = SharedWriter::new(tx).with_stream_credit(true);
        let (_events, rx) = mpsc::channel(8);
        let mut stream = VeilStream::new(7, writer, rx);
        drop(frames);
        let error = stream.write_all(b"cannot write").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), WRITER_CLOSED);
    }
}
