//! Lossy wrappers for simulating unreliable links.
//!
//! Two wrappers are provided:
//!
//! * [`LossyStream`] — wraps `AsyncRead + AsyncWrite`; drops outgoing bytes
//!   with a configurable probability (for TCP-based transports).
//! * [`LossyLink`] — wraps `Arc<dyn LocalLink>`; drops `send` calls with a
//!   configurable probability (for mesh-layer `InMemoryLink`-based tests).

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use veil_util::lock;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    node::mesh::link::{LocalLink, SendResult},
    proto::mesh::MeshFrame,
};

// ── LossParams ────────────────────────────────────────────────────────────────

/// Parameters controlling simulated network impairments.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LossParams {
    /// Probability of dropping each outgoing write (0.0 = no loss, 1.0 = always drop).
    pub outgoing_drop_rate: f64,
}

impl Default for LossParams {
    fn default() -> Self {
        Self {
            outgoing_drop_rate: 0.0,
        }
    }
}

impl LossParams {
    /// No impairment.
    pub fn clean() -> Self {
        Self::default()
    }

    /// 50% outgoing packet loss.
    pub fn lossy_50() -> Self {
        Self {
            outgoing_drop_rate: 0.5,
        }
    }
}

// ── LossyStream ───────────────────────────────────────────────────────────────

/// A stream that can simulate packet loss and latency on outgoing data.
///
/// Reads are passed through unchanged. Writes may be silently dropped
/// (to simulate loss) or buffered until a latency delay expires (to simulate
/// a slow link). Both impairments use a simple XorShift RNG seeded from the
/// stream's memory address to avoid `rand` dependency in test code.
pub struct LossyStream<S> {
    inner: S,
    params: LossParams,
    rng: u64,
}

impl<S> LossyStream<S> {
    pub fn new(inner: S, params: LossParams) -> Self {
        // Seed RNG from current time (nanoseconds) — avoids unsafe pointer casts
        // and works correctly on all platforms including WASM and CHERI.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(1)
            .wrapping_add(1);
        Self {
            inner,
            params,
            rng: seed,
        }
    }

    /// Cheap XorShift64 pseudo-random u64.
    fn next_random(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    fn should_drop(&mut self) -> bool {
        if self.params.outgoing_drop_rate <= 0.0 {
            return false;
        }
        if self.params.outgoing_drop_rate >= 1.0 {
            return true;
        }
        let r = self.next_random();
        // Map [0,1): r / u64::MAX
        (r as f64) / (u64::MAX as f64) < self.params.outgoing_drop_rate
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LossyStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LossyStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.should_drop() {
            // Silently discard the write — pretend it succeeded.
            return Poll::Ready(Ok(buf.len()));
        }
        Pin::new(&mut me.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ── LossyLink ─────────────────────────────────────────────────────────────────

/// A [`LocalLink`] wrapper that drops `send` calls with probability `drop_rate`.
///
/// Reads (receives) are not affected — only outgoing frames are subject to loss.
/// Uses a simple XorShift64 RNG (no `rand` dependency) protected by a `Mutex`
/// so the wrapper is `Send + Sync`.
///
/// A dropped frame returns [`SendResult::Ok`] to the caller (silent loss), so
/// the sender does not see an error and does not disconnect.
///
/// # Example
///
/// ```ignore
/// let (base_link, inbox) = InMemoryLink::pair(node_id);
/// let lossy = LossyLink::new(Arc::new(base_link), 0.5, 42);
/// // ~50 % of frames sent through `lossy` will be silently dropped.
/// ```
pub struct LossyLink {
    inner: Arc<dyn LocalLink>,
    drop_rate: f64,
    rng: Mutex<u64>,
}

impl LossyLink {
    /// Wrap `inner` with `drop_rate` probability of silent frame loss.
    ///
    /// `seed` initialises the XorShift64 RNG; different seeds produce
    /// different drop patterns even at the same rate.
    pub fn new(inner: Arc<dyn LocalLink>, drop_rate: f64, seed: u64) -> Arc<Self> {
        Arc::new(Self {
            inner,
            drop_rate,
            rng: Mutex::new(seed.wrapping_add(1)),
        })
    }

    fn should_drop(&self) -> bool {
        if self.drop_rate <= 0.0 {
            return false;
        }
        if self.drop_rate >= 1.0 {
            return true;
        }
        let mut rng = lock!(self.rng);
        let mut x = *rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *rng = x;
        (x as f64) / (u64::MAX as f64) < self.drop_rate
    }
}

impl LocalLink for LossyLink {
    fn remote_node_id(&self) -> [u8; 32] {
        self.inner.remote_node_id()
    }

    fn send(&self, frame: &MeshFrame) -> SendResult {
        if self.should_drop() {
            return SendResult::Ok; // silently discard
        }
        self.inner.send(frame)
    }

    fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn clean_stream_passes_all_writes() {
        let (client, server) = tokio::io::duplex(1024);
        let mut lossy = LossyStream::new(client, LossParams::clean());
        let data = b"hello world";
        lossy.write_all(data).await.unwrap();
        drop(lossy);
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut server = server;
        server.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, data);
    }

    #[tokio::test]
    async fn always_drop_discards_data() {
        let (client, server) = tokio::io::duplex(1024);
        let mut lossy = LossyStream::new(
            client,
            LossParams {
                outgoing_drop_rate: 1.0,
            },
        );
        lossy.write_all(b"should be dropped").await.unwrap(); // "succeeds" but drops data
        drop(lossy);
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut server = server;
        // Read with timeout — should see only EOF (0 bytes written)
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            server.read_to_end(&mut buf),
        )
        .await;
        assert_eq!(buf.len(), 0, "all data was dropped");
    }

    #[test]
    fn should_drop_50_percent_on_average() {
        let params = LossParams::lossy_50();
        let mut ls = LossyStream::new(std::io::Cursor::new(vec![0u8; 0]), params);
        let trials = 10_000;
        let dropped: u32 = (0..trials).map(|_| ls.should_drop() as u32).sum();
        let rate = dropped as f64 / trials as f64;
        assert!(
            (rate - 0.5).abs() < 0.05,
            "drop rate {rate:.3} should be ~0.5"
        );
    }

    // ── LossyLink tests ───────────────────────────────────────────────────────

    use crate::{
        node::mesh::link::InMemoryLink,
        proto::mesh::{MeshFrame, RealmId},
    };

    fn mesh_frame() -> MeshFrame {
        MeshFrame::new(
            RealmId([0u8; 16]),
            [1u8; 32],
            [2u8; 32],
            4,
            b"loss-test".to_vec(),
        )
    }

    #[test]
    fn lossy_link_zero_drop_passes_all() {
        let (base, inbox) = InMemoryLink::pair([2u8; 32]);
        let lossy = LossyLink::new(Arc::new(base), 0.0, 1);
        for _ in 0..100 {
            assert_eq!(lossy.send(&mesh_frame()), SendResult::Ok);
        }
        assert_eq!(
            inbox.lock().unwrap().len(),
            100,
            "all frames must be delivered"
        );
    }

    #[test]
    fn lossy_link_full_drop_discards_all() {
        let (base, inbox) = InMemoryLink::pair([2u8; 32]);
        let lossy = LossyLink::new(Arc::new(base), 1.0, 1);
        for _ in 0..100 {
            // Returns Ok even though frames are dropped (silent loss).
            assert_eq!(lossy.send(&mesh_frame()), SendResult::Ok);
        }
        assert_eq!(
            inbox.lock().unwrap().len(),
            0,
            "all frames must be silently dropped"
        );
    }

    #[test]
    fn lossy_link_50_percent_drop_rate() {
        let (base, inbox) = InMemoryLink::pair([2u8; 32]);
        let lossy = LossyLink::new(Arc::new(base), 0.5, 12345);
        let trials = 10_000u32;
        for _ in 0..trials {
            lossy.send(&mesh_frame());
        }
        let delivered = inbox.lock().unwrap().len() as f64;
        let rate = delivered / trials as f64;
        assert!(
            (rate - 0.5).abs() < 0.05,
            "delivery rate {rate:.3} should be ~0.5"
        );
    }

    #[test]
    fn lossy_link_forwards_node_id_and_alive() {
        let (base, _inbox) = InMemoryLink::pair([7u8; 32]);
        let lossy = LossyLink::new(Arc::new(base), 0.0, 1);
        assert_eq!(lossy.remote_node_id(), [7u8; 32]);
        assert!(lossy.is_alive());
    }
}
