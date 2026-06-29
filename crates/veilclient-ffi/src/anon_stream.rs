//! Anonymous reliable byte-streams over veil's onion transport.
//!
//! The fire-and-forget anonymous DATAGRAM path has no congestion control, so a
//! fast sender outruns the relays' bounded TX queues and ~80 % of a bulk
//! transfer is dropped (the ~200 KB/s file-transfer wall). [`AnonStreamHub`]
//! fixes that by running `veil-onion-stream` (end-to-end ARQ + AIMD congestion
//! control) OVER the same anonymous-authenticated send/recv: it binds one
//! dedicated stream endpoint and multiplexes [`OnionStream`]s over it, keyed by
//! `(peer_node, stream_id)`. The crypto cost per cell is exactly today's
//! anonymous send; the win is the CC clocking the sender to the bottleneck
//! relay instead of blasting.

use std::io;
use std::sync::Arc;

use tokio::sync::mpsc;
use veil_onion_stream::{Addr, CellSender, Config, OnionStream, StreamMux};
use veilclient::{AppSender, IncomingMessage};

/// Well-known endpoint the onion-stream cells ride (distinct from the chat
/// inbox). Both peers bind it; a peer's app id is `deriveAppId(peer_node,
/// STREAM_NAMESPACE, STREAM_NAME)` — the caller supplies it (mirrors how the
/// direct `veil_stream_open` takes `dst_app_id`).
pub const STREAM_NAMESPACE: &str = "xveil";
pub const STREAM_NAME: &str = "onion-stream";
pub const STREAM_ENDPOINT_ID: u32 = 12;

/// [`CellSender`] over `send_anonymous_authenticated` — the only veil-specific
/// seam the generic mux needs.
struct AnonCells {
    sender: Arc<AppSender>,
}

impl CellSender for AnonCells {
    async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
        self.sender
            .send_anonymous_authenticated(dst.node, dst.app, STREAM_ENDPOINT_ID, &cell)
            .await
            .map_err(|e| io::Error::other(format!("anon stream send: {e}")))
    }
}

/// Node-wide multiplexer for anonymous streams (one per node, built lazily on
/// the first open/accept). Keeps the stream endpoint bound for its lifetime.
pub struct AnonStreamHub {
    mux: Arc<StreamMux<AnonCells>>,
    _sender: Arc<AppSender>,
}

impl AnonStreamHub {
    /// Build over a freshly-bound stream endpoint's `sender` + raw inbound
    /// datagram channel `msg_rx` (from `AppReceiver::into_parts`). `me` = this
    /// node id. MUST be called inside the tokio runtime (spawns the inbound
    /// feed + the mux demux).
    pub fn new(me: [u8; 32], sender: AppSender, mut msg_rx: mpsc::Receiver<IncomingMessage>) -> Self {
        let sender = Arc::new(sender);
        // Inbound feed: authenticated anonymous datagrams on the stream endpoint
        // → (Addr{src_node, src_app}, cell). The src address is the peer's stream
        // endpoint, which is exactly where the accept side sends its returns.
        let (in_tx, in_rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            while let Some(msg) = msg_rx.recv().await {
                // The authenticated anonymous transport delivers src_app_id =
                // [0;32] (it carries no sender app id — service_tasks.rs). So
                // DERIVE the peer's onion-stream endpoint app from its node id —
                // it's the deterministic `app_id(node, ns, name)` both ends bind
                // under. Using the zeroed src_app_id would address returns to an
                // unbound endpoint ("no app bound to endpoint_id=12" → dropped).
                let app = veil_app::address::app_id(
                    &msg.src_node_id,
                    STREAM_NAMESPACE,
                    STREAM_NAME,
                );
                let addr = Addr { node: msg.src_node_id, app };
                if in_tx.send((addr, msg.data)).await.is_err() {
                    break;
                }
            }
        });
        let cells = Arc::new(AnonCells { sender: sender.clone() });
        // The onion RTT is SECONDS and highly variable (relay queues), so the
        // ms-scale defaults fire the RTO long before an ACK can return → every
        // cell looks "lost" → cwnd collapses to 1 + the RTO backs off to its cap
        // → a ~1-cell-per-30s crawl. Start the RTO conservative AND floor it so
        // the Jacobson-Karels estimator can warm up from real samples (and so a
        // latency spike can't mis-fire), and widen the window to keep enough in
        // flight to fill the high-RTT pipe.
        let mss = veil_onion_stream::MSS as u32;
        let cfg = Config {
            // The onion RTT is several seconds; floor the RTO at 10 s so it only
            // fires on REAL loss, never before an ACK can return (the SACK-aware
            // retransmit + fast-retransmit handle actual loss faster than this).
            init_rto_ms: 12_000,
            min_rto_ms: 10_000,
            max_rto_ms: 60_000,
            handshake_rto_ms: 6_000,
            max_retransmits: 15,
            // Window ≥ bandwidth·RTT so the pipe can fill: ~3 MB covers ~228 KB/s
            // at ~13 s RTT. cwnd slow-starts up to it (capped by real loss).
            recv_window: 8192 * mss,
            init_cwnd: 32 * mss,
            ..Config::default()
        };
        let mux = Arc::new(StreamMux::new(me, cells, in_rx, cfg));
        AnonStreamHub { mux, _sender: sender }
    }

    /// Open a stream to a peer (`dst` = its node id + stream-endpoint app id).
    pub fn open(&self, dst: Addr) -> OnionStream {
        self.mux.open(dst)
    }

    /// Accept the next inbound stream, or `None` if the transport closed.
    pub async fn accept(&self) -> Option<(OnionStream, Addr)> {
        self.mux.accept().await
    }
}
