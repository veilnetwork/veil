//! Anonymous reliable byte-streams over veil's onion transport.
//!
//! The fire-and-forget anonymous DATAGRAM path has no congestion control, so a
//! fast sender outruns the relays' bounded TX queues and ~80 % of a bulk
//! transfer is dropped (the ~200 KB/s file-transfer wall). [`AnonStreamHub`]
//! fixes that by running `veil-onion-stream` (end-to-end ARQ + AIMD congestion
//! control) over a [`CellSender`]. Two backends:
//!
//! - DEFAULT (`AnonCells`): each cell rides `send_anonymous_authenticated` — a
//!   FRESH onion circuit + per-cell signature/verify. Reliable, but the per-cell
//!   circuit build inflates the RTT and the varying paths cause reordering →
//!   spurious recoveries → ~42 KB/s (device-measured).
//! - PINNED CIRCUIT (`CircuitCells`, opt-in `VEIL_ONION_STREAM_CIRCUIT=1`): one
//!   build-once stateful onion circuit to a rendezvous relay R; cheap XOR
//!   `CircuitData` cells, no per-cell ECDH/signature, in-order, stable RTT. R
//!   splices each cell onto the peer's registered circuit. Validation-grade
//!   shortcut (deterministic cookies + auto-agreed R + in-band sender id); needs
//!   the embedded node (in-process `NodeServices`).

use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::sync::mpsc;
use veil_anonymity::circuit_register::COOKIE_LEN;
use veil_onion_stream::{Addr, CellSender, Config, OnionStream, StreamMux};
use veilclient::{AppSender, IncomingMessage};

/// Emit a one-line diagnostic that NEVER panics. `eprintln!` PANICS if the
/// underlying stderr write fails — and under `flutter run` the desktop app's
/// stderr is a pipe that can break, so an `eprintln!` mid-stream panicked and,
/// unwinding across the `extern "C"` FFI boundary, aborted the whole process
/// (the observed silent desktop crash). Write directly and swallow any error;
/// mirror to logcat on Android (the node's tracing logger doesn't reach it).
fn diag(msg: &str) {
    #[cfg(target_os = "android")]
    log::warn!("{msg}");
    #[cfg(not(target_os = "android"))]
    {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "{msg}");
    }
}

/// Well-known endpoint the onion-stream cells ride (distinct from the chat
/// inbox). Both peers bind it; a peer's app id is `deriveAppId(peer_node,
/// STREAM_NAMESPACE, STREAM_NAME)` — the caller supplies it (mirrors how the
/// direct `veil_stream_open` takes `dst_app_id`).
pub const STREAM_NAMESPACE: &str = "xveil";
pub const STREAM_NAME: &str = "onion-stream";
pub const STREAM_ENDPOINT_ID: u32 = 12;

/// Gate for the PINNED STATEFUL-CIRCUIT stream path (Phase 1d). TEST-BUILD
/// DEFAULT = ON (env vars can't be set on the mobile app, and on open-failure we
/// fall back to the datagram path anyway). Set `VEIL_ONION_STREAM_CIRCUIT=0` to
/// force the datagram path (e.g. on desktop). Both peers must agree (same build).
/// FOR MERGE: flip the default back to opt-in.
const CIRCUIT_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT";

/// Whether to attempt the pinned-circuit backend (default ON; `=0` forces off).
fn circuit_enabled() -> bool {
    std::env::var(CIRCUIT_ENV).map(|v| v != "0").unwrap_or(true)
}

/// Smaller MSS for the circuit path so the onion-stream cell + the
/// `[cookie 16][sender_node 32]` splice envelope fit one 384-B CircuitData cell.
const CIRCUIT_MSS: usize = 256;

/// Deterministic 16-byte stream cookie for a node — both ends derive the peer's
/// the same way (domain-separated app-id, distinct from the chat endpoint).
fn stream_cookie(node: &[u8; 32]) -> [u8; COOKIE_LEN] {
    let id = veil_app::address::app_id(node, STREAM_NAMESPACE, "stream-cookie");
    let mut c = [0u8; COOKIE_LEN];
    c.copy_from_slice(&id[..COOKIE_LEN]);
    c
}

/// [`CellSender`] over `send_anonymous_authenticated` — the default datagram path.
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

/// [`CellSender`] over a PINNED stateful onion circuit to a rendezvous relay R.
/// Each cell goes as `[target_cookie 16][my_node 32][stream cell]`: R strips the
/// cookie and splices `[my_node][cell]` down the target's registered circuit; the
/// target reads `my_node` to demux the peer (the splice strips the sender's
/// identity, so it rides in-band — acceptable on the trusted test net).
struct CircuitCells {
    services: veil_node_runtime::NodeServices,
    me: [u8; 32],
    /// Filled by the background open task once the circuit to R is up. Sends
    /// before then are dropped (the ARQ / handshake RTO retransmits).
    circuit: Arc<tokio::sync::Mutex<Option<veil_node_runtime::DataCircuit>>>,
}

impl CellSender for CircuitCells {
    async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
        let guard = self.circuit.lock().await;
        let Some(circuit) = guard.as_ref() else {
            // Circuit not up yet — drop this cell; the ARQ/handshake RTO resends.
            return Ok(());
        };
        let cookie = stream_cookie(&dst.node);
        let mut env = Vec::with_capacity(COOKIE_LEN + 32 + cell.len());
        env.extend_from_slice(&cookie);
        env.extend_from_slice(&self.me);
        env.extend_from_slice(&cell);
        self.services
            .send_circuit_cell(circuit, &env)
            .map_err(|e| io::Error::other(format!("circuit stream send: {e:?}")))
    }
}

/// One of the two [`CellSender`] backends (gated at hub build).
enum HubCells {
    Anon(AnonCells),
    Circuit(CircuitCells),
}

impl CellSender for HubCells {
    async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
        match self {
            HubCells::Anon(c) => c.send(dst, cell).await,
            HubCells::Circuit(c) => c.send(dst, cell).await,
        }
    }
}

/// Inbound feed for the datagram path: authenticated anonymous datagrams on the
/// stream endpoint → (Addr{src_node, derived_app}, cell).
fn spawn_anon_feed(mut msg_rx: mpsc::Receiver<IncomingMessage>, in_tx: mpsc::Sender<(Addr, Vec<u8>)>) {
    tokio::spawn(async move {
        while let Some(msg) = msg_rx.recv().await {
            // The authenticated anonymous transport delivers src_app_id = [0;32]
            // (no sender app id) — DERIVE the peer's stream endpoint app from its
            // node id (the deterministic `app_id(node, ns, name)` both ends bind).
            let app = veil_app::address::app_id(&msg.src_node_id, STREAM_NAMESPACE, STREAM_NAME);
            let addr = Addr { node: msg.src_node_id, app };
            if in_tx.send((addr, msg.data)).await.is_err() {
                break;
            }
        }
    });
}

/// Node-wide multiplexer for anonymous streams (one per node, built lazily on
/// the first open/accept). Keeps the stream endpoint bound for its lifetime.
pub struct AnonStreamHub {
    mux: Arc<StreamMux<HubCells>>,
    _sender: Arc<AppSender>,
}

impl AnonStreamHub {
    /// Build over a freshly-bound stream endpoint's `sender` + raw inbound
    /// datagram channel `msg_rx`. `me` = this node id. MUST be called inside the
    /// tokio runtime. Opts into the pinned-circuit backend when
    /// `VEIL_ONION_STREAM_CIRCUIT` is set AND an embedded node is present AND a
    /// rendezvous relay is resolvable; otherwise the datagram path (no regression).
    pub fn new(me: [u8; 32], sender: AppSender, msg_rx: mpsc::Receiver<IncomingMessage>) -> Self {
        let sender = Arc::new(sender);
        let (in_tx, in_rx) = mpsc::channel(1024);

        // Try the pinned-circuit backend (default on) + embedded; else datagram.
        let circuit_cells = if circuit_enabled() {
            try_open_circuit(me, in_tx.clone())
        } else {
            None
        };

        let (cells, mss) = match circuit_cells {
            Some(c) => (HubCells::Circuit(c), CIRCUIT_MSS),
            None => {
                // Datagram path (default / fallback): feed inbound from msg_rx.
                spawn_anon_feed(msg_rx, in_tx);
                (HubCells::Anon(AnonCells { sender: sender.clone() }), veil_onion_stream::MSS)
            }
        };
        // Surface which backend engaged (desktop: stderr; phone: logcat).
        let backend = match &cells {
            HubCells::Circuit(_) => "onion-stream: circuit mode — opening R in background",
            HubCells::Anon(_) => "onion-stream: datagram path (no embedded node)",
        };
        diag(backend);

        // The onion RTT is SECONDS and highly variable; floor the RTO so it only
        // fires on REAL loss, pace the sender, and cap the window below the path's
        // standing-queue-drop onset (see the device-debug saga in memory).
        let cfg = Config {
            mss,
            init_rto_ms: 12_000,
            min_rto_ms: 10_000,
            max_rto_ms: 60_000,
            handshake_rto_ms: 6_000,
            max_retransmits: 15,
            recv_window: (1024 * mss) as u32,
            init_cwnd: (32 * mss) as u32,
            ..Config::default()
        };
        let mux = Arc::new(StreamMux::new(me, Arc::new(cells), in_rx, cfg));
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

/// Open the pinned stream circuit to an auto-agreed R, register this node's
/// cookie, and spawn the inbound feed that turns `[sender_node 32][cell]` return
/// cells into (Addr, cell). `None` (→ datagram fallback) if not embedded or no
/// relay is resolvable yet.
fn try_open_circuit(me: [u8; 32], in_tx: mpsc::Sender<(Addr, Vec<u8>)>) -> Option<CircuitCells> {
    // Only available with an in-process embedded node; else datagram path.
    let services = veil_node_runtime::embedded_services()?;
    let cookie = stream_cookie(&me);
    let circuit: Arc<tokio::sync::Mutex<Option<veil_node_runtime::DataCircuit>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    // Open the circuit to R in the BACKGROUND (async relay-dir fetch + CircuitBuild
    // + ACK). Proactive (not lazy-on-send) so the RECEIVER is ready to take inbound
    // splices before it ever sends. Cells before it's up drop; the ARQ resends.
    let circuit_slot = Arc::clone(&circuit);
    let services_bg = services.clone();
    tokio::spawn(async move {
        let reg_kp = veil_crypto::generate_keypair(veil_types::SignatureAlgorithm::Ed25519);
        let epoch = AtomicU64::new(0);
        // The proactive open fires at hub creation — which, on the RECEIVER, is the
        // accept loop starting right after node-arm, BEFORE any relay session is up
        // (observed on-device: connected=0 routing=3 -> NoRelays). warm only works
        // over connected relays, so RETRY with backoff until sessions establish and
        // a terminus R resolves. Cheap while connected=0 (the empty warm returns at
        // once); the loop ends on first success and the task dies with the runtime
        // on app exit, so an indefinite wait through a long pre-unlock idle is fine.
        let mut backoff_ms = 1_500u64;
        let mut attempt = 0u32;
        let (circ, mut recv_rx) = loop {
            attempt += 1;
            match services_bg
                .open_stream_circuit_auto(cookie, &reg_kp, &epoch)
                .await
            {
                Ok(pair) => break pair,
                Err(e) => {
                    if attempt == 1 || attempt % 15 == 0 {
                        diag(&format!("onion-stream: circuit open retry #{attempt}: {e:?}"));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = backoff_ms.saturating_mul(2).min(8_000);
                }
            }
        };
        // Inbound feed: each return cell is `[sender_node 32][stream cell]`.
        tokio::spawn(async move {
            while let Some(framed) = recv_rx.recv().await {
                if framed.len() < 32 {
                    continue;
                }
                let mut node = [0u8; 32];
                node.copy_from_slice(&framed[..32]);
                let app = veil_app::address::app_id(&node, STREAM_NAMESPACE, STREAM_NAME);
                let cell = framed[32..].to_vec();
                if in_tx.send((Addr { node, app }, cell)).await.is_err() {
                    break;
                }
            }
        });
        *circuit_slot.lock().await = Some(circ);
        diag(&format!("onion-stream: PINNED CIRCUIT opened (after {attempt} tries)"));
    });
    Some(CircuitCells { services, me, circuit })
}
