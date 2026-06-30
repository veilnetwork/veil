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
//! - PINNED CIRCUIT (`CircuitCells`, opt-in `VEIL_ONION_STREAM_CIRCUIT=1`): a
//!   build-once inbound stateful circuit to this node's published rendezvous relay
//!   plus lazy per-peer outbound circuits to each receiver's published R; cheap XOR
//!   `CircuitData` cells, no per-cell ECDH/signature, in-order, stable RTT. R
//!   splices each cell onto the peer's registered circuit. Still carries validation
//!   shortcuts (deterministic stream cookies + in-band sender id); needs the
//!   embedded node (in-process `NodeServices`).

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

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

/// Gate for the PINNED STATEFUL-CIRCUIT stream path.
///
/// Production-safe default is OFF: the stable datagram path remains the default
/// unless a deployment explicitly opts into the pinned circuit. Values:
///
/// - `1|true|yes|on|published|prod|production`: resolve published rendezvous ads
///   and build per-peer circuits to the receiver's R (normal path).
/// - `validation|legacy|min-routing`: old test-net shortcut where both endpoints
///   independently pick `min(routing)` as R.
///
/// Both peers must agree.
const CIRCUIT_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CircuitMode {
    PublishedRendezvous,
    ValidationMinRouting,
}

/// Whether/how to attempt the pinned-circuit backend (default OFF; opt in via env).
fn circuit_mode() -> Option<CircuitMode> {
    std::env::var(CIRCUIT_ENV)
        .ok()
        .and_then(|v| circuit_env_value_mode(&v))
}

fn circuit_env_value_mode(v: &str) -> Option<CircuitMode> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "published" | "prod" | "production" => {
            Some(CircuitMode::PublishedRendezvous)
        }
        "validation" | "legacy" | "min-routing" | "min_routing" => {
            Some(CircuitMode::ValidationMinRouting)
        }
        _ => None,
    }
}

/// Smaller MSS for the circuit path so the onion-stream cell + the
/// `[cookie 16][sender_node 32]` splice envelope fit one 384-B CircuitData cell.
const CIRCUIT_MSS: usize =
    veil_onion_stream::wire::MAX_CELL - COOKIE_LEN - 32 - veil_onion_stream::wire::DATA_OVERHEAD; // 318 B payload, exactly fills 382-B inner
const CIRCUIT_HOPS: usize = 2;
const CIRCUIT_REFRESH_AFTER: Duration = Duration::from_secs(120);
const CIRCUIT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(10);
const CIRCUIT_RETIRE_GRACE: Duration = Duration::from_secs(30);

/// Deterministic 16-byte stream cookie for a node — both ends derive the peer's
/// the same way (domain-separated app-id, distinct from the chat endpoint).
fn stream_cookie(node: &[u8; 32]) -> [u8; COOKIE_LEN] {
    // v2 leaves any pre-fix registration (whose random anti-squat key cannot be
    // reproduced after a hub restart) in a different relay-registry slot. Both
    // updated peers derive the same v2 cookie immediately; no 600 s TTL wait.
    let id = veil_app::address::app_id(node, STREAM_NAMESPACE, "stream-cookie-v2");
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
/// identity, so it rides in-band — the next production-anonymity item removes
/// this clear sender id).
struct CircuitCells {
    services: veil_node_runtime::NodeServices,
    me: [u8; 32],
    mode: CircuitMode,
    reg_kp: Arc<veil_crypto::GeneratedKeyPair>,
    epoch: Arc<AtomicU64>,
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
    /// Filled by the background open task once this node's receiving circuit is up.
    /// Validation mode also uses this single circuit for outbound sends.
    inbound_circuit: Arc<tokio::sync::Mutex<Option<Arc<veil_node_runtime::DataCircuit>>>>,
    /// Published-ad mode opens one outbound circuit per receiver R. Each circuit
    /// also registers our stream cookie at that R so ACKs can splice back.
    outbound_circuits: Arc<tokio::sync::Mutex<HashMap<[u8; 32], CircuitEntry>>>,
}

#[derive(Clone)]
struct CircuitEntry {
    circuit: Arc<veil_node_runtime::DataCircuit>,
    opened_at: Instant,
}

impl CellSender for CircuitCells {
    async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
        let Some(circuit) = self.circuit_for(dst.node).await? else {
            // Circuit not up yet — drop this cell; the ARQ/handshake RTO resends.
            return Ok(());
        };
        let cookie = stream_cookie(&dst.node);
        let mut env = Vec::with_capacity(COOKIE_LEN + 32 + cell.len());
        env.extend_from_slice(&cookie);
        env.extend_from_slice(&self.me);
        env.extend_from_slice(&cell);
        self.services
            .send_circuit_cell(&circuit, &env)
            .map_err(|e| io::Error::other(format!("circuit stream send: {e:?}")))
    }
}

impl CircuitCells {
    async fn circuit_for(
        &self,
        dst_node: [u8; 32],
    ) -> io::Result<Option<Arc<veil_node_runtime::DataCircuit>>> {
        match self.mode {
            CircuitMode::ValidationMinRouting => Ok(self.inbound_circuit.lock().await.clone()),
            CircuitMode::PublishedRendezvous => self.ensure_outbound_circuit(dst_node).await,
        }
    }

    async fn ensure_outbound_circuit(
        &self,
        dst_node: [u8; 32],
    ) -> io::Result<Option<Arc<veil_node_runtime::DataCircuit>>> {
        let now = Instant::now();
        if let Some(entry) = self.outbound_circuits.lock().await.get(&dst_node)
            && now.duration_since(entry.opened_at) < CIRCUIT_REFRESH_AFTER
        {
            return Ok(Some(Arc::clone(&entry.circuit)));
        }

        let (candidate, recv_rx) = self
            .services
            .open_stream_circuit_to_receiver_ad(
                dst_node,
                stream_cookie(&self.me),
                &self.reg_kp,
                &self.epoch,
                CIRCUIT_HOPS,
            )
            .await
            .map_err(|e| io::Error::other(format!("circuit stream open to receiver ad: {e:?}")))?;

        if !confirm_circuit(&candidate).await {
            self.services
                .close_data_circuit(candidate.origin_circuit_id());
            return Ok(None);
        }

        spawn_circuit_feed(recv_rx, self.in_tx.clone());
        let candidate = Arc::new(candidate);
        let retired = self.outbound_circuits.lock().await.insert(
            dst_node,
            CircuitEntry {
                circuit: Arc::clone(&candidate),
                opened_at: Instant::now(),
            },
        );
        retire_circuit_later(&self.services, retired.map(|r| r.circuit));
        Ok(Some(candidate))
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
fn spawn_anon_feed(
    mut msg_rx: mpsc::Receiver<IncomingMessage>,
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
) {
    tokio::spawn(async move {
        while let Some(msg) = msg_rx.recv().await {
            // The authenticated anonymous transport delivers src_app_id = [0;32]
            // (no sender app id) — DERIVE the peer's stream endpoint app from its
            // node id (the deterministic `app_id(node, ns, name)` both ends bind).
            let app = veil_app::address::app_id(&msg.src_node_id, STREAM_NAMESPACE, STREAM_NAME);
            let addr = Addr {
                node: msg.src_node_id,
                app,
            };
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

        // Try the pinned-circuit backend (explicit opt-in) + embedded; else datagram.
        let circuit_cells = if let Some(mode) = circuit_mode() {
            try_open_circuit(me, in_tx.clone(), mode)
        } else {
            None
        };

        let (cells, mss) = match circuit_cells {
            Some(c) => (HubCells::Circuit(c), CIRCUIT_MSS),
            None => {
                // Datagram path (default / fallback): feed inbound from msg_rx.
                spawn_anon_feed(msg_rx, in_tx);
                (
                    HubCells::Anon(AnonCells {
                        sender: sender.clone(),
                    }),
                    veil_onion_stream::MSS,
                )
            }
        };
        // Surface which backend engaged (desktop: stderr; phone: logcat).
        let backend = match &cells {
            HubCells::Circuit(c) => match c.mode {
                CircuitMode::PublishedRendezvous => {
                    "onion-stream: circuit mode — published rendezvous ads"
                }
                CircuitMode::ValidationMinRouting => {
                    "onion-stream: circuit mode — validation min-routing"
                }
            },
            HubCells::Anon(_) => "onion-stream: datagram path (no embedded node)",
        };
        diag(backend);

        // The onion RTT is SECONDS and highly variable; floor the RTO so it only
        // fires on REAL loss, pace the sender, and cap the window below the path's
        // standing-queue-drop onset (see the device-debug saga in memory).
        //
        // recv_window IS the throughput cap: pacing spreads `min(cwnd, rwnd)` over
        // one RTT, so steady-state ≈ 2·rwnd/srtt. On the in-order, LOSS-FREE pinned
        // circuit the window is the SOLE limiter — a 37 MB device transfer ran with
        // cwnd→27 MB and ZERO retransmits, capped at 134 KB/s = 2·256 KB / 3.8 s.
        // Widen it ~12× there to fill the multi-second-RTT pipe (targets ~1.5 MB/s;
        // cwnd + slow-start still find the real ceiling if the relay can't sustain
        // it). The LOSSY datagram path keeps the small window — a big one there
        // re-arms the slow-start-overshoot relay-queue drop the saga fought.
        let recv_window = match &cells {
            // Bound standing data to a little over 3x the measured clean-path
            // BDP (~225 KiB at 1.5 MiB/s × 150 ms). The former 3–4 MiB window
            // let a fixed-rate pacer build a multi-megabyte relay queue before
            // end-to-end loss became visible, producing tens of thousands of
            // correlated drops and an RTO collapse.
            HubCells::Circuit(_) => 896 * 1024,
            HubCells::Anon(_) => (1024 * mss) as u32,
        };
        let cfg = Config {
            mss,
            init_rto_ms: 12_000,
            min_rto_ms: 10_000,
            max_rto_ms: 60_000,
            handshake_rto_ms: 6_000,
            max_retransmits: 15,
            recv_window,
            init_cwnd: (32 * mss) as u32,
            max_pacing_batch: if matches!(&cells, HubCells::Circuit(_)) {
                24
            } else {
                4
            },
            // Every ACK consumes the same fixed-size circuit cell as DATA.
            // The pinned path is loss-free/in-order, so cumulative ACKs can be
            // thinned without delaying loss signalling: gaps and duplicates
            // still ACK immediately, and the timer bounds tail latency.
            ack_every: if matches!(&cells, HubCells::Circuit(_)) {
                32
            } else {
                2
            },
            ack_delay_ms: 5,
            ..Config::default()
        };
        let mux = Arc::new(StreamMux::new(me, Arc::new(cells), in_rx, cfg));
        AnonStreamHub {
            mux,
            _sender: sender,
        }
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

/// Open the pinned inbound stream circuit, register this node's cookie, and spawn
/// the inbound feed that turns `[sender_node 32][cell]` return cells into
/// (Addr, cell). Published mode uses this node's advertised rendezvous R;
/// validation mode uses the old auto-agreed test-net R. `None` (→ datagram
/// fallback) if not embedded.
fn try_open_circuit(
    me: [u8; 32],
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
    mode: CircuitMode,
) -> Option<CircuitCells> {
    // Only available with an in-process embedded node; else datagram path.
    let services = veil_node_runtime::embedded_services()?;
    let cookie = stream_cookie(&me);
    let inbound_circuit: Arc<tokio::sync::Mutex<Option<Arc<veil_node_runtime::DataCircuit>>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let outbound_circuits = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let reg_kp = Arc::new(services.onion_stream_registration_keypair());
    let epoch = Arc::new(AtomicU64::new(0));
    // Open the circuit to R in the BACKGROUND (async relay-dir fetch + CircuitBuild
    // + ACK). Proactive (not lazy-on-send) so the RECEIVER is ready to take inbound
    // splices before it ever sends. Cells before it's up drop; the ARQ resends.
    //
    // A relay circuit is idle-GC'd after 300 s. Keeping this handle forever made
    // the first transfer after five idle minutes black-hole: the local origin and
    // CellSender still existed, but R no longer had the forward lookup. Refresh at
    // 120 s, wait for CircuitBuilt before swapping, and leave the old return sink
    // alive briefly so in-flight cells from the previous path can drain.
    let circuit_slot = Arc::clone(&inbound_circuit);
    let services_bg = services.clone();
    let reg_kp_bg = Arc::clone(&reg_kp);
    let epoch_bg = Arc::clone(&epoch);
    let in_tx_bg = in_tx.clone();
    tokio::spawn(async move {
        // The proactive open fires at hub creation — which, on the RECEIVER, is the
        // accept loop starting right after node-arm, BEFORE any relay session is up
        // (observed on-device: connected=0 routing=3 -> NoRelays). warm only works
        // over connected relays, so RETRY with backoff until sessions establish and
        // a terminus R resolves. Cheap while connected=0 (the empty warm returns at
        // once); the loop ends on first success and the task dies with the runtime
        // on app exit, so an indefinite wait through a long pre-unlock idle is fine.
        let mut backoff_ms = 1_500u64;
        let mut attempt = 0u32;
        let mut generation = 0u64;
        loop {
            attempt += 1;
            let opened = match mode {
                CircuitMode::PublishedRendezvous => {
                    services_bg
                        .open_stream_circuit_to_receiver_ad(
                            me,
                            cookie,
                            &reg_kp_bg,
                            &epoch_bg,
                            CIRCUIT_HOPS,
                        )
                        .await
                }
                CircuitMode::ValidationMinRouting => {
                    services_bg
                        .open_stream_circuit_auto(cookie, &reg_kp_bg, &epoch_bg)
                        .await
                }
            };
            let (candidate, recv_rx) = match opened {
                Ok(pair) => pair,
                Err(e) => {
                    if attempt == 1 || attempt % 15 == 0 {
                        diag(&format!(
                            "onion-stream: circuit open retry #{attempt}: {e:?}"
                        ));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = backoff_ms.saturating_mul(2).min(8_000);
                    continue;
                }
            };

            // open_stream_circuit_auto is intentionally optimistic: it returns
            // once CircuitBuild is queued. Do not publish the handle until R has
            // accepted the cookie registration and CircuitBuilt came back.
            if !confirm_circuit(&candidate).await {
                services_bg.close_data_circuit(candidate.origin_circuit_id());
                if attempt == 1 || attempt % 15 == 0 {
                    diag(&format!(
                        "onion-stream: circuit confirmation timed out on attempt #{attempt}"
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2).min(8_000);
                continue;
            }

            // Inbound feed: each return cell is `[sender_node 32][stream cell]`.
            // Start it before swapping so cells arriving immediately after the
            // confirmation are already consumed from the bounded return queue.
            spawn_circuit_feed(recv_rx, in_tx_bg.clone());

            let retired = circuit_slot.lock().await.replace(Arc::new(candidate));
            generation += 1;
            backoff_ms = 1_500;
            if generation == 1 {
                diag(&format!(
                    "onion-stream: PINNED CIRCUIT opened ({mode:?}, after {attempt} tries)"
                ));
            } else {
                diag(&format!(
                    "onion-stream: PINNED CIRCUIT refreshed ({mode:?}, generation {generation})"
                ));
            }

            retire_circuit_later(&services_bg, retired);

            tokio::time::sleep(CIRCUIT_REFRESH_AFTER).await;
        }
    });
    Some(CircuitCells {
        services,
        me,
        mode,
        reg_kp,
        epoch,
        in_tx,
        inbound_circuit,
        outbound_circuits,
    })
}

async fn confirm_circuit(circuit: &veil_node_runtime::DataCircuit) -> bool {
    let confirm_deadline = tokio::time::Instant::now() + CIRCUIT_CONFIRM_TIMEOUT;
    while !circuit.is_confirmed() && tokio::time::Instant::now() < confirm_deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    circuit.is_confirmed()
}

fn spawn_circuit_feed(mut recv_rx: mpsc::Receiver<Vec<u8>>, in_tx: mpsc::Sender<(Addr, Vec<u8>)>) {
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
}

fn retire_circuit_later(
    services: &veil_node_runtime::NodeServices,
    circuit: Option<Arc<veil_node_runtime::DataCircuit>>,
) {
    if let Some(old) = circuit {
        let old_id = old.origin_circuit_id();
        let retire_services = services.clone();
        tokio::spawn(async move {
            tokio::time::sleep(CIRCUIT_RETIRE_GRACE).await;
            retire_services.close_data_circuit(old_id);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{CircuitMode, circuit_env_value_mode};

    #[test]
    fn circuit_env_is_strict_opt_in() {
        for value in [
            "1",
            "true",
            "TRUE",
            " yes ",
            "On",
            "published",
            "prod",
            "production",
        ] {
            assert_eq!(
                circuit_env_value_mode(value),
                Some(CircuitMode::PublishedRendezvous),
                "{value:?} should opt into published-rendezvous circuit mode"
            );
        }
        for value in ["validation", "legacy", "min-routing", "min_routing"] {
            assert_eq!(
                circuit_env_value_mode(value),
                Some(CircuitMode::ValidationMinRouting),
                "{value:?} should opt into validation circuit mode"
            );
        }
        for value in ["", "0", "false", "no", "off", "anything-else"] {
            assert!(
                circuit_env_value_mode(value).is_none(),
                "{value:?} should leave circuit mode off"
            );
        }
    }
}
