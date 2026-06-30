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
//!   splices each cell onto the peer's registered circuit. Published mode hides
//!   the sender node id from R behind an opaque per-circuit tag plus encrypted
//!   handshake intro; validation mode keeps the old clear sender-id shortcut.
//!   Needs the embedded node (in-process `NodeServices`).

use std::collections::HashMap;
use std::io;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use tokio::sync::mpsc;
use veil_anonymity::circuit_register::COOKIE_LEN;
use veil_onion_stream::wire::Frame;
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
/// unless a deployment explicitly opts into the pinned circuit. On Android,
/// where process env is not normally injectable, the same values are also read
/// from system property `debug.veil.onion_stream_circuit`. Values:
///
/// - `1|true|yes|on|published|prod|production`: resolve published rendezvous ads
///   and build per-peer circuits to the receiver's R (normal path).
/// - `validation|legacy|min-routing`: old test-net shortcut where both endpoints
///   independently pick `min(routing)` as R.
///
/// Both peers must agree.
const CIRCUIT_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT";
#[cfg(target_os = "android")]
const ANDROID_CIRCUIT_PROP: &str = "debug.veil.onion_stream_circuit";

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
        .or_else(android_circuit_property_mode)
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

#[cfg(not(target_os = "android"))]
fn android_circuit_property_mode() -> Option<CircuitMode> {
    None
}

#[cfg(target_os = "android")]
fn android_circuit_property_mode() -> Option<CircuitMode> {
    use std::ffi::{CStr, CString};

    unsafe extern "C" {
        fn __system_property_get(
            name: *const libc::c_char,
            value: *mut libc::c_char,
        ) -> libc::c_int;
    }

    let name = CString::new(ANDROID_CIRCUIT_PROP).ok()?;
    // Android PROP_VALUE_MAX is 92 including NUL. libc does not expose it on all
    // targets, so keep the platform constant local.
    let mut value = [0 as libc::c_char; 92];
    let len = unsafe { __system_property_get(name.as_ptr(), value.as_mut_ptr()) };
    if len <= 0 {
        return None;
    }
    let value = unsafe { CStr::from_ptr(value.as_ptr()) }.to_string_lossy();
    circuit_env_value_mode(&value)
}

/// Smaller MSS for the circuit path so the onion-stream cell + the
/// `[cookie 16][peer_tag 32]` splice envelope fit one 384-B CircuitData cell.
const CIRCUIT_PEER_TAG_LEN: usize = 32;
const CIRCUIT_MSS: usize = veil_onion_stream::wire::MAX_CELL
    - COOKIE_LEN
    - CIRCUIT_PEER_TAG_LEN
    - veil_onion_stream::wire::DATA_OVERHEAD; // 318 B payload, exactly fills 382-B inner
const CIRCUIT_INTRO_MARKER: u8 = 0xA7;
const CIRCUIT_INTRO_PLAINTEXT_MAGIC: &[u8; 16] = b"xveil-stream-v1!";
const CIRCUIT_INTRO_PLAINTEXT_LEN: usize = 16 + CIRCUIT_PEER_TAG_LEN + 32;
const CIRCUIT_INTRO_LEN: usize =
    veil_anonymity::rendezvous::INTRODUCE_OVERHEAD + CIRCUIT_INTRO_PLAINTEXT_LEN;
const CIRCUIT_HOPS: usize = 2;
const CIRCUIT_IDLE_REFRESH_AFTER: Duration = Duration::from_secs(45);
// A long-lived outbound circuit can black-hole after a bulk stream RTOs. The
// content layer then opens a fresh stream and sends SYNs, but idle-based refresh
// alone keeps reusing the same stale circuit because every retry updates
// `last_used`. On a new stream handshake, rotate an old circuit if it has not
// carried real DATA/ACK traffic recently. This avoids mid-stream timed rotation
// while making resume retries pick a fresh rendezvous path quickly.
const CIRCUIT_HANDSHAKE_REOPEN_AFTER: Duration = Duration::from_secs(15);
const CIRCUIT_PUBLISHED_RELAY_EXPAND_AFTER: Duration = Duration::from_secs(5);
const CIRCUIT_REFRESH_POLL: Duration = Duration::from_secs(5);
const CIRCUIT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(10);
// Existing streams may still be using the previous published rendezvous relay
// for their ACK path after a refresh. Keep the old circuit/registration around
// long enough for a multi-megabyte transfer to drain instead of black-holing the
// in-flight stream midway through the file.
const CIRCUIT_RETIRE_GRACE: Duration = Duration::from_secs(600);

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

fn random_peer_tag() -> [u8; CIRCUIT_PEER_TAG_LEN] {
    let mut tag = [0u8; CIRCUIT_PEER_TAG_LEN];
    OsRng.fill_bytes(&mut tag);
    tag
}

fn stream_peer_intro_plaintext(
    sender_node: &[u8; 32],
    peer_tag: &[u8; CIRCUIT_PEER_TAG_LEN],
) -> [u8; CIRCUIT_INTRO_PLAINTEXT_LEN] {
    let mut out = [0u8; CIRCUIT_INTRO_PLAINTEXT_LEN];
    out[..16].copy_from_slice(CIRCUIT_INTRO_PLAINTEXT_MAGIC);
    out[16..16 + CIRCUIT_PEER_TAG_LEN].copy_from_slice(peer_tag);
    out[16 + CIRCUIT_PEER_TAG_LEN..].copy_from_slice(sender_node);
    out
}

fn parse_stream_peer_intro_plaintext(
    peer_tag: &[u8; CIRCUIT_PEER_TAG_LEN],
    plaintext: &[u8],
) -> Option<[u8; 32]> {
    if plaintext.len() != CIRCUIT_INTRO_PLAINTEXT_LEN {
        return None;
    }
    if &plaintext[..16] != CIRCUIT_INTRO_PLAINTEXT_MAGIC {
        return None;
    }
    if &plaintext[16..16 + CIRCUIT_PEER_TAG_LEN] != peer_tag {
        return None;
    }
    let mut node = [0u8; 32];
    node.copy_from_slice(&plaintext[16 + CIRCUIT_PEER_TAG_LEN..]);
    Some(node)
}

fn seal_stream_peer_intro(
    sender_node: &[u8; 32],
    peer_tag: &[u8; CIRCUIT_PEER_TAG_LEN],
    receiver_x25519_pk: &[u8; 32],
) -> io::Result<Vec<u8>> {
    let plaintext = stream_peer_intro_plaintext(sender_node, peer_tag);
    let sealed = veil_anonymity::rendezvous::encrypt_introduce(&plaintext, receiver_x25519_pk)
        .map_err(|e| io::Error::other(format!("seal stream peer intro: {e:?}")))?;
    if sealed.len() != CIRCUIT_INTRO_LEN {
        return Err(io::Error::other(format!(
            "sealed stream peer intro length {} != {CIRCUIT_INTRO_LEN}",
            sealed.len()
        )));
    }
    Ok(sealed)
}

fn open_stream_peer_intro(
    services: &veil_node_runtime::NodeServices,
    peer_tag: &[u8; CIRCUIT_PEER_TAG_LEN],
    sealed: &[u8],
) -> Option<[u8; 32]> {
    if sealed.len() != CIRCUIT_INTRO_LEN {
        return None;
    }
    let plaintext = services.decrypt_stream_peer_intro(sealed)?;
    parse_stream_peer_intro_plaintext(peer_tag, &plaintext)
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
/// Validation cells go as `[target_cookie 16][my_node 32][stream cell]`. In
/// published mode the relay sees only `[target_cookie 16][peer_tag 32][cell]`;
/// SYN/SYN_ACK prepend one encrypted peer-intro after `peer_tag` so only the
/// receiver can map the opaque tag back to the sender's node id.
struct CircuitCells {
    services: veil_node_runtime::NodeServices,
    me: [u8; 32],
    mode: CircuitMode,
    reg_kp: Arc<veil_crypto::GeneratedKeyPair>,
    epoch: Arc<AtomicU64>,
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
    /// Last successful stream-cell traffic through any pinned circuit owned by
    /// this hub. The inbound registration may be refreshed after a quiet period,
    /// but never while a file transfer is actively moving DATA/ACK cells.
    activity: Arc<Mutex<Instant>>,
    /// Filled by the background open task once this node's receiving circuit(s)
    /// are up. Published mode keeps one registration per advertised rendezvous
    /// relay; validation mode keeps a single circuit and also uses it for sends.
    inbound_circuits: Arc<tokio::sync::Mutex<Vec<Arc<veil_node_runtime::DataCircuit>>>>,
    /// Published-ad mode opens one outbound circuit per receiver R. Each circuit
    /// also registers our stream cookie at that R so ACKs can splice back.
    outbound_circuits: Arc<tokio::sync::Mutex<HashMap<[u8; 32], CircuitEntry>>>,
    /// Peers for which a cold/stale outbound circuit is currently being opened
    /// in the background. A stream cell sender must never block the stream driver
    /// on circuit construction; the ARQ layer retransmits dropped cells.
    outbound_opening: Arc<tokio::sync::Mutex<HashMap<[u8; 32], Instant>>>,
}

#[derive(Clone)]
struct CircuitEntry {
    circuit: Arc<veil_node_runtime::DataCircuit>,
    peer_tag: [u8; CIRCUIT_PEER_TAG_LEN],
    receiver_x25519_pk: [u8; 32],
    opened_at: Instant,
    last_used: Instant,
    last_non_handshake: Instant,
}

impl CircuitEntry {
    fn route(&self) -> CircuitRoute {
        CircuitRoute {
            circuit: Arc::clone(&self.circuit),
            envelope: CircuitEnvelope::ProtectedIntro {
                peer_tag: self.peer_tag,
                receiver_x25519_pk: self.receiver_x25519_pk,
            },
        }
    }
}

struct CircuitRoute {
    circuit: Arc<veil_node_runtime::DataCircuit>,
    envelope: CircuitEnvelope,
}

#[derive(Clone, Copy)]
enum CircuitEnvelope {
    LegacyClearSender {
        sender_node: [u8; 32],
    },
    ProtectedIntro {
        peer_tag: [u8; CIRCUIT_PEER_TAG_LEN],
        receiver_x25519_pk: [u8; 32],
    },
}

impl CellSender for CircuitCells {
    async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
        let decoded = Frame::decode(&cell);
        let is_handshake = matches!(decoded, Some(Frame::Syn { .. } | Frame::SynAck { .. }));
        let Some(route) = self.circuit_for(dst.node, is_handshake).await? else {
            // Circuit not up yet — drop this cell; the ARQ/handshake RTO resends.
            return Ok(());
        };
        let cookie = stream_cookie(&dst.node);
        let protected_intro_len =
            matches!(route.envelope, CircuitEnvelope::ProtectedIntro { .. }) && is_handshake;
        let mut env = Vec::with_capacity(
            COOKIE_LEN
                + CIRCUIT_PEER_TAG_LEN
                + cell.len()
                + if protected_intro_len {
                    1 + CIRCUIT_INTRO_LEN
                } else {
                    0
                },
        );
        env.extend_from_slice(&cookie);
        match route.envelope {
            CircuitEnvelope::LegacyClearSender { sender_node } => {
                env.extend_from_slice(&sender_node);
            }
            CircuitEnvelope::ProtectedIntro {
                peer_tag,
                receiver_x25519_pk,
            } => {
                env.extend_from_slice(&peer_tag);
                if is_handshake {
                    let intro = seal_stream_peer_intro(&self.me, &peer_tag, &receiver_x25519_pk)?;
                    env.push(CIRCUIT_INTRO_MARKER);
                    env.extend_from_slice(&intro);
                }
            }
        }
        env.extend_from_slice(&cell);
        if env.len() > veil_onion_stream::wire::MAX_CELL {
            return Err(io::Error::other(format!(
                "circuit stream envelope too large: {} > {}",
                env.len(),
                veil_onion_stream::wire::MAX_CELL
            )));
        }
        self.services
            .send_circuit_cell(&route.circuit, &env)
            .map_err(|e| io::Error::other(format!("circuit stream send: {e:?}")))?;
        mark_circuit_activity(&self.activity);
        if !is_handshake {
            self.mark_outbound_non_handshake(dst.node).await;
        }
        Ok(())
    }
}

impl CircuitCells {
    async fn circuit_for(
        &self,
        dst_node: [u8; 32],
        is_handshake: bool,
    ) -> io::Result<Option<CircuitRoute>> {
        match self.mode {
            CircuitMode::ValidationMinRouting => Ok(self
                .inbound_circuits
                .lock()
                .await
                .first()
                .cloned()
                .map(|circuit| CircuitRoute {
                    circuit,
                    envelope: CircuitEnvelope::LegacyClearSender {
                        sender_node: self.me,
                    },
                })),
            CircuitMode::PublishedRendezvous => {
                self.ensure_outbound_circuit(dst_node, is_handshake).await
            }
        }
    }

    async fn ensure_outbound_circuit(
        &self,
        dst_node: [u8; 32],
        is_handshake: bool,
    ) -> io::Result<Option<CircuitRoute>> {
        let now = Instant::now();
        let retired = {
            let mut circuits = self.outbound_circuits.lock().await;
            if let Some(entry) = circuits.get_mut(&dst_node) {
                let idle_for = now.duration_since(entry.last_used);
                let age = now.duration_since(entry.opened_at);
                let quiet_for = now.duration_since(entry.last_non_handshake);
                if is_handshake && age >= CIRCUIT_HANDSHAKE_REOPEN_AFTER {
                    diag(&format!(
                        "onion-stream: outbound circuit handshake on old/quiet path \
                         (age={}s quiet={}s) — reopening",
                        age.as_secs(),
                        quiet_for.as_secs()
                    ));
                    circuits.remove(&dst_node).map(|entry| entry.circuit)
                } else if idle_for < CIRCUIT_IDLE_REFRESH_AFTER {
                    entry.last_used = now;
                    return Ok(Some(entry.route()));
                } else {
                    diag(&format!(
                        "onion-stream: outbound circuit idle for {}s — reopening in background",
                        idle_for.as_secs()
                    ));
                    circuits.remove(&dst_node).map(|entry| entry.circuit)
                }
            } else {
                None
            }
        };
        if let Some(retired) = retired {
            retire_circuits_later(&self.services, vec![retired]);
        }
        {
            let circuits = self.outbound_circuits.lock().await;
            if let Some(entry) = circuits.get(&dst_node) {
                return Ok(Some(entry.route()));
            }
        }

        if is_handshake {
            return self.open_outbound_for_handshake(dst_node).await;
        }

        self.ensure_outbound_opening(dst_node).await;
        Ok(None)
    }

    async fn mark_outbound_non_handshake(&self, dst_node: [u8; 32]) {
        let now = Instant::now();
        if let Some(entry) = self.outbound_circuits.lock().await.get_mut(&dst_node) {
            entry.last_used = now;
            entry.last_non_handshake = now;
        }
    }

    async fn ensure_outbound_opening(&self, dst_node: [u8; 32]) {
        let now = Instant::now();
        {
            let mut opening = self.outbound_opening.lock().await;
            if let Some(started) = opening.get(&dst_node) {
                // Circuit open/confirmation can legitimately take a few seconds
                // on a cold phone. Do not start a stampede of duplicate opens;
                // if a task gets wedged, allow a later retransmit to kick a new one.
                if now.duration_since(*started) < CIRCUIT_CONFIRM_TIMEOUT * 2 {
                    return;
                }
            }
            opening.insert(dst_node, now);
        }

        let services = self.services.clone();
        let me = self.me;
        let reg_kp = Arc::clone(&self.reg_kp);
        let epoch = Arc::clone(&self.epoch);
        let in_tx = self.in_tx.clone();
        let activity = Arc::clone(&self.activity);
        let outbound_circuits = Arc::clone(&self.outbound_circuits);
        let outbound_opening = Arc::clone(&self.outbound_opening);
        tokio::spawn(async move {
            let opened = open_outbound_circuit(
                services.clone(),
                dst_node,
                me,
                reg_kp,
                epoch,
                in_tx,
                activity,
                outbound_circuits,
            )
            .await;
            outbound_opening.lock().await.remove(&dst_node);
            if let Err(e) = opened {
                diag(&format!(
                    "onion-stream: outbound circuit open failed for {}: {e}",
                    short_node(&dst_node)
                ));
            }
        });
    }

    async fn open_outbound_for_handshake(
        &self,
        dst_node: [u8; 32],
    ) -> io::Result<Option<CircuitRoute>> {
        let now = Instant::now();
        let should_open = {
            let mut opening = self.outbound_opening.lock().await;
            if let Some(started) = opening.get(&dst_node) {
                now.duration_since(*started) >= CIRCUIT_CONFIRM_TIMEOUT * 2
            } else {
                true
            }
            .then(|| opening.insert(dst_node, now))
            .is_some()
        };

        if should_open {
            let opened = open_outbound_circuit(
                self.services.clone(),
                dst_node,
                self.me,
                Arc::clone(&self.reg_kp),
                Arc::clone(&self.epoch),
                self.in_tx.clone(),
                Arc::clone(&self.activity),
                Arc::clone(&self.outbound_circuits),
            )
            .await;
            self.outbound_opening.lock().await.remove(&dst_node);
            if let Err(e) = opened {
                diag(&format!(
                    "onion-stream: outbound circuit handshake-open failed for {}: {e}",
                    short_node(&dst_node)
                ));
            }
        } else {
            let deadline = Instant::now() + CIRCUIT_CONFIRM_TIMEOUT;
            while Instant::now() < deadline {
                if let Some(entry) = self.outbound_circuits.lock().await.get(&dst_node) {
                    return Ok(Some(entry.route()));
                }
                if !self.outbound_opening.lock().await.contains_key(&dst_node) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }

        let circuits = self.outbound_circuits.lock().await;
        Ok(circuits.get(&dst_node).map(CircuitEntry::route))
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
            // On the pinned circuit path a no-ACK RTO usually means the
            // current stream/circuit went black-hole, not that a little more
            // exponential backoff will help. Fail fast and let the content layer
            // resume on a fresh stream instead of waiting ~2 minutes for its
            // payload-write idle timeout. The datagram path keeps the conservative
            // retry budget.
            max_retransmits: if matches!(&cells, HubCells::Circuit(_)) {
                2
            } else {
                15
            },
            recv_window,
            init_cwnd: (32 * mss) as u32,
            max_pacing_batch: if matches!(&cells, HubCells::Circuit(_)) {
                // 12 × 318 B/ms ≈ 3.8 MB/s stream-payload ceiling: comfortably
                // above the old 1.5 MB/s target while still keeping bursts half
                // the previous 24-cell aggressive profile.
                12
            } else {
                4
            },
            rto_rewind_no_sack: matches!(&cells, HubCells::Circuit(_)),
            // Every ACK consumes the same fixed-size circuit cell as DATA.
            // The pinned path is loss-free/in-order, so cumulative ACKs can be
            // thinned without delaying loss signalling: gaps and duplicates
            // still ACK immediately, and the timer bounds tail latency.
            ack_every: if matches!(&cells, HubCells::Circuit(_)) {
                // A little more ACK traffic buys faster loss signalling and keeps
                // SACK state fresh during relay-queue drops.
                16
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
    let inbound_circuits: Arc<tokio::sync::Mutex<Vec<Arc<veil_node_runtime::DataCircuit>>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let outbound_circuits = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let outbound_opening = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let activity = Arc::new(Mutex::new(Instant::now()));
    let reg_kp = Arc::new(services.onion_stream_registration_keypair());
    let epoch = Arc::new(AtomicU64::new(0));
    // Open the circuit to R in the BACKGROUND (async relay-dir fetch + CircuitBuild
    // + ACK). Proactive (not lazy-on-send) so the RECEIVER is ready to take inbound
    // splices before it ever sends. Cells before it's up drop; the ARQ resends.
    //
    // Do NOT blindly rotate the pinned circuit by wall-clock time. Device traces
    // showed a 37 MB transfer running at ~1.7 MB/s until a timed refresh swapped
    // the rendezvous registration mid-stream; the sender kept pushing but the
    // receiver stopped advancing at ~54 %. Instead, refresh only after the whole
    // stream backend has been idle long enough that stale relay registrations are
    // more likely than in-flight cells.
    let circuit_slot = Arc::clone(&inbound_circuits);
    let services_bg = services.clone();
    let reg_kp_bg = Arc::clone(&reg_kp);
    let epoch_bg = Arc::clone(&epoch);
    let in_tx_bg = in_tx.clone();
    let activity_bg = Arc::clone(&activity);
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
            let opened =
                match open_inbound_circuits(&services_bg, me, cookie, &reg_kp_bg, &epoch_bg, mode)
                    .await
                {
                    Ok(opened) => opened,
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

            let mut confirmed = Vec::with_capacity(opened.len());
            let mut confirmed_relays = Vec::with_capacity(opened.len());
            for (relay, candidate, recv_rx) in opened {
                // Circuit open is intentionally optimistic: it returns once
                // CircuitBuild is queued. Do not publish the handle until R has
                // accepted the cookie registration and CircuitBuilt came back.
                if !confirm_circuit(&candidate).await {
                    services_bg.close_data_circuit(candidate.origin_circuit_id());
                    if let Some(relay) = relay {
                        diag(&format!(
                            "onion-stream: inbound circuit confirmation timed out at R={}",
                            short_node(&relay)
                        ));
                    }
                    continue;
                }

                // Inbound feed: legacy validation cells are `[sender_node 32][cell]`;
                // published cells are `[peer_tag 32][intro?][cell]`.
                // Start it before swapping so cells arriving immediately after the
                // confirmation are already consumed from the bounded return queue.
                spawn_circuit_feed(
                    services_bg.clone(),
                    recv_rx,
                    in_tx_bg.clone(),
                    Some(Arc::clone(&activity_bg)),
                );
                if let Some(relay) = relay {
                    confirmed_relays.push(relay);
                }
                confirmed.push(Arc::new(candidate));
            }

            if confirmed.is_empty() {
                if attempt == 1 || attempt % 15 == 0 {
                    diag(&format!(
                        "onion-stream: circuit confirmation timed out on attempt #{attempt}"
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2).min(8_000);
                continue;
            }

            let retired = {
                let mut slot = circuit_slot.lock().await;
                std::mem::replace(&mut *slot, confirmed)
            };
            let generation_opened_at = Instant::now();
            generation += 1;
            backoff_ms = 1_500;
            let relay_suffix = if confirmed_relays.is_empty() {
                String::new()
            } else {
                format!(
                    " R=[{}]",
                    confirmed_relays
                        .iter()
                        .map(short_node)
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            if generation == 1 {
                diag(&format!(
                    "onion-stream: PINNED CIRCUIT opened ({mode:?}, {} registration(s), after {attempt} tries){relay_suffix}",
                    circuit_slot.lock().await.len()
                ));
            } else {
                diag(&format!(
                    "onion-stream: PINNED CIRCUIT refreshed ({mode:?}, {} registration(s), generation {generation}){relay_suffix}",
                    circuit_slot.lock().await.len()
                ));
            }

            retire_circuits_later(&services_bg, retired);

            loop {
                tokio::time::sleep(CIRCUIT_REFRESH_POLL).await;
                let generation_age = Instant::now().saturating_duration_since(generation_opened_at);
                let idle_for = circuit_idle_for(&activity_bg);
                if mode == CircuitMode::PublishedRendezvous {
                    let have = circuit_slot.lock().await.len();
                    let want = services_bg.local_published_rendezvous_relays().len();
                    if want > have
                        && generation_age >= CIRCUIT_PUBLISHED_RELAY_EXPAND_AFTER
                        && idle_for >= CIRCUIT_PUBLISHED_RELAY_EXPAND_AFTER
                    {
                        diag(&format!(
                            "onion-stream: published rendezvous set expanded {have}->{want} — refreshing inbound circuits"
                        ));
                        break;
                    }
                }
                if generation_age >= CIRCUIT_IDLE_REFRESH_AFTER
                    && idle_for >= CIRCUIT_IDLE_REFRESH_AFTER
                {
                    diag(&format!(
                        "onion-stream: inbound circuit idle for {}s — refreshing",
                        idle_for.as_secs()
                    ));
                    break;
                }
            }
        }
    });
    Some(CircuitCells {
        services,
        me,
        mode,
        reg_kp,
        epoch,
        in_tx,
        activity,
        inbound_circuits,
        outbound_circuits,
        outbound_opening,
    })
}

type OpenedInboundCircuit = (
    Option<[u8; 32]>,
    veil_node_runtime::DataCircuit,
    mpsc::Receiver<Vec<u8>>,
);

async fn open_inbound_circuits(
    services: &veil_node_runtime::NodeServices,
    me: [u8; 32],
    cookie: [u8; COOKIE_LEN],
    reg_kp: &veil_crypto::GeneratedKeyPair,
    epoch: &AtomicU64,
    mode: CircuitMode,
) -> Result<Vec<OpenedInboundCircuit>, veil_types::AnonOnionSendError> {
    use veil_types::AnonOnionSendError;

    match mode {
        CircuitMode::ValidationMinRouting => services
            .open_stream_circuit_auto(cookie, reg_kp, epoch)
            .await
            .map(|(circuit, rx)| vec![(None, circuit, rx)]),
        CircuitMode::PublishedRendezvous => {
            let mut relays = services.local_published_rendezvous_relays();
            if let Ok(resolved) = services.resolve_stream_rendezvous_relays(me).await {
                for relay in resolved {
                    if !relays.contains(&relay) {
                        relays.push(relay);
                    }
                }
            }
            if relays.is_empty() {
                return Err(AnonOnionSendError::NoRendezvous);
            }

            let mut opened = Vec::with_capacity(relays.len());
            let mut last_err = AnonOnionSendError::NoRelays;
            for relay in relays {
                match services
                    .open_stream_circuit_to_rendezvous_relay(
                        relay,
                        cookie,
                        reg_kp,
                        epoch,
                        CIRCUIT_HOPS,
                    )
                    .await
                {
                    Ok((circuit, rx)) => opened.push((Some(relay), circuit, rx)),
                    Err(e) => {
                        last_err = e;
                        diag(&format!(
                            "onion-stream: inbound published R={} open failed: {last_err:?}",
                            short_node(&relay)
                        ));
                    }
                }
            }
            if opened.is_empty() {
                Err(last_err)
            } else {
                Ok(opened)
            }
        }
    }
}

async fn open_outbound_circuit(
    services: veil_node_runtime::NodeServices,
    dst_node: [u8; 32],
    me: [u8; 32],
    reg_kp: Arc<veil_crypto::GeneratedKeyPair>,
    epoch: Arc<AtomicU64>,
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
    activity: Arc<Mutex<Instant>>,
    outbound_circuits: Arc<tokio::sync::Mutex<HashMap<[u8; 32], CircuitEntry>>>,
) -> Result<(), String> {
    let ads = services
        .resolve_stream_rendezvous_ads(dst_node)
        .await
        .map_err(|e| format!("resolve receiver ads: {e:?}"))?;

    let mut last_err = "no receiver rendezvous ad opened".to_string();
    for ad in ads {
        let (candidate, recv_rx) = match services
            .open_stream_circuit_to_rendezvous_relay(
                ad.rendezvous_node_id,
                stream_cookie(&me),
                &reg_kp,
                &epoch,
                CIRCUIT_HOPS,
            )
            .await
        {
            Ok(opened) => opened,
            Err(e) => {
                last_err = format!(
                    "R={} open failed: {e:?}",
                    short_node(&ad.rendezvous_node_id)
                );
                continue;
            }
        };

        if !confirm_circuit(&candidate).await {
            services.close_data_circuit(candidate.origin_circuit_id());
            last_err = format!(
                "R={} confirmation timed out",
                short_node(&ad.rendezvous_node_id)
            );
            continue;
        }

        spawn_circuit_feed(
            services.clone(),
            recv_rx,
            in_tx,
            Some(Arc::clone(&activity)),
        );
        let candidate = Arc::new(candidate);
        let now = Instant::now();
        let retired = outbound_circuits.lock().await.insert(
            dst_node,
            CircuitEntry {
                circuit: Arc::clone(&candidate),
                peer_tag: random_peer_tag(),
                receiver_x25519_pk: ad.receiver_x25519_pk,
                opened_at: now,
                last_used: now,
                last_non_handshake: now,
            },
        );
        mark_circuit_activity(&activity);
        diag(&format!(
            "onion-stream: outbound circuit ready for {} via R={}",
            short_node(&dst_node),
            short_node(&ad.rendezvous_node_id)
        ));
        let retired = retired.map(|r| r.circuit).into_iter().collect();
        retire_circuits_later(&services, retired);
        return Ok(());
    }
    Err(format!("open to receiver ad: {last_err}"))
}

async fn confirm_circuit(circuit: &veil_node_runtime::DataCircuit) -> bool {
    let confirm_deadline = tokio::time::Instant::now() + CIRCUIT_CONFIRM_TIMEOUT;
    while !circuit.is_confirmed() && tokio::time::Instant::now() < confirm_deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    circuit.is_confirmed()
}

fn spawn_circuit_feed(
    services: veil_node_runtime::NodeServices,
    mut recv_rx: mpsc::Receiver<Vec<u8>>,
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
    activity: Option<Arc<Mutex<Instant>>>,
) {
    tokio::spawn(async move {
        let mut peer_tags = HashMap::<[u8; CIRCUIT_PEER_TAG_LEN], [u8; 32]>::new();
        while let Some(framed) = recv_rx.recv().await {
            if let Some(activity) = activity.as_ref() {
                mark_circuit_activity(activity);
            }
            if framed.len() < CIRCUIT_PEER_TAG_LEN {
                continue;
            }
            let mut tag = [0u8; CIRCUIT_PEER_TAG_LEN];
            tag.copy_from_slice(&framed[..CIRCUIT_PEER_TAG_LEN]);
            let mut cell_offset = CIRCUIT_PEER_TAG_LEN;
            let node = if framed.get(cell_offset) == Some(&CIRCUIT_INTRO_MARKER) {
                if framed.len() < cell_offset + 1 + CIRCUIT_INTRO_LEN {
                    continue;
                }
                let sealed = &framed[cell_offset + 1..cell_offset + 1 + CIRCUIT_INTRO_LEN];
                let Some(node) = open_stream_peer_intro(&services, &tag, sealed) else {
                    continue;
                };
                if peer_tags.len() >= 4096 && !peer_tags.contains_key(&tag) {
                    peer_tags.clear();
                }
                peer_tags.insert(tag, node);
                cell_offset += 1 + CIRCUIT_INTRO_LEN;
                node
            } else if let Some(node) = peer_tags.get(&tag) {
                *node
            } else {
                // Backward-compatible validation/legacy path: the first 32 bytes
                // are the clear sender node id rather than an opaque tag.
                tag
            };
            if framed.len() <= cell_offset {
                continue;
            }
            let app = veil_app::address::app_id(&node, STREAM_NAMESPACE, STREAM_NAME);
            let cell = framed[cell_offset..].to_vec();
            if in_tx.send((Addr { node, app }, cell)).await.is_err() {
                break;
            }
        }
    });
}

fn mark_circuit_activity(activity: &Arc<Mutex<Instant>>) {
    *activity.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
}

fn circuit_idle_for(activity: &Arc<Mutex<Instant>>) -> Duration {
    Instant::now().duration_since(*activity.lock().unwrap_or_else(|p| p.into_inner()))
}

fn short_node(node: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &node[..4] {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn retire_circuits_later(
    services: &veil_node_runtime::NodeServices,
    circuits: Vec<Arc<veil_node_runtime::DataCircuit>>,
) {
    for old in circuits {
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
    use super::{
        CIRCUIT_INTRO_LEN, CIRCUIT_MSS, CIRCUIT_PEER_TAG_LEN, CircuitMode, circuit_env_value_mode,
        parse_stream_peer_intro_plaintext, stream_peer_intro_plaintext,
    };
    use veil_anonymity::circuit_register::COOKIE_LEN;
    use veil_onion_stream::wire::{DATA_OVERHEAD, Frame, MAX_CELL};

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

    #[test]
    fn protected_circuit_envelopes_fit_one_cell_without_reducing_data_mss() {
        let payload = [0xABu8; CIRCUIT_MSS];
        let data = Frame::Data {
            stream_id: 7,
            seq: 0,
            win: 1024,
            payload: &payload,
        }
        .encode();
        assert_eq!(
            COOKIE_LEN + CIRCUIT_PEER_TAG_LEN + data.len(),
            MAX_CELL,
            "protected DATA must still exactly fill one CircuitData inner cell"
        );
        assert_eq!(
            CIRCUIT_MSS,
            MAX_CELL - COOKIE_LEN - CIRCUIT_PEER_TAG_LEN - DATA_OVERHEAD
        );

        let syn = Frame::Syn {
            stream_id: 7,
            isn: 11,
            win: 4096,
        }
        .encode();
        let syn_ack = Frame::SynAck {
            stream_id: 7,
            isn: 13,
            win: 4096,
            ack: 11,
        }
        .encode();
        assert!(COOKIE_LEN + CIRCUIT_PEER_TAG_LEN + 1 + CIRCUIT_INTRO_LEN + syn.len() <= MAX_CELL);
        assert!(
            COOKIE_LEN + CIRCUIT_PEER_TAG_LEN + 1 + CIRCUIT_INTRO_LEN + syn_ack.len() <= MAX_CELL
        );
    }

    #[test]
    fn stream_peer_intro_plaintext_is_bound_to_peer_tag() {
        let sender = [0x11u8; 32];
        let tag = [0x22u8; CIRCUIT_PEER_TAG_LEN];
        let plaintext = stream_peer_intro_plaintext(&sender, &tag);
        assert_eq!(
            parse_stream_peer_intro_plaintext(&tag, &plaintext),
            Some(sender)
        );

        let mut other_tag = tag;
        other_tag[0] ^= 0x01;
        assert_eq!(
            parse_stream_peer_intro_plaintext(&other_tag, &plaintext),
            None
        );

        let mut wrong_domain = plaintext;
        wrong_domain[0] ^= 0x01;
        assert_eq!(parse_stream_peer_intro_plaintext(&tag, &wrong_domain), None);
    }
}
