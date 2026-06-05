//! Peer-to-peer chat node: every host runs the same binary and is BOTH
//! a server (accepts incoming MESSAGE frames) AND a client (sends a
//! MESSAGE to a random peer at a random interval between 1 ms and
//! 100 ms — high-cadence load mode for live demos / Grafana traffic
//! visualisation. Drop the upper bound for sustained throughput tests.
//!
//! Wire format on top of the IPC API (single-byte msg type prefix):
//!
//! MESSAGE = [0x4D][2B name_len BE][name_bytes][2B body_len BE][body_bytes]
//!
//! Operational pattern:
//! 1. First boot: `chat_node --dump-app-id <socket> <my_name>` prints
//!    the bound app_id_hex on stdout and exits — used by the deploy
//!    playbook to harvest each node's app_id before peer-list
//!    generation.
//! 2. Steady state: `chat_node <socket> <my_name> <peer_list.txt>` —
//!    reads `<peer_list.txt>` (one `node_id_hex node_id_hex` per
//!    line + comments), binds, and runs both loops.
//!
//! Peer-list line format (whitespace separated):
//! <peer_node_id_hex_64ch> <peer_app_id_hex_64ch> <peer_endpoint_id> <peer_name>
//!
//! Lines starting with `#` are ignored. The host's OWN entry can stay
//! in the list — `chat_node` skips entries whose node_id equals the
//! locally-known node_id (passed via `VEIL_LOCAL_NODE_ID` env so the
//! binary doesn't have to query its own daemon).

#[cfg(not(unix))]
fn main() {
    eprintln!("chat_node is Unix-only.");
    std::process::exit(0);
}

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use veilclient::{ClientError, VeilClient};

#[cfg(unix)]
const MSG_MESSAGE: u8 = 0x4D;
#[cfg(unix)]
const ENDPOINT_ID: u32 = 200;
#[cfg(unix)]
const NAMESPACE: &str = "myapp.example";
#[cfg(unix)]
const APP_NAME: &str = "chat-node";

#[cfg(unix)]
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(unix)]
struct Peer {
    node_id: [u8; 32],
    app_id: [u8; 32],
    endpoint_id: u32,
    name: String,
}

#[cfg(unix)]
fn read_peer_list(path: &Path) -> std::io::Result<Vec<Peer>> {
    let raw = std::fs::read_to_string(path)?;
    let mut peers = Vec::new();
    for (lineno, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let node_hex = parts.next();
        let app_hex = parts.next();
        let ep_str = parts.next();
        let name = parts.next();
        match (node_hex, app_hex, ep_str, name) {
            (Some(n), Some(a), Some(e), Some(name_s)) => {
                let nid = match parse_hex32(n) {
                    Some(x) => x,
                    None => {
                        eprintln!("[warn] line {}: bad node_id hex: {}", lineno + 1, n);
                        continue;
                    }
                };
                let aid = match parse_hex32(a) {
                    Some(x) => x,
                    None => {
                        eprintln!("[warn] line {}: bad app_id hex: {}", lineno + 1, a);
                        continue;
                    }
                };
                let ep: u32 = match e.parse() {
                    Ok(x) => x,
                    Err(_) => {
                        eprintln!("[warn] line {}: bad endpoint_id: {}", lineno + 1, e);
                        continue;
                    }
                };
                peers.push(Peer {
                    node_id: nid,
                    app_id: aid,
                    endpoint_id: ep,
                    name: name_s.to_owned(),
                });
            }
            _ => {
                eprintln!("[warn] line {}: expected 4 fields", lineno + 1);
            }
        }
    }
    Ok(peers)
}

// Tiny LCG so we don't pull a full RNG crate.
#[cfg(unix)]
struct LcgRng {
    state: u64,
}
#[cfg(unix)]
impl LcgRng {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xDEADBEEF);
        Self { state: nanos | 1 }
    }
    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }
    /// Inclusive bounds [lo, hi].
    fn next_in_range(&mut self, lo: u32, hi: u32) -> u32 {
        let span = hi - lo + 1;
        lo + (self.next_u32() % span)
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), ClientError> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 && args[1] == "--dump-app-id" {
        // Mode 1: print app_id and exit. Used by the deploy playbook
        // to harvest each node's app_id before generating the
        // peer-list that gets pushed to every node.
        let socket_path = &args[2];
        let _my_name = &args[3];
        let client = VeilClient::connect(socket_path).await?;
        let handle = client.bind_named(NAMESPACE, APP_NAME, ENDPOINT_ID).await?;
        let app_id_hex: String = handle
            .app_id()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        println!("{}", app_id_hex);
        // Drop the bind so the app_id is freed (a fresh bind on the
        // same NAMESPACE/APP_NAME/endpoint will reproduce it under
        // EPHEMERAL semantics).
        return Ok(());
    }
    if args.len() != 4 {
        eprintln!("Usage:");
        eprintln!("  chat_node --dump-app-id <socket> <my_name>");
        eprintln!("  chat_node <socket> <my_name> <peer_list.txt>");
        std::process::exit(1);
    }
    let socket_path = args[1].clone();
    let my_name = args[2].clone();
    let peer_list_path = std::path::PathBuf::from(&args[3]);

    let local_node_hex = std::env::var("VEIL_LOCAL_NODE_ID").unwrap_or_default();
    let local_node_id = parse_hex32(&local_node_hex);

    let peers_all = read_peer_list(&peer_list_path).expect("read peer-list");
    let peers: Vec<Peer> = peers_all
        .into_iter()
        .filter(|p| Some(p.node_id) != local_node_id)
        .collect();
    if peers.is_empty() {
        eprintln!("[!] peer list empty (after filtering self) — nothing to send to");
        std::process::exit(2);
    }
    println!(
        "chat_node {} up: {} peers loaded (self filtered out)",
        my_name,
        peers.len(),
    );
    for p in &peers {
        println!(
            "  peer {} node={} app={} ep={}",
            p.name,
            hex_short(&p.node_id),
            hex_short(&p.app_id),
            p.endpoint_id,
        );
    }

    // Outer reconnect loop — survives daemon restarts / IPC disconnects
    // without exiting the process. Exponential backoff starts at 1 s
    // doubles on each consecutive failure, caps at 30 s. Reset to 1 s
    // once a session reaches steady-state (≥ 1 successful send).
    // Without this, `chat_node` exits on any send error and relies on
    // systemd to restart it; with this, the application persists IPC
    // identity (`app_id`) across daemon flaps via EPHEMERAL re-bind
    // semantics — same NAMESPACE/APP_NAME/endpoint reproduces the
    // same app_id, so peer-list entries remain valid.
    let mut backoff_secs: u64 = 1;
    let mut reconnect_count: u64 = 0;
    loop {
        match run_session(&socket_path, &my_name, &peers).await {
            Ok(()) => {
                // run_session loops indefinitely; Ok only on clean shutdown
                // (currently unreachable, but kept for future SIGTERM handling).
                return Ok(());
            }
            Err(e) => {
                reconnect_count += 1;
                eprintln!(
                    "[!] session ended ({}): {} — reconnecting in {}s (attempt #{})",
                    short_error_kind(&e),
                    e,
                    backoff_secs,
                    reconnect_count,
                );
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(30);
            }
        }
    }
}

/// One IPC session: connect → bind → send/recv → return when anything fails.
/// Errors bubble up to the outer reconnect loop in `main`.
#[cfg(unix)]
async fn run_session(socket_path: &str, my_name: &str, peers: &[Peer]) -> Result<(), ClientError> {
    let client = VeilClient::connect(socket_path).await?;
    let handle = client.bind_named(NAMESPACE, APP_NAME, ENDPOINT_ID).await?;
    let app_id_hex: String = handle
        .app_id()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!(
        "bound: endpoint={} app_id={}",
        handle.endpoint_id(),
        app_id_hex
    );

    // Split into independent send/recv halves so the receiver task
    // can drain at line-rate while the sender task blasts at the
    // configured cadence. Daemon's IPC delivery channel is
    // DELIVERY_CHANNEL_CAP=1024 frames; if the receiver falls behind
    // it overflows and the daemon force-closes the IPC connection
    // ("broken pipe" on the next send). Independent tasks fix that
    // by ensuring recv keeps draining regardless of send activity.
    let (sender, mut receiver) = handle.into_split();

    // ── Receiver task ──────────────────────────────────────────────────────
    // Drain at line rate — DO NOT parse or allocate per-message. At 60 KB
    // payload × 200 msg/sec the SDK's mpsc::UnboundedReceiver fills with
    // multi-MB of buffered messages if anything in this loop is slower
    // than the daemon's delivery rate. Each Ok(Some(msg)) is dropped
    // immediately by going out of scope at the end of the match arm.
    // Sample-print every 1000th to keep an observable trail without
    // turning the hot path into a UTF-8 string-slice + println pipeline
    // (those alloc + grow logs dominate at this rate).
    let _recv_handle = tokio::spawn(async move {
        let mut count: u64 = 0;
        loop {
            match receiver.recv().await {
                Ok(Some(msg)) => {
                    count += 1;
                    if count.is_multiple_of(1000) {
                        // Pull just the source node prefix from msg.src_node_id
                        // — cheap, no allocation on the body itself.
                        let s = msg.src_node_id;
                        println!(
                            "[<-] #{} from {:02x}{:02x}{:02x}{:02x} ({} bytes)",
                            count,
                            s[0],
                            s[1],
                            s[2],
                            s[3],
                            msg.data.len()
                        );
                    }
                    drop(msg);
                }
                Ok(None) => {
                    eprintln!("[!] IPC delivery channel closed");
                    break;
                }
                Err(e) => {
                    eprintln!("[!] recv error: {}", e);
                    break;
                }
            }
        }
    });

    // ── Sender loop (main task) ─────────────────────────────────────────────
    let mut rng = LcgRng::new();
    let mut counter: u64 = 0;
    // Random initial delay so 8 nodes don't wake on the same edge.
    tokio::time::sleep(Duration::from_micros(rng.next_in_range(100, 4_000) as u64)).await;

    // Build the payload buffer ONCE — at 200+ msg/sec we don't want to
    // allocate a 60 KB Vec on every iteration. Wire format
    // `[0x4D][2B name_len][name][2B body_len][body]` is mostly fixed
    // per-process; only the counter portion of the body changes, and
    // we patch that in-place at a known offset.
    const PAYLOAD_TARGET_BYTES: usize = 61440;
    const FILLER_PATTERN: &[u8] = b"0123456789ABCDEF";
    let name_bytes = my_name.as_bytes();
    let body_total = PAYLOAD_TARGET_BYTES;
    let total = 1 + 2 + name_bytes.len() + 2 + body_total;
    let mut payload = Vec::with_capacity(total);
    payload.push(MSG_MESSAGE);
    payload.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(name_bytes);
    payload.extend_from_slice(&(body_total as u16).to_be_bytes());
    // Body: header placeholder (32 bytes) + filler. We rewrite the
    // first N bytes of the body in-place each tick with the counter.
    let body_start = payload.len();
    payload.resize(body_start + body_total, 0);
    let mut filler_off = body_start + 32;
    while filler_off < body_start + body_total {
        let take = (body_start + body_total - filler_off).min(FILLER_PATTERN.len());
        payload[filler_off..filler_off + take].copy_from_slice(&FILLER_PATTERN[..take]);
        filler_off += take;
    }

    // Optional rate cap. When CHAT_TARGET_KBITS is set (and >0), send at a
    // fixed cadence computed from the *actual* payload size so this node's
    // generated app-traffic ≈ that many kbit/s. Unset → original stress
    // cadence (random 100–4000 µs ≈ 96 Mbit/s). Per-node, not aggregate.
    //   interval_us = payload_bytes * 8 bits * 1e6 µs/s / (kbits * 1e3 bps/kbps)
    //              = payload_bytes * 8000 / kbits
    let rate_interval_us: Option<u64> = std::env::var("CHAT_TARGET_KBITS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&kbits| kbits > 0)
        .map(|kbits| (total as u64).saturating_mul(8000) / kbits.max(1));
    match rate_interval_us {
        Some(us) => eprintln!(
            "[rate] CHAT_TARGET_KBITS set → one {total}-byte msg every {us} µs (~{} kbit/s/node)",
            (total as u64).saturating_mul(8000) / us.max(1)
        ),
        None => eprintln!("[rate] CHAT_TARGET_KBITS unset → stress cadence (100–4000 µs)"),
    }

    loop {
        counter += 1;
        // Patch the leading 32 bytes of the body with the new counter
        // header. Pad with spaces if the formatted header is shorter.
        let hdr = format!("#{} from {} ", counter, my_name);
        let hdr_bytes = hdr.as_bytes();
        let n = hdr_bytes.len().min(32);
        payload[body_start..body_start + n].copy_from_slice(&hdr_bytes[..n]);
        for b in payload[body_start + n..body_start + 32].iter_mut() {
            *b = b' ';
        }

        let target = &peers[rng.next_in_range(0, peers.len() as u32 - 1) as usize];
        // Per-send 5s watchdog. After fixing the IPC select! cancel-safety
        // bug we still observed one node where chat_node bound, printed the
        // banner, and hung indefinitely — recv was draining (so the SDK
        // reader was alive) but `sender.send.await` never returned for
        // ≥6 minutes with no log output. Rather than chase the wedge to
        // completion, exit and let systemd restart so the cluster heals.
        let send_fut = sender.send(target.node_id, target.app_id, target.endpoint_id, &payload);
        match tokio::time::timeout(Duration::from_secs(5), send_fut).await {
            Ok(Ok(())) => {
                if counter.is_multiple_of(100) {
                    println!(
                        "[->] #{} → {} ({} bytes)",
                        counter,
                        target.name,
                        payload.len()
                    );
                }
            }
            Ok(Err(e)) => {
                eprintln!("[!] send #{} to {} failed: {}", counter, target.name, e);
                return Err(e);
            }
            Err(_) => {
                eprintln!(
                    "[!] send #{} to {} timed out after 5s — bubbling up for reconnect",
                    counter, target.name
                );
                return Err(ClientError::ConnectionClosed);
            }
        }

        let next_us = rate_interval_us.unwrap_or_else(|| rng.next_in_range(100, 4_000) as u64);
        tokio::time::sleep(Duration::from_micros(next_us)).await;
    }
}

#[cfg(unix)]
fn short_error_kind(e: &ClientError) -> &'static str {
    match e {
        ClientError::Io(_) => "io",
        ClientError::Handshake { .. } => "handshake",
        ClientError::Bind { .. } => "bind",
        ClientError::StreamOpen { .. } => "stream_open",
        ClientError::ConnectionClosed => "closed",
        ClientError::Protocol(_) => "protocol",
    }
}

#[cfg(unix)]
fn hex_short(b: &[u8; 32]) -> String {
    b.iter().take(4).map(|x| format!("{:02x}", x)).collect()
}
