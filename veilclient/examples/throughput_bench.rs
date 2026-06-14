//! Minimal SDK-level throughput bench for measuring veil-stack
//! throughput without TUN/ogate overhead.
//!
//! Usage:
//!   throughput_bench server <socket> <name>
//!   throughput_bench client <socket> <name> <peer-list.txt> [seconds] [payload_bytes]
//!
//! peer-list.txt format: `<name> <node_id_hex> <app_id_hex> <endpoint_id>`

// `VeilClient` is `#[cfg(unix)]`-only, so the whole example is gated to unix.
// A stub entry point keeps `cargo build/clippy --all-targets` green on Windows.
#[cfg(not(unix))]
fn main() {
    eprintln!("throughput_bench example is only supported on unix targets");
}

#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use veilclient::{ClientError, VeilClient};

#[cfg(unix)]
const NAMESPACE: &str = "throughput-bench";
#[cfg(unix)]
const ENDPOINT_ID: u32 = 1;

#[cfg(unix)]
#[derive(Debug)]
struct Peer {
    name: String,
    node_id: [u8; 32],
    app_id: [u8; 32],
    endpoint_id: u32,
}

#[cfg(unix)]
fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("hex parse at {}: {}", i, e))?;
    }
    Ok(out)
}

#[cfg(unix)]
fn load_peer_list(path: &Path, exclude_name: &str) -> Result<Vec<Peer>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read: {}", e))?;
    let mut out = Vec::new();
    for (lineno, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(format!("line {}: need 4 fields", lineno + 1));
        }
        let name = parts[0].to_string();
        if name == exclude_name {
            continue;
        }
        let node_id =
            parse_hex32(parts[1]).map_err(|e| format!("line {} node_id: {}", lineno + 1, e))?;
        let app_id =
            parse_hex32(parts[2]).map_err(|e| format!("line {} app_id: {}", lineno + 1, e))?;
        let endpoint_id: u32 = parts[3]
            .parse()
            .map_err(|e| format!("line {} endpoint_id: {}", lineno + 1, e))?;
        out.push(Peer {
            name,
            node_id,
            app_id,
            endpoint_id,
        });
    }
    Ok(out)
}

#[cfg(unix)]
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), ClientError> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: throughput_bench {{server|client|dump-app-id}} <socket> <name> [...]");
        std::process::exit(2);
    }
    let mode = args[1].as_str();
    let socket = Path::new(&args[2]);
    let name = &args[3];

    if mode == "dump-app-id" {
        let client = VeilClient::connect(socket).await?;
        let handle = client.bind_named(NAMESPACE, name, ENDPOINT_ID).await?;
        let info = client.node_identity().await?;
        // Print: <name> <node_id_hex> <app_id_hex> <endpoint_id>
        let node_id_hex: String = info.node_id.iter().map(|b| format!("{:02x}", b)).collect();
        let app_id_hex: String = handle
            .app_id()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        println!("{} {} {} {}", name, node_id_hex, app_id_hex, ENDPOINT_ID);
        return Ok(());
    }

    if mode == "server" {
        let client = VeilClient::connect(socket).await?;
        let handle = client.bind_named(NAMESPACE, name, ENDPOINT_ID).await?;
        eprintln!(
            "[server] bound name={} app_id={:?}",
            name,
            &handle.app_id()[..4]
        );
        let (_sender, mut receiver) = handle.into_split();
        let mut total: u64 = 0;
        let mut t0 = Instant::now();
        let mut last_report = t0;
        let mut last_total: u64 = 0;
        let mut started = false;
        loop {
            match receiver.recv().await {
                Ok(Some(msg)) => {
                    if !started {
                        t0 = Instant::now();
                        last_report = t0;
                        started = true;
                    }
                    total += msg.data.len() as u64;
                    drop(msg);
                    let now = Instant::now();
                    if now.duration_since(last_report) >= Duration::from_secs(1) {
                        let interval = (now - last_report).as_secs_f64();
                        let mbps = (total - last_total) as f64 * 8.0 / interval / 1e6;
                        eprintln!("[server] +{interval:.2}s mbps={mbps:.1}");
                        last_report = now;
                        last_total = total;
                    }
                }
                Ok(None) => {
                    eprintln!("[server] channel closed");
                    break;
                }
                Err(e) => {
                    eprintln!("[server] recv error: {}", e);
                    break;
                }
            }
        }
        let elapsed = (Instant::now() - t0).as_secs_f64();
        if elapsed > 0.0 {
            let avg_mbps = total as f64 * 8.0 / elapsed / 1e6;
            eprintln!("[server] TOTAL bytes={total} elapsed={elapsed:.2}s avg_mbps={avg_mbps:.1}");
        }
        return Ok(());
    }

    if mode == "client" {
        if args.len() < 5 {
            eprintln!(
                "usage: throughput_bench client <socket> <name> <peer-list.txt> [seconds] [payload_bytes]"
            );
            std::process::exit(2);
        }
        let peer_list_path = Path::new(&args[4]);
        let seconds: f64 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(10.0);
        let payload_bytes: usize = args.get(6).and_then(|s| s.parse().ok()).unwrap_or(60_000);

        let peers = load_peer_list(peer_list_path, name).map_err(ClientError::Protocol)?;
        if peers.is_empty() {
            eprintln!("[client] no peers in list (after filtering self)");
            std::process::exit(1);
        }
        let target = &peers[0];
        eprintln!(
            "[client] connecting to {} (payload={} B, secs={})",
            target.name, payload_bytes, seconds
        );

        let client = VeilClient::connect(socket).await?;
        let handle = client.bind_named(NAMESPACE, name, ENDPOINT_ID).await?;
        let (sender, _receiver) = handle.into_split();

        let payload = vec![0xABu8; payload_bytes];
        let deadline = Instant::now() + Duration::from_secs_f64(seconds);
        let mut total: u64 = 0;
        let mut count: u64 = 0;
        let mut errors: u64 = 0;
        let mut t0 = Instant::now();
        let mut last_report = t0;
        let mut last_total: u64 = 0;
        let mut started = false;

        // Wait a moment for session to stabilize.
        tokio::time::sleep(Duration::from_millis(500)).await;

        while Instant::now() < deadline {
            match sender
                .send(target.node_id, target.app_id, target.endpoint_id, &payload)
                .await
            {
                Ok(()) => {
                    if !started {
                        t0 = Instant::now();
                        last_report = t0;
                        started = true;
                    }
                    total += payload.len() as u64;
                    count += 1;
                    let now = Instant::now();
                    if now.duration_since(last_report) >= Duration::from_secs(1) {
                        let interval = (now - last_report).as_secs_f64();
                        let mbps = (total - last_total) as f64 * 8.0 / interval / 1e6;
                        let pps = (count as f64) / (now - t0).as_secs_f64();
                        eprintln!("[client] +{interval:.2}s mbps={mbps:.1} pps_avg={pps:.0}");
                        last_report = now;
                        last_total = total;
                    }
                }
                Err(e) => {
                    errors += 1;
                    if errors < 5 {
                        eprintln!("[client] send err: {}", e);
                    }
                    if errors > 1000 {
                        break;
                    }
                }
            }
        }
        let elapsed = (Instant::now() - t0).as_secs_f64();
        if elapsed > 0.0 {
            let avg_mbps = total as f64 * 8.0 / elapsed / 1e6;
            let avg_pps = count as f64 / elapsed;
            eprintln!(
                "[client] TOTAL bytes={total} packets={count} elapsed={elapsed:.2}s avg_mbps={avg_mbps:.1} pps={avg_pps:.0} errors={errors}"
            );
        }
        return Ok(());
    }

    eprintln!("unknown mode: {}", mode);
    std::process::exit(2);
}
