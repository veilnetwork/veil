use std::io::Write as _;
use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::debug_transport::handle_debug_attached_stream;
use super::{
    cli::{DebugCommand, DebugNodeCommand, DebugPeersCommand},
    debug_transport::handle_debug_transport_command,
    util::map_node_error,
};
use veil_cfg::{self, ConfigError, Result};
use veil_node_runtime::admin::{
    self as node, ADMIN_PROTOCOL_VERSION, AdminCommand, AdminRequest, AdminResponse, AdminResult,
};
use veil_proto::family::{
    AppMsg, ControlMsg, DeliveryMsg, DiagMsg, DiscoveryMsg, FrameFamily, LocalAppMsg, MeshMsg,
    PexMsg, RelayChainMsg, RoutingMsg, SessionMsg, TunnelMsg,
};
use veil_transport::BoxIoStream;

pub fn handle_debug_command(config_arg: Option<&Path>, command: DebugCommand) -> Result<()> {
    match command {
        DebugCommand::Transport(args) => handle_debug_transport_command(config_arg, args.command),
        DebugCommand::Peers(args) => match args.command {
            DebugPeersCommand::Connect { peer_id } => {
                handle_debug_peer_connect(config_arg, peer_id)
            }
            DebugPeersCommand::Discovered => handle_debug_peers_discovered(config_arg),
        },
        DebugCommand::Node(args) => match args.command {
            DebugNodeCommand::Accept { listen_id } => {
                handle_debug_node_accept(config_arg, listen_id)
            }
        },
        DebugCommand::Ping {
            node_id,
            count,
            interval,
            timeout,
        } => handle_debug_ping(config_arg, node_id, count, interval, timeout),
        DebugCommand::Trace {
            node_id,
            max_hops,
            timeout,
        } => handle_debug_trace(config_arg, node_id, max_hops, timeout),
        DebugCommand::TraceQuery { trace_id } => handle_debug_trace_query(config_arg, trace_id),
        DebugCommand::Capture {
            node_id,
            family,
            limit,
            output,
            verbose,
        } => handle_debug_capture(config_arg, node_id, family, limit, output, verbose),
        DebugCommand::RelaySend {
            path,
            app_id,
            endpoint_id,
            data,
        } => handle_debug_relay_send(config_arg, path, app_id, endpoint_id, data),
    }
}

fn handle_debug_relay_send(
    config_arg: Option<&Path>,
    path: String,
    app_id: String,
    endpoint_id: u32,
    data_hex: String,
) -> Result<()> {
    let runtime = super::util::build_runtime()?;
    runtime.block_on(async move {
        let socket = load_admin_socket(config_arg)?;
        let path_vec: Vec<String> = path
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        if path_vec.is_empty() {
            return Err(ConfigError::ValidationFailed(
                "path must contain at least one comma-separated node_id".to_owned(),
            ));
        }
        let cmd = AdminCommand::RelaySend {
            path: path_vec,
            app_id,
            endpoint_id,
            data_hex,
        };
        let response = node::send_request(&socket, cmd)
            .await
            .map_err(map_node_error)?;
        if let Some(err) = response.error {
            return Err(ConfigError::ValidationFailed(err));
        }
        let Some(AdminResult::RelaySendResult {
            sent,
            first_hop,
            hops,
        }) = response.result
        else {
            return Err(ConfigError::ValidationFailed(
                "admin server returned unexpected relay-send response".to_owned(),
            ));
        };
        println!("relay-send: hops={hops} first_hop={first_hop} sent_to_first_hop={sent}");
        if !sent {
            println!("WARN: first-hop session not registered — frame dropped at sender");
        }
        Ok(())
    })
}

// ── existing debug commands ───────────────────────────────────────────────────

fn handle_debug_peer_connect(config_arg: Option<&Path>, peer_id: veil_cfg::PeerId) -> Result<()> {
    let runtime = super::util::build_runtime()?;
    runtime.block_on(async move {
        let socket = load_admin_socket(config_arg)?;
        let stream = node::open_peer_debug_stream(&socket, peer_id)
            .await
            .map_err(map_node_error)?;
        handle_debug_attached_stream(Box::new(stream) as BoxIoStream).await
    })
}

fn handle_debug_peers_discovered(config_arg: Option<&Path>) -> Result<()> {
    let runtime = super::util::build_runtime()?;
    runtime.block_on(async move {
        let socket = load_admin_socket(config_arg)?;
        let response = node::send_request(&socket, AdminCommand::PeersDiscovered)
            .await
            .map_err(map_node_error)?;
        if let Some(err) = response.error {
            return Err(ConfigError::ValidationFailed(err));
        }
        let Some(AdminResult::DiscoveredPeers { peers }) = response.result else {
            return Err(ConfigError::ValidationFailed(
                "admin server returned unexpected peers-discovered response".to_owned(),
            ));
        };
        if peers.is_empty() {
            println!("no discovered peers (PEX/bootstrap/autodiscovery have not added anyone)");
            return Ok(());
        }
        println!("peer_id     source          bootstrap_only  node_id                                                           transport");
        for p in &peers {
            println!(
                "0x{:08x}  {:<14}  {:<14}  {}  {}",
                p.peer_id,
                p.source,
                if p.bootstrap_only { "yes" } else { "no" },
                p.node_id,
                p.transport,
            );
        }
        Ok(())
    })
}

fn handle_debug_node_accept(
    config_arg: Option<&Path>,
    listen_id: veil_cfg::ListenId,
) -> Result<()> {
    let runtime = super::util::build_runtime()?;
    runtime.block_on(async move {
        let socket = load_admin_socket(config_arg)?;
        let stream = node::open_listen_debug_stream(&socket, listen_id)
            .await
            .map_err(map_node_error)?;
        handle_debug_attached_stream(Box::new(stream) as BoxIoStream).await
    })
}

// ── diagnostic commands ─────────────────────────────────────────────

fn handle_debug_ping(
    config_arg: Option<&Path>,
    node_id: String,
    count: u32,
    interval_ms: u64,
    timeout_ms: u64,
) -> Result<()> {
    let runtime = super::util::build_runtime()?;
    runtime.block_on(async move {
        let socket = load_admin_socket(config_arg)?;
        let command = AdminCommand::DebugPing {
            target:      node_id,
            count,
            interval_ms,
            timeout_ms,
        };
        let lines = open_streaming_command(&socket, command).await?;
        for line in &lines {
            let resp: AdminResponse = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Some(err) = resp.error {
                eprintln!("error: {err}");
                break;
            }
            match resp.result {
                Some(AdminResult::Ack { message }) => println!("{message}"),
                Some(AdminResult::PingReply { seq, rtt_us, peer_id }) => {
                    println!("[{seq}] rtt={rtt_us} µs  peer={}", short_id(&peer_id));
                }
                Some(AdminResult::PingStats { sent, received, lost, rtt_min_us, rtt_avg_us, rtt_max_us }) => {
                    println!(
                        "--- ping stats ---\n{sent} sent, {received} received, {lost} lost\nrtt min/avg/max = {rtt_min_us}/{rtt_avg_us}/{rtt_max_us} µs"
                    );
                }
                _ => {}
            }
        }
        Ok(())
    })
}

fn handle_debug_trace(
    config_arg: Option<&Path>,
    node_id: String,
    max_hops: u8,
    timeout_ms: u64,
) -> Result<()> {
    let runtime = super::util::build_runtime()?;
    runtime.block_on(async move {
        let socket = load_admin_socket(config_arg)?;
        let command = AdminCommand::DebugTrace {
            target: node_id,
            max_hops,
            timeout_ms,
        };
        let lines = open_streaming_command(&socket, command).await?;
        for line in &lines {
            let resp: AdminResponse = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Some(err) = resp.error {
                eprintln!("error: {err}");
                break;
            }
            match resp.result {
                Some(AdminResult::Ack { message }) => println!("{message}"),
                Some(AdminResult::TraceHop {
                    idx,
                    node_id,
                    rtt_us,
                }) => {
                    if node_id == "*" {
                        println!(" {idx:>2}  *  (timeout)");
                    } else {
                        println!(" {idx:>2}  {}  rtt={rtt_us} µs", short_id(&node_id));
                    }
                }
                Some(AdminResult::TraceDone { hops }) => {
                    println!("--- trace complete ({hops} hops) ---");
                }
                _ => {}
            }
        }
        Ok(())
    })
}

fn handle_debug_trace_query(config_arg: Option<&Path>, trace_id: String) -> Result<()> {
    let runtime = super::util::build_runtime()?;
    runtime.block_on(async move {
        let socket = load_admin_socket(config_arg)?;
        let response = node::send_request(&socket, AdminCommand::TraceQuery { trace_id })
            .await
            .map_err(map_node_error)?;
        if let Some(err) = response.error {
            return Err(ConfigError::ValidationFailed(err));
        }
        let Some(AdminResult::TraceHops { trace_id, hops }) = response.result else {
            return Err(ConfigError::ValidationFailed(
                "admin server returned unexpected trace-query response".to_owned(),
            ));
        };
        if hops.is_empty() {
            println!("trace_id={trace_id}: no hops recorded (sample miss or expired)");
            return Ok(());
        }
        println!("trace_id={trace_id}  hops={}", hops.len());
        println!("idx  from        to          rtt_ms  timestamp_ms");
        for (i, h) in hops.iter().enumerate() {
            println!(
                "{:>3}  {}  {}  {:>6}  {}",
                i,
                short_id(&h.from_peer),
                short_id(&h.to_peer),
                h.hop_rtt_ms,
                h.timestamp_ms,
            );
        }
        Ok(())
    })
}

fn handle_debug_capture(
    config_arg: Option<&Path>,
    filter_node_id: Option<String>,
    filter_family: Option<u8>,
    limit: Option<u32>,
    output: Option<std::path::PathBuf>,
    verbose: bool,
) -> Result<()> {
    let runtime = super::util::build_runtime()?;
    runtime.block_on(async move {
        let socket = load_admin_socket(config_arg)?;
        let command = AdminCommand::DebugCapture {
            filter_node_id,
            filter_family,
            limit,
        };
        let mut out_file: Option<std::fs::File> = output
            .as_ref()
            .map(|p| std::fs::File::create(p).map_err(ConfigError::Io))
            .transpose()?;

        // Stream line-by-line so frames are printed as they arrive rather than
        // waiting for the server to close the connection (which never happens
        // for unlimited captures).
        let mut stream = node::connect_admin_client_any(&socket)
            .await
            .map_err(map_node_error)?;
        let request = serde_json::to_string(&AdminRequest {
            version: ADMIN_PROTOCOL_VERSION,
            command,
        })
        .map_err(|e| ConfigError::ValidationFailed(e.to_string()))?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(ConfigError::Io)?;
        stream.write_all(b"\n").await.map_err(ConfigError::Io)?;

        let mut reader = BufReader::new(stream);
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await.map_err(ConfigError::Io)?;
            if n == 0 {
                break;
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                continue;
            }

            let resp: AdminResponse = match serde_json::from_str(trimmed) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Some(err) = resp.error {
                eprintln!("error: {err}");
                break;
            }
            match resp.result {
                Some(AdminResult::Ack { .. }) => {}
                Some(AdminResult::CaptureFrame {
                    ts_us,
                    direction,
                    src_id,
                    dst_id,
                    family,
                    msg_type,
                    body_len,
                    body_hex,
                    e2e_plaintext,
                }) => {
                    let ts_secs = ts_us / 1_000_000;
                    let ts_us_part = ts_us % 1_000_000;
                    let hh = (ts_secs % 86400) / 3600;
                    let mm = (ts_secs % 3600) / 60;
                    let ss = ts_secs % 60;
                    let family_name = family_name(family);
                    let msg_name = msg_type_name(family, msg_type);
                    let e2e_tag = if e2e_plaintext {
                        " [E2E-plaintext]"
                    } else {
                        ""
                    };
                    println!(
                        "{hh:02}:{mm:02}:{ss:02}.{ts_us_part:06}  {direction}  {} → {}  \
                         {family_name}/{msg_name}  len={body_len}{e2e_tag}",
                        short_id(&src_id),
                        short_id(&dst_id),
                    );
                    if verbose {
                        print_hex_dump(&body_hex);
                    }
                    if let Some(ref mut f) = out_file {
                        let json = serde_json::json!({
                            "ts_us":     ts_us,
                            "direction": direction,
                            "src_id":    src_id,
                            "dst_id":    dst_id,
                            "family":    family,
                            "msg_type":  msg_type,
                            "body_len":  body_len,
                            "body_hex":  body_hex,
                            "e2e_plaintext": e2e_plaintext,
                        });
                        let _ = writeln!(f, "{json}");
                    }
                }
                _ => {}
            }
        }
        Ok(())
    })
}

/// Human-readable frame family name, taken from the protocol definition.
///
/// This used to be a hand-copied `match` and it had drifted: family 10 was
/// still labelled `Budget` long after the wire renamed it to `RelayChain`, so
/// a capture of onion circuit cells read as budget accounting. The enum's own
/// doc promises that "a new family cannot be added without a name" — which is
/// true of `FrameFamily::label()`, where the compiler checks exhaustiveness,
/// and false of any second copy of it. So there is no second copy any more.
fn family_name(family: u8) -> String {
    match FrameFamily::try_from(family) {
        Ok(fam) => fam.label().to_owned(),
        Err(_) => format!("unknown({family})"),
    }
}

/// Human-readable `msg_type` name within a family, taken from the protocol
/// definition.
///
/// Every family's message enum carries `TryFrom<u16>` and derives `Debug`, so
/// the variant name comes from the wire definition itself: a new message type
/// is named automatically, and a new *family* fails to compile here until it
/// is added to the match.
fn msg_type_name(family: u8, msg_type: u16) -> String {
    let Ok(fam) = FrameFamily::try_from(family) else {
        return format!("?({msg_type})");
    };
    // Decode `msg_type` as `$ty` and print the variant name it decodes to.
    macro_rules! named {
        ($ty:ty) => {
            <$ty>::try_from(msg_type)
                .map(|m| format!("{m:?}"))
                .unwrap_or_else(|_| format!("?({msg_type})"))
        };
    }
    match fam {
        FrameFamily::Session => named!(SessionMsg),
        FrameFamily::Control => named!(ControlMsg),
        FrameFamily::Discovery => named!(DiscoveryMsg),
        FrameFamily::Delivery => named!(DeliveryMsg),
        FrameFamily::App => named!(AppMsg),
        FrameFamily::Mesh => named!(MeshMsg),
        FrameFamily::LocalApp => named!(LocalAppMsg),
        FrameFamily::Tunnel => named!(TunnelMsg),
        FrameFamily::Routing => named!(RoutingMsg),
        FrameFamily::Diag => named!(DiagMsg),
        FrameFamily::RelayChain => named!(RelayChainMsg),
        FrameFamily::PeerExchange => named!(PexMsg),
    }
}

/// Print a hex dump in tcpdump style: `offset hex-bytes |ascii|`.
/// `hex_str` is a lowercase hex string (pairs of chars per byte).
fn print_hex_dump(hex_str: &str) {
    // Decode hex string into bytes.
    let bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
        .collect();

    for (chunk_idx, chunk) in bytes.chunks(16).enumerate() {
        let offset = chunk_idx * 16;
        // Hex columns (space-separated, padded to 16 bytes wide).
        let hex_cols: String = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        // ASCII sidebar (printable chars only).
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("  {:04x}  {hex_cols:<47}  |{ascii}|", offset);
    }
    println!();
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Open a streaming admin connection: send command, read ACK, return all
/// subsequent lines until EOF.
async fn open_streaming_command(socket: &Path, command: AdminCommand) -> Result<Vec<String>> {
    let mut stream = node::connect_admin_client_any(socket)
        .await
        .map_err(map_node_error)?;
    let request = serde_json::to_string(&AdminRequest {
        version: ADMIN_PROTOCOL_VERSION,
        command,
    })
    .map_err(|e| ConfigError::ValidationFailed(e.to_string()))?;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(ConfigError::Io)?;
    stream.write_all(b"\n").await.map_err(ConfigError::Io)?;
    // Do NOT shutdown write side — server needs to detect EOF from us for cleanup
    // but we read until server closes its side.

    let mut lines = Vec::new();
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.map_err(ConfigError::Io)?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end().to_owned();
        if !trimmed.is_empty() {
            lines.push(trimmed);
        }
    }
    Ok(lines)
}

fn load_admin_socket(config_arg: Option<&Path>) -> Result<std::path::PathBuf> {
    let path = veil_cfg::locate_config(config_arg)?;
    let config = veil_cfg::load_config(&path)?;
    // Pass config dir so TCP-endpoint anchor matches what the server wrote
    // (default `runtime_dir = config dir` for multi-node ergonomics).
    node::admin_socket_path(&config, path.parent()).map_err(map_node_error)
}

/// Show first 8 chars of a hex node_id for compact display.
fn short_id(hex: &str) -> &str {
    &hex[..hex.len().min(8)]
}

#[cfg(test)]
mod capture_name_tests {
    use super::*;

    /// Every family in the protocol, so the round-trip below cannot silently
    /// skip the one that drifted.
    const ALL: [FrameFamily; 12] = [
        FrameFamily::Session,
        FrameFamily::Control,
        FrameFamily::Discovery,
        FrameFamily::Delivery,
        FrameFamily::App,
        FrameFamily::Mesh,
        FrameFamily::LocalApp,
        FrameFamily::Tunnel,
        FrameFamily::Routing,
        FrameFamily::Diag,
        FrameFamily::RelayChain,
        FrameFamily::PeerExchange,
    ];

    /// The row that actually drifted: family 10 is the onion relay chain, and
    /// type 5 on it is a circuit data cell. The hand-copied table called the
    /// family `Budget` and had no name for the type at all, so a capture of
    /// onion traffic read as budget accounting with an unnamed message.
    #[test]
    fn family_ten_is_the_relay_chain() {
        assert_eq!(family_name(10), "relay_chain");
        assert_eq!(msg_type_name(10, 5), "CircuitData");
    }

    /// There is no second copy of the family table. Break-check: hand-write a
    /// name for any single family in `family_name` and this goes red.
    #[test]
    fn every_family_names_itself_as_the_protocol_does() {
        for fam in ALL {
            assert_eq!(
                family_name(fam as u8),
                fam.label(),
                "family {} disagrees with its protocol label",
                fam as u8
            );
        }
    }

    /// Numbers the protocol does not define are reported as unknown rather
    /// than guessed at — a capture must not invent a name for a frame this
    /// build cannot decode.
    #[test]
    fn unknown_numbers_are_marked_not_guessed() {
        assert_eq!(family_name(200), "unknown(200)");
        assert_eq!(msg_type_name(200, 3), "?(3)");
        assert_eq!(msg_type_name(8, 4242), "?(4242)");
    }
}
