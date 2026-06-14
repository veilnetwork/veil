//! Multi-party chat client (matches `chat_server` example).
//!
//! Mode of operation: subscribe + emit a heartbeat message every
//! `--interval-ms` ms + print every received broadcast. Designed for
//! automated demos / soak tests across a testnet — no interactive
//! stdin, no shutdown signal handling beyond Ctrl-C.
//!
//! Wire format: see `chat_server.rs`.
//!
//! Usage:
//! chat_client <ipc_socket> <server_node_hex> <server_app_id_hex> \
//! <server_endpoint_id> <my_name> [--interval-ms N]

#[cfg(not(unix))]
fn main() {
    eprintln!("chat_client is Unix-only.");
    std::process::exit(0);
}

#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use veilclient::{ClientError, VeilClient};

#[cfg(unix)]
const MSG_SUBSCRIBE: u8 = 0x53;
#[cfg(unix)]
const MSG_MESSAGE: u8 = 0x4D;

#[cfg(unix)]
fn parse_hex32(s: &str) -> [u8; 32] {
    if s.len() != 64 {
        panic!("hex must be 64 chars");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("invalid hex");
    }
    out
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), ClientError> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "Usage: chat_client <socket> <server_node_hex> <server_app_id_hex> \
             <server_endpoint_id> <my_name> [--interval-ms N]"
        );
        std::process::exit(1);
    }
    let socket_path = &args[1];
    let server_node = parse_hex32(&args[2]);
    let server_app = parse_hex32(&args[3]);
    let server_ep: u32 = args[4].parse().expect("endpoint_id must be u32");
    let my_name = args[5].clone();
    let mut interval_ms: u64 = 5_000;
    let mut i = 6;
    while i < args.len() {
        match args[i].as_str() {
            "--interval-ms" => {
                interval_ms = args[i + 1].parse().expect("interval-ms must be u64");
                i += 2;
            }
            other => {
                eprintln!("[warn] unknown arg: {}", other);
                i += 1;
            }
        }
    }

    let client = VeilClient::connect(socket_path).await?;
    // Bind on the SAME endpoint_id we subscribe with — server addresses
    // the broadcast (our_node, our_app_id, our_endpoint).
    let mut handle = client
        .bind("myapp.example", "chat-client", server_ep)
        .await?;
    let my_app_id_hex: String = handle
        .app_id()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!(
        "chat_client {} up: endpoint_id={} app_id={} → server={} ep={}",
        my_name,
        handle.endpoint_id(),
        my_app_id_hex,
        hex_short(&server_node),
        server_ep,
    );

    // Send SUBSCRIBE. Wire: [0x53][32B my_app_id][4B my_endpoint BE].
    {
        let mut payload = Vec::with_capacity(1 + 32 + 4);
        payload.push(MSG_SUBSCRIBE);
        payload.extend_from_slice(handle.app_id());
        payload.extend_from_slice(&handle.endpoint_id().to_be_bytes());
        handle
            .send(server_node, server_app, server_ep, &payload)
            .await?;
        println!("[->] SUBSCRIBE sent");
    }

    // Two concurrent loops:
    // heartbeat: every interval, send "hello #N from <my_name>"
    // recv: print incoming MESSAGE frames forever
    // Run both on the same handle by `select!`'ing inside one loop; the
    // veilclient API uses owned `&mut handle`, so split via channel
    // would clone the world. Tokio's `select!` over `recv` + a sleep
    // is the simplest pattern.
    let mut counter: u64 = 0;
    let mut sleeper = tokio::time::interval(Duration::from_millis(interval_ms));
    sleeper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    sleeper.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            biased;
            _ = sleeper.tick() => {
                counter += 1;
                let body = format!("hello #{} from {}", counter, my_name);
                let mut payload = Vec::with_capacity(1 + 2 + my_name.len() + 2 + body.len());
                payload.push(MSG_MESSAGE);
                let name_bytes = my_name.as_bytes();
                payload.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
                payload.extend_from_slice(name_bytes);
                payload.extend_from_slice(&(body.len() as u16).to_be_bytes());
                payload.extend_from_slice(body.as_bytes());
                if let Err(e) = handle.send(server_node, server_app, server_ep, &payload).await {
                    eprintln!("[!] send #{} failed: {}", counter, e);
                } else {
                    println!("[->] MESSAGE #{} sent ({} bytes)", counter, payload.len() - 1);
                }
            }
            recvd = handle.recv() => {
                match recvd {
                    Ok(Some(msg)) => {
                        if msg.data.first() != Some(&MSG_MESSAGE) {
                            eprintln!(
                                "[?] unexpected frame type 0x{:02x} from {}",
                                msg.data.first().copied().unwrap_or(0),
                                hex_short(&msg.src_node_id),
                            );
                            continue;
                        }
                        // [0x4D][2B name_len][name][2B msg_len][msg]
                        if msg.data.len() < 1 + 2 {
                            eprintln!("[warn] short MESSAGE from {}", hex_short(&msg.src_node_id));
                            continue;
                        }
                        let name_len = u16::from_be_bytes([msg.data[1], msg.data[2]]) as usize;
                        if msg.data.len() < 1 + 2 + name_len + 2 {
                            eprintln!("[warn] truncated MESSAGE name from {}", hex_short(&msg.src_node_id));
                            continue;
                        }
                        let name_bytes = &msg.data[3 .. 3 + name_len];
                        let msg_len_off = 3 + name_len;
                        let msg_len = u16::from_be_bytes([
                            msg.data[msg_len_off], msg.data[msg_len_off + 1],
                        ]) as usize;
                        let body_off = msg_len_off + 2;
                        if msg.data.len() < body_off + msg_len {
                            eprintln!("[warn] truncated MESSAGE body from {}", hex_short(&msg.src_node_id));
                            continue;
                        }
                        let body_bytes = &msg.data[body_off .. body_off + msg_len];
                        let from = String::from_utf8_lossy(name_bytes);
                        let body = String::from_utf8_lossy(body_bytes);
                        println!("[<-] {} → {}: {}", hex_short(&msg.src_node_id), from, body);
                    }
                    Ok(None) => {
                        eprintln!("[!] IPC closed — exiting");
                        break;
                    }
                    Err(e) => {
                        eprintln!("[!] recv error: {}", e);
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn hex_short(b: &[u8; 32]) -> String {
    b.iter().take(4).map(|x| format!("{:02x}", x)).collect()
}
