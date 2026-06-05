//! Multi-party chat server example.
//!
//! Maintains an in-memory subscriber list and broadcasts MESSAGE frames to
//! every subscriber except the sender. Wire format on top of the IPC API:
//!
//! SUBSCRIBE = [0x53][32B subscriber_app_id][4B subscriber_endpoint_id BE]
//! MESSAGE = [0x4D][2B name_len BE][name_bytes][2B msg_len BE][msg_bytes]
//!
//! On SUBSCRIBE the server registers `(src_node_id, sub_app_id, sub_endpoint)`
//! and ack's nothing (idempotent). On MESSAGE it re-emits the same payload
//! to every other subscriber. Disconnects are detected via send-failure +
//! lazy eviction (a subscriber whose forward fails is dropped).
//!
//! Usage:
//! chat_server <ipc_socket> <namespace> <name> <endpoint_id>
//!
//! Unix-only. Drop the matching `chat_client` on N other nodes pointing
//! at this server's `(node_id, app_id, endpoint_id)`.

#[cfg(not(unix))]
fn main() {
    eprintln!("chat_server is Unix-only.");
    std::process::exit(0);
}

#[cfg(unix)]
use veilclient::{ClientError, VeilClient};

#[cfg(unix)]
const MSG_SUBSCRIBE: u8 = 0x53; // 'S'
#[cfg(unix)]
const MSG_MESSAGE: u8 = 0x4D; // 'M'

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), ClientError> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: chat_server <socket> <namespace> <name> <endpoint_id>");
        std::process::exit(1);
    }
    let socket_path = &args[1];
    let namespace = &args[2];
    let name = &args[3];
    let endpoint_id: u32 = args[4].parse().expect("endpoint_id must be u32");

    let client = VeilClient::connect(socket_path).await?;
    let mut handle = client.bind(namespace, name, endpoint_id).await?;
    let app_id_hex: String = handle
        .app_id()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!(
        "chat_server up: endpoint_id={} app_id={}",
        handle.endpoint_id(),
        app_id_hex
    );
    println!("Subscribers connect via the SUBSCRIBE wire format documented in the source.");

    // (node_id, app_id, endpoint_id) — order of insertion preserved for
    // deterministic broadcast logging.
    let mut subscribers: Vec<([u8; 32], [u8; 32], u32)> = Vec::new();

    while let Some(msg) = handle.recv().await? {
        if msg.data.is_empty() {
            eprintln!("[warn] empty frame from {}", hex_short(&msg.src_node_id));
            continue;
        }
        match msg.data[0] {
            MSG_SUBSCRIBE => {
                if msg.data.len() < 1 + 32 + 4 {
                    eprintln!(
                        "[warn] short SUBSCRIBE from {}",
                        hex_short(&msg.src_node_id)
                    );
                    continue;
                }
                let mut sub_app_id = [0u8; 32];
                sub_app_id.copy_from_slice(&msg.data[1..33]);
                let sub_endpoint =
                    u32::from_be_bytes([msg.data[33], msg.data[34], msg.data[35], msg.data[36]]);
                let entry = (msg.src_node_id, sub_app_id, sub_endpoint);
                if !subscribers.contains(&entry) {
                    subscribers.push(entry);
                    println!(
                        "[+] SUBSCRIBE from node={} app={} endpoint={} (total: {})",
                        hex_short(&msg.src_node_id),
                        hex_short(&sub_app_id),
                        sub_endpoint,
                        subscribers.len(),
                    );
                }
            }
            MSG_MESSAGE => {
                let preview_len = msg.data.len().min(80);
                println!(
                    "[~] MESSAGE from node={} ({} bytes) — broadcasting to {} subs",
                    hex_short(&msg.src_node_id),
                    msg.data.len() - 1,
                    subscribers.len().saturating_sub(1),
                );
                if msg.data.len() < preview_len {
                    eprintln!("[warn] frame too short for preview");
                }
                // Broadcast to every subscriber except the sender.
                let mut to_drop: Vec<usize> = Vec::new();
                for (i, (n, a, e)) in subscribers.iter().enumerate() {
                    if *n == msg.src_node_id {
                        continue;
                    }
                    if let Err(err) = handle.send(*n, *a, *e, &msg.data).await {
                        eprintln!(
                            "[!] forward to {} failed: {} — dropping subscriber",
                            hex_short(n),
                            err,
                        );
                        to_drop.push(i);
                    }
                }
                // Lazy eviction.
                for idx in to_drop.into_iter().rev() {
                    subscribers.swap_remove(idx);
                }
            }
            other => {
                eprintln!(
                    "[warn] unknown msg type 0x{:02x} from {}",
                    other,
                    hex_short(&msg.src_node_id),
                );
            }
        }
    }
    let _ = name;
    Ok(())
}

#[cfg(unix)]
fn hex_short(b: &[u8; 32]) -> String {
    b.iter().take(4).map(|x| format!("{:02x}", x)).collect()
}
