//! Ping client example — sends a datagram and waits for the echo.
//!
//! Usage:
//! cargo run --example ping_client -- /run/veil/app.sock <dst_node_hex> <endpoint_id>
//!
//! Unix-only — see `examples/echo_server.rs` for the rationale.

#[cfg(not(unix))]
fn main() {
    eprintln!("ping_client example is Unix-only (requires UnixStream-based VeilClient).");
    std::process::exit(0);
}

#[cfg(unix)]
use veilclient::{ClientError, VeilClient};

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), ClientError> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "Usage: ping_client <socket_path> <dst_node_hex_64chars> <dst_app_id_hex_64chars> <endpoint_id>"
        );
        std::process::exit(1);
    }
    let socket_path = &args[1];
    let dst_node_hex = &args[2];
    let dst_app_hex = &args[3];
    let endpoint_id: u32 = args[4].parse().expect("endpoint_id must be u32");

    let parse_hex32 = |s: &str| -> [u8; 32] {
        if s.len() != 64 {
            panic!("hex must be 64 chars");
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("invalid hex");
        }
        out
    };

    let dst_node_id = parse_hex32(dst_node_hex);
    let dst_app_id = parse_hex32(dst_app_hex);

    let client = VeilClient::connect(socket_path).await?;
    println!("Connected to veil node.");

    // Bind with the SAME endpoint_id we're targeting, so echo_server's
    // reflected reply (which uses its own endpoint_id == our target's
    // endpoint_id) lands on our handle. Otherwise the reply has
    // nowhere to deliver and is dropped at the IPC layer.
    let mut handle = client.bind("ping.example", "client", endpoint_id).await?;
    let my_app_id_hex: String = handle
        .app_id()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!(
        "Bound with endpoint_id={} app_id={}",
        handle.endpoint_id(),
        my_app_id_hex
    );

    // Echo-server protocol: first 32 bytes of payload = reply-target app_id
    // (= our own app_id, so the server reflects back to us).
    let mut payload = Vec::with_capacity(36);
    payload.extend_from_slice(handle.app_id());
    payload.extend_from_slice(b"ping");
    handle
        .send(dst_node_id, dst_app_id, endpoint_id, &payload)
        .await?;
    println!(
        "Sent ping ({} total bytes, 4 payload bytes after 32-byte reply-app_id)",
        payload.len()
    );

    // Wait up to 5 seconds for a reply.
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), handle.recv()).await;

    match timeout {
        Ok(Ok(Some(msg))) => {
            println!(
                "Pong received: {} bytes from {:?}",
                msg.data.len(),
                &msg.src_node_id[..4]
            );
        }
        Ok(Ok(None)) => println!("Connection closed before pong arrived."),
        Ok(Err(e)) => eprintln!("Recv error: {e}"),
        Err(_) => println!("Timeout — no pong within 5 s."),
    }

    Ok(())
}
