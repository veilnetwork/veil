//! Echo server example — binds an endpoint and reflects every incoming datagram.
//!
//! Usage:
//! cargo run --example echo_server -- /run/veil/app.sock myapp.example echo 42
//!
//! Unix-only: uses `VeilClient` over a Unix-domain IPC socket. On Windows
//! applications should talk to the IPC TCP backend via raw frames — see
//! `examples/ovl_proto.py` in the repo root for the wire protocol.

#[cfg(not(unix))]
fn main() {
    eprintln!("echo_server example is Unix-only (requires UnixStream-based VeilClient).");
    std::process::exit(0);
}

#[cfg(unix)]
use veilclient::{ClientError, VeilClient};

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), ClientError> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: echo_server <socket_path> <namespace> <name> <endpoint_id>");
        std::process::exit(1);
    }
    let socket_path = &args[1];
    let namespace = &args[2];
    let name = &args[3];
    let endpoint_id: u32 = args[4].parse().expect("endpoint_id must be u32");

    let client = VeilClient::connect(socket_path).await?;
    println!("Connected to veil node.");

    let mut handle = client.bind(namespace, name, endpoint_id).await?;
    let app_id_hex: String = handle
        .app_id()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!(
        "Bound endpoint {} (app_id={})",
        handle.endpoint_id(),
        app_id_hex,
    );

    println!("Listening for datagrams — ctrl-C to stop.");
    while let Some(msg) = handle.recv().await? {
        println!(
            "Received {} bytes from {:?}",
            msg.data.len(),
            &msg.src_node_id[..4]
        );
        // Reflect back — the destination app_id is carried in the first 32 bytes
        // of the payload by the ping client (application-level convention).
        if msg.data.len() >= 32 {
            let mut dst_app_id = [0u8; 32];
            dst_app_id.copy_from_slice(&msg.data[..32]);
            let data = &msg.data[32..];
            handle
                .send(msg.src_node_id, dst_app_id, endpoint_id, data)
                .await?;
        }
    }

    Ok(())
}
