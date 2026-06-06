//! Quick dial smoke test: connect к а remote `obfs4-tcp://host:port`
//! and complete the handshake.  Reports success/failure.
//!
//! Usage: `obfs4-dial <host:port> <psk_b64_file>`

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::net::TcpStream;
use veil_obfs4::{NodeIdMacKey, obfs4_client_connect};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <host:port> <psk_b64_file>", args[0]);
        std::process::exit(2);
    }
    let target = &args[1];
    let psk_path = &args[2];

    let raw = std::fs::read_to_string(psk_path)?;
    let decoded = BASE64.decode(raw.trim())?;
    if decoded.len() != 32 {
        eprintln!("PSK must be 32 bytes, got {}", decoded.len());
        std::process::exit(2);
    }
    let mut psk_bytes = [0u8; 32];
    psk_bytes.copy_from_slice(&decoded);
    let psk = NodeIdMacKey(psk_bytes);

    println!("dialing {target} ...");
    let t0 = std::time::Instant::now();
    let tcp = TcpStream::connect(target).await?;
    let after_tcp = t0.elapsed();
    println!("TCP connected after {after_tcp:?}");

    println!("running obfs4 handshake ...");
    let t_hs = std::time::Instant::now();
    let _stream = obfs4_client_connect(tcp, &psk).await?;
    let after_hs = t_hs.elapsed();
    let total = t0.elapsed();
    println!("✓ obfs4 handshake completed after {after_hs:?} (total {total:?})");
    println!("✓ smoke test PASSED");
    Ok(())
}
