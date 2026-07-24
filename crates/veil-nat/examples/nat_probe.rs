//! NAT mapping classifier for Stage B diagnostics.
//!
//! Queries every reflector passed on the command line from the SAME local UDP
//! socket and compares the observed server-reflexive endpoints:
//!   * identical mapping across reflector IPs  => endpoint-independent (cone)
//!   * mapping varies per destination          => symmetric / CGNAT-style
//!
//! A second socket repeats the sweep so the port-allocation delta between
//! consecutive sockets is visible (port-prediction feasibility input).
//!
//! Usage: nat_probe <reflector-addr> [<reflector-addr> ...]

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::net::UdpSocket;
use veil_nat::discover_udp_mapping;

fn token(salt: u8) -> [u8; 16] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let pid = std::process::id();
    let mut out = [salt; 16];
    out[..4].copy_from_slice(&nanos.to_be_bytes());
    out[4..8].copy_from_slice(&pid.to_be_bytes());
    out
}

async fn sweep(
    label: &str,
    reflectors: &[SocketAddr],
) -> std::io::Result<BTreeMap<SocketAddr, Option<SocketAddr>>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local = socket.local_addr()?;
    let mut observed = BTreeMap::new();
    for (index, reflector) in reflectors.iter().enumerate() {
        let mapping = discover_udp_mapping(
            &socket,
            *reflector,
            token(index as u8),
            Duration::from_secs(2),
        )
        .await?;
        match mapping {
            Some(mapped) => println!("{label} local={local} reflector={reflector} mapped={mapped}"),
            None => println!("{label} local={local} reflector={reflector} mapped=NONE"),
        }
        observed.insert(*reflector, mapping);
    }
    // Re-query the first reflector to confirm the mapping is stable in time,
    // not merely identical across destinations.
    if let Some(first) = reflectors.first() {
        let again = discover_udp_mapping(&socket, *first, token(0xEE), Duration::from_secs(2)).await?;
        match again {
            Some(mapped) => println!("{label} recheck reflector={first} mapped={mapped}"),
            None => println!("{label} recheck reflector={first} mapped=NONE"),
        }
    }
    Ok(observed)
}

fn classify(label: &str, observed: &BTreeMap<SocketAddr, Option<SocketAddr>>) {
    let answered: Vec<SocketAddr> = observed.values().flatten().copied().collect();
    if answered.len() < 2 {
        println!("{label} verdict=INSUFFICIENT replies={}", answered.len());
        return;
    }
    let ports: Vec<u16> = answered.iter().map(SocketAddr::port).collect();
    let ips: Vec<_> = answered.iter().map(|a| a.ip()).collect();
    let same_port = ports.windows(2).all(|w| w[0] == w[1]);
    let same_ip = ips.windows(2).all(|w| w[0] == w[1]);
    if same_port && same_ip {
        println!("{label} verdict=ENDPOINT_INDEPENDENT (cone, punchable)");
    } else if same_ip {
        println!("{label} verdict=SYMMETRIC (same IP, per-destination ports {ports:?})");
    } else {
        println!("{label} verdict=SYMMETRIC_MULTI_IP (ips {ips:?} ports {ports:?})");
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let reflectors: Vec<SocketAddr> = std::env::args()
        .skip(1)
        .filter_map(|arg| arg.parse().ok())
        .collect();
    if reflectors.is_empty() {
        eprintln!("usage: nat_probe <reflector-addr> [<reflector-addr> ...]");
        std::process::exit(2);
    }
    let first = sweep("SOCK_A", &reflectors).await?;
    classify("SOCK_A", &first);
    let second = sweep("SOCK_B", &reflectors).await?;
    classify("SOCK_B", &second);
    let ports = |m: &BTreeMap<SocketAddr, Option<SocketAddr>>| -> Vec<u16> {
        m.values().flatten().map(SocketAddr::port).collect()
    };
    println!("PORTS_A={:?} PORTS_B={:?}", ports(&first), ports(&second));
    Ok(())
}
