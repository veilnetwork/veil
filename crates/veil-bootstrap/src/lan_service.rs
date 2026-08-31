//! The socket half of bootstrap layer 6. See [`crate::lan`] for the wire
//! format and for why it is the one BitTorrent uses.
//!
//! # Sharing the port
//!
//! This binds the port a real BitTorrent client also wants, and that is
//! deliberate — it is the same group, so it has to be. The bind therefore
//! asks for address reuse (and port reuse where the platform has it) before
//! it asks for the port: a node that took 6771 exclusively would break the
//! user's torrent client, and a machine that suddenly stopped doing LSD the
//! day veil was installed is a more interesting event than either program on
//! its own.
//!
//! # What this costs when idle
//!
//! One datagram of about 200 bytes per announce interval, to the local
//! segment only — a multicast TTL of 1 does not leave the link, so this
//! traffic is never metered and never leaves the building. Receiving costs
//! whatever the LAN already carries; on a segment with torrent clients that
//! is a handful of datagrams a minute, each rejected in a few hundred
//! nanoseconds of BLAKE3.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use veil_types::BootstrapPeer;

use crate::lan::{
    CURRENT_EXCHANGE_VERSION, LSD_GROUP_V4, LSD_PORT, LanAnnounce, MAX_ANNOUNCE_BYTES, SALT_LEN,
    decode_announce, encode_announce,
};

/// BEP 14 asks clients not to announce more often than every five minutes.
/// We are a guest on that group; keeping its own manners is both polite and
/// the least remarkable thing to do.
pub const DEFAULT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);

/// A bound LAN discovery socket.
pub struct LanDiscovery {
    socket: UdpSocket,
    /// What this node says about itself.
    announce: LanAnnounce,
}

impl LanDiscovery {
    /// Join the group and bind the port.
    ///
    /// Binds `0.0.0.0` and joins on the unspecified interface, which leaves
    /// the choice of interface to the routing table. On a multi-homed host
    /// that is one interface rather than all of them — a real limit, and the
    /// reason it is acceptable is that the payload carries no address, so the
    /// only cost is not being heard on the other segments, never being heard
    /// wrongly.
    pub async fn bind(announce: LanAnnounce) -> io::Result<Self> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        // Reuse BEFORE bind, or the option does not apply to it.
        sock.set_reuse_address(true)?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
        sock.set_nonblocking(true)?;
        let bind_addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LSD_PORT));
        sock.bind(&bind_addr.into())?;
        sock.join_multicast_v4(&LSD_GROUP_V4, &Ipv4Addr::UNSPECIFIED)?;
        // Stay on the link. This is the whole scope guarantee of the layer.
        sock.set_multicast_ttl_v4(1)?;

        let std_sock: std::net::UdpSocket = sock.into();
        Ok(Self {
            socket: UdpSocket::from_std(std_sock)?,
            announce,
        })
    }

    /// The address this socket is bound to — for tests and diagnostics.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send one announce, with a fresh salt.
    pub async fn announce_once(&self) -> io::Result<()> {
        use rand_core::RngCore as _;
        let mut salt = [0u8; SALT_LEN];
        rand_core::OsRng.fill_bytes(&mut salt);
        let wire = encode_announce(
            &self.announce,
            salt,
            CURRENT_EXCHANGE_VERSION,
            IpAddr::V4(LSD_GROUP_V4),
        );
        let dest = SocketAddr::from(SocketAddrV4::new(LSD_GROUP_V4, LSD_PORT));
        self.socket.send_to(wire.as_bytes(), dest).await?;
        Ok(())
    }

    /// Wait for one datagram and say what it was.
    ///
    /// `Ok(None)` means the datagram was not a veil announce, or was our own —
    /// both ordinary on a shared group, neither an error.
    pub async fn recv_peer(&self) -> io::Result<Option<BootstrapPeer>> {
        let mut buf = [0u8; MAX_ANNOUNCE_BYTES];
        let (n, from) = self.socket.recv_from(&mut buf).await?;
        Ok(self.interpret(&buf[..n], from.ip()))
    }

    /// The decision `recv_peer` makes, with the socket taken out of it.
    ///
    /// Split out because it is the half worth testing: a multicast round trip
    /// needs a network stack that forwards to loopback, which not every CI
    /// container has, and a test that silently does not exercise the code is
    /// worse than no test.
    pub fn interpret(&self, datagram: &[u8], from: IpAddr) -> Option<BootstrapPeer> {
        let heard = decode_announce(datagram)?;
        if heard.public_key == self.announce.public_key {
            // Our own announce, arriving back through multicast loopback.
            return None;
        }
        Some(heard.into_bootstrap_peer(from))
    }

    /// Announce on a timer and report what is heard, until the channel is
    /// dropped.
    ///
    /// Returns when the receiver goes away, which is what makes this stoppable:
    /// the caller drops its end and this returns rather than being aborted
    /// mid-send.
    pub async fn run(
        self,
        interval: Duration,
        found: tokio::sync::mpsc::Sender<BootstrapPeer>,
    ) -> io::Result<()> {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.announce_once().await {
                        // A LAN that will not take a multicast datagram is a
                        // normal state (no route, interface down); it must not
                        // end the layer.
                        log::debug!("lan_discovery: announce failed: {e}");
                    }
                }
                heard = self.recv_peer() => {
                    match heard {
                        Ok(Some(peer)) => {
                            if found.send(peer).await.is_err() {
                                return Ok(());
                            }
                        }
                        Ok(None) => {}
                        Err(e) => return Err(e),
                    }
                }
                _ = found.closed() => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::LanScheme;

    fn announce(key: u8) -> LanAnnounce {
        LanAnnounce {
            public_key: [key; 32],
            pow_nonce: [1, 2, 3, 4],
            port: 5556,
            scheme: LanScheme::Obfs4Tcp,
        }
    }

    fn wire_from(a: &LanAnnounce) -> String {
        encode_announce(
            a,
            [9, 9, 9, 9],
            CURRENT_EXCHANGE_VERSION,
            IpAddr::V4(LSD_GROUP_V4),
        )
    }

    async fn bound(key: u8) -> Option<LanDiscovery> {
        // A host with no multicast-capable interface cannot bind this; say so
        // rather than failing, and let the caller decide.
        LanDiscovery::bind(announce(key)).await.ok()
    }

    #[tokio::test]
    async fn our_own_announce_coming_back_is_not_a_peer() {
        // Multicast loopback is on by default on most stacks, so a node hears
        // itself. Dialling yourself is the failure this prevents.
        let Some(node) = bound(0xAA).await else {
            return;
        };
        let own = wire_from(&announce(0xAA));
        assert!(
            node.interpret(own.as_bytes(), "192.168.1.42".parse().unwrap())
                .is_none(),
            "a node took its own announce for a peer"
        );
    }

    #[tokio::test]
    async fn a_neighbours_announce_becomes_a_dialable_peer() {
        let Some(node) = bound(0xAA).await else {
            return;
        };
        let theirs = wire_from(&announce(0xBB));
        let peer = node
            .interpret(theirs.as_bytes(), "192.168.1.43".parse().unwrap())
            .expect("a neighbour's announce was not understood");
        assert_eq!(peer.transport, "obfs4-tcp://192.168.1.43:5556");
    }

    #[tokio::test]
    async fn the_traffic_of_the_group_is_ignored_without_complaint() {
        let Some(node) = bound(0xAA).await else {
            return;
        };
        let noise: Vec<&[u8]> = vec![
            b"BT-SEARCH * HTTP/1.1\r\nPort: 6881\r\nInfohash: 00\r\n\r\n",
            b"\x00\x01\x02\x03",
            b"",
        ];
        for n in noise {
            assert!(node.interpret(n, "192.168.1.44".parse().unwrap()).is_none());
        }
    }

    #[tokio::test]
    async fn binding_twice_works_because_the_port_is_shared() {
        // The property that keeps a torrent client alive on the same host: if
        // this regresses, the second bind is the one that fails, and in the
        // field the second program is somebody else's.
        let Some(first) = bound(0xAA).await else {
            return;
        };
        let second = LanDiscovery::bind(announce(0xBB)).await;
        assert!(
            second.is_ok(),
            "a second bind on the shared LSD port failed: {:?}",
            second.err()
        );
        assert_eq!(first.local_addr().unwrap().port(), LSD_PORT);
    }

    #[tokio::test]
    async fn the_socket_tests_above_are_not_vacuous() {
        // Every test in this module skips itself when the bind fails, because
        // a container without a multicast-capable interface cannot do this and
        // should not turn red for it. That escape is also how all four could
        // quietly test nothing. This one says which happened.
        match LanDiscovery::bind(announce(0xCC)).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("LAN DISCOVERY SOCKET TESTS SKIPPED ON THIS HOST: {e}");
                assert!(
                    std::env::var("VEIL_LAN_SOCKET_MAY_SKIP").is_ok(),
                    "cannot bind the LSD port here ({e}), so the four tests \
                     above tested nothing; set VEIL_LAN_SOCKET_MAY_SKIP=1 if \
                     that is expected on this host"
                );
            }
        }
    }

    #[tokio::test]
    #[ignore = "needs a real multicast-capable interface; run with --ignored"]
    async fn two_nodes_on_one_wire_actually_find_each_other() {
        // The end-to-end claim of this layer, over a real network stack:
        // everything above tests the decision, this tests that the datagram
        // leaves and arrives. Ignored by default because it needs an interface
        // that forwards multicast, which a CI container may not have -- run it
        // with `cargo test -p veil-bootstrap --lib lan_service -- --ignored`.
        //
        // Run 2026-08-31 on macOS 15 over en0: it failed once, on its first
        // execution, and passed the fourteen runs after it -- including three
        // from freshly compiled binaries, which is what the "first run of a new
        // binary" guess predicted would fail and they did not. The cause of
        // that one failure is not known. That is why this stays ignored: an
        // end-to-end test that fails once in fifteen for reasons nobody has
        // named is worth running by hand and not worth wiring into a gate.
        let listener = LanDiscovery::bind(announce(0xAA))
            .await
            .expect("bind listener");
        let speaker = LanDiscovery::bind(announce(0xBB))
            .await
            .expect("bind speaker");

        let heard = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(Some(peer)) = listener.recv_peer().await {
                        return peer;
                    }
                }
            })
            .await
        });

        for _ in 0..5 {
            speaker.announce_once().await.expect("announce");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let peer = heard
            .await
            .expect("join")
            .expect("nothing arrived within five seconds");
        assert!(
            peer.transport.starts_with("obfs4-tcp://"),
            "unexpected transport {}",
            peer.transport
        );
        assert_eq!(
            peer.public_key,
            {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode([0xBBu8; 32])
            },
            "heard somebody, but not the speaker"
        );
    }
}
