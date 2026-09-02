//! The socket half of bootstrap layer 6. See [`crate::lan`] for the wire
//! format and for why it is the one BitTorrent uses.
//!
//! # Sharing the port
//!
//! This binds the port a real BitTorrent client also wants, and that is
//! deliberate — it is the same group, so it has to be. The bind therefore asks
//! for `SO_REUSEADDR` before it asks for the port: a node that took 6771
//! exclusively would break the user's torrent client, and a machine that
//! suddenly stopped doing LSD the day veil was installed is a more interesting
//! event than either program on its own.
//!
//! `SO_REUSEPORT` goes with it on the platforms that have it, because on BSD
//! a second bind fails without it — see the note at the bind for what was
//! measured.
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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use tokio::net::UdpSocket;
use veil_types::BootstrapPeer;

use crate::lan::{
    CURRENT_EXCHANGE_VERSION, LSD_GROUP_V4, LSD_GROUP_V6, LSD_PORT, LanAnnounce,
    MAX_ANNOUNCE_BYTES, SALT_LEN, decode_announce, encode_announce,
};

/// BEP 14 asks clients not to announce more often than every five minutes.
/// We are a guest on that group; keeping its own manners is both polite and
/// the least remarkable thing to do.
///
/// The loop that uses this lives in the node runtime rather than here, on
/// purpose: a driver spawned from inside this crate would have to be owned by
/// somebody, and a `JoinHandle` dropped on shutdown DETACHES rather than
/// aborting — which is how a socket outlives the node that opened it.
pub const DEFAULT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);

/// How long to wait before announce number `already_sent`.
///
/// Not a flat interval, because a flat one leaves a real gap: a node that
/// starts six seconds after its neighbour missed that neighbour's only
/// announce and waits five minutes for the next. Measured, not imagined --
/// two nodes on this machine, and the second one found nothing for exactly
/// that reason.
///
/// So the first few come quickly and then back off to BEP 14's cadence: a
/// node joining a quiet LAN is heard within a minute, and a node that has
/// been up for an hour costs the segment one small datagram every five
/// minutes.
pub fn announce_delay(already_sent: u32) -> Duration {
    match already_sent {
        0 => Duration::from_secs(0),
        1 => Duration::from_secs(3),
        2 => Duration::from_secs(12),
        3 => Duration::from_secs(45),
        _ => DEFAULT_ANNOUNCE_INTERVAL,
    }
}

/// A bound LAN discovery socket.
pub struct LanDiscovery {
    socket: UdpSocket,
    /// The IPv6 half, on `LSD_GROUP_V6`. `None` where the host has no IPv6.
    ///
    /// The group has been exported and covered by an encoding test since this
    /// layer was written, and nothing ever bound it: the code read as though
    /// it spoke both families and spoke one.
    socket6: Option<UdpSocket>,
    /// What this node says about itself, or `None` when it has nothing to
    /// say. A node with no listener a stranger could dial still LISTENS —
    /// "it asks and it listens; only publishing is opt-in" — and until this
    /// was optional, having nothing to announce meant the whole layer, receive
    /// included, never started (report21 V20-M4).
    announce: Option<LanAnnounce>,
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
        Self::bind_inner(Some(announce)).await
    }

    /// Bind the same sockets with nothing to announce: receive only.
    pub async fn bind_listen_only() -> io::Result<Self> {
        Self::bind_inner(None).await
    }

    async fn bind_inner(announce: Option<LanAnnounce>) -> io::Result<Self> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        // Reuse BEFORE bind, or the option does not apply to it.
        //
        // Both options, and SO_REUSEPORT is not optional on BSD: measured on
        // macOS 15, a second bind of this port with SO_REUSEADDR alone fails
        // with EADDRINUSE, which would mean the second veil node on a host --
        // or veil beside a torrent client -- simply has no local discovery.
        //
        // Fan-out survives it. The worry that SO_REUSEPORT makes the kernel
        // hand each datagram to ONE socket of the group is real for unicast
        // UDP on Linux; measured here with two listeners on 0.0.0.0:6771, both
        // received every datagram.
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
        // The v6 half, on the group this crate has exported and never used.
        // Attempted, not required: a host with no IPv6 is ordinary, and the v4
        // half is what local discovery has always run on.
        let socket6 = Self::bind_v6().ok();
        Ok(Self {
            socket: UdpSocket::from_std(std_sock)?,
            socket6,
            announce,
        })
    }

    /// The IPv6 listener: same port, same scope guarantee, `ff15::efc0:988f`.
    fn bind_v6() -> io::Result<UdpSocket> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        sock.set_reuse_address(true)?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
        sock.set_nonblocking(true)?;
        // v6-only: the v4 half has its own socket, and a dual-stack bind would
        // fight it for the port.
        sock.set_only_v6(true)?;
        let bind_addr = SocketAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, LSD_PORT, 0, 0));
        sock.bind(&bind_addr.into())?;
        // Interface 0 asks the kernel to pick; a host with several is joined on
        // its default, which is the same promise the v4 side makes.
        sock.join_multicast_v6(&LSD_GROUP_V6, 0)?;
        sock.set_multicast_hops_v6(1)?;
        let std_sock: std::net::UdpSocket = sock.into();
        UdpSocket::from_std(std_sock)
    }

    /// The address this socket is bound to — for tests and diagnostics.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send one announce, with a fresh salt.
    pub async fn announce_once(&self) -> io::Result<()> {
        use rand_core::RngCore as _;
        let Some(self_announce) = &self.announce else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this node has no listener to announce",
            ));
        };
        let mut salt = [0u8; SALT_LEN];
        rand_core::OsRng.fill_bytes(&mut salt);
        let wire = encode_announce(
            self_announce,
            salt,
            CURRENT_EXCHANGE_VERSION,
            IpAddr::V4(LSD_GROUP_V4),
        );
        let dest = SocketAddr::from(SocketAddrV4::new(LSD_GROUP_V4, LSD_PORT));
        // The two families are announced INDEPENDENTLY. `?` here meant a v4
        // send that fails -- which is what a segment with no IPv4 route gives
        // on every attempt -- returned before the v6 announce was composed, so
        // the half that could have worked never ran (report21 V20-L1).
        let sent4 = self.socket.send_to(wire.as_bytes(), dest).await;

        // The same announce on the v6 group, with its own salt, so the two
        // datagrams are not linkable to each other. A host without IPv6 skips
        // it.
        let sent6 = match &self.socket6 {
            Some(sock6) => {
                let mut salt6 = [0u8; SALT_LEN];
                rand_core::OsRng.fill_bytes(&mut salt6);
                let wire6 = encode_announce(
                    self_announce,
                    salt6,
                    CURRENT_EXCHANGE_VERSION,
                    IpAddr::V6(LSD_GROUP_V6),
                );
                let dest6 = SocketAddr::from(SocketAddrV6::new(LSD_GROUP_V6, LSD_PORT, 0, 0));
                Some(sock6.send_to(wire6.as_bytes(), dest6).await)
            }
            None => None,
        };

        // An announce went out if EITHER family carried it. Only when every
        // family this host has refused is there nothing to report but the
        // failure, and then it is the v4 error -- the one the caller has
        // always seen.
        if sent6.is_some_and(|r| r.is_ok()) {
            return Ok(());
        }
        sent4.map(|_| ())
    }

    /// Wait for one datagram and say what it was.
    ///
    /// `Ok(None)` means the datagram was not a veil announce, or was our own —
    /// both ordinary on a shared group, neither an error.
    /// BOTH families, whichever speaks first. The v6 socket was bound, joined
    /// to its group and sent on, and then never read: a neighbour on a segment
    /// with no IPv4 announced into silence (report21 V20-L1).
    pub async fn recv_peer(&self) -> io::Result<Option<BootstrapPeer>> {
        let mut buf4 = [0u8; MAX_ANNOUNCE_BYTES];
        let mut buf6 = [0u8; MAX_ANNOUNCE_BYTES];
        let Some(sock6) = &self.socket6 else {
            let (n, from) = self.socket.recv_from(&mut buf4).await?;
            return Ok(self.interpret(&buf4[..n], from.ip()));
        };
        tokio::select! {
            r = self.socket.recv_from(&mut buf4) => {
                let (n, from) = r?;
                Ok(self.interpret(&buf4[..n], from.ip()))
            }
            r = sock6.recv_from(&mut buf6) => {
                let (n, from) = r?;
                Ok(self.interpret(&buf6[..n], from.ip()))
            }
        }
    }

    /// The decision `recv_peer` makes, with the socket taken out of it.
    ///
    /// Split out because it is the half worth testing: a multicast round trip
    /// needs a network stack that forwards to loopback, which not every CI
    /// container has, and a test that silently does not exercise the code is
    /// worse than no test.
    pub fn interpret(&self, datagram: &[u8], from: IpAddr) -> Option<BootstrapPeer> {
        let heard = decode_announce(datagram)?;
        if self
            .announce
            .as_ref()
            .is_some_and(|mine| heard.public_key == mine.public_key)
        {
            // Our own announce, arriving back through multicast loopback.
            return None;
        }
        Some(heard.into_bootstrap_peer(from))
    }
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn the_v6_group_is_bound_and_not_merely_exported() {
        // `LSD_GROUP_V6` has been a public constant with an encoding test
        // since this layer was written, and nothing ever bound it -- the code
        // read as though it spoke both families and spoke one. On a host with
        // no IPv6 the absence is ordinary and the v4 half must still work.
        let announce = LanAnnounce {
            public_key: [7u8; 32],
            pow_nonce: [1, 2, 3, 4],
            port: 5556,
            scheme: crate::lan::LanScheme::Obfs4Tcp,
        };
        let d = LanDiscovery::bind(announce)
            .await
            .expect("v4 bind is required");
        assert!(
            d.local_addr().is_ok(),
            "the v4 half stopped working when the v6 half was added"
        );
        // Announcing must not fail because of the v6 half, whether or not this
        // host has IPv6.
        d.announce_once().await.expect("an announce still goes out");

        // And when the host does have IPv6, the socket is really bound to the
        // discovery port rather than an ephemeral one.
        if let Some(sock6) = &d.socket6 {
            let addr = sock6.local_addr().expect("bound");
            assert!(addr.is_ipv6(), "the v6 socket is not v6");
            assert_eq!(
                addr.port(),
                LSD_PORT,
                "the v6 half bound a port nobody is listening on"
            );
        }
    }
    /// report21 V20-M4: a node with nothing to announce still listens.
    ///
    /// The layer's own rule is that a node which does not publish still "asks
    /// and listens" — and having no advertisable listener, or an identity key
    /// the LAN payload cannot carry, used to end the whole task before the
    /// socket was bound. A client that only wanted to FIND the machine down
    /// the hall found nothing, for the reason that it had nothing to offer.
    #[tokio::test]
    async fn a_node_with_nothing_to_announce_still_binds_and_listens() {
        let d = LanDiscovery::bind_listen_only()
            .await
            .expect("the receive half must not depend on having something to say");
        assert!(
            d.local_addr().is_ok(),
            "listen-only did not bind the discovery socket"
        );

        // It hears a neighbour exactly as an announcing node does.
        let neighbour = announce(0x5A);
        let wire = wire_from(&neighbour);
        let heard = d
            .interpret(
                wire.as_bytes(),
                "192.168.1.9".parse().expect("a neighbour address"),
            )
            .expect("a listen-only node heard nothing");
        assert_eq!(heard.transport, "obfs4-tcp://192.168.1.9:5556");

        // And it refuses to announce rather than sending something empty.
        let err = d
            .announce_once()
            .await
            .expect_err("a node with nothing to say announced anyway");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    /// report21 V20-L1: the v6 half is READ, and the two announces are
    /// independent of each other.
    ///
    /// The socket was bound, joined to its group and sent on — and then never
    /// read, so a neighbour on a segment with no IPv4 announced into silence
    /// while this node's changelog said dual-stack. And the v4 send carried a
    /// `?`, so on exactly that segment it returned before the v6 announce was
    /// even composed.
    ///
    /// Structural, because the behaviour needs two hosts on one v6 segment:
    /// a unit test on a machine that may have no IPv6 at all cannot tell a
    /// working v6 path from an absent one.
    #[test]
    fn both_families_are_read_and_announced_independently() {
        let src = include_str!("lan_service.rs");
        let production = src.split("#[cfg(test)]").next().expect("production half");

        let recv = production
            .split("pub async fn recv_peer")
            .nth(1)
            .and_then(|t| t.split("\n    pub fn interpret").next())
            .expect("the receive path");
        assert!(
            recv.contains("self.socket.recv_from"),
            "the v4 half is no longer read; this guard has to be re-aimed"
        );
        assert!(
            recv.contains("sock6.recv_from"),
            "the v6 socket is bound, joined and sent on, and nothing reads \
             it: an IPv6-only neighbour announces into silence"
        );

        let announce = production
            .split("pub async fn announce_once")
            .nth(1)
            .and_then(|t| t.split("\n    /// BOTH families").next())
            .expect("the announce path");
        assert!(
            announce.contains("IpAddr::V6(LSD_GROUP_V6)"),
            "the v6 announce is gone; this guard has to be re-aimed"
        );
        assert!(
            !announce.contains("self.socket.send_to(wire.as_bytes(), dest).await?"),
            "the v4 send returns early again, so a segment with no IPv4 route \
             never gets as far as composing the v6 announce"
        );
    }

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

    #[test]
    fn the_announce_schedule_starts_quick_and_settles() {
        // A node joining a quiet LAN has to be heard soon; a node that has been
        // up for an hour must not keep talking. Both halves, plus the
        // monotonicity that makes "settles" mean anything.
        let delays: Vec<Duration> = (0..8).map(announce_delay).collect();
        assert_eq!(delays[0], Duration::from_secs(0), "the first is immediate");
        for pair in delays.windows(2) {
            assert!(
                pair[1] >= pair[0],
                "the schedule goes backwards: {:?} then {:?}",
                pair[0],
                pair[1]
            );
        }
        assert_eq!(
            *delays.last().unwrap(),
            DEFAULT_ANNOUNCE_INTERVAL,
            "the schedule never settles at the BEP's cadence"
        );
        // The early ones have to fit inside a minute, or "heard soon" is not
        // true and this schedule buys nothing over a flat interval.
        let early: Duration = delays
            .iter()
            .take_while(|d| **d < DEFAULT_ANNOUNCE_INTERVAL)
            .sum();
        assert!(
            early <= Duration::from_secs(60),
            "the early announces span {early:?}, which is not soon"
        );
        assert!(
            delays
                .iter()
                .filter(|d| **d < DEFAULT_ANNOUNCE_INTERVAL)
                .count()
                >= 3,
            "one early announce is not a burst"
        );
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
