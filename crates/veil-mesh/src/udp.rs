//! UDP-backed local mesh transport.
//!
//! # Overview
//!
//! `UdpLink` sends `MeshFrame`s to a remote endpoint over UDP unicast.
//! `UdpRealm` binds a UDP socket, receives frames, and dispatches them to
//! registered handlers.
//!
//! # Frame framing
//!
//! Each UDP datagram carries exactly one `MeshFrame` (no length prefix needed
//! since UDP already provides message boundaries). The maximum datagram size
//! is bounded by `MAX_UDP_FRAME` = 65,507 bytes which UDP allows on IPv4.
//!
//! # Usage
//!
//! ```ignore
//! use std::net::SocketAddr;
//! use veilcore::node::mesh::udp::UdpRealm;
//! use veilcore::proto::mesh::RealmId;
//!
//! #[tokio::main]
//! async fn main() {
//!     let realm = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), RealmId([1u8; 16]), None)
//!         .await
//!         .unwrap();
//!     let local_addr = realm.local_addr();
//! }
//! ```

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use veil_util::lock;

use tokio::net::UdpSocket;

use veil_proto::mesh::{MeshFrame, RealmId};

use super::{
    beacon::{BeaconReceiver, BeaconSender},
    link::{LocalLink, SendResult},
    neighbor::NeighborTable,
};

/// Maximum UDP payload size we accept.
pub const MAX_UDP_FRAME: usize = 65_507;

// ── UdpLink ───────────────────────────────────────────────────────────────────

/// A `LocalLink` that delivers frames via UDP unicast.
///
/// Internally uses a `std::net::UdpSocket` (blocking send) so the `LocalLink`
/// trait contract (must not block indefinitely) is satisfied by the OS UDP send
/// buffer being non-blocking.
///
/// ## Stale-neighbor detection
///
/// UDP is connectionless — a peer can go offline without causing a send error
/// on the local side. `UdpLink` tracks `last_success_secs` (unix timestamp of
/// the last successful `send`). `is_alive` returns `false` if no successful
/// send has occurred within `UDP_NEIGHBOR_IDLE_TIMEOUT_SECS`, so the periodic
/// `prune_dead` call in the runtime cleanup loop will remove the stale entry.
pub struct UdpLink {
    remote_id: [u8; 32],
    remote_addr: SocketAddr,
    socket: Arc<std::net::UdpSocket>,
    alive: Arc<Mutex<bool>>,
    /// Unix timestamp (seconds) of the last successful `send_to`.
    /// Initialised to `now` so a freshly-created link is not immediately dead.
    last_success_secs: AtomicU64,
    /// Realm-wide obfuscation key (opt-in via `realm_psk`). `Some` => every
    /// DATA datagram is AEAD-sealed with `veil-udp-obfs` before send, so
    /// passive DPI sees only ciphertext. Shared (`Arc`) across all links in the
    /// realm — derived once in [`UdpRealm::bind`]. `None` => plaintext send.
    obfs: Option<Arc<veil_udp_obfs::ObfsKey>>,
    /// Per-link AEAD counter input for `seal_datagram`. The 16-byte random
    /// nonce prefix already guarantees nonce uniqueness; this monotonic counter
    /// is the documented secondary input (and aids the peer's replay window if
    /// one is ever enabled). Unused when `obfs` is `None`.
    obfs_counter: AtomicU64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl UdpLink {
    /// Create a new `UdpLink` to `remote_addr` on behalf of `local_socket`.
    pub fn new(
        remote_id: [u8; 32],
        remote_addr: SocketAddr,
        socket: Arc<std::net::UdpSocket>,
        obfs: Option<Arc<veil_udp_obfs::ObfsKey>>,
    ) -> Self {
        Self {
            remote_id,
            remote_addr,
            socket,
            alive: Arc::new(Mutex::new(true)),
            last_success_secs: AtomicU64::new(now_secs()),
            obfs,
            obfs_counter: AtomicU64::new(0),
        }
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn disconnect(&self) {
        *lock!(self.alive) = false;
    }

    /// Shared send path for [`LocalLink::send`] and [`Self::send_encoded`].
    ///
    /// When a realm `obfs` key is configured the pre-encoded frame is
    /// AEAD-sealed via `veil-udp-obfs` (fresh random nonce per datagram)
    /// before `send_to`; otherwise the bytes go out verbatim (unchanged
    /// plaintext path). A genuine socket error marks the link `Disconnected`;
    /// an obfs seal failure (frame too large to wrap within the UDP limit)
    /// drops that single frame but keeps the link alive.
    fn send_bytes(&self, encoded: &[u8]) -> SendResult {
        if !*lock!(self.alive) {
            return SendResult::Disconnected;
        }
        let sealed;
        let out: &[u8] = match &self.obfs {
            Some(key) => {
                let counter = self.obfs_counter.fetch_add(1, Ordering::Relaxed);
                match veil_udp_obfs::seal_datagram(key, counter, encoded) {
                    Ok(s) => {
                        sealed = s;
                        &sealed
                    }
                    Err(e) => {
                        log::warn!("veil-mesh: obfs seal failed, dropping frame: {e}");
                        return SendResult::Ok;
                    }
                }
            }
            None => encoded,
        };
        match self.socket.send_to(out, self.remote_addr) {
            Ok(_) => {
                self.last_success_secs.store(now_secs(), Ordering::Relaxed);
                SendResult::Ok
            }
            Err(_) => {
                *lock!(self.alive) = false;
                SendResult::Disconnected
            }
        }
    }
}

impl LocalLink for UdpLink {
    fn remote_node_id(&self) -> [u8; 32] {
        self.remote_id
    }

    fn send(&self, frame: &MeshFrame) -> SendResult {
        let encoded = frame.encode();
        self.send_bytes(&encoded)
    }

    /// Use pre-encoded bytes directly — avoids re-encoding for each broadcast
    /// hop. (With obfs enabled each hop still re-seals with a fresh nonce; only
    /// the `MeshFrame::encode` is shared.)
    fn send_encoded(&self, encoded: &std::sync::Arc<[u8]>) -> SendResult {
        self.send_bytes(encoded)
    }

    fn is_alive(&self) -> bool {
        if !*lock!(self.alive) {
            return false;
        }
        // Dead-silence detection: if no successful send in the idle timeout
        // window the peer is assumed offline (UDP gives no error for silent
        // peers, so we use time-since-last-success as a proxy).
        let idle_secs = now_secs().saturating_sub(self.last_success_secs.load(Ordering::Relaxed));
        idle_secs < veil_proto::budget::UDP_NEIGHBOR_IDLE_TIMEOUT_SECS
    }
}

// ── UdpRealm ─────────────────────────────────────────────────────────────────

/// Receives `MeshFrame`s on a bound UDP socket.
///
/// Call `recv_frame` in an async loop to get incoming frames. The caller is
/// responsible for dispatching them through `MeshForwarder`.
pub struct UdpRealm {
    realm_id: RealmId,
    socket: Arc<UdpSocket>,
    /// Shared std socket for creating `UdpLink`s that send from the same port.
    std_socket: Arc<std::net::UdpSocket>,
    /// Realm-wide obfuscation key, derived once from `realm_psk` (opt-in).
    /// Threaded into every [`UdpLink`] (send) and the [`BeaconReceiver`], and
    /// used in [`Self::recv_frame`] to open sealed DATA datagrams. `None` =>
    /// plaintext mesh (unchanged behaviour).
    obfs: Option<Arc<veil_udp_obfs::ObfsKey>>,
}

impl UdpRealm {
    /// Bind a UDP socket and create a realm listener.
    ///
    /// When `realm_psk` is `Some`, a realm-wide [`veil_udp_obfs::ObfsKey`] is
    /// derived once (HKDF context = `realm_id` zero-padded to 32 bytes, so two
    /// realms sharing a PSK still get distinct keys) and used to seal/open DATA
    /// datagrams. `None` => plaintext mesh, byte-for-byte unchanged behaviour.
    pub async fn bind(
        addr: SocketAddr,
        realm_id: RealmId,
        realm_psk: Option<&[u8]>,
    ) -> std::io::Result<Self> {
        // Bind as std socket first so we can clone for UdpLink (sync send).
        let std_raw = std::net::UdpSocket::bind(addr)?;
        let std_socket = std_raw.try_clone()?;
        // Both sockets are non-blocking: the async socket for recv, the std
        // socket for sync send in UdpLink. A blocking send_to would stall
        // the tokio worker thread on network saturation.
        std_socket.set_nonblocking(true)?;
        std_raw.set_nonblocking(true)?;
        let async_socket = UdpSocket::from_std(std_raw)?;
        let obfs = realm_psk.map(|psk| {
            let mut ctx = [0u8; 32];
            ctx[..16].copy_from_slice(&realm_id.0);
            Arc::new(veil_udp_obfs::ObfsKey::derive(psk, &ctx))
        });
        Ok(Self {
            realm_id,
            socket: Arc::new(async_socket),
            std_socket: Arc::new(std_socket),
            obfs,
        })
    }

    /// Local address this realm is listening on.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn realm_id(&self) -> RealmId {
        self.realm_id
    }

    /// The realm-wide obfuscation key (opt-in via `realm_psk`), for callers
    /// that construct a [`BeaconReceiver`] directly rather than via
    /// [`Self::make_beacon_receiver`] (e.g. the node-runtime mesh gateway).
    /// `None` => plaintext mesh.
    pub fn obfs_key(&self) -> Option<Arc<veil_udp_obfs::ObfsKey>> {
        self.obfs.clone()
    }

    /// Create a `UdpLink` toward `remote_addr` for `remote_id`.
    pub fn link_to(&self, remote_id: [u8; 32], remote_addr: SocketAddr) -> UdpLink {
        UdpLink::new(
            remote_id,
            remote_addr,
            Arc::clone(&self.std_socket),
            self.obfs.clone(),
        )
    }

    /// Spawn a [`BeaconSender`] task that periodically broadcasts this node's
    /// presence to `broadcast_addr`.
    ///
    /// `BeaconSender` binds its own ephemeral send socket so it does not
    /// interfere with the realm's receive socket. The caller owns the returned
    /// `JoinHandle` and can abort it on shutdown.
    ///
    /// Use [`DEFAULT_BEACON_INTERVAL`] for `interval` unless you have a reason
    /// to change it.
    pub async fn spawn_beacon_sender(
        &self,
        local_node_id: [u8; 32],
        broadcast_addr: SocketAddr,
        interval: Duration,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        self.spawn_beacon_sender_with_role(
            local_node_id,
            broadcast_addr,
            interval,
            shutdown_rx,
            0,
            None,
        )
        .await
    }

    /// Like [`spawn_beacon_sender`] but also advertises `role_flags` and
    /// `veil_addr` in each beacon.
    pub async fn spawn_beacon_sender_with_role(
        &self,
        local_node_id: [u8; 32],
        broadcast_addr: SocketAddr,
        interval: Duration,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
        role_flags: u8,
        veil_addr: Option<String>,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        self.spawn_beacon_sender_with_role_and_key(
            local_node_id,
            broadcast_addr,
            interval,
            shutdown_rx,
            role_flags,
            veil_addr,
            None,
        )
        .await
    }

    /// spawn beacon sender with optional signing key for authentication.
    #[allow(clippy::too_many_arguments)] // low-level socket spawn; grouping these into a struct adds ceremony without clarity
    pub async fn spawn_beacon_sender_with_role_and_key(
        &self,
        local_node_id: [u8; 32],
        broadcast_addr: SocketAddr,
        interval: Duration,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
        role_flags: u8,
        veil_addr: Option<String>,
        signing: Option<(veil_types::SignatureAlgorithm, String, String)>, // (algo, pubkey_b64, privkey_b64)
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        let bind_addr: SocketAddr = if broadcast_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let mut sender = BeaconSender::new(
            self.realm_id,
            local_node_id,
            broadcast_addr,
            bind_addr,
            interval,
        )
        .await?
        .set_role(role_flags, veil_addr)
        // C-03: seal broadcast beacons with the realm key when `realm_psk` is
        // configured, so the stable node_id is not broadcast in the clear.
        .with_obfs(self.obfs.clone());
        if let Some((algo, pk_b64, sk_b64)) = signing {
            sender = sender.set_signing_key(algo, pk_b64, sk_b64);
        }
        Ok(tokio::spawn(sender.run(shutdown_rx)))
    }

    /// Create a [`BeaconReceiver`] that uses this realm's shared socket to
    /// construct back-links toward beacon senders.
    ///
    /// The caller must route broadcast frames to it from the receive loop:
    ///
    /// ```ignore
    /// let (frame, addr) = realm.recv_frame.await?;
    /// if frame.is_broadcast {
    /// receiver.handle_beacon(&frame, addr);
    /// } else {
    /// //... normal dispatch
    /// }
    /// ```
    pub fn make_beacon_receiver(&self, neighbors: NeighborTable) -> BeaconReceiver {
        BeaconReceiver::new(
            self.realm_id,
            neighbors,
            Arc::clone(&self.std_socket),
            self.obfs.clone(),
        )
    }

    /// Receive one `MeshFrame` from the socket.
    ///
    /// Returns `(frame, sender_addr)` on success. Drops datagrams that fail
    /// to decode or exceed `MAX_UDP_FRAME`.
    pub async fn recv_frame(&self) -> std::io::Result<(MeshFrame, SocketAddr)> {
        let mut buf = vec![0u8; MAX_UDP_FRAME];
        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await?;
            let wire = &buf[..len];
            // With a realm obfs key, legitimate peers seal every frame (C-03
            // seals beacons too). On open failure we fall back to a plaintext
            // decode ONLY for BROADCAST frames — cleartext beacons may still
            // arrive from cross-config / discovering peers, and are separately
            // gated by `BeaconReceiver::require_signed`. An unsealed UNICAST
            // frame is a DATA injection attempt and is REJECTED, so realm_psk
            // gates admission of DATA, not just its confidentiality. Without a
            // key, decode directly (unchanged behaviour).
            let frame = match &self.obfs {
                Some(key) => match veil_udp_obfs::open_datagram(key, wire) {
                    Ok((_counter, payload)) => MeshFrame::decode(&payload).ok(),
                    Err(_) => MeshFrame::decode(wire).ok().filter(MeshFrame::is_broadcast),
                },
                None => MeshFrame::decode(wire).ok(),
            };
            if let Some(frame) = frame {
                return Ok((frame, src));
            }
            // Malformed datagram — silently drop and retry
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighbor::{MeshNeighborProvider, NeighborTable};
    use veil_proto::mesh::{MeshFrame, RealmId};

    fn sample_frame() -> MeshFrame {
        MeshFrame::new(
            RealmId([0xAA; 16]),
            [1u8; 32],
            [2u8; 32],
            5,
            b"udp-test".to_vec(),
        )
    }

    #[tokio::test]
    async fn udp_realm_bind_and_local_addr() {
        let realm = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), RealmId([1u8; 16]), None)
            .await
            .unwrap();
        let addr = realm.local_addr().unwrap();
        assert!(addr.port() != 0);
    }

    #[tokio::test]
    async fn udp_link_send_recv_roundtrip() {
        let realm_a = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), RealmId([0u8; 16]), None)
            .await
            .unwrap();
        let realm_b = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), RealmId([0u8; 16]), None)
            .await
            .unwrap();
        let addr_b = realm_b.local_addr().unwrap();

        // A → B
        let link_a_to_b = realm_a.link_to([2u8; 32], addr_b);
        let frame = sample_frame();
        assert_eq!(link_a_to_b.send(&frame), SendResult::Ok);

        let (received, _src) =
            tokio::time::timeout(std::time::Duration::from_secs(2), realm_b.recv_frame())
                .await
                .expect("timeout")
                .unwrap();

        assert_eq!(received, frame);
    }

    /// Opt-in obfuscation: with a realm `realm_psk`, a frame sent over a
    /// `UdpLink` is AEAD-sealed on the wire and transparently opened by the
    /// receiving `UdpRealm` (round-trips identically to the plaintext path),
    /// while a realm keyed with a *different* PSK cannot recover it.
    #[tokio::test]
    async fn udp_obfs_roundtrip_and_wrong_psk_rejected() {
        let realm_id = RealmId([0x7E; 16]);
        let psk: &[u8] = b"correct-horse-battery-staple-001"; // >= 16 bytes

        let realm_a = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, Some(psk))
            .await
            .unwrap();
        let realm_b = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, Some(psk))
            .await
            .unwrap();
        let addr_b = realm_b.local_addr().unwrap();

        // Matching PSK: the sealed datagram opens back to the exact frame.
        let link = realm_a.link_to([2u8; 32], addr_b);
        let frame = sample_frame();
        assert_eq!(link.send(&frame), SendResult::Ok);
        let (received, _src) =
            tokio::time::timeout(std::time::Duration::from_secs(2), realm_b.recv_frame())
                .await
                .expect("timeout")
                .unwrap();
        assert_eq!(
            received, frame,
            "matching-PSK realm must open the sealed frame"
        );

        // Wrong PSK: realm_c derives a different key, so `open_datagram` fails
        // and the plaintext-decode fallback rejects the ciphertext -> the frame
        // is dropped and nothing is delivered within the window.
        let wrong: &[u8] = b"a-totally-different-psk-value-99";
        let realm_c = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, Some(wrong))
            .await
            .unwrap();
        let addr_c = realm_c.local_addr().unwrap();
        let link_ac = realm_a.link_to([3u8; 32], addr_c);
        assert_eq!(link_ac.send(&frame), SendResult::Ok);
        let res =
            tokio::time::timeout(std::time::Duration::from_millis(300), realm_c.recv_frame()).await;
        assert!(
            res.is_err(),
            "wrong-PSK realm must NOT decode the sealed frame"
        );
    }

    /// M-2 (audit 2026-06-03): in a PSK realm an UNSEALED *unicast* DATA frame
    /// (injected by a peer without the PSK) is rejected — `realm_psk` gates DATA
    /// admission, not just confidentiality. An unsealed *broadcast* frame still
    /// parses, preserving cleartext beacon / discovery interop across configs.
    #[tokio::test]
    async fn obfs_realm_rejects_unsealed_unicast_but_accepts_broadcast() {
        use veil_proto::mesh::BROADCAST_NODE_ID;
        let realm_id = RealmId([0x55; 16]);
        let psk: &[u8] = b"correct-horse-battery-staple-001";

        // Sender has NO psk -> emits PLAINTEXT frames; receiver HAS the psk.
        let plain_sender = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, None)
            .await
            .unwrap();
        let sealed_recv = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, Some(psk))
            .await
            .unwrap();
        let addr = sealed_recv.local_addr().unwrap();

        // Unsealed UNICAST DATA must be dropped (recv_frame times out).
        let unicast = sample_frame();
        assert!(!unicast.is_broadcast());
        assert_eq!(
            plain_sender.link_to([2u8; 32], addr).send(&unicast),
            SendResult::Ok
        );
        let dropped = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            sealed_recv.recv_frame(),
        )
        .await;
        assert!(
            dropped.is_err(),
            "unsealed unicast DATA must be dropped in a PSK realm"
        );

        // Unsealed BROADCAST (beacon/discovery) is still accepted.
        let bcast = MeshFrame::new(
            realm_id,
            [1u8; 32],
            BROADCAST_NODE_ID,
            5,
            b"beacon".to_vec(),
        );
        assert!(bcast.is_broadcast());
        assert_eq!(
            plain_sender.link_to(BROADCAST_NODE_ID, addr).send(&bcast),
            SendResult::Ok
        );
        let (received, _src) =
            tokio::time::timeout(std::time::Duration::from_secs(2), sealed_recv.recv_frame())
                .await
                .expect("broadcast must be delivered")
                .unwrap();
        assert_eq!(received, bcast, "unsealed broadcast must still parse");
    }

    #[tokio::test]
    async fn disconnected_link_returns_error() {
        let realm = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), RealmId([0u8; 16]), None)
            .await
            .unwrap();
        let link = realm.link_to([9u8; 32], "127.0.0.1:1".parse().unwrap());
        link.disconnect();
        assert_eq!(link.send(&sample_frame()), SendResult::Disconnected);
    }

    // ── 73.4: Beacon discovery integration ───────────────────────────────────

    /// Two UdpRealm nodes on loopback: after one beacon send, node B appears
    /// in node A's NeighborTable.
    #[tokio::test]
    async fn beacon_discovery_registers_neighbor() {
        let realm_id = RealmId([0xBB; 16]);
        let node_b_id = [2u8; 32];

        let realm_a = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, None)
            .await
            .unwrap();
        let realm_b = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, None)
            .await
            .unwrap();

        let addr_a = realm_a.local_addr().unwrap();
        let neighbors_a = NeighborTable::new();
        // legacy opt-out: these discovery/rate-limit tests use unsigned beacons
        // (`new_basic`); the default now requires signed.
        let mut receiver_a = realm_a
            .make_beacon_receiver(neighbors_a.clone())
            .with_require_signed(false);

        // B sends beacons directly to A's address (unicast on loopback).
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let _task = realm_b
            .spawn_beacon_sender(node_b_id, addr_a, Duration::from_millis(30), shutdown_rx)
            .await
            .unwrap();

        // A receives one frame and dispatches it to BeaconReceiver.
        let (frame, src) = tokio::time::timeout(Duration::from_secs(3), realm_a.recv_frame())
            .await
            .expect("beacon not received within 3 s")
            .unwrap();

        assert!(frame.is_broadcast(), "beacon must be a broadcast frame");
        let accepted = receiver_a.handle_beacon(&frame, src);
        assert!(accepted, "beacon should be accepted");
        assert!(
            neighbors_a.link_to(&node_b_id).is_some(),
            "node B should appear in A's neighbor table after beacon",
        );

        let _ = shutdown_tx.send(true);
    }

    /// C-03: with a realm `realm_psk`, a broadcast beacon is AEAD-sealed on the
    /// wire — the stable `node_id` does NOT appear in cleartext — yet a realm
    /// member (same PSK) opens it back to a valid broadcast `MeshFrame`.
    #[tokio::test]
    async fn sealed_beacon_hides_node_id_on_wire() {
        let realm_id = RealmId([0x5A; 16]);
        let psk: &[u8] = b"correct-horse-battery-staple-001";
        let node_b_id = [0xAB; 32];

        // A plain capture socket that just records the raw datagram bytes.
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sink_addr = sink.local_addr().unwrap();
        let realm_b = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, Some(psk))
            .await
            .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let _task = realm_b
            .spawn_beacon_sender(node_b_id, sink_addr, Duration::from_millis(20), shutdown_rx)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), sink.recv_from(&mut buf))
            .await
            .expect("sealed beacon not captured")
            .unwrap();
        let wire = &buf[..n];

        // The stable node_id must NOT be observable in cleartext.
        assert!(
            !wire.windows(32).any(|w| w == node_b_id),
            "node_id leaked in cleartext on a sealed beacon",
        );
        // A realm member re-derives the key and opens it to a broadcast frame.
        let mut ctx = [0u8; 32];
        ctx[..16].copy_from_slice(&realm_id.0);
        let key = veil_udp_obfs::ObfsKey::derive(psk, &ctx);
        let (_counter, opened) =
            veil_udp_obfs::open_datagram(&key, wire).expect("realm member opens the beacon");
        let frame = MeshFrame::decode(&opened).expect("opens to a MeshFrame");
        assert!(frame.is_broadcast(), "beacon must be a broadcast frame");

        let _ = shutdown_tx.send(true);
    }

    /// C-03 end-to-end: two realms sharing a `realm_psk` — B's sealed beacon is
    /// opened by A's `recv_frame` and registers B as a neighbour, exactly like
    /// the plaintext path but over the obfuscated wire.
    #[tokio::test]
    async fn sealed_beacon_discovery_registers_neighbor() {
        let realm_id = RealmId([0xBE; 16]);
        let psk: &[u8] = b"correct-horse-battery-staple-001";
        let node_b_id = [2u8; 32];

        let realm_a = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, Some(psk))
            .await
            .unwrap();
        let realm_b = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, Some(psk))
            .await
            .unwrap();
        let addr_a = realm_a.local_addr().unwrap();
        let neighbors_a = NeighborTable::new();
        // legacy opt-out: these discovery/rate-limit tests use unsigned beacons
        // (`new_basic`); the default now requires signed.
        let mut receiver_a = realm_a
            .make_beacon_receiver(neighbors_a.clone())
            .with_require_signed(false);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let _task = realm_b
            .spawn_beacon_sender(node_b_id, addr_a, Duration::from_millis(30), shutdown_rx)
            .await
            .unwrap();

        let (frame, src) = tokio::time::timeout(Duration::from_secs(3), realm_a.recv_frame())
            .await
            .expect("sealed beacon not received within 3 s")
            .unwrap();
        assert!(frame.is_broadcast(), "beacon must be a broadcast frame");
        assert!(
            receiver_a.handle_beacon(&frame, src),
            "sealed beacon accepted"
        );
        assert!(
            neighbors_a.link_to(&node_b_id).is_some(),
            "node B discovered via the sealed beacon",
        );

        let _ = shutdown_tx.send(true);
    }

    // ── 73.5: Rate-limit blocks flood at UdpRealm level ──────────────────────

    /// Send MAX_BEACONS_PER_IP_PER_WINDOW + 1 beacons from B; only the first
    /// MAX_BEACONS_PER_IP_PER_WINDOW should be accepted by the BeaconReceiver.
    #[tokio::test]
    async fn beacon_flood_rate_limited_via_udp_realm() {
        use crate::beacon::MAX_BEACONS_PER_IP_PER_WINDOW;
        use veil_proto::mesh::{BROADCAST_NODE_ID, MeshBeaconPayload};

        let realm_id = RealmId([0xCC; 16]);
        let realm_a = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, None)
            .await
            .unwrap();
        let realm_b = UdpRealm::bind("127.0.0.1:0".parse().unwrap(), realm_id, None)
            .await
            .unwrap();

        let addr_a = realm_a.local_addr().unwrap();
        let neighbors_a = NeighborTable::new();
        // legacy opt-out: these discovery/rate-limit tests use unsigned beacons
        // (`new_basic`); the default now requires signed.
        let mut receiver_a = realm_a
            .make_beacon_receiver(neighbors_a.clone())
            .with_require_signed(false);

        // Flood: send MAX+1 beacons from B using distinct node IDs (so the
        // "already in table" check doesn't short-circuit the rate limiter).
        let std_b = realm_b.std_socket.clone();
        let total = MAX_BEACONS_PER_IP_PER_WINDOW + 1;
        for i in 0..total {
            let mut node_id = [0u8; 32];
            node_id[0] = i as u8;
            let beacon = MeshBeaconPayload::new_basic(node_id, realm_id);
            let frame = MeshFrame::new(realm_id, node_id, BROADCAST_NODE_ID, 1, beacon.encode());
            std_b.send_to(&frame.encode(), addr_a).unwrap();
        }

        // Receive all frames synchronously (they're already in the socket buffer).
        let mut accepted = 0u32;
        for _ in 0..total {
            let (frame, src) = tokio::time::timeout(Duration::from_secs(2), realm_a.recv_frame())
                .await
                .expect("frame not received in time")
                .unwrap();
            if receiver_a.handle_beacon(&frame, src) {
                accepted += 1;
            }
        }

        assert_eq!(
            accepted, MAX_BEACONS_PER_IP_PER_WINDOW,
            "rate limiter should accept exactly the limit",
        );
    }

    // ── 204.Stale silent-dead UDP neighbor detection ─────────────────────

    /// A freshly-created `UdpLink` (never sent) is alive because `last_success`
    /// is initialised to `now`.
    #[test]
    fn fresh_link_is_alive() {
        let socket = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let link = UdpLink::new([1u8; 32], "127.0.0.1:9999".parse().unwrap(), socket, None);
        assert!(link.is_alive(), "fresh link should be alive");
    }

    /// A link whose `last_success_secs` is backdated beyond the idle timeout
    /// must report `is_alive == false` — simulating a silent-dead peer.
    #[test]
    fn silent_dead_link_becomes_not_alive() {
        let socket = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let link = UdpLink::new([2u8; 32], "127.0.0.1:9999".parse().unwrap(), socket, None);

        // Backdate last_success beyond the idle timeout.
        let expired =
            now_secs().saturating_sub(veil_proto::budget::UDP_NEIGHBOR_IDLE_TIMEOUT_SECS + 1);
        link.last_success_secs.store(expired, Ordering::Relaxed);

        assert!(
            !link.is_alive(),
            "link with expired last_success should be dead"
        );
    }

    /// Explicit disconnect still marks the link dead regardless of last_success.
    #[test]
    fn disconnected_link_is_not_alive() {
        let socket = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let link = UdpLink::new([3u8; 32], "127.0.0.1:9999".parse().unwrap(), socket, None);
        link.disconnect();
        assert!(
            !link.is_alive(),
            "explicitly disconnected link should be dead"
        );
    }
}
