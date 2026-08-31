//! Bootstrap layer 6: finding a peer on the same local network.
//!
//! Every layer above this one needs something the project publishes — a seed
//! list compiled into the binary, an HTTPS URL somebody has to host, a DNS
//! domain somebody has to own. This layer needs nothing at all: two nodes on
//! one LAN find each other by talking to the wire between them.
//!
//! # Why this looks like BitTorrent
//!
//! The datagram this module writes is a BitTorrent Local Service Discovery
//! announce (BEP 14): the same multicast group, the same port, the same
//! `BT-SEARCH` request line. That is deliberate and it is the whole design.
//!
//! A node that discovers over multicast has to join a group, and joining is
//! not private: the IGMP membership report goes to the switch, and anyone on
//! the segment can see which host joined which group. A group of our own would
//! therefore announce "this machine runs veil" to the local network before we
//! sent a single byte — on a hotel or office LAN that is exactly the fact
//! worth hiding. Joining BitTorrent's group says "this machine runs a torrent
//! client", which is one of the least remarkable things a host can say.
//!
//! The payload rides in the `Infohash` headers, which BEP 14 already allows to
//! repeat: two of them carry 40 bytes, and 40 bytes is what a peer needs.
//! A real BitTorrent client that receives one of ours looks up an infohash
//! nobody is serving and finds nothing, which costs it a lookup and no more.
//!
//! # What the obfuscation is, and what it is not
//!
//! Those 40 bytes are XORed with a keystream derived from a per-announce salt,
//! the port and an exchange-version nonce. The salt travels in BEP 14's own
//! `cookie` header — an opaque field the BEP already has, which real clients
//! already fill with opaque bytes — so every input to the key is public and a
//! listener on the LAN can decrypt exactly as easily as we can. This buys one
//! thing: there is no constant byte string anywhere in the packet, and the same
//! node announcing twice writes entirely different bytes both times.
//!
//! It buys nothing against an adversary who knows this scheme and wants to test
//! whether a specific host speaks veil. That adversary decrypts as easily as we
//! do. Nothing in this module should be described to a user as making local
//! discovery private; the honest claim is that it does not stand out.
//!
//! # The address is not in the packet
//!
//! Nothing in the payload says where to dial. A peer's address is the source
//! address of the datagram that carried it, which the socket reports and the
//! sender cannot choose. That is a structural guarantee rather than a checked
//! one: there is no field to forge, so a neighbour cannot announce somebody
//! else's host and have us dial it. It also means a sender does not have to
//! know which interface its datagram will leave by, which on a multi-homed
//! host it does not.
//!
//! # This layer is opt-in
//!
//! Announcing on a LAN tells that LAN a machine on it runs veil. Whether that
//! is acceptable depends on whose LAN it is, and only the operator knows.
//! See `global.local_discovery` — off unless asked for, for the same reason
//! `global.bootstrap` is.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use veil_types::{BootstrapPeer, SignatureAlgorithm};

/// The IPv4 multicast group BEP 14 uses. Link-local scope: routers do not
/// forward it, which is what makes this layer local by construction rather
/// than by promise.
pub const LSD_GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 192, 152, 143);

/// The IPv6 group from the same BEP (`ff15::efc0:988f`).
pub const LSD_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff15, 0, 0, 0, 0, 0, 0xefc0, 0x988f);

/// BEP 14's port, for both groups.
pub const LSD_PORT: u16 = 6771;

/// The version this build writes.
pub const CURRENT_EXCHANGE_VERSION: u8 = 1;

/// Every version this build can still *read*.
///
/// A version nonce that only ever matched itself would make each release a
/// flag day on the LAN: an upgraded node and its not-yet-upgraded neighbour
/// would sit on the same wire, both announcing, neither seeing the other, and
/// nothing in either log would say why. Decoding walks this list, so adding a
/// version costs one entry here and breaks nobody.
pub const KNOWN_EXCHANGE_VERSIONS: &[u8] = &[1];

/// Ceiling on a datagram we will even look at. BEP 14 announces are a couple
/// of hundred bytes; this is room to spare and a bound on the parser.
pub const MAX_ANNOUNCE_BYTES: usize = 1400;

/// Bytes carried inside the `Infohash` headers: 32 of key, 4 of nonce, 1 of
/// scheme and 3 of check. Exactly two infohashes' worth, which is why the
/// split falls here and not somewhere more comfortable.
const PAYLOAD_LEN: usize = 40;
const INFOHASH_LEN: usize = 20;

/// Per-announce salt, carried in the `cookie` header. Four bytes is what BEP
/// 14 cookies look like in the wild and it is enough: the salt only has to
/// stop two announces sharing a keystream, not resist search.
pub const SALT_LEN: usize = 4;

const DOMAIN: &[u8] = b"veil.bootstrap.lan-discovery";

/// The transport a peer speaks, as one byte on the wire.
///
/// The announce carries an address and a port, and those two do not say how to
/// talk to what is listening: a network configured for obfs4 and one configured
/// for plain TCP look identical from outside. Guessing would make this layer
/// work on the deployment the author happened to test and quietly not on the
/// others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanScheme {
    Obfs4Tcp,
    Tcp,
    Tls,
    Quic,
    Ws,
    Wss,
}

impl LanScheme {
    /// Every variant, so a guard can walk them instead of trusting a list
    /// somebody remembered to extend.
    pub const ALL: &'static [LanScheme] = &[
        LanScheme::Obfs4Tcp,
        LanScheme::Tcp,
        LanScheme::Tls,
        LanScheme::Quic,
        LanScheme::Ws,
        LanScheme::Wss,
    ];

    const fn code(self) -> u8 {
        match self {
            LanScheme::Obfs4Tcp => 0,
            LanScheme::Tcp => 1,
            LanScheme::Tls => 2,
            LanScheme::Quic => 3,
            LanScheme::Ws => 4,
            LanScheme::Wss => 5,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(LanScheme::Obfs4Tcp),
            1 => Some(LanScheme::Tcp),
            2 => Some(LanScheme::Tls),
            3 => Some(LanScheme::Quic),
            4 => Some(LanScheme::Ws),
            5 => Some(LanScheme::Wss),
            _ => None,
        }
    }

    /// The URI scheme, spelled as [`BootstrapPeer::transport`] spells it.
    pub const fn uri_scheme(self) -> &'static str {
        match self {
            LanScheme::Obfs4Tcp => "obfs4-tcp",
            LanScheme::Tcp => "tcp",
            LanScheme::Tls => "tls",
            LanScheme::Quic => "quic",
            LanScheme::Ws => "ws",
            LanScheme::Wss => "wss",
        }
    }
}

/// What one node tells the LAN about itself.
///
/// Deliberately not a [`BootstrapPeer`]: that type carries an address, and the
/// address of an announce is the address the datagram came from, not a claim
/// inside it. Keeping the claim out of the payload means a sender cannot name
/// somebody else's host and have us dial it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanAnnounce {
    /// Ed25519 identity public key.
    pub public_key: [u8; 32],
    /// PoW nonce for node_id derivation.
    pub pow_nonce: [u8; 4],
    /// The port the node listens on — which is NOT [`LSD_PORT`].
    pub port: u16,
    /// How to talk to that port.
    pub scheme: LanScheme,
}

impl LanAnnounce {
    /// Attach the address the datagram actually arrived from.
    pub fn into_bootstrap_peer(self, from: IpAddr) -> BootstrapPeer {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let host = match from {
            IpAddr::V4(v4) => v4.to_string(),
            // A bracketed literal, or the URI has an ambiguous colon.
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        BootstrapPeer {
            transport: format!("{}://{host}:{}", self.scheme.uri_scheme(), self.port),
            public_key: b64.encode(self.public_key),
            nonce: b64.encode(self.pow_nonce),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }
    }
}

/// Keystream for one (version, salt, port). BLAKE3 in XOF mode, so no cipher
/// dependency enters this crate for 40 bytes of XOR.
fn keystream(version: u8, salt: [u8; SALT_LEN], port: u16) -> [u8; PAYLOAD_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN);
    h.update(b"/stream");
    h.update(&[version]);
    h.update(&salt);
    h.update(&port.to_be_bytes());
    let mut out = [0u8; PAYLOAD_LEN];
    h.finalize_xof().fill(&mut out);
    out
}

/// The three check bytes: what separates one of ours from a real torrent
/// announce.
///
/// Without them a random 40 bytes is accepted whenever its scheme byte happens
/// to land in range — one announce in forty-odd — and each acceptance is a dial
/// at a host that never asked for one. With them it is one in forty-odd times
/// 2^24.
///
/// They commit to the salt and the port as well, which is belt to the
/// keystream's braces: both already feed the keystream, so rewriting either
/// header in flight garbles the whole payload before the check is even
/// reached. Committing again here costs nothing and keeps the binding if the
/// derivation above ever changes.
fn check_bytes(
    version: u8,
    public_key: &[u8; 32],
    pow_nonce: &[u8; 4],
    scheme_code: u8,
    salt: [u8; SALT_LEN],
    port: u16,
) -> [u8; 3] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN);
    h.update(b"/check");
    h.update(&[version]);
    h.update(public_key);
    h.update(pow_nonce);
    h.update(&[scheme_code]);
    h.update(&salt);
    h.update(&port.to_be_bytes());
    let full = h.finalize();
    let b = full.as_bytes();
    [b[0], b[1], b[2]]
}

/// Render an announce as a BEP 14 datagram.
///
/// `salt` should be fresh random bytes per announce; it travels in the `cookie`
/// header and is what makes two announces from one node share no bytes. It is
/// a parameter rather than drawn here so this stays a pure function with
/// reproducible output, which is the only reason its tests can assert on bytes.
///
/// `group` is the multicast group this datagram is addressed to — [`LSD_GROUP_V4`]
/// or [`LSD_GROUP_V6`]. BEP 14 wants it echoed in `Host`, and a receiver ignores
/// it; getting it wrong costs realism, which is the only thing it is for.
pub fn encode_announce(
    announce: &LanAnnounce,
    salt: [u8; SALT_LEN],
    version: u8,
    group: IpAddr,
) -> String {
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..32].copy_from_slice(&announce.public_key);
    payload[32..36].copy_from_slice(&announce.pow_nonce);
    payload[36] = announce.scheme.code();
    payload[37..40].copy_from_slice(&check_bytes(
        version,
        &announce.public_key,
        &announce.pow_nonce,
        announce.scheme.code(),
        salt,
        announce.port,
    ));

    let ks = keystream(version, salt, announce.port);
    for (p, k) in payload.iter_mut().zip(ks.iter()) {
        *p ^= *k;
    }

    let authority = match group {
        IpAddr::V4(v4) => format!("{v4}:{LSD_PORT}"),
        IpAddr::V6(v6) => format!("[{v6}]:{LSD_PORT}"),
    };
    format!(
        "BT-SEARCH * HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Port: {}\r\n\
         Infohash: {}\r\n\
         Infohash: {}\r\n\
         cookie: {}\r\n\
         \r\n\r\n",
        announce.port,
        hex_lower(&payload[..INFOHASH_LEN]),
        hex_lower(&payload[INFOHASH_LEN..]),
        hex_lower(&salt),
    )
}

/// Read a datagram back, or decide it was not ours.
///
/// Takes no address, and that is the point: see the module note on why the
/// address a peer is dialled at is the one the socket reports and never one
/// the datagram could carry. Attach it with [`LanAnnounce::into_bootstrap_peer`].
pub fn decode_announce(datagram: &[u8]) -> Option<LanAnnounce> {
    if datagram.len() > MAX_ANNOUNCE_BYTES {
        return None;
    }
    let text = std::str::from_utf8(datagram).ok()?;
    let mut lines = text.split("\r\n");
    if !lines.next()?.eq_ignore_ascii_case("BT-SEARCH * HTTP/1.1") {
        return None;
    }

    let mut port: Option<u16> = None;
    let mut salt: Option<[u8; SALT_LEN]> = None;
    let mut infohashes: Vec<&str> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("Port") {
            port = value.parse::<u16>().ok();
        } else if name.eq_ignore_ascii_case("cookie") {
            salt = unhex_exact::<SALT_LEN>(value);
        } else if name.eq_ignore_ascii_case("Infohash") && infohashes.len() < 2 {
            infohashes.push(value);
        }
    }

    let port = port?;
    let salt = salt?;
    if port == 0 || infohashes.len() != 2 {
        return None;
    }

    let mut payload = [0u8; PAYLOAD_LEN];
    for (i, hash) in infohashes.iter().enumerate() {
        let raw = unhex_exact::<INFOHASH_LEN>(hash)?;
        payload[i * INFOHASH_LEN..(i + 1) * INFOHASH_LEN].copy_from_slice(&raw);
    }

    for &version in KNOWN_EXCHANGE_VERSIONS {
        let ks = keystream(version, salt, port);
        let mut plain = payload;
        for (p, k) in plain.iter_mut().zip(ks.iter()) {
            *p ^= *k;
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&plain[..32]);
        let mut pow_nonce = [0u8; 4];
        pow_nonce.copy_from_slice(&plain[32..36]);
        let Some(scheme) = LanScheme::from_code(plain[36]) else {
            continue;
        };
        let want = check_bytes(version, &public_key, &pow_nonce, plain[36], salt, port);
        if want != plain[37..40] {
            continue;
        }
        return Some(LanAnnounce {
            public_key,
            pow_nonce,
            port,
            scheme,
        });
    }
    None
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn unhex_exact<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: IpAddr = IpAddr::V4(LSD_GROUP_V4);
    const SALT: [u8; SALT_LEN] = [0xde, 0xad, 0xbe, 0xef];

    fn sample(scheme: LanScheme, port: u16) -> LanAnnounce {
        LanAnnounce {
            public_key: [7u8; 32],
            pow_nonce: [1, 2, 3, 4],
            port,
            scheme,
        }
    }

    fn hashes(wire: &str) -> Vec<String> {
        wire.lines()
            .filter_map(|l| l.strip_prefix("Infohash: "))
            .map(|v| v.trim().to_owned())
            .collect()
    }

    #[test]
    fn every_scheme_survives_the_wire() {
        // Walks the variants rather than a list somebody has to remember to
        // extend: a seventh scheme added without a code fails here, not in the
        // field on the one deployment that uses it.
        assert!(!LanScheme::ALL.is_empty());
        // And walking ALL is only a guard while ALL is complete. A variant
        // given a code and a from_code arm but forgotten here would otherwise
        // make this test blind to exactly the scheme nobody tested.
        let reachable = (0u8..=255)
            .filter(|c| LanScheme::from_code(*c).is_some())
            .count();
        assert_eq!(
            reachable,
            LanScheme::ALL.len(),
            "a scheme is decodable but missing from LanScheme::ALL"
        );
        for &scheme in LanScheme::ALL {
            let announce = sample(scheme, 5556);
            let wire = encode_announce(&announce, SALT, CURRENT_EXCHANGE_VERSION, V4);
            let back = decode_announce(wire.as_bytes())
                .unwrap_or_else(|| panic!("{scheme:?} did not survive"));
            assert_eq!(back, announce, "{scheme:?}");
            assert_eq!(
                LanScheme::from_code(scheme.code()),
                Some(scheme),
                "{scheme:?} code is not injective"
            );
        }
    }

    #[test]
    fn there_is_nowhere_in_the_payload_to_claim_an_address() {
        // The structural half of the guarantee: decode takes no address and
        // returns none, so the only address anywhere in this path is the one
        // the socket reports. A field to forge would have to appear in
        // LanAnnounce first, and this is what would have to be edited.
        let announce = sample(LanScheme::Obfs4Tcp, 5556);
        let wire = encode_announce(&announce, SALT, 1, V4);
        let back = decode_announce(wire.as_bytes()).unwrap();
        let from_a: IpAddr = "192.168.1.42".parse().unwrap();
        let from_b: IpAddr = "10.0.0.7".parse().unwrap();
        assert_eq!(
            back.clone().into_bootstrap_peer(from_a).transport,
            "obfs4-tcp://192.168.1.42:5556"
        );
        assert_eq!(
            back.into_bootstrap_peer(from_b).transport,
            "obfs4-tcp://10.0.0.7:5556",
            "the dialled address came from something other than the caller"
        );
    }

    #[test]
    fn real_bittorrent_announces_are_not_mistaken_for_ours() {
        // What actually arrives on that group. Every one must decode to
        // nothing, or sharing BitTorrent's group costs us a dial per torrent.
        //
        // Five hundred of them, not one: a single sample proves almost nothing
        // here. A datagram with no check bytes is still rejected whenever its
        // scheme byte lands out of range, which is 250 times in 256 — so one
        // hard-coded announce passes this test even with the integrity check
        // deleted. It did, when I broke the check to find out.
        let mut rejected = 0usize;
        for i in 0..500u32 {
            let mut h = blake3::Hasher::new();
            h.update(b"a plausible torrent");
            h.update(&i.to_le_bytes());
            let mut bytes = [0u8; 44];
            h.finalize_xof().fill(&mut bytes);
            let bt = format!(
                "BT-SEARCH * HTTP/1.1\r\n\
                 Host: {LSD_GROUP_V4}:{LSD_PORT}\r\n\
                 Port: {}\r\n\
                 Infohash: {}\r\n\
                 Infohash: {}\r\n\
                 cookie: {}\r\n\
                 \r\n\r\n",
                6881 + (i % 16),
                hex_lower(&bytes[..20]),
                hex_lower(&bytes[20..40]),
                hex_lower(&bytes[40..]),
            );
            if decode_announce(bt.as_bytes()).is_none() {
                rejected += 1;
            }
        }
        assert_eq!(
            rejected, 500,
            "a torrent announce was taken for a veil peer"
        );
    }

    #[test]
    fn corrupting_the_check_bytes_alone_is_rejected() {
        // The deterministic half of the same guard. Everything here decodes:
        // the salt is intact, so the keystream is right, and the scheme byte
        // is untouched and valid. Only the check disagrees, and only the check
        // can catch it.
        let wire = encode_announce(&sample(LanScheme::Obfs4Tcp, 5556), SALT, 1, V4);
        assert!(decode_announce(wire.as_bytes()).is_some());
        let hs = hashes(&wire);
        let mut second = unhex_exact::<INFOHASH_LEN>(&hs[1]).unwrap();
        second[INFOHASH_LEN - 1] ^= 0x01;
        let corrupted = wire.replace(&hs[1], &hex_lower(&second));
        assert_ne!(
            corrupted, wire,
            "the test did not actually corrupt anything"
        );
        assert!(
            decode_announce(corrupted.as_bytes()).is_none(),
            "a payload whose check bytes do not match was accepted"
        );
    }

    #[test]
    fn rewriting_a_header_in_flight_breaks_the_check_instead_of_redirecting_a_dial() {
        let wire = encode_announce(&sample(LanScheme::Obfs4Tcp, 5556), SALT, 1, V4);
        for (from, to) in [
            ("Port: 5556", "Port: 6666"),
            ("cookie: dead", "cookie: beef"),
        ] {
            let tampered = wire.replace(from, to);
            assert_ne!(tampered, wire, "the test did not actually change {from}");
            assert!(
                decode_announce(tampered.as_bytes()).is_none(),
                "a rewritten {from} was accepted"
            );
        }
    }

    #[test]
    fn the_key_is_nowhere_on_the_wire_and_one_node_never_writes_the_same_bytes_twice() {
        // The whole point of the XOR and of a per-announce salt. Without the
        // keystream the public key appears verbatim in the hex; without the
        // salt in the keystream this node's announces are byte-identical on
        // every network it ever joins, which is a fingerprint.
        let announce = sample(LanScheme::Obfs4Tcp, 5556);
        let a = encode_announce(&announce, [1, 1, 1, 1], 1, V4);
        let b = encode_announce(&announce, [2, 2, 2, 2], 1, V4);
        assert!(
            !a.contains(&hex_lower(&announce.public_key)),
            "public key is on the wire in clear"
        );
        assert_eq!(hashes(&a).len(), 2);
        // The FIRST infohash specifically: those 20 bytes lie wholly inside
        // the public key, so nothing but the keystream can make them differ.
        // Comparing whole datagrams would not test this — the cookie differs
        // by construction, so the packets differ even under a keystream that
        // ignores the salt entirely.
        assert_ne!(
            hashes(&a)[0],
            hashes(&b)[0],
            "the key region is identical across salts: the keystream ignores the salt"
        );
    }

    #[test]
    fn an_unknown_exchange_version_is_ignored_and_the_current_one_is_readable() {
        assert!(
            KNOWN_EXCHANGE_VERSIONS.contains(&CURRENT_EXCHANGE_VERSION),
            "this build cannot read what it writes"
        );
        let future = KNOWN_EXCHANGE_VERSIONS.iter().max().unwrap() + 1;
        let wire = encode_announce(&sample(LanScheme::Obfs4Tcp, 5556), SALT, future, V4);
        assert!(decode_announce(wire.as_bytes()).is_none());
    }

    #[test]
    fn malformed_datagrams_return_none_rather_than_panicking() {
        let good = encode_announce(&sample(LanScheme::Tcp, 5556), SALT, 1, V4);
        let cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"\xff\xfe\xfd".to_vec(),
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            b"BT-SEARCH * HTTP/1.1\r\nPort: 0\r\ncookie: deadbeef\r\n\r\n".to_vec(),
            b"BT-SEARCH * HTTP/1.1\r\nPort: notanumber\r\n\r\n".to_vec(),
            b"BT-SEARCH * HTTP/1.1\r\nPort: 5556\r\nInfohash: zz\r\n\r\n".to_vec(),
            // Well-formed but with the salt gone: nothing to key on.
            good.replace("cookie: deadbeef\r\n", "").into_bytes(),
            good.as_bytes()[..good.len() / 2].to_vec(),
            vec![b'x'; MAX_ANNOUNCE_BYTES + 1],
        ];
        for case in cases {
            assert!(
                decode_announce(&case).is_none(),
                "accepted a malformed datagram: {:?}",
                String::from_utf8_lossy(&case)
            );
        }
    }

    #[test]
    fn the_datagram_is_shaped_like_the_bep_it_borrows() {
        // A receiver that is a real BitTorrent client has to be able to parse
        // this without choking, or the cover story is worse than none.
        let wire = encode_announce(&sample(LanScheme::Obfs4Tcp, 5556), SALT, 1, V4);
        assert!(wire.starts_with("BT-SEARCH * HTTP/1.1\r\n"));
        assert!(wire.contains(&format!("Host: {LSD_GROUP_V4}:{LSD_PORT}\r\n")));
        assert!(wire.contains("cookie: deadbeef\r\n"));
        assert!(wire.ends_with("\r\n\r\n\r\n"));
        let hs = hashes(&wire);
        assert_eq!(hs.len(), 2);
        for h in hs {
            assert_eq!(h.len(), 40, "an infohash is 20 bytes of hex");
            assert!(
                h.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            );
        }
        // The v6 group is bracketed, or the authority has an ambiguous colon.
        let v6 = encode_announce(
            &sample(LanScheme::Quic, 5556),
            SALT,
            1,
            IpAddr::V6(LSD_GROUP_V6),
        );
        assert!(v6.contains(&format!("Host: [{LSD_GROUP_V6}]:{LSD_PORT}\r\n")));
    }

    #[test]
    fn the_peer_it_becomes_is_the_one_the_rest_of_bootstrap_expects() {
        use base64::Engine as _;
        let announce = sample(LanScheme::Obfs4Tcp, 5556);
        let peer = announce
            .clone()
            .into_bootstrap_peer("192.168.1.42".parse().unwrap());
        assert_eq!(peer.transport, "obfs4-tcp://192.168.1.42:5556");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&peer.public_key)
                .unwrap(),
            announce.public_key
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&peer.nonce)
                .unwrap(),
            announce.pow_nonce
        );
        assert_eq!(peer.algo, SignatureAlgorithm::Ed25519);
        // A v6 peer's authority is bracketed too.
        let v6 = sample(LanScheme::Tcp, 5556).into_bootstrap_peer("fe80::1".parse().unwrap());
        assert_eq!(v6.transport, "tcp://[fe80::1]:5556");
    }
}
