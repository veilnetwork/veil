//! What counts as somebody's inside.
//!
//! Every address this crate handles arrives from a stranger: a compact `nodes`
//! list in a KRPC response, a `values` entry, a record posted at a meeting
//! point. Acting on one means sending a packet to it, and a stranger who can
//! choose that address chooses which host on OUR side of the network receives
//! traffic from us — a loopback service, the machine on the next desk, a cloud
//! metadata endpoint. The handshake fails either way; which ports answered is
//! the answer they were after, and our host did the probing (report21 V20-M1b).
//!
//! ONE predicate, so the DHT ingress and the dial path cannot drift apart. The
//! dial path adds its own refusals on top — an address that is merely useless
//! to dial is not the same thing as one that is somebody's inside.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `ip` names a host on somebody's private or local network rather
/// than on the public internet.
///
/// A v4 address WEARING a v6 coat is a v4 address: `::ffff:127.0.0.1` is not
/// `Ipv6Addr::is_loopback` — only `::1` is — so without normalising first,
/// every rule below could be stepped around by writing the address the other
/// way (report21 V20-M1a).
pub fn is_internal(ip: IpAddr) -> bool {
    match normalize(ip) {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => is_internal_v6(v6),
    }
}

/// A mapped or IPv4-compatible v6 address as the v4 address it carries.
pub fn normalize(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else { return ip };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }
    // `::a.b.c.d`, the deprecated IPv4-compatible form: the same embedded
    // address without the `ffff` to key off. `::` and `::1` are not that —
    // they are the unspecified and loopback addresses and keep their own
    // meaning.
    let seg = v6.segments();
    if seg[..6] == [0, 0, 0, 0, 0, 0] && seg[6] != 0 {
        return IpAddr::V4(Ipv4Addr::from(((seg[6] as u32) << 16) | (seg[7] as u32)));
    }
    ip
}

fn is_internal_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        // Carrier NAT (100.64.0.0/10): another operator's inside, not a place
        // the public internet can reach.
        || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        // 0.0.0.0/8 "this network", and 240.0.0.0/4 reserved: neither names a
        // host anybody can reach, and both are cheap to try.
        || v4.octets()[0] == 0
        || v4.octets()[0] >= 240
}

fn is_internal_v6(v6: Ipv6Addr) -> bool {
    let seg = v6.segments();
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        // fc00::/7 unique-local and fe80::/10 link-local.
        || (seg[0] & 0xfe00) == 0xfc00
        || (seg[0] & 0xffc0) == 0xfe80
        // 64:ff9b::/96 is a NAT64 prefix: what is behind it is somebody
        // else's v4 network, reachable only through their translator.
        || seg[..4] == [0x0064, 0xff9b, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_written_the_other_way_is_the_same_address() {
        for inside in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.54",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "64:ff9b::7f00:1",
        ] {
            let ip: IpAddr = inside.parse().expect(inside);
            assert!(is_internal(ip), "{inside} was taken for a public address");
        }

        // The SAME addresses in v6 notation. Without normalisation none of the
        // v6 rules looks at the octets, so every refusal above could be had by
        // spelling it this way.
        for coat in [
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "::ffff:192.168.1.54",
            "::ffff:169.254.169.254",
            "::ffff:100.64.0.1",
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
            "::127.0.0.1",
            "::10.1.2.3",
        ] {
            let ip: IpAddr = coat.parse().expect(coat);
            assert!(
                is_internal(ip),
                "{coat} passed as public: a v4 address in a v6 coat is a v4 \
                 address, and the rules must see through it"
            );
        }

        // Vacuity: a public address must still be public, in either notation,
        // or the filter refuses the whole internet.
        for outside in [
            "8.8.8.8",
            "203.12.31.146",
            "1.1.1.1",
            "203.0.113.9", // documentation: not routed, but nobody's inside
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
            "2001:db8::1", // likewise documentation
        ] {
            let ip: IpAddr = outside.parse().expect(outside);
            assert!(!is_internal(ip), "{outside} was refused as internal");
        }
    }

    #[test]
    fn the_compatible_form_carries_the_address_it_says_it_does() {
        assert_eq!(
            normalize("::ffff:192.0.2.7".parse().unwrap()),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            normalize("::192.0.2.7".parse().unwrap()),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
        // `::` and `::1` mean themselves and are not compatible-form v4.
        assert_eq!(
            normalize("::".parse().unwrap()),
            "::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            normalize("::1".parse().unwrap()),
            "::1".parse::<IpAddr>().unwrap()
        );
        // An ordinary v6 address is left alone.
        assert_eq!(
            normalize("2001:4860:4860::8888".parse().unwrap()),
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        );
    }
}
