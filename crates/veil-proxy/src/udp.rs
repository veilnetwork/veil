//! Bounded datagram framing used inside one authenticated veil proxy stream.
//!
//! SOCKS5 UDP packets are datagrams while APP_DATA is an ordered byte stream,
//! so message boundaries must be restored explicitly. The frame is:
//!
//! ```text
//! [body_len: u32 BE][ATYP: u8][address][port: u16 BE][payload]
//! ```
//!
//! `body_len` is capped before allocation. Fragmented SOCKS5 UDP packets are
//! rejected by the ingress and never enter this framing.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::socks5::ProxyDestination;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// Leaves enough headroom for address/framing within a 64 KiB APP_DATA chunk.
pub const MAX_UDP_PAYLOAD: usize = 60 * 1024;
const MAX_FRAME_BODY: usize = MAX_UDP_PAYLOAD + 1 + 255 + 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyDatagram {
    pub destination: ProxyDestination,
    pub payload: Vec<u8>,
}

pub fn encode_datagram(datagram: &ProxyDatagram) -> std::io::Result<Vec<u8>> {
    if datagram.payload.len() > MAX_UDP_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UDP payload exceeds veil proxy limit",
        ));
    }

    let mut body = Vec::with_capacity(datagram.payload.len() + 32);
    if let Ok(ipv4) = datagram.destination.host.parse::<std::net::Ipv4Addr>() {
        body.push(ATYP_IPV4);
        body.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = datagram.destination.host.parse::<std::net::Ipv6Addr>() {
        body.push(ATYP_IPV6);
        body.extend_from_slice(&ipv6.octets());
    } else {
        let host = datagram.destination.host.as_bytes();
        if host.is_empty() || host.len() > u8::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP destination domain length is invalid",
            ));
        }
        body.push(ATYP_DOMAIN);
        body.push(host.len() as u8);
        body.extend_from_slice(host);
    }
    body.extend_from_slice(&datagram.destination.port.to_be_bytes());
    body.extend_from_slice(&datagram.payload);
    if body.len() > MAX_FRAME_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UDP frame exceeds veil proxy limit",
        ));
    }

    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub async fn read_datagram<R>(reader: &mut R) -> std::io::Result<ProxyDatagram>
where
    R: AsyncRead + Unpin,
{
    let body_len = reader.read_u32().await? as usize;
    if !(1 + 2..=MAX_FRAME_BODY).contains(&body_len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid UDP frame length",
        ));
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    parse_body(&body)
}

pub fn parse_socks5_datagram(packet: &[u8]) -> std::io::Result<ProxyDatagram> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid SOCKS5 UDP reserved bytes",
        ));
    }
    if packet[2] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fragmented SOCKS5 UDP packets are unsupported",
        ));
    }
    parse_body(&packet[3..])
}

pub fn encode_socks5_datagram(datagram: &ProxyDatagram) -> std::io::Result<Vec<u8>> {
    let framed = encode_datagram(datagram)?;
    let body = &framed[4..];
    let mut packet = Vec::with_capacity(body.len() + 3);
    packet.extend_from_slice(&[0, 0, 0]);
    packet.extend_from_slice(body);
    Ok(packet)
}

fn parse_body(body: &[u8]) -> std::io::Result<ProxyDatagram> {
    let mut cursor = 0usize;
    let atyp = take_u8(body, &mut cursor)?;
    let host = match atyp {
        ATYP_IPV4 => {
            let octets = take(body, &mut cursor, 4)?;
            std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).to_string()
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = take(body, &mut cursor, 16)?
                .try_into()
                .expect("length checked");
            std::net::Ipv6Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let len = take_u8(body, &mut cursor)? as usize;
            if len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "empty UDP destination domain",
                ));
            }
            String::from_utf8(take(body, &mut cursor, len)?.to_vec()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid UDP destination domain",
                )
            })?
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported UDP destination address type",
            ));
        }
    };
    let port = u16::from_be_bytes(
        take(body, &mut cursor, 2)?
            .try_into()
            .expect("length checked"),
    );
    let payload = body[cursor..].to_vec();
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UDP payload exceeds veil proxy limit",
        ));
    }
    Ok(ProxyDatagram {
        destination: ProxyDestination::tcp(host, port),
        payload,
    })
}

fn take_u8(body: &[u8], cursor: &mut usize) -> std::io::Result<u8> {
    Ok(take(body, cursor, 1)?[0])
}

fn take<'a>(body: &'a [u8], cursor: &mut usize, len: usize) -> std::io::Result<&'a [u8]> {
    let end = cursor.checked_add(len).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "UDP frame length overflow")
    })?;
    let value = body.get(*cursor..end).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated UDP frame")
    })?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn framing_roundtrips_ipv4_ipv6_and_domain() {
        for destination in [
            ProxyDestination::tcp("1.1.1.1", 53),
            ProxyDestination::tcp("2606:4700:4700::1111", 53),
            ProxyDestination::tcp("resolver.example", 853),
        ] {
            let expected = ProxyDatagram {
                destination,
                payload: b"question".to_vec(),
            };
            let frame = encode_datagram(&expected).unwrap();
            let actual = read_datagram(&mut frame.as_slice()).await.unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn socks5_udp_framing_roundtrips() {
        let expected = ProxyDatagram {
            destination: ProxyDestination::tcp("example.com", 443),
            payload: vec![1, 2, 3, 4],
        };
        let packet = encode_socks5_datagram(&expected).unwrap();
        assert_eq!(parse_socks5_datagram(&packet).unwrap(), expected);
    }

    #[test]
    fn fragmented_and_oversized_datagrams_fail_closed() {
        assert!(parse_socks5_datagram(&[0, 0, 1, ATYP_IPV4]).is_err());
        let oversized = ProxyDatagram {
            destination: ProxyDestination::tcp("1.1.1.1", 53),
            payload: vec![0; MAX_UDP_PAYLOAD + 1],
        };
        assert!(encode_datagram(&oversized).is_err());
    }
}
