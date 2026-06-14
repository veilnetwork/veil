//! Wire protocol: proxy-connect header + status reply.
//!
//! See module-level doc in [`crate`] for the byte layout reference.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Status byte sent by the server after reading the connect header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectStatus {
    /// Server accepted the request and opened the TCP outbound;
    /// bidirectional pipe is now active.
    Ok = 0x00,
    /// Caller's node_id is not in the server's `allowed_node_ids` list,
    /// or the destination is a forbidden (RFC1918 / loopback / metadata)
    /// address and `allow_private` is off.
    Denied = 0x01,
    /// TCP-connect to destination failed (DNS error, refused, timeout).
    ConnectFailed = 0x02,
    /// Malformed wire header (host_len > 255, truncated, invalid UTF-8).
    BadRequest = 0x03,
}

impl ConnectStatus {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Ok),
            0x01 => Some(Self::Denied),
            0x02 => Some(Self::ConnectFailed),
            0x03 => Some(Self::BadRequest),
            _ => None,
        }
    }
}

/// Maximum length of the host field in bytes.  Matches DNS limit
/// (longest legitimate domain name) and mirrors the bound applied in
/// `veil-proxy::exit`.
pub const MAX_HOST_LEN: usize = 255;

/// S2.B: marker byte announcing an **app-layer cert preamble** before
/// the regular connect header.  The byte is unambiguous wrt the legacy
/// `[host_len u16 BE]` wire prefix — a legitimate host_len BE starts
/// either with 0x00 (host_len ≤ 255 → high byte zero) or a small value;
/// 0xC0 here is safely outside that range and lets the server detect
/// the new format on the first byte.
///
/// Wire shape (when present):
/// ```text
/// [0]      marker = 0xC0
/// [1..3]   cert_len u16 BE  (≤ MAX_APP_CERT_LEN)
/// [3..N]   cert_blob
/// [N..]    (existing connect header: host_len u16 BE + host + port)
/// ```
pub const APP_CERT_MARKER: u8 = 0xC0;

/// Hard cap on the cert blob length carried on the wire.  Real
/// `MembershipCert` blobs are < 1 KiB (Ed25519 sig = 64 B, body ≈ 80 B,
/// envelope overhead ≤ 100 B).  4 KiB leaves headroom for Falcon-512
/// signatures (~666 B) and future schema extensions without a wire bump.
pub const MAX_APP_CERT_LEN: usize = 4096;

/// Encode a connect header `[host_len u16 BE][host bytes][port u16 BE]`.
///
/// Returns `None` if `host` is empty or longer than [`MAX_HOST_LEN`].
pub fn encode_connect_header(host: &str, port: u16) -> Option<Vec<u8>> {
    let host_bytes = host.as_bytes();
    if host_bytes.is_empty() || host_bytes.len() > MAX_HOST_LEN {
        return None;
    }
    let mut buf = Vec::with_capacity(2 + host_bytes.len() + 2);
    buf.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(host_bytes);
    buf.extend_from_slice(&port.to_be_bytes());
    Some(buf)
}

/// Read a connect header off a byte stream.
pub async fn read_connect_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<(String, u16)> {
    let mut host_len_buf = [0u8; 2];
    reader.read_exact(&mut host_len_buf).await?;
    let host_len = u16::from_be_bytes(host_len_buf) as usize;
    if host_len == 0 || host_len > MAX_HOST_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("host_len {host_len} out of range [1, {MAX_HOST_LEN}]"),
        ));
    }
    let mut host_bytes = vec![0u8; host_len];
    reader.read_exact(&mut host_bytes).await?;
    let host = String::from_utf8(host_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("host UTF-8: {e}")))?;
    let mut port_buf = [0u8; 2];
    reader.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);
    if port == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "port is 0"));
    }
    Ok((host, port))
}

/// Write a one-byte status reply.
pub async fn write_status<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    status: ConnectStatus,
) -> io::Result<()> {
    writer.write_all(&[status as u8]).await
}

/// Encode an app-cert preamble `[0xC0][cert_len u16 BE][cert_blob]`.
///
/// Returns `None` if `cert_blob` is empty or longer than
/// [`MAX_APP_CERT_LEN`].
pub fn encode_app_cert_preamble(cert_blob: &[u8]) -> Option<Vec<u8>> {
    if cert_blob.is_empty() || cert_blob.len() > MAX_APP_CERT_LEN {
        return None;
    }
    let mut buf = Vec::with_capacity(1 + 2 + cert_blob.len());
    buf.push(APP_CERT_MARKER);
    buf.extend_from_slice(&(cert_blob.len() as u16).to_be_bytes());
    buf.extend_from_slice(cert_blob);
    Some(buf)
}

/// Outcome of reading the stream prefix on the server side.
#[derive(Debug)]
pub enum StreamPrefix {
    /// Client sent a cert preamble (S2.B); body holds the raw cert blob.
    /// Server should `decode_cert_blob` + `verify_membership_cert`,
    /// then read the regular connect header that follows.
    Cert(Vec<u8>),
    /// Client went straight to the connect header (legacy / no cert).
    /// `peeked_host_len_hi` is the first byte that's already consumed —
    /// the server must construct the connect-header read with this byte
    /// as the high half of host_len.
    NoPreamble { peeked_host_len_hi: u8 },
}

/// Peek the first byte off the stream and decide if a cert preamble
/// follows.  When marker matches, consume cert_len + blob and return
/// `Cert(blob)`.  Otherwise the byte is returned as `peeked_host_len_hi`
/// so the caller can splice it back into the host_len read.
pub async fn read_stream_prefix<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<StreamPrefix> {
    let mut marker = [0u8; 1];
    reader.read_exact(&mut marker).await?;
    if marker[0] != APP_CERT_MARKER {
        return Ok(StreamPrefix::NoPreamble {
            peeked_host_len_hi: marker[0],
        });
    }
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let cert_len = u16::from_be_bytes(len_buf) as usize;
    if cert_len == 0 || cert_len > MAX_APP_CERT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cert_len {cert_len} out of range [1, {MAX_APP_CERT_LEN}]"),
        ));
    }
    let mut blob = vec![0u8; cert_len];
    reader.read_exact(&mut blob).await?;
    Ok(StreamPrefix::Cert(blob))
}

/// Read a connect header **knowing the high byte of host_len was
/// already consumed**.  Used after `read_stream_prefix` returned
/// `NoPreamble { peeked_host_len_hi }`.
pub async fn read_connect_header_with_peeked_hi<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    peeked_host_len_hi: u8,
) -> io::Result<(String, u16)> {
    let mut host_len_lo = [0u8; 1];
    reader.read_exact(&mut host_len_lo).await?;
    let host_len = u16::from_be_bytes([peeked_host_len_hi, host_len_lo[0]]) as usize;
    if host_len == 0 || host_len > MAX_HOST_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("host_len {host_len} out of range [1, {MAX_HOST_LEN}]"),
        ));
    }
    let mut host_bytes = vec![0u8; host_len];
    reader.read_exact(&mut host_bytes).await?;
    let host = String::from_utf8(host_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("host UTF-8: {e}")))?;
    let mut port_buf = [0u8; 2];
    reader.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);
    if port == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "port is 0"));
    }
    Ok((host, port))
}

/// Read a one-byte status reply.
pub async fn read_status<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<ConnectStatus> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b).await?;
    ConnectStatus::from_byte(b[0]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown status byte 0x{:02x}", b[0]),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_rejects_empty_host() {
        assert!(encode_connect_header("", 80).is_none());
    }

    #[test]
    fn encode_rejects_oversized_host() {
        let huge = "a".repeat(MAX_HOST_LEN + 1);
        assert!(encode_connect_header(&huge, 80).is_none());
    }

    #[test]
    fn encode_max_size_host_succeeds() {
        let max = "a".repeat(MAX_HOST_LEN);
        let buf = encode_connect_header(&max, 443).expect("encode max");
        assert_eq!(buf.len(), 2 + MAX_HOST_LEN + 2);
    }

    #[tokio::test]
    async fn roundtrip_ipv4_host() {
        let encoded = encode_connect_header("192.0.2.1", 8080).expect("encode");
        let mut cursor = std::io::Cursor::new(encoded);
        let (host, port) = read_connect_header(&mut cursor).await.expect("decode");
        assert_eq!(host, "192.0.2.1");
        assert_eq!(port, 8080);
    }

    #[tokio::test]
    async fn roundtrip_dns_host() {
        let encoded = encode_connect_header("example.test", 443).expect("encode");
        let mut cursor = std::io::Cursor::new(encoded);
        let (host, port) = read_connect_header(&mut cursor).await.expect("decode");
        assert_eq!(host, "example.test");
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn read_rejects_zero_host_len() {
        let buf = vec![0x00, 0x00, 0x01, 0xbb];
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_connect_header(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_rejects_zero_port() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x04]);
        buf.extend_from_slice(b"host");
        buf.extend_from_slice(&[0x00, 0x00]);
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_connect_header(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn roundtrip_status() {
        for variant in [
            ConnectStatus::Ok,
            ConnectStatus::Denied,
            ConnectStatus::ConnectFailed,
            ConnectStatus::BadRequest,
        ] {
            let mut buf = Vec::new();
            write_status(&mut buf, variant).await.unwrap();
            let mut cursor = std::io::Cursor::new(buf);
            let read = read_status(&mut cursor).await.unwrap();
            assert_eq!(variant, read);
        }
    }

    #[tokio::test]
    async fn app_cert_preamble_roundtrip() {
        let cert = b"fake-cert-blob".to_vec();
        let preamble = encode_app_cert_preamble(&cert).expect("encode");
        // Marker + length + body.
        assert_eq!(preamble[0], APP_CERT_MARKER);
        assert_eq!(
            u16::from_be_bytes([preamble[1], preamble[2]]) as usize,
            cert.len()
        );
        assert_eq!(&preamble[3..], &cert[..]);

        let mut cursor = std::io::Cursor::new(preamble);
        let prefix = read_stream_prefix(&mut cursor).await.expect("decode");
        match prefix {
            StreamPrefix::Cert(blob) => assert_eq!(blob, cert),
            other => panic!("expected Cert(_), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_preamble_returns_peeked_byte() {
        // First byte of a regular connect header for host_len=256 (=0x0100).
        // The 0x01 first byte ≠ APP_CERT_MARKER, so read_stream_prefix
        // returns NoPreamble + the 0x01 byte as peeked_host_len_hi.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x04]); // host_len = 4
        buf.extend_from_slice(b"host");
        buf.extend_from_slice(&[0x01, 0xbb]); // port = 443
        let mut cursor = std::io::Cursor::new(buf);
        let prefix = read_stream_prefix(&mut cursor).await.expect("decode");
        let peeked = match prefix {
            StreamPrefix::NoPreamble { peeked_host_len_hi } => peeked_host_len_hi,
            other => panic!("expected NoPreamble, got {other:?}"),
        };
        // Splice peeked byte back into the connect-header read.
        let (host, port) = read_connect_header_with_peeked_hi(&mut cursor, peeked)
            .await
            .expect("read connect header");
        assert_eq!(host, "host");
        assert_eq!(port, 443);
    }

    #[test]
    fn app_cert_preamble_rejects_empty() {
        assert!(encode_app_cert_preamble(&[]).is_none());
    }

    #[test]
    fn app_cert_preamble_rejects_oversized() {
        let huge = vec![0u8; MAX_APP_CERT_LEN + 1];
        assert!(encode_app_cert_preamble(&huge).is_none());
    }

    #[tokio::test]
    async fn read_stream_prefix_rejects_zero_cert_len() {
        let buf = vec![APP_CERT_MARKER, 0x00, 0x00];
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_stream_prefix(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_status_rejects_unknown_byte() {
        let buf = vec![0xff];
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_status(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
