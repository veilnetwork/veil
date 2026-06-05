//! S2.B: ogate cert-message wire format.
//!
//! Wire shape:
//! ```text
//! [0]     marker = 0xC0
//! [1..3]  cert_len u16 BE
//! [3..N]  cert_blob
//! ```
//!
//! Marker `0xC0` is unambiguous wrt other AppData carry on ogate's stream:
//! * IPv4 packets start с 0x4_ (version nibble = 4).
//! * IPv6 packets start с 0x6_ (version nibble = 6).
//! * Batch envelopes (Phase E27) start с 0xB1.
//!
//! Receivers dispatch on the first byte: if 0xC0, parse cert-message
//! (separately от the IP-packet path); else fall through к the regular
//! IP-packet path.

/// First byte of an ogate cert message.  Outside the IPv4/IPv6 version-
/// nibble range и distinct от batch envelope's 0xB1.
pub const CERT_MARKER: u8 = 0xC0;

/// Hard cap on the embedded cert blob (matches oproxy's MAX_APP_CERT_LEN).
pub const MAX_CERT_LEN: usize = 4096;

/// Returns `true` if `data` looks like а cert message (= starts с marker).
#[inline]
pub fn is_cert_message(data: &[u8]) -> bool {
    data.first() == Some(&CERT_MARKER)
}

/// Encode а cert message containing `cert_blob`.  Returns `None` if the
/// blob is empty или exceeds [`MAX_CERT_LEN`].
pub fn encode_cert_message(cert_blob: &[u8]) -> Option<Vec<u8>> {
    if cert_blob.is_empty() || cert_blob.len() > MAX_CERT_LEN {
        return None;
    }
    let mut buf = Vec::with_capacity(3 + cert_blob.len());
    buf.push(CERT_MARKER);
    buf.extend_from_slice(&(cert_blob.len() as u16).to_be_bytes());
    buf.extend_from_slice(cert_blob);
    Some(buf)
}

/// Decode а cert message.  Returns `Ok(cert_blob)` on success or
/// а descriptive error on malformed input.
pub fn decode_cert_message(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() < 3 {
        return Err("cert message too short (< 3 bytes)");
    }
    if data[0] != CERT_MARKER {
        return Err("missing CERT_MARKER prefix");
    }
    let cert_len = u16::from_be_bytes([data[1], data[2]]) as usize;
    if cert_len == 0 || cert_len > MAX_CERT_LEN {
        return Err("cert_len out of [1, MAX_CERT_LEN]");
    }
    if data.len() != 3 + cert_len {
        return Err("cert_len does not match payload length");
    }
    Ok(data[3..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cert = b"fake-cert-blob".to_vec();
        let msg = encode_cert_message(&cert).expect("encode");
        assert!(is_cert_message(&msg));
        let decoded = decode_cert_message(&msg).expect("decode");
        assert_eq!(decoded, cert);
    }

    #[test]
    fn ipv4_packet_not_misidentified() {
        // Synthetic IPv4 header: version 4 → first byte 0x45 (IHL=5).
        let ipv4 = [
            0x45u8, 0, 0, 28, 0, 0, 0, 0, 64, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        ];
        assert!(!is_cert_message(&ipv4));
    }

    #[test]
    fn ipv6_packet_not_misidentified() {
        // IPv6 first byte: version=6 → 0x60 (high nibble).
        let ipv6 = [0x60u8, 0, 0, 0];
        assert!(!is_cert_message(&ipv6));
    }

    #[test]
    fn batch_envelope_not_misidentified() {
        let batch = [0xB1u8, 0, 0];
        assert!(!is_cert_message(&batch));
    }

    #[test]
    fn rejects_empty_cert() {
        assert!(encode_cert_message(&[]).is_none());
    }

    #[test]
    fn rejects_oversize_cert() {
        let huge = vec![0u8; MAX_CERT_LEN + 1];
        assert!(encode_cert_message(&huge).is_none());
    }

    #[test]
    fn decode_rejects_short_input() {
        assert!(decode_cert_message(&[0xC0]).is_err());
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        // Marker + cert_len=10 но only 5 bytes payload.
        let bad = [0xC0u8, 0, 10, 1, 2, 3, 4, 5];
        assert!(decode_cert_message(&bad).is_err());
    }
}
