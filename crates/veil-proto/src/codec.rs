use super::{
    ProtoError,
    header::{FrameHeader, HEADER_SIZE, MAGIC, VERSION},
};

/// Absolute hard ceiling on frame body size (16 MiB).
/// Frames claiming a larger body are rejected at decode time regardless of any
/// per-session limit.
pub const MAX_FRAME_BODY: u32 = 16 * 1024 * 1024;

/// Default per-session frame body limit (1 MiB).
/// Use [`decode_header_with_limit`] to enforce a tighter bound per session.
pub const DEFAULT_MAX_FRAME_BODY: u32 = 1024 * 1024;

/// Encode a [`FrameHeader`] into a fixed 24-byte array.
///
/// The `MAGIC` constant and `VERSION` are written unconditionally; the values
/// stored in `header.version` and the magic bytes are not trusted.
pub fn encode_header(header: &FrameHeader) -> [u8; HEADER_SIZE] {
    let mut buf = [0u8; HEADER_SIZE];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION;
    buf[5] = header.family;
    [buf[6], buf[7]] = header.msg_type.to_be_bytes();
    [buf[8], buf[9]] = header.flags.to_be_bytes();
    [buf[10], buf[11]] = header.header_len.to_be_bytes();
    [buf[12], buf[13], buf[14], buf[15]] = header.body_len.to_be_bytes();
    [buf[16], buf[17], buf[18], buf[19]] = header.stream_id.to_be_bytes();
    [buf[20], buf[21], buf[22], buf[23]] = header.request_id.to_be_bytes();
    buf
}

/// The AEAD associated data for one OVL1 frame: its ENTIRE final wire header.
///
/// The AAD used to be three bytes — `family` and `msg_type` — which left
/// `flags`, `header_len`, `body_len`, `stream_id` and `request_id` outside the
/// Poly1305 tag. On `tcp://`, `ws://` and `socks://`, which are registered
/// transports and carry no outer authentication of their own, an on-path
/// attacker could take an authentic frame and rewrite those fields
/// (audit V-01):
///
/// * move a valid `AppData`/`AppClose` onto a DIFFERENT stream;
/// * change `request_id` so a DHT response is delivered to the wrong waiter;
/// * change `body_len` so the peer waits for bytes that never come, allocates
///   for them, or tears the session down.
///
/// The ciphertext was authentic in every case. Only its placement was forged,
/// and placement is where the meaning lives.
///
/// Binding the whole header fixes that, and it costs nothing on the wire: the
/// AAD is not transmitted, it is the header the receiver already has. The
/// header passed here MUST be the final one — on the send path that means
/// AFTER `body_len` has been set to the ciphertext length, or the receiver
/// computes different bytes and every frame fails to open.
///
/// ⚠️ Wire-breaking. A peer computing the old 3-byte AAD cannot open these
/// frames and vice versa, which is why [`crate::header::VERSION`] went to 2 in
/// the same change: a mismatched peer is refused at `decode_header` with
/// `UnsupportedVersion`, which says what is wrong, instead of failing every
/// AEAD open with a decrypt error that looks like corruption or an attack.
#[inline]
pub fn frame_aad(header: &FrameHeader) -> [u8; HEADER_SIZE] {
    encode_header(header)
}

/// encode a full frame (header + body) into a single `Vec<u8>`
/// with exactly one allocation.
///
/// Replaces the common pattern
/// ```ignore
/// let mut frame = encode_header(&hdr).to_vec;
/// frame.extend_from_slice(&body);
/// ```
/// which allocates `HEADER_SIZE` bytes first, then may reallocate on extend
/// if the body is larger than the initial capacity. This helper sizes the
/// Vec correctly up-front (`HEADER_SIZE + body.len`) so the extend is a
/// single memcpy with no growth.
///
/// Used in dispatch hot paths that re-serialise frames per candidate hop.
pub fn encode_frame(header: &FrameHeader, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_SIZE + body.len());
    buf.extend_from_slice(&encode_header(header));
    buf.extend_from_slice(body);
    buf
}

/// Decode a [`FrameHeader`] using a caller-supplied body-size limit.
///
/// `max_body` is clamped [`MAX_FRAME_BODY`] (16 MiB) so callers cannot
/// accidentally bypass the hard ceiling. Pass [`DEFAULT_MAX_FRAME_BODY`] for
/// the 1 MiB default, or a value from `SessionConfig::max_frame_body_bytes`
/// for per-session tuning.
pub fn decode_header_with_limit(buf: &[u8], max_body: u32) -> Result<FrameHeader, ProtoError> {
    let max_body = max_body.min(MAX_FRAME_BODY);
    decode_header_inner(buf, max_body)
}

/// Decode a [`FrameHeader`] from a byte slice.
///
/// Returns [`ProtoError::BufferTooShort`] if fewer than 24 bytes are available.
/// Returns [`ProtoError::InvalidMagic`] / [`ProtoError::UnsupportedVersion`] on
/// bad magic or version mismatch.
/// Returns [`ProtoError::BodyTooLarge`] if `body_len > MAX_FRAME_BODY`.
pub fn decode_header(buf: &[u8]) -> Result<FrameHeader, ProtoError> {
    decode_header_inner(buf, MAX_FRAME_BODY)
}

fn decode_header_inner(buf: &[u8], max_body: u32) -> Result<FrameHeader, ProtoError> {
    if buf.len() < HEADER_SIZE {
        return Err(ProtoError::BufferTooShort {
            need: HEADER_SIZE,
            got: buf.len(),
        });
    }

    let magic = [buf[0], buf[1], buf[2], buf[3]];
    if magic != MAGIC {
        return Err(ProtoError::InvalidMagic(magic));
    }

    let version = buf[4];
    if version != VERSION {
        return Err(ProtoError::UnsupportedVersion(version));
    }

    let family = buf[5];
    let msg_type = u16::from_be_bytes([buf[6], buf[7]]);
    let flags = u16::from_be_bytes([buf[8], buf[9]]);
    let header_len = u16::from_be_bytes([buf[10], buf[11]]);
    let body_len = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let stream_id = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let request_id = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);

    // strict header_len: OVL1 v1 frames have a fixed 24-byte
    // header (no TLV extensions yet). Reject any other value to prevent
    // future-version-confusion attacks where a peer claims a larger
    // header AND smuggles control bytes. When TLV extensions ship, this
    // check becomes a range: `if !(HEADER_SIZE as u16..=MAX_TLV_HEADER).contains(&header_len)`.
    if header_len as usize != crate::HEADER_SIZE {
        return Err(ProtoError::Malformed(format!(
            "header_len={header_len} but expected {} (OVL1 v1 has no TLV header extensions)",
            crate::HEADER_SIZE,
        )));
    }

    if body_len > max_body {
        return Err(ProtoError::BodyTooLarge {
            body_len,
            max: max_body,
        });
    }

    Ok(FrameHeader {
        version,
        family,
        msg_type,
        flags,
        header_len,
        body_len,
        stream_id,
        request_id,
    })
}

#[cfg(test)]
mod v01_tests {
    use super::*;
    use crate::header::HEADER_SIZE;

    fn hdr() -> FrameHeader {
        let mut h = FrameHeader::new(3, 3); // App family, AppData
        h.body_len = 100;
        h.stream_id = 7;
        h.request_id = 42;
        h.flags = 1;
        h
    }

    /// Every byte of the header is inside the tag.
    ///
    /// The AAD used to be `[family, msg_type_hi, msg_type_lo]`, which left
    /// `flags`, `header_len`, `body_len`, `stream_id` and `request_id` outside
    /// it. On a transport with no outer authentication — `tcp://`, `ws://`,
    /// `socks://`, all registered — an on-path attacker could take an
    /// AUTHENTIC frame and change any of them: move an `AppData` to another
    /// stream, redirect a DHT response by rewriting `request_id`, or change
    /// `body_len` so the peer waits for bytes that never arrive (audit V-01).
    ///
    /// The ciphertext stayed valid in every one of those. Only its placement
    /// was forged, and placement is where the meaning is.
    #[test]
    fn every_header_field_changes_the_aad() {
        let base = frame_aad(&hdr());
        assert_eq!(base.len(), HEADER_SIZE, "the AAD is the whole header");

        let mut moved_stream = hdr();
        moved_stream.stream_id = 8;
        assert_ne!(
            frame_aad(&moved_stream),
            base,
            "a frame moved to another stream must not authenticate"
        );

        let mut other_waiter = hdr();
        other_waiter.request_id = 43;
        assert_ne!(
            frame_aad(&other_waiter),
            base,
            "a response redirected to another waiter must not authenticate"
        );

        let mut lied_length = hdr();
        lied_length.body_len = 101;
        assert_ne!(
            frame_aad(&lied_length),
            base,
            "a rewritten body_len must not authenticate"
        );

        let mut reprioritised = hdr();
        reprioritised.flags = 2;
        assert_ne!(frame_aad(&reprioritised), base, "flags are covered");

        let mut wider_header = hdr();
        wider_header.header_len = 32;
        assert_ne!(frame_aad(&wider_header), base, "header_len is covered");

        // ...and the two fields the old AAD did cover are still covered.
        let mut other_family = hdr();
        other_family.family = 4;
        assert_ne!(frame_aad(&other_family), base);
        let mut other_type = hdr();
        other_type.msg_type = 4;
        assert_ne!(frame_aad(&other_type), base);
    }

    /// The receiver rebuilds the AAD from a DECODED header, the sender builds
    /// it from the one it is about to encode. Those must be the same bytes, or
    /// nothing opens.
    #[test]
    fn the_aad_survives_an_encode_decode_round_trip() {
        let sent = hdr();
        let wire = encode_header(&sent);
        let received = decode_header(&wire).expect("decode our own header");
        assert_eq!(
            frame_aad(&received),
            frame_aad(&sent),
            "sender and receiver must compute identical AAD"
        );
        assert_eq!(frame_aad(&sent), wire, "the AAD IS the wire header");
    }

    /// A peer on the old major is refused by NAME, not by a decrypt failure
    /// that looks like corruption.
    #[test]
    fn a_previous_major_version_is_rejected_at_decode() {
        let mut wire = encode_header(&hdr());
        wire[4] = 1; // the version this change replaced
        match decode_header(&wire) {
            Err(ProtoError::UnsupportedVersion(v)) => assert_eq!(v, 1),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }
}
