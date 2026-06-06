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
