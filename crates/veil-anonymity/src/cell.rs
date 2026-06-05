//! Fixed-size cell padding.
//!
//! All anonymity-layer traffic flows in 512-byte cells regardless of
//! the underlying message size. An on-path observer sees a stream of
//! identical-size chunks and cannot infer:
//!
//! * The actual message length (bounded only by `pack` loops or
//!   multi-cell sequences — not yet implemented at this layer; v1
//!   ships single-cell messages only).
//! * Whether two cells belong to the same logical message.
//!
//! Combined with layered AEAD encryption (a separate sub-
//! piece), the on-path observer also can't tell who sent a cell or
//! who its final destination is.
//!
//! # Wire format (single cell, exactly 512 bytes)
//!
//! ```text
//! [0..2] payload_len u16 BE (0..=510)
//! [2..2+L] payload L bytes
//! [2+L..] zero padding (510 - L) bytes
//! ```
//!
//! ## Why u16 BE for length
//!
//! u16 BE is enough for L [0, 510] (max payload), and matches every
//! other length-prefixed wire format in this codebase (proto/header
//! proto/codec, proto/family). Using BE means a future wire-trace
//! parser can `xxd` a cell and read the length without endianness
//! confusion.
//!
//! ## Why zero padding instead of random
//!
//! Cells are encrypted by the caller (layered AEAD when wired into
//! 's circuit infrastructure). The ciphertext is already
//! pseudo-random regardless of plaintext content, so zero padding
//! provides no additional information leak vs random padding while
//! being:
//!
//! * Cheaper to produce (no CPRNG pull per cell).
//! * Trivially testable (assert padding bytes are 0x00).
//! * Catchable as a malleability attack — a corrupt cell that
//!   somehow has non-zero padding bytes will fail the unpack-time
//!   padding check, an extra defense layer beyond AEAD authentication.
//!
//! ## What this module does NOT do
//!
//! v1 is intentionally minimal:
//!
//! * **No multi-cell messages.** Caller's payload must fit in
//!   [`MAX_PAYLOAD_PER_CELL`] = 510 bytes. Multi-cell sequencing
//!   belongs in a higher layer that owns sequence numbers + reassembly.
//! * **No encryption.** Cells contain plaintext at this layer; the
//!   caller wraps them in AEAD before the wire. This separation
//!   keeps the cell primitive testable without crypto fixtures and
//!   lets the caller pick its own AEAD shape (single-key vs onion).
//! * **No timing controls.** Cell-rate shaping (constant-rate emit
//!   vs natural traffic) belongs in the dispatcher integration
//!   which is its own sub-piece.
//!
//! Each of those is its own file when its time comes — kept out of
//! this primitive so a regression in one doesn't tangle into another.

/// Wire-format size of a cell. Constant across the entire anonymity
/// layer; changing it would invalidate every in-flight cell + every
/// observer's signature analysis assumption.
pub const CELL_SIZE: usize = 512;

/// Bytes available for caller payload after the 2-byte length header.
/// A `pack`-able message must fit in this; longer messages need a
/// higher-layer fragmenting protocol (deferred — see module docs).
pub const MAX_PAYLOAD_PER_CELL: usize = CELL_SIZE - 2;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CellError {
    #[error("payload {got} B exceeds MAX_PAYLOAD_PER_CELL ({max} B)")]
    PayloadTooLarge { got: usize, max: usize },
    #[error("input is {got} B; cells are exactly {expected} B")]
    BadCellSize { got: usize, expected: usize },
    #[error("declared payload_len {declared} > MAX_PAYLOAD_PER_CELL ({max})")]
    DeclaredLenTooLarge { declared: usize, max: usize },
    #[error("padding byte at offset {offset} is {got:#04x}, expected 0x00")]
    NonZeroPadding { offset: usize, got: u8 },
}

/// Pack `payload` into a fixed-size 512-byte cell. Caller's payload
/// must be at most [`MAX_PAYLOAD_PER_CELL`] = 510 bytes; longer
/// messages must be fragmented at a higher layer (see module docs).
pub fn pack(payload: &[u8]) -> Result<[u8; CELL_SIZE], CellError> {
    if payload.len() > MAX_PAYLOAD_PER_CELL {
        return Err(CellError::PayloadTooLarge {
            got: payload.len(),
            max: MAX_PAYLOAD_PER_CELL,
        });
    }
    let mut cell = [0u8; CELL_SIZE];
    let len = payload.len() as u16;
    cell[0..2].copy_from_slice(&len.to_be_bytes());
    cell[2..2 + payload.len()].copy_from_slice(payload);
    // Bytes [2 + payload.len.. CELL_SIZE] stay 0x00 from the
    // `[0u8; CELL_SIZE]` initialisation — that's the zero padding.
    Ok(cell)
}

/// Unpack a cell back into its original payload. Validates:
///
/// * Input is exactly [`CELL_SIZE`] bytes.
/// * Declared payload length fits within the cell.
/// * Every padding byte is exactly `0x00` — non-zero padding indicates
///   either bit-rot in transit (caller didn't AEAD-wrap), a
///   malleability attempt, or a buggy `pack` implementation
///   somewhere in the network. Either way the cell is rejected
///   rather than silently treating padding as data.
pub fn unpack(cell: &[u8]) -> Result<Vec<u8>, CellError> {
    if cell.len() != CELL_SIZE {
        return Err(CellError::BadCellSize {
            got: cell.len(),
            expected: CELL_SIZE,
        });
    }
    let payload_len = u16::from_be_bytes([cell[0], cell[1]]) as usize;
    if payload_len > MAX_PAYLOAD_PER_CELL {
        return Err(CellError::DeclaredLenTooLarge {
            declared: payload_len,
            max: MAX_PAYLOAD_PER_CELL,
        });
    }
    // scan the entire padding
    // region in constant time. The previous implementation returned
    // on the first non-zero byte, leaking a position oracle through
    // timing — outer-layer AEAD authentication makes this oracle
    // hard to exploit in practice, but defense-in-depth costs us
    // nothing since the loop runs to completion regardless and
    // OR-folding the bytes is already O(N). We surface the FIRST
    // non-zero offset for debug-log clarity, but only AFTER scanning
    // the entire region.
    let padding_start = 2 + payload_len;
    let mut bad_or: u8 = 0;
    let mut first_bad: Option<(usize, u8)> = None;
    for (i, &byte) in cell[padding_start..].iter().enumerate() {
        bad_or |= byte;
        // Record the first bad byte without branching on the
        // current loop's success — we still scan to the end.
        if first_bad.is_none() && byte != 0 {
            first_bad = Some((padding_start + i, byte));
        }
    }
    if bad_or != 0
        && let Some((offset, got)) = first_bad
    {
        return Err(CellError::NonZeroPadding { offset, got });
    }
    Ok(cell[2..2 + payload_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epic482_2_round_trip_small_payload() {
        let payload = b"hello world";
        let cell = pack(payload).expect("pack");
        assert_eq!(
            cell.len(),
            CELL_SIZE,
            "cell must be exactly {CELL_SIZE} bytes"
        );
        let recovered = unpack(&cell).expect("unpack");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn epic482_2_round_trip_empty_payload() {
        // Zero-length payload is valid — it produces a fully-padded
        // cell that's indistinguishable on the wire from a "filler"
        // cell, which is exactly what cover-traffic emitters need.
        let cell = pack(&[]).expect("pack empty");
        let recovered = unpack(&cell).expect("unpack empty");
        assert_eq!(recovered, Vec::<u8>::new());
        // Sanity: the entire cell after the length header must be zero.
        assert!(
            cell[2..].iter().all(|&b| b == 0),
            "empty payload cell must be all zeros after the 2B length header"
        );
    }

    #[test]
    fn epic482_2_round_trip_max_size_payload() {
        // The boundary case: payload exactly fills the cell. Padding
        // region is empty; entire cell is header + payload.
        let payload = vec![0xABu8; MAX_PAYLOAD_PER_CELL];
        let cell = pack(&payload).expect("pack max");
        let recovered = unpack(&cell).expect("unpack max");
        assert_eq!(recovered, payload);
        assert_eq!(recovered.len(), MAX_PAYLOAD_PER_CELL);
    }

    #[test]
    fn epic482_2_pack_rejects_oversize_payload() {
        let payload = vec![0u8; MAX_PAYLOAD_PER_CELL + 1];
        let err = pack(&payload).unwrap_err();
        assert!(
            matches!(err, CellError::PayloadTooLarge { .. }),
            "oversize payload must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic482_2_unpack_rejects_wrong_size_input() {
        // A cell that's not exactly CELL_SIZE bytes is malformed at
        // the framing layer (caller fed us garbage). Reject loudly
        // rather than padding-or-truncating which would mask bugs.
        let too_small = vec![0u8; CELL_SIZE - 1];
        let too_big = vec![0u8; CELL_SIZE + 1];
        assert!(matches!(
            unpack(&too_small).unwrap_err(),
            CellError::BadCellSize { .. },
        ));
        assert!(matches!(
            unpack(&too_big).unwrap_err(),
            CellError::BadCellSize { .. },
        ));
    }

    #[test]
    fn epic482_2_unpack_rejects_declared_len_overflowing_cell() {
        // Construct a cell whose declared payload_len header points
        // past the end of the cell. An attacker who flips a length
        // byte must NOT cause the unpacker to read out-of-bounds OR
        // silently produce a too-long payload.
        let mut cell = [0u8; CELL_SIZE];
        cell[0..2].copy_from_slice(&((MAX_PAYLOAD_PER_CELL + 1) as u16).to_be_bytes());
        let err = unpack(&cell).unwrap_err();
        assert!(
            matches!(err, CellError::DeclaredLenTooLarge { .. }),
            "declared len > MAX must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic482_2_unpack_rejects_nonzero_padding_byte() {
        let payload = b"short";
        let mut cell = pack(payload).unwrap();
        // Flip the last padding byte. The unpacker must catch this
        // even though the declared payload length is correct — a
        // bit-flip in the padding region is either bit-rot or a
        // malleability attempt.
        cell[CELL_SIZE - 1] = 0xFF;
        let err = unpack(&cell).unwrap_err();
        assert!(
            matches!(
                err,
                CellError::NonZeroPadding {
                    offset: 511,
                    got: 0xFF
                }
            ),
            "non-zero padding byte must be detected: {err:?}"
        );
    }

    #[test]
    fn epic482_2_unpack_rejects_nonzero_padding_at_first_byte_after_payload() {
        // Edge case: the very first byte of the padding region is
        // non-zero. Must be detected (no off-by-one in the loop).
        let payload = b"xyz";
        let mut cell = pack(payload).unwrap();
        let first_padding_offset = 2 + payload.len();
        cell[first_padding_offset] = 0x01;
        let err = unpack(&cell).unwrap_err();
        assert_eq!(
            err,
            CellError::NonZeroPadding {
                offset: first_padding_offset,
                got: 0x01
            },
            "first padding byte must be checked",
        );
    }

    #[test]
    fn epic482_2_two_distinct_payloads_produce_distinct_cells_but_same_size() {
        // Sanity: anonymity property is "all cells have the same size"
        // NOT "all cells have the same content" (that would be useless).
        let cell_a = pack(b"alice@example").unwrap();
        let cell_b = pack(b"bob@somewhere").unwrap();
        assert_eq!(
            cell_a.len(),
            cell_b.len(),
            "all cells must be the same size on the wire"
        );
        assert_ne!(
            cell_a, cell_b,
            "distinct payloads must produce distinct cell contents \
             (otherwise pack is broken)"
        );
    }

    #[test]
    fn epic482_2_payload_size_does_not_leak_to_observer_via_cell_size() {
        // The whole point: an observer who sees the cell bytes
        // cannot tell whether the payload is 1 byte or 510 bytes.
        // Both cells are exactly CELL_SIZE bytes.
        let cell_one_byte = pack(b"X").unwrap();
        let cell_full = pack(&vec![b'Y'; MAX_PAYLOAD_PER_CELL]).unwrap();
        assert_eq!(
            cell_one_byte.len(),
            cell_full.len(),
            "1-byte and 510-byte payloads MUST yield same on-wire size"
        );
        assert_eq!(cell_one_byte.len(), CELL_SIZE);
    }
}
