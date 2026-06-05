//! Cursor-based decode helpers.
//!
//! Protocol decoders frequently walk a buffer sequentially: read a `u16`
//! then a variable-length slice, then another fixed-size array. Each read
//! needs (a) bounds-check the buffer (b) advance a running position
//! cursor (c) report a field-specific error message on truncation.
//!
//! Before consolidation every proto module duplicated these five helpers
//! (see [`read_u8`], [`read_u16`], [`read_u32`], [`read_u64`]
//! [`read_array`], [`read_bytes`]) as private functions — 10+ copies total.
//! They now live here and each decoder imports what it uses.
//!
//! The signatures deliberately differ from the offset-based helpers in
//! [`super`] (`read_array(buf, offset)`, `read_u16_be(buf, offset)` etc.):
//! the cursor variants take `&mut usize` and advance it, so chained reads
//! compose naturally without explicit offset arithmetic. Both styles have
//! legitimate use-cases and coexist intentionally.

use super::ProtoError;

/// Read one byte at `*pos`, advance cursor by 1.
#[inline(always)]
pub(crate) fn read_u8(buf: &[u8], pos: &mut usize, field: &'static str) -> Result<u8, ProtoError> {
    let v = *buf
        .get(*pos)
        .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
    *pos += 1;
    Ok(v)
}

/// Read big-endian `u16` at `*pos`, advance cursor by 2.
/// `checked_add` defends 32-bit-debug-build panic on
/// pos+N wraparound. Release builds were already safe (the wrapped
/// `buf.get(start..wrapped)` returns None), но debug builds panic при
/// integer add overflow — affecting fuzzing и CI.
#[inline(always)]
pub(crate) fn read_u16(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<u16, ProtoError> {
    let end = pos
        .checked_add(2)
        .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
    // SAFETY: `.get(..pos+2)` on success returns exactly a 2-byte slice
    // so `try_into::<[u8; 2]>` is infallible.
    let v = u16::from_be_bytes(slice.try_into().expect("2-byte slice"));
    *pos = end;
    Ok(v)
}

/// Read big-endian `u32` at `*pos`, advance cursor by 4.
#[inline(always)]
pub(crate) fn read_u32(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<u32, ProtoError> {
    let end = pos
        .checked_add(4)
        .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
    let v = u32::from_be_bytes(slice.try_into().expect("4-byte slice"));
    *pos = end;
    Ok(v)
}

/// Read big-endian `u64` at `*pos`, advance cursor by 8.
#[inline(always)]
pub(crate) fn read_u64(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<u64, ProtoError> {
    let end = pos
        .checked_add(8)
        .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
    let v = u64::from_be_bytes(slice.try_into().expect("8-byte slice"));
    *pos = end;
    Ok(v)
}

/// Read fixed-size byte array at `*pos`, advance cursor by `N`. Free-function
/// counterpart [`BoundedDecoder::read_array`] for callers that already track
/// their own `pos` cursor (D6: 7 hand-rolled `read_array` copies в
/// pairing_invite/name_claim_v2/instance_registry/identity_document/prekey_bundle/
/// recipient/identity_proof migrate к this canonical version).
#[inline(always)]
pub(crate) fn read_array<const N: usize>(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<[u8; N], ProtoError> {
    let slice = buf
        .get(
            *pos..pos
                .checked_add(N)
                .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?,
        )
        .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
    // SAFETY: `.get(..pos+N)` returns slice of exactly N bytes when `Some`
    // so try_into::<[u8; N]> is infallible.
    let arr = slice.try_into().expect("N-byte slice");
    *pos += N;
    Ok(arr)
}

/// Read `len` bytes at `*pos` into a `Vec`, advance cursor by `len`.
#[inline(always)]
pub(crate) fn read_bytes(
    buf: &[u8],
    pos: &mut usize,
    len: usize,
    field: &'static str,
) -> Result<Vec<u8>, ProtoError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
    let v = slice.to_vec();
    *pos = end;
    Ok(v)
}

// ── BoundedDecoder ────────────────────────────────────────────
//
// Higher-level wrapper around the cursor helpers above. Three benefits over
// raw `read_*(buf, &mut pos, …)` calls:
//
// 1. **Encapsulation** — buf + pos held in one struct, no chance of forgetting
// to advance `pos` or accidentally feeding the wrong cursor to the next
// call. Refactoring а decoder doesn't desync state.
//
// 2. **Length-prefixed-with-cap** — the most common protocol pattern is "read
// а u16/u32 length, validate ≤ MAX, read that many bytes." Pre-R3 every
// decoder hand-rolled this 4-line idiom (~50 sites across `veil-proto`).
// `read_u16_prefixed_bytes(max, field)` does it in one call с consistent
// error shape (`ValueTooLarge` instead of ad-hoc strings).
//
// 3. **Trailing-bytes guard** — `assert_eof` rejects garbage bytes after а
// well-formed payload. Pre-R3, ~30% of decoders silently ignored trailers
// (а DoS amplifier / API ambiguity vector); the rest hand-checked.
//
// Migration strategy: NEW decoders use `BoundedDecoder`; old decoders migrate
// when touched. Both styles compose c the same `ProtoError` taxonomy и share
// the underlying cursor helpers, so mixing-and-matching is fine.

/// Stateful decoder holding а byte buffer + read cursor.
///
/// Construction is а pure borrow — no allocation, no validation. Each
/// `read_*` method advances the cursor on success; on failure the cursor
/// position is unspecified (caller treats the decode as failed).
///
/// **Not thread-safe** — `&mut self` ensures sequential ownership.
pub struct BoundedDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BoundedDecoder<'a> {
    /// Wrap а buffer for sequential decoding starting at offset 0.
    #[inline(always)]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Read а single u8 at the cursor, advance by 1.
    #[inline(always)]
    pub fn read_u8(&mut self, field: &'static str) -> Result<u8, ProtoError> {
        read_u8(self.buf, &mut self.pos, field)
    }

    /// Read big-endian u16 at the cursor, advance by 2.
    #[inline(always)]
    pub fn read_u16(&mut self, field: &'static str) -> Result<u16, ProtoError> {
        read_u16(self.buf, &mut self.pos, field)
    }

    /// Read big-endian u64 at the cursor, advance by 8.
    #[inline(always)]
    pub fn read_u64(&mut self, field: &'static str) -> Result<u64, ProtoError> {
        read_u64(self.buf, &mut self.pos, field)
    }

    /// Read а fixed-size byte array at the cursor, advance by `N`.
    ///
    /// Const-generic length avoids а runtime allocation; use this for
    /// known-fixed sizes (32-byte node_id, 16-byte instance_id, etc.).
    ///
    /// Audit batch 2026-05-25 phase M: use `checked_add` для the end
    /// offset к match the free-function helpers (`read_u8`, `read_u16`,
    /// `read_u32`, `read_u64`, `read_bytes`).  Without it, а 32-bit
    /// debug build could panic on `self.pos + N` overflow if а decoder
    /// somehow accumulated а pos near `usize::MAX`; in release the wrap
    /// would silently slice into garbage, leading к а decode-error or
    /// — worse — а valid-looking-but-corrupt parse.  Slice `get()`
    /// returns `None` on out-of-bounds so error path stays the same.
    #[inline(always)]
    pub fn read_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], ProtoError> {
        let end = self
            .pos
            .checked_add(N)
            .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| ProtoError::Malformed(format!("truncated: {field}")))?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        self.pos = end;
        Ok(out)
    }

    /// Read `len` bytes at the cursor into а new `Vec`, advance by `len`.
    #[inline(always)]
    pub fn read_bytes(&mut self, len: usize, field: &'static str) -> Result<Vec<u8>, ProtoError> {
        read_bytes(self.buf, &mut self.pos, len, field)
    }

    /// Reject а decode if any bytes remain unread.
    ///
    /// ** seven other previously-public
    /// helper methods (`pos`, `remaining`, `read_u32`
    /// `read_u16_prefixed_bytes`, `read_u32_prefixed_bytes`
    /// `read_u8_prefixed_string`, `skip_remaining`) were removed because
    /// they had no callers — `BoundedDecoder` introduction (
    /// R3) only migrated `mlkem_cert.rs`, и the rest of the proto
    /// decoders kept using the cursor-based free functions directly.
    /// If а future migration epic completes the surface (all proto
    /// decoders на `BoundedDecoder`), restore the helpers from git
    /// history (commit предшествующий cleanup).
    pub fn assert_eof(&self) -> Result<(), ProtoError> {
        if self.pos < self.buf.len() {
            return Err(ProtoError::TrailingBytes {
                trailing: self.buf.len() - self.pos,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u8_advances_cursor() {
        let buf = [0xAB, 0xCD];
        let mut pos = 0;
        assert_eq!(read_u8(&buf, &mut pos, "test").unwrap(), 0xAB);
        assert_eq!(pos, 1);
    }

    #[test]
    fn read_u32_be_roundtrip() {
        let buf = 0xDEADBEEFu32.to_be_bytes();
        let mut pos = 0;
        assert_eq!(read_u32(&buf, &mut pos, "test").unwrap(), 0xDEADBEEF);
        assert_eq!(pos, 4);
    }

    #[test]
    fn read_bytes_len_zero_is_empty() {
        let buf = [0u8; 10];
        let mut pos = 5;
        let v = read_bytes(&buf, &mut pos, 0, "test").unwrap();
        assert!(v.is_empty());
        assert_eq!(pos, 5);
    }
}
