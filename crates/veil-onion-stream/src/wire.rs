//! On-the-wire frame format carried INSIDE one onion circuit cell.
//!
//! The circuit hands us an opaque, length-preserved payload of at most
//! [`MAX_CELL`] = 382 bytes per cell (the circuit's own `[len][payload][pad]`
//! framing is already stripped, so a decoder sees exactly the bytes the encoder
//! wrote — no trailing pad). One frame per cell.
//!
//! Layout: `[ver u8][type u8][stream_id u32] …` — all multi-byte fields
//! big-endian. See each [`Frame`] variant for the rest.

use crate::seq;

/// Protocol version (bumped on any incompatible frame-layout change).
pub const PROTO_VER: u8 = 1;

/// Max opaque bytes the circuit carries in one cell (`MAX_CIRCUIT_INNER`).
/// Tracks veil-anonymity's `CIRCUIT_PAYLOAD_BYTES - 2` (this crate stays
/// transport-agnostic, so the tie is by convention; veilclient-ffi holds a
/// compile-time assert). 2026-07-02: bumped with the circuit cell
/// 384 -> 4096 -> 16384.
pub const MAX_CELL: usize = 16382;

/// `DATA` fixed overhead: `ver+type(2) + stream_id(4) + seq(4) + win(4) + len(2)`.
pub const DATA_OVERHEAD: usize = 16;

/// Max stream payload bytes per `DATA` cell — the stream MSS.
pub const MSS: usize = MAX_CELL - DATA_OVERHEAD; // 16366

/// Max selective-ACK ranges in one `ACK` frame (15 + 8·8 = 79 B ≤ MAX_CELL).
pub const MAX_SACKS: usize = 8;

mod ty {
    pub const SYN: u8 = 1;
    pub const SYN_ACK: u8 = 2;
    pub const DATA: u8 = 3;
    pub const ACK: u8 = 4;
    pub const FIN: u8 = 5;
    pub const RST: u8 = 6;
}

/// `RST` reason codes. The receiver maps these to [`crate`]-level events; the
/// app cares mainly about TIMED_OUT/APP (→ "interrupted, resume") vs a clean
/// `FIN` (→ EOF).
pub mod reset_reason {
    /// Application asked to abort (local close before EOF).
    pub const APP: u8 = 0;
    /// Idle / dead circuit detected by the driver's keepalive.
    pub const TIMED_OUT: u8 = 1;
    /// No such stream, or the peer is not accepting.
    pub const REFUSED: u8 = 2;
    /// Malformed frame / protocol violation.
    pub const PROTOCOL: u8 = 3;
}

/// A half-open selective-ACK range `[start, end)` of received byte offsets above
/// the cumulative ACK point.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SackRange {
    pub start: u32,
    pub end: u32,
}

/// A fixed-capacity, inline (alloc-free) list of up to [`MAX_SACKS`] ranges.
#[derive(Clone, Copy, Default)]
pub struct SackVec {
    ranges: [SackRange; MAX_SACKS],
    len: u8,
}

impl SackVec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `r`; returns `false` (and drops it) if already full.
    pub fn push(&mut self, r: SackRange) -> bool {
        let i = self.len as usize;
        if i >= MAX_SACKS {
            return false;
        }
        self.ranges[i] = r;
        self.len += 1;
        true
    }

    pub fn as_slice(&self) -> &[SackRange] {
        &self.ranges[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// Compare/format only the LIVE prefix — the tail past `len` is stale.
impl PartialEq for SackVec {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for SackVec {}
impl std::fmt::Debug for SackVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

/// One protocol frame. Borrows its `DATA` payload from the input cell (zero-copy
/// on the bulk path); everything else is inline.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Frame<'a> {
    /// Open a full-duplex stream. `isn` = initial send sequence for the opener's
    /// direction; `win` = opener's initial receive window.
    Syn { stream_id: u32, isn: u32, win: u32 },
    /// Accept a stream. `isn` = acceptor's initial send seq; `win` = its window;
    /// `ack` = acknowledges the SYN (= opener's `isn`).
    SynAck {
        stream_id: u32,
        isn: u32,
        win: u32,
        ack: u32,
    },
    /// Stream data: `seq` = byte offset of `payload[0]`; `win` = sender's current
    /// receive window (piggy-backed for the reverse direction).
    Data {
        stream_id: u32,
        seq: u32,
        win: u32,
        payload: &'a [u8],
    },
    /// Acknowledgement: `ack` = next contiguous byte expected (cumulative);
    /// `win` = receive window; `sacks` = out-of-order ranges already buffered.
    Ack {
        stream_id: u32,
        ack: u32,
        win: u32,
        sacks: SackVec,
    },
    /// Clean end of the sender's direction; `seq` = total bytes sent (the offset
    /// just past the final byte). Delivered to the reader as EOF.
    Fin { stream_id: u32, seq: u32 },
    /// Abnormal teardown; see [`reset_reason`]. The app treats this as
    /// "interrupted" (resume) rather than EOF.
    Rst { stream_id: u32, reason: u8 },
}

impl Frame<'_> {
    /// Encode into `out` (cleared first). The result is ≤ [`MAX_CELL`]; ready to
    /// hand to the circuit as one cell's payload.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.clear();
        out.push(PROTO_VER);
        match *self {
            Frame::Syn {
                stream_id,
                isn,
                win,
            } => {
                out.push(ty::SYN);
                put_u32(out, stream_id);
                put_u32(out, isn);
                put_u32(out, win);
            }
            Frame::SynAck {
                stream_id,
                isn,
                win,
                ack,
            } => {
                out.push(ty::SYN_ACK);
                put_u32(out, stream_id);
                put_u32(out, isn);
                put_u32(out, win);
                put_u32(out, ack);
            }
            Frame::Data {
                stream_id,
                seq,
                win,
                payload,
            } => {
                debug_assert!(payload.len() <= MSS, "DATA payload {} > MSS", payload.len());
                out.push(ty::DATA);
                put_u32(out, stream_id);
                put_u32(out, seq);
                put_u32(out, win);
                put_u16(out, payload.len() as u16);
                out.extend_from_slice(payload);
            }
            Frame::Ack {
                stream_id,
                ack,
                win,
                sacks,
            } => {
                out.push(ty::ACK);
                put_u32(out, stream_id);
                put_u32(out, ack);
                put_u32(out, win);
                out.push(sacks.len() as u8);
                for r in sacks.as_slice() {
                    put_u32(out, r.start);
                    put_u32(out, r.end);
                }
            }
            Frame::Fin { stream_id, seq } => {
                out.push(ty::FIN);
                put_u32(out, stream_id);
                put_u32(out, seq);
            }
            Frame::Rst { stream_id, reason } => {
                out.push(ty::RST);
                put_u32(out, stream_id);
                out.push(reason);
            }
        }
        debug_assert!(out.len() <= MAX_CELL, "frame {} > MAX_CELL", out.len());
    }

    /// Convenience: encode to a fresh `Vec`.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(MAX_CELL);
        self.encode_into(&mut v);
        v
    }

    /// Decode one frame from a cell payload, or `None` if malformed/truncated.
    pub fn decode(buf: &[u8]) -> Option<Frame<'_>> {
        let mut r = Reader::new(buf);
        if r.u8()? != PROTO_VER {
            return None;
        }
        let t = r.u8()?;
        let stream_id = r.u32()?;
        let frame = match t {
            ty::SYN => Frame::Syn {
                stream_id,
                isn: r.u32()?,
                win: r.u32()?,
            },
            ty::SYN_ACK => Frame::SynAck {
                stream_id,
                isn: r.u32()?,
                win: r.u32()?,
                ack: r.u32()?,
            },
            ty::DATA => {
                let s = r.u32()?;
                let win = r.u32()?;
                let len = r.u16()? as usize;
                if len > MSS {
                    return None;
                }
                let payload = r.take(len)?;
                Frame::Data {
                    stream_id,
                    seq: s,
                    win,
                    payload,
                }
            }
            ty::ACK => {
                let ack = r.u32()?;
                let win = r.u32()?;
                let n = r.u8()? as usize;
                if n > MAX_SACKS {
                    return None;
                }
                let mut sacks = SackVec::new();
                for _ in 0..n {
                    sacks.push(SackRange {
                        start: r.u32()?,
                        end: r.u32()?,
                    });
                }
                Frame::Ack {
                    stream_id,
                    ack,
                    win,
                    sacks,
                }
            }
            ty::FIN => Frame::Fin {
                stream_id,
                seq: r.u32()?,
            },
            ty::RST => Frame::Rst {
                stream_id,
                reason: r.u8()?,
            },
            _ => return None,
        };
        Some(frame)
    }

    /// The stream id this frame targets.
    pub fn stream_id(&self) -> u32 {
        match *self {
            Frame::Syn { stream_id, .. }
            | Frame::SynAck { stream_id, .. }
            | Frame::Data { stream_id, .. }
            | Frame::Ack { stream_id, .. }
            | Frame::Fin { stream_id, .. }
            | Frame::Rst { stream_id, .. } => stream_id,
        }
    }
}

/// Validate that two SACK ranges are well-formed and strictly above `ack`.
/// (Used by the engine; exposed for tests.)
pub fn sack_above(ack: u32, r: SackRange) -> bool {
    seq::lt(r.start, r.end) && seq::geq(r.start, ack)
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Bounds-checked sequential reader; every getter returns `None` past the end.
struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.b.get(self.i..self.i + 2)?;
        self.i += 2;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.b.get(self.i..self.i + 4)?;
        self.i += 4;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.i..self.i + n)?;
        self.i += n;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(f: Frame<'_>) {
        let enc = f.encode();
        assert!(enc.len() <= MAX_CELL, "frame over MAX_CELL: {}", enc.len());
        let dec = Frame::decode(&enc).expect("decode");
        assert_eq!(dec, f);
    }

    #[test]
    fn roundtrip_all_types() {
        roundtrip(Frame::Syn {
            stream_id: 7,
            isn: 1000,
            win: 65536,
        });
        roundtrip(Frame::SynAck {
            stream_id: 7,
            isn: 2000,
            win: 65536,
            ack: 1001,
        });
        roundtrip(Frame::Data {
            stream_id: 7,
            seq: 1234,
            win: 40000,
            payload: b"hello onion stream",
        });
        roundtrip(Frame::Fin {
            stream_id: 7,
            seq: 999_999,
        });
        roundtrip(Frame::Rst {
            stream_id: 7,
            reason: reset_reason::TIMED_OUT,
        });
        let mut sacks = SackVec::new();
        sacks.push(SackRange {
            start: 100,
            end: 200,
        });
        sacks.push(SackRange {
            start: 300,
            end: 366,
        });
        roundtrip(Frame::Ack {
            stream_id: 7,
            ack: 50,
            win: 30000,
            sacks,
        });
    }

    #[test]
    fn data_at_full_mss_fits_one_cell() {
        let payload = vec![0xABu8; MSS];
        let f = Frame::Data {
            stream_id: 1,
            seq: 0,
            win: 1,
            payload: &payload,
        };
        let enc = f.encode();
        assert_eq!(
            enc.len(),
            MAX_CELL,
            "full DATA cell must be exactly MAX_CELL"
        );
        assert_eq!(Frame::decode(&enc).unwrap(), f);
    }

    #[test]
    fn ack_with_max_sacks_fits() {
        let mut sacks = SackVec::new();
        for i in 0..MAX_SACKS as u32 {
            assert!(sacks.push(SackRange {
                start: i * 10,
                end: i * 10 + 5,
            }));
        }
        assert!(
            !sacks.push(SackRange {
                start: 9999,
                end: 10000
            }),
            "9th push rejected"
        );
        let f = Frame::Ack {
            stream_id: 42,
            ack: 0,
            win: 1,
            sacks,
        };
        let enc = f.encode();
        assert!(enc.len() <= MAX_CELL);
        assert_eq!(Frame::decode(&enc).unwrap(), f);
    }

    #[test]
    fn truncation_yields_none() {
        let f = Frame::SynAck {
            stream_id: 7,
            isn: 2000,
            win: 65536,
            ack: 1001,
        };
        let enc = f.encode();
        for cut in 0..enc.len() {
            assert!(
                Frame::decode(&enc[..cut]).is_none(),
                "prefix {cut} must not decode"
            );
        }
    }

    #[test]
    fn bad_version_and_type_rejected() {
        let mut enc = Frame::Fin {
            stream_id: 1,
            seq: 2,
        }
        .encode();
        enc[0] = PROTO_VER + 1;
        assert!(Frame::decode(&enc).is_none());
        let mut enc2 = Frame::Fin {
            stream_id: 1,
            seq: 2,
        }
        .encode();
        enc2[1] = 0xFE; // unknown type
        assert!(Frame::decode(&enc2).is_none());
    }

    #[test]
    fn oversized_sack_count_rejected() {
        // Hand-craft an ACK claiming MAX_SACKS+1 ranges.
        let mut b = vec![PROTO_VER, ty::ACK];
        b.extend_from_slice(&7u32.to_be_bytes()); // stream_id
        b.extend_from_slice(&0u32.to_be_bytes()); // ack
        b.extend_from_slice(&0u32.to_be_bytes()); // win
        b.push((MAX_SACKS + 1) as u8); // nsack too big
        assert!(Frame::decode(&b).is_none());
    }
}
