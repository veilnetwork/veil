//! Transport-hint IPC payload.
//!
//! Wire format (response to `LocalAppMsg::TransportHintQuery`):
//!
//! ```text
//! [0] count: u8 (number of hint entries; 0 = no data yet)
//! [1..] entries: count × HintEntry
//!
//! HintEntry:
//! [0] scheme_len: u8
//! [1..] scheme: utf8 (≤ 16 bytes by convention; e.g. "tcp", "tls")
//! [..] success_pct: u8 (0..=100)
//! [..] sample_count: u16 BE (saturates at u16::MAX; recent decay applies)
//! ```
//!
//! Entries are pre-sorted by the server (success_pct desc, sample_count desc).

use crate::ProtoError;

/// One entry [`TransportHintResultPayload`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportHintEntry {
    /// Transport URI scheme (e.g. `"tcp"`, `"tls"`, `"quic"`, `"wss"`).
    pub scheme: String,
    /// Success rate as a percentage (0..=100).
    pub success_pct: u8,
    /// Number of probe samples this rate is based on (saturates at u16::MAX).
    pub sample_count: u16,
}

/// Response payload [`crate::family::LocalAppMsg::TransportHintResult`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TransportHintResultPayload {
    /// Hint entries, sorted best-first by the server.
    pub entries: Vec<TransportHintEntry>,
}

impl TransportHintResultPayload {
    /// Maximum entries in a single response. Exceeds the count of registered
    /// transport schemes, so this only truncates pathological cases.
    pub const MAX_ENTRIES: usize = 16;

    /// Encode to the wire format.
    pub fn encode(&self) -> Vec<u8> {
        let count = self.entries.len().min(Self::MAX_ENTRIES);
        // Pre-size: 1 byte count + per-entry (1 + scheme.len + 1 + 2).
        let cap = 1 + self
            .entries
            .iter()
            .take(count)
            .map(|e| 4 + e.scheme.len())
            .sum::<usize>();
        let mut buf = Vec::with_capacity(cap);
        buf.push(count as u8);
        for e in self.entries.iter().take(count) {
            let scheme_len = e.scheme.len().min(255);
            buf.push(scheme_len as u8);
            buf.extend_from_slice(&e.scheme.as_bytes()[..scheme_len]);
            buf.push(e.success_pct);
            buf.extend_from_slice(&e.sample_count.to_be_bytes());
        }
        buf
    }

    /// Decode from the wire format.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooShort { need: 1, got: 0 });
        }
        let count = buf[0] as usize;
        // Cap allocation at MAX_ENTRIES — encode truncates writers to this
        // bound, so any greater count on the wire is malformed/hostile.
        if count > Self::MAX_ENTRIES {
            return Err(ProtoError::ValueTooLarge {
                field: "transport_hints.count",
                value: count as u64,
                max: Self::MAX_ENTRIES as u64,
            });
        }
        let mut pos = 1;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            if pos + 1 > buf.len() {
                return Err(ProtoError::BufferTooShort {
                    need: pos + 1,
                    got: buf.len(),
                });
            }
            let scheme_len = buf[pos] as usize;
            pos += 1;
            if pos + scheme_len + 3 > buf.len() {
                return Err(ProtoError::BufferTooShort {
                    need: pos + scheme_len + 3,
                    got: buf.len(),
                });
            }
            let scheme = std::str::from_utf8(&buf[pos..pos + scheme_len])
                .map_err(|_| ProtoError::InvalidUtf8)?
                .to_owned();
            pos += scheme_len;
            let success_pct = buf[pos];
            pos += 1;
            let sample_count = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            entries.push(TransportHintEntry {
                scheme,
                success_pct,
                sample_count,
            });
        }
        Ok(TransportHintResultPayload { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_roundtrip() {
        let p = TransportHintResultPayload::default();
        let enc = p.encode();
        assert_eq!(enc, vec![0u8]);
        let dec = TransportHintResultPayload::decode(&enc).unwrap();
        assert!(dec.entries.is_empty());
    }

    #[test]
    fn populated_roundtrip() {
        let p = TransportHintResultPayload {
            entries: vec![
                TransportHintEntry {
                    scheme: "tls".to_owned(),
                    success_pct: 95,
                    sample_count: 200,
                },
                TransportHintEntry {
                    scheme: "tcp".to_owned(),
                    success_pct: 80,
                    sample_count: 150,
                },
                TransportHintEntry {
                    scheme: "quic".to_owned(),
                    success_pct: 5,
                    sample_count: 40,
                },
            ],
        };
        let enc = p.encode();
        let dec = TransportHintResultPayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn truncates_at_max_entries() {
        let entries = (0..(TransportHintResultPayload::MAX_ENTRIES + 5))
            .map(|i| TransportHintEntry {
                scheme: format!("s{i}"),
                success_pct: 50,
                sample_count: 1,
            })
            .collect::<Vec<_>>();
        let p = TransportHintResultPayload { entries };
        let enc = p.encode();
        assert_eq!(enc[0] as usize, TransportHintResultPayload::MAX_ENTRIES);
    }

    #[test]
    fn rejects_truncated_buffer() {
        // Says count=1 but no entry data.
        assert!(TransportHintResultPayload::decode(&[1u8]).is_err());
    }

    #[test]
    fn rejects_empty_buffer() {
        assert!(TransportHintResultPayload::decode(&[]).is_err());
    }

    #[test]
    fn rejects_count_above_max_entries() {
        // 1-byte buffer claiming count = MAX_ENTRIES + 1 must error before
        // allocating; otherwise an attacker controls Vec::with_capacity.
        let bad = [(TransportHintResultPayload::MAX_ENTRIES + 1) as u8];
        match TransportHintResultPayload::decode(&bad) {
            Err(ProtoError::ValueTooLarge { field, .. }) => {
                assert_eq!(field, "transport_hints.count");
            }
            other => panic!("expected ValueTooLarge, got {other:?}"),
        }
    }
}
