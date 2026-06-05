//! Peer Exchange (PEX) wire format —.
//!
//! Random-walk based transport discovery so nodes can establish direct
//! connections instead of relying on relay chains.

use super::ProtoError;

/// Minimum identity PoW difficulty (matches `config init` default).
pub const MIN_IDENTITY_DIFFICULTY: u8 = 16;

/// Maximum peers in a single PEX result.
pub const MAX_PEX_PEERS: usize = 16;

/// PEX challenge response validity window (seconds).
pub const PEX_CHALLENGE_TTL_SECS: u64 = 60;

// ── PexWalk ──────────────────────────────────────────────────────────────────

/// Random-walk request for peer discovery.
///
/// ```text
/// [0..8] walk_id u64 BE
/// [8..40] target_node_id [u8; 32] — random DHT routing destination
/// [40..72] origin_node_id [u8; 32] — requester's node_id
/// [72..74] origin_pubkey_len u16 BE
/// [74..N] origin_pubkey bytes
/// [N..N+8] origin_nonce u64 LE — requester's identity PoW nonce
/// [N+8..N+72] origin_sig [u8; 64] — Ed25519 sig over (walk_id || target_node_id)
/// [N+72] ttl u8
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PexWalk {
    pub walk_id: u64,
    pub target_node_id: [u8; 32],
    pub origin_node_id: [u8; 32],
    pub origin_pubkey: Vec<u8>,
    pub origin_nonce: u64,
    pub origin_sig: [u8; 64],
    pub ttl: u8,
}

impl PexWalk {
    pub fn encode(&self) -> Vec<u8> {
        let pk_len = self.origin_pubkey.len();
        let total = 8 + 32 + 32 + 2 + pk_len + 8 + 64 + 1;
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&self.walk_id.to_be_bytes());
        buf.extend_from_slice(&self.target_node_id);
        buf.extend_from_slice(&self.origin_node_id);
        buf.extend_from_slice(&(pk_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.origin_pubkey);
        buf.extend_from_slice(&self.origin_nonce.to_le_bytes());
        buf.extend_from_slice(&self.origin_sig);
        buf.push(self.ttl);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 8 + 32 + 32 + 2 {
            return Err(ProtoError::BufferTooShort {
                need: 74,
                got: buf.len(),
            });
        }
        let walk_id = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let mut target_node_id = [0u8; 32];
        target_node_id.copy_from_slice(&buf[8..40]);
        let mut origin_node_id = [0u8; 32];
        origin_node_id.copy_from_slice(&buf[40..72]);
        let pk_len = u16::from_be_bytes([buf[72], buf[73]]) as usize;
        let min_remaining = pk_len + 8 + 64 + 1;
        if buf.len() < 74 + min_remaining {
            return Err(ProtoError::BufferTooShort {
                need: 74 + min_remaining,
                got: buf.len(),
            });
        }
        let origin_pubkey = buf[74..74 + pk_len].to_vec();
        let off = 74 + pk_len;
        let origin_nonce = u64::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]);
        let mut origin_sig = [0u8; 64];
        origin_sig.copy_from_slice(&buf[off + 8..off + 72]);
        let ttl = buf[off + 72];
        Ok(Self {
            walk_id,
            target_node_id,
            origin_node_id,
            origin_pubkey,
            origin_nonce,
            origin_sig,
            ttl,
        })
    }

    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 32);
        buf.extend_from_slice(&self.walk_id.to_be_bytes());
        buf.extend_from_slice(&self.target_node_id);
        buf
    }
}

// ── PexChallenge ─────────────────────────────────────────────────────────────

/// PoW challenge sent by the node that terminates the walk.
///
/// ```text
/// [0..8] walk_id u64 BE
/// [8..40] challenge_nonce [u8; 32]
/// [40..48] timestamp u64 BE (unix seconds)
/// [48] difficulty u8
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PexChallenge {
    pub walk_id: u64,
    pub challenge_nonce: [u8; 32],
    pub timestamp: u64,
    pub difficulty: u8,
}

impl PexChallenge {
    pub const WIRE_SIZE: usize = 8 + 32 + 8 + 1;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..8].copy_from_slice(&self.walk_id.to_be_bytes());
        buf[8..40].copy_from_slice(&self.challenge_nonce);
        buf[40..48].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[48] = self.difficulty;
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let walk_id = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let mut challenge_nonce = [0u8; 32];
        challenge_nonce.copy_from_slice(&buf[8..40]);
        let timestamp = u64::from_be_bytes([
            buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
        ]);
        let difficulty = buf[48];
        Ok(Self {
            walk_id,
            challenge_nonce,
            timestamp,
            difficulty,
        })
    }
}

// ── PexResponse ──────────────────────────────────────────────────────────────

/// PoW solution + signature proving the requester solved the challenge.
///
/// ```text
/// [0..8] walk_id u64 BE
/// [8..40] challenge_nonce [u8; 32]
/// [40..72] pow_solution [u8; 32]
/// [72..136] origin_sig [u8; 64]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PexResponse {
    pub walk_id: u64,
    pub challenge_nonce: [u8; 32],
    pub pow_solution: [u8; 32],
    pub origin_sig: [u8; 64],
}

impl PexResponse {
    pub const WIRE_SIZE: usize = 8 + 32 + 32 + 64;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..8].copy_from_slice(&self.walk_id.to_be_bytes());
        buf[8..40].copy_from_slice(&self.challenge_nonce);
        buf[40..72].copy_from_slice(&self.pow_solution);
        buf[72..136].copy_from_slice(&self.origin_sig);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let walk_id = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let mut challenge_nonce = [0u8; 32];
        challenge_nonce.copy_from_slice(&buf[8..40]);
        let mut pow_solution = [0u8; 32];
        pow_solution.copy_from_slice(&buf[40..72]);
        let mut origin_sig = [0u8; 64];
        origin_sig.copy_from_slice(&buf[72..136]);
        Ok(Self {
            walk_id,
            challenge_nonce,
            pow_solution,
            origin_sig,
        })
    }
}

// ── PexPeer ──────────────────────────────────────────────────────────────────

/// A single peer entry returned in PexResult.
///
/// ```text
/// [0..32] node_id [u8; 32]
/// [32..34] transport_len u16 BE
/// [34..T] transport UTF-8 string
/// [T..T+2] pubkey_len u16 BE
/// [T+2..P] public_key bytes
/// [P..P+8] nonce u64 LE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PexPeer {
    pub node_id: [u8; 32],
    pub transport: String,
    pub public_key: Vec<u8>,
    pub nonce: u64,
}

impl PexPeer {
    pub fn encode(&self) -> Vec<u8> {
        let t_len = self.transport.len();
        let pk_len = self.public_key.len();
        let total = 32 + 2 + t_len + 2 + pk_len + 8;
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&(t_len as u16).to_be_bytes());
        buf.extend_from_slice(self.transport.as_bytes());
        buf.extend_from_slice(&(pk_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ProtoError> {
        if buf.len() < 36 {
            return Err(ProtoError::BufferTooShort {
                need: 36,
                got: buf.len(),
            });
        }
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&buf[0..32]);
        let t_len = u16::from_be_bytes([buf[32], buf[33]]) as usize;
        let off = 34 + t_len;
        if buf.len() < off + 2 {
            return Err(ProtoError::BufferTooShort {
                need: off + 2,
                got: buf.len(),
            });
        }
        let transport = std::str::from_utf8(&buf[34..off])
            .map_err(|_| ProtoError::InvalidUtf8)?
            .to_owned();
        let pk_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        let pk_end = off + 2 + pk_len;
        if buf.len() < pk_end + 8 {
            return Err(ProtoError::BufferTooShort {
                need: pk_end + 8,
                got: buf.len(),
            });
        }
        let public_key = buf[off + 2..pk_end].to_vec();
        let nonce = u64::from_le_bytes([
            buf[pk_end],
            buf[pk_end + 1],
            buf[pk_end + 2],
            buf[pk_end + 3],
            buf[pk_end + 4],
            buf[pk_end + 5],
            buf[pk_end + 6],
            buf[pk_end + 7],
        ]);
        let consumed = pk_end + 8;
        Ok((
            Self {
                node_id,
                transport,
                public_key,
                nonce,
            },
            consumed,
        ))
    }
}

// ── PexResult ────────────────────────────────────────────────────────────────

/// Peer list returned after successful PoW verification.
///
/// ```text
/// [0..8] walk_id u64 BE
/// [8..10] count u16 BE
/// [10..] peers PexPeer × count
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PexResult {
    pub walk_id: u64,
    pub peers: Vec<PexPeer>,
}

impl PexResult {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.walk_id.to_be_bytes());
        let count = self.peers.len().min(MAX_PEX_PEERS);
        buf.extend_from_slice(&(count as u16).to_be_bytes());
        for peer in self.peers.iter().take(MAX_PEX_PEERS) {
            buf.extend_from_slice(&peer.encode());
        }
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 10 {
            return Err(ProtoError::BufferTooShort {
                need: 10,
                got: buf.len(),
            });
        }
        let walk_id = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let count = u16::from_be_bytes([buf[8], buf[9]]) as usize;
        if count > MAX_PEX_PEERS {
            return Err(ProtoError::ValueTooLarge {
                field: "PexResult.count",
                value: count as u64,
                max: MAX_PEX_PEERS as u64,
            });
        }
        let mut peers = Vec::with_capacity(count);
        let mut off = 10;
        for _ in 0..count {
            let (peer, consumed) = PexPeer::decode(&buf[off..])?;
            peers.push(peer);
            off += consumed;
        }
        Ok(Self { walk_id, peers })
    }
}

// ── Difficulty formula ───────────────────────────────────────────────────────

/// Compute PEX challenge difficulty based on identity PoW levels.
///
/// Higher `src_difficulty` (requester invested more PoW) → lower challenge.
/// Equal nodes → challenge = MIN_IDENTITY_DIFFICULTY.
/// Weaker requester → higher challenge.
///
/// Clamped to `[MIN_IDENTITY_DIFFICULTY, node_difficulty.saturating_sub(1)]`.
pub fn compute_pex_challenge_difficulty(src_difficulty: u8, node_difficulty: u8) -> u8 {
    let a = node_difficulty
        .saturating_sub(src_difficulty)
        .saturating_sub(1);
    let raw = MIN_IDENTITY_DIFFICULTY.saturating_add(a);
    let max = node_difficulty
        .saturating_sub(1)
        .max(MIN_IDENTITY_DIFFICULTY);
    raw.clamp(MIN_IDENTITY_DIFFICULTY, max)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pex_walk_roundtrip() {
        let walk = PexWalk {
            walk_id: 0x1234,
            target_node_id: [0xAA; 32],
            origin_node_id: [0xBB; 32],
            origin_pubkey: vec![1, 2, 3, 4, 5],
            origin_nonce: 42,
            origin_sig: [0xCC; 64],
            ttl: 7,
        };
        let encoded = walk.encode();
        let decoded = PexWalk::decode(&encoded).unwrap();
        assert_eq!(decoded, walk);
    }

    #[test]
    fn pex_challenge_roundtrip() {
        let ch = PexChallenge {
            walk_id: 99,
            challenge_nonce: [0x11; 32],
            timestamp: 1700000000,
            difficulty: 18,
        };
        let encoded = ch.encode();
        let decoded = PexChallenge::decode(&encoded).unwrap();
        assert_eq!(decoded, ch);
    }

    #[test]
    fn pex_response_roundtrip() {
        let resp = PexResponse {
            walk_id: 77,
            challenge_nonce: [0x22; 32],
            pow_solution: [0x33; 32],
            origin_sig: [0x44; 64],
        };
        let encoded = resp.encode();
        let decoded = PexResponse::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn pex_result_roundtrip_empty() {
        let result = PexResult {
            walk_id: 1,
            peers: vec![],
        };
        let encoded = result.encode();
        let decoded = PexResult::decode(&encoded).unwrap();
        assert_eq!(decoded, result);
    }

    #[test]
    fn pex_result_roundtrip_with_peers() {
        let result = PexResult {
            walk_id: 42,
            peers: vec![
                PexPeer {
                    node_id: [0x11; 32],
                    transport: "tls://node1.example.com:9906".into(),
                    public_key: vec![0xAA; 32],
                    nonce: 100,
                },
                PexPeer {
                    node_id: [0x22; 32],
                    transport: "quic://node2.example.com:8443".into(),
                    public_key: vec![0xBB; 32],
                    nonce: 200,
                },
            ],
        };
        let encoded = result.encode();
        let decoded = PexResult::decode(&encoded).unwrap();
        assert_eq!(decoded, result);
    }

    #[test]
    fn pex_result_rejects_too_many_peers() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&42u64.to_be_bytes());
        buf.extend_from_slice(&(MAX_PEX_PEERS as u16 + 1).to_be_bytes());
        assert!(PexResult::decode(&buf).is_err());
    }

    #[test]
    fn difficulty_formula_equal_nodes() {
        assert_eq!(compute_pex_challenge_difficulty(24, 24), 16);
    }

    #[test]
    fn difficulty_formula_weaker_requester() {
        // node=24, src=16 → a = 24-16-1 = 7 → 16+7 = 23, clamped to 23
        assert_eq!(compute_pex_challenge_difficulty(16, 24), 23);
    }

    #[test]
    fn difficulty_formula_stronger_requester() {
        // node=20, src=30 → a = 0 (saturating) → 16, clamped [16, 19]
        assert_eq!(compute_pex_challenge_difficulty(30, 20), 16);
    }

    #[test]
    fn difficulty_formula_both_minimum() {
        assert_eq!(compute_pex_challenge_difficulty(16, 16), 16);
    }

    #[test]
    fn difficulty_formula_high_difference() {
        // node=64, src=16 → a = 64-16-1 = 47 → 16+47 = 63, clamped to 63
        assert_eq!(compute_pex_challenge_difficulty(16, 64), 63);
    }
}
