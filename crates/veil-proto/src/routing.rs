//! Routing-plane payload structs for the OVL1 binary protocol.
//!
//! Covers the gossip route-announcement protocol and the on-demand
//! route-discovery + PoW direct-session bootstrap.
//!
//! All integers are big-endian. Signatures are ed25519 (64 bytes).
//!
//! # Message overview
//!
//! | Struct | `RoutingMsg` variant |
//! |-------------------------|-----------------------|------|
//! | `RouteAnnouncePayload` | `RouteAnnounce` | 60 |
//! | `RouteWithdrawPayload` | `RouteWithdraw` | 60 |
//! | `RouteRequestPayload` | `RouteRequest` | 61 |
//! | `RouteResponsePayload` | `RouteResponse` | 61 |
//! | `PowChallengePayload` | `PowChallenge` | 61 |
//! | `PowResponsePayload` | `PowResponse` | 61 |
//! | `PowAcceptPayload` | `PowAccept` | 61 |

use super::ProtoError;

// ── RouteAnnouncePayload ──────────────────────────────────────────────────────

/// Gossip advertisement: the signer (`via_node_id`) can relay traffic to
/// `origin_node_id` in `hop_count` hops.
///
/// Wire layout:
/// ```text
/// [0..32] origin_node_id [u8; 32] — the reachable node being announced
/// [32..64] via_node_id [u8; 32] — announcing node (= signer)
/// [64] hop_count u8 — hops from via to origin (1 = direct)
/// [65] ttl u8 — remaining propagation TTL (max 8)
/// [66..70] sequence u32 BE — monotonic counter (per origin+via pair)
/// [70..74] timestamp u32 BE — Unix seconds (freshness / replay guard)
/// [74..138] signature [u8; 64] — ed25519(via_privkey
/// origin||via||hop_count||ttl||seq||ts)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAnnouncePayload {
    /// Reachable node being announced.
    pub origin_node_id: [u8; 32],
    /// Announcing relay node (= signer).
    pub via_node_id: [u8; 32],
    /// Hops from `via` to `origin` (1 = direct).
    pub hop_count: u8,
    /// Remaining propagation TTL (max 8).
    pub ttl: u8,
    /// Monotonic counter (origin) pair.
    pub sequence: u32,
    /// Unix-seconds timestamp used for freshness / replay guard.
    pub timestamp: u32,
    /// Ed25519 signature over [`Self::signable_bytes`].
    pub signature: [u8; 64],
}

impl RouteAnnouncePayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 32 + 1 + 1 + 4 + 4 + 64; // 138

    /// Bytes that are covered by the signature (all fields except the sig itself).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(74);
        buf.extend_from_slice(&self.origin_node_id);
        buf.extend_from_slice(&self.via_node_id);
        buf.push(self.hop_count);
        buf.push(self.ttl);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf
    }

    /// Encode to the fixed 138-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.origin_node_id);
        buf[32..64].copy_from_slice(&self.via_node_id);
        buf[64] = self.hop_count;
        buf[65] = self.ttl;
        buf[66..70].copy_from_slice(&self.sequence.to_be_bytes());
        buf[70..74].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[74..138].copy_from_slice(&self.signature);
        buf
    }

    /// Parse from a 138-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            origin_node_id: super::read_array::<32>(buf, 0)?,
            via_node_id: super::read_array::<32>(buf, 32)?,
            hop_count: buf[64],
            ttl: buf[65],
            sequence: super::read_u32_be(buf, 66)?,
            timestamp: super::read_u32_be(buf, 70)?,
            signature: super::read_array::<64>(buf, 74)?,
        })
    }
}

// ── RouteWithdrawPayload ──────────────────────────────────────────────────────

/// Gossip retraction: the signer (`via_node_id`) can no longer relay to
/// `origin_node_id`.
///
/// Wire layout:
/// ```text
/// [0..32] origin_node_id [u8; 32]
/// [32..64] via_node_id [u8; 32]
/// [64..68] sequence u32 BE — must be > last seen Announce sequence
/// [68..132] signature [u8; 64] — ed25519(via_privkey, origin||via||seq)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteWithdrawPayload {
    /// Node the retraction applies to.
    pub origin_node_id: [u8; 32],
    /// Announcing relay node (= signer).
    pub via_node_id: [u8; 32],
    /// Must be greater than the last seen Announce sequence.
    pub sequence: u32,
    /// Ed25519 signature over [`Self::signable_bytes`].
    pub signature: [u8; 64],
    /// Hop counter — incremented by each forwarder. Frames with
    /// `hop_count >= max_gossip_hops` are NOT forwarded.
    pub hop_count: u8,
}

impl RouteWithdrawPayload {
    /// Fixed wire size including the `hop_count` byte.
    pub const WIRE_SIZE: usize = 32 + 32 + 4 + 64 + 1; // 133

    /// Bytes covered by the signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(68);
        buf.extend_from_slice(&self.origin_node_id);
        buf.extend_from_slice(&self.via_node_id);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&self.origin_node_id);
        buf.extend_from_slice(&self.via_node_id);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf.push(self.hop_count);
        buf
    }

    /// Parse from the fixed 133-byte wire layout.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            origin_node_id: super::read_array::<32>(buf, 0)?,
            via_node_id: super::read_array::<32>(buf, 32)?,
            sequence: super::read_u32_be(buf, 64)?,
            signature: super::read_array::<64>(buf, 68)?,
            hop_count: buf[132],
        })
    }
}

// ── RouteRequestPayload ───────────────────────────────────────────────────────

/// On-demand query: "Does anyone know how to reach `target_node_id`?"
///
/// Wire layout:
/// ```text
/// [0..32] target_node_id [u8; 32]
/// [32..64] requester_node_id [u8; 32]
/// [64..68] request_id u32 BE — random, used to match the response
/// [68] ttl u8 — remaining forward hops
/// [69..133] signature [u8; 64] — ed25519(requester_privkey
/// target||requester||req_id||ttl)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRequestPayload {
    /// Node we're asking about.
    pub target_node_id: [u8; 32],
    /// Node asking the question (= signer).
    pub requester_node_id: [u8; 32],
    /// Random token correlating the response.
    pub request_id: u32,
    /// Remaining forward hops.
    pub ttl: u8,
    /// Ed25519 signature over [`Self::signable_bytes`].
    pub signature: [u8; 64],
}

impl RouteRequestPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 32 + 4 + 1 + 64; // 133

    /// Bytes covered by the signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(69);
        buf.extend_from_slice(&self.target_node_id);
        buf.extend_from_slice(&self.requester_node_id);
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        buf.push(self.ttl);
        buf
    }

    /// Encode to the fixed 133-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.target_node_id);
        buf[32..64].copy_from_slice(&self.requester_node_id);
        buf[64..68].copy_from_slice(&self.request_id.to_be_bytes());
        buf[68] = self.ttl;
        buf[69..133].copy_from_slice(&self.signature);
        buf
    }

    /// Parse from a 133-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            target_node_id: super::read_array::<32>(buf, 0)?,
            requester_node_id: super::read_array::<32>(buf, 32)?,
            request_id: super::read_u32_be(buf, 64)?,
            ttl: buf[68],
            signature: super::read_array::<64>(buf, 69)?,
        })
    }
}

// ── RouteResponsePayload ──────────────────────────────────────────────────────

/// Answer to a `RouteRequest`: provides direct transports and/or relay node_ids
/// for the target, plus the target's ML-KEM-768 public key (used by).
///
/// Wire layout:
/// ```text
/// [0..32] target_node_id [u8; 32]
/// [32..64] requester_node_id [u8; 32]
/// [64..68] request_id u32 BE
/// [68] transport_count u8
/// for each transport:
/// len: u8 + utf8_bytes[len] — e.g. "tcp://1.2.3.4:7001"
/// [..] relay_count u8
/// for each relay:
/// relay_node_id: [u8; 32]
/// [..] mlkem_pubkey_len u16 BE — 0 if not available
/// mlkem_pubkey: [u8; len] — ML-KEM-768 public key (1184 B)
/// [..] signature [u8; 64] — ed25519(target_privkey...)
/// [..] ed25519_pubkey_len u16 BE — 0 if not included (optional)
/// ed25519_pubkey: [u8; len] — Ed25519 verifying key (32 B)
/// allows requester to verify the sig
/// for unknown targets via
/// BLAKE3(pubkey) == target_node_id
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteResponsePayload {
    /// Node this response is about.
    pub target_node_id: [u8; 32],
    /// Original requester's `node_id`.
    pub requester_node_id: [u8; 32],
    /// Echo of the request's `request_id` for correlation.
    pub request_id: u32,
    /// Direct listen transports of the target (UTF-8 strings).
    pub transports: Vec<String>,
    /// Relay node_ids through which the target is reachable.
    pub relay_ids: Vec<[u8; 32]>,
    /// ML-KEM-768 public key of the target (1184 bytes), if known.
    pub mlkem_pubkey: Option<Vec<u8>>,
    /// Ed25519 signature produced by the target.
    pub signature: [u8; 64],
    /// Ed25519 verifying key of the target (32 bytes), appended after the
    /// signature. Allows the requester to verify this response even when the
    /// target's public key is not yet in `peer_pubkeys` — the requester checks
    /// `BLAKE3(ed25519_pubkey) == target_node_id` before trusting it.
    pub ed25519_pubkey: Option<Vec<u8>>,
    /// capability/region labels claimed by the target and signed
    /// as part of `signable_bytes`. Lets requesters filter routes by
    /// attribute (e.g. only routes whose target advertises `b"exit"` and
    /// `b"low\0"`). Must contain at most [`crate::budget::MAX_TARGET_LABELS`]
    /// entries; the wire format is backwards-compatible (older nodes either
    /// stop reading at the signature or at the optional ed25519_pubkey
    /// trailer; new nodes encode an empty count when no labels are set).
    pub target_labels: Vec<[u8; crate::budget::LABEL_WIDTH]>,
}

impl RouteResponsePayload {
    /// Minimum wire size: fixed fields only, no transports/relays/mlkem.
    pub const MIN_WIRE_SIZE: usize = 32 + 32 + 4 + 1 + 1 + 2 + 64; // 136

    /// Bytes signed/verified by the target — all fields except the trailing signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.target_node_id);
        buf.extend_from_slice(&self.requester_node_id);
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        use crate::budget::{MAX_RELAY_IDS, MAX_TRANSPORT_ADDRS, MAX_TRANSPORT_STR_LEN};
        debug_assert!(
            self.transports.len() <= MAX_TRANSPORT_ADDRS,
            "transports truncated on encode"
        );
        let tc = self.transports.len().min(MAX_TRANSPORT_ADDRS);
        buf.push(tc as u8);
        for t in self.transports.iter().take(MAX_TRANSPORT_ADDRS) {
            let bytes = t.as_bytes();
            debug_assert!(
                bytes.len() <= MAX_TRANSPORT_STR_LEN,
                "transport string truncated on encode"
            );
            let len = bytes.len().min(MAX_TRANSPORT_STR_LEN);
            buf.push(len as u8);
            buf.extend_from_slice(&bytes[..len]);
        }
        debug_assert!(
            self.relay_ids.len() <= MAX_RELAY_IDS,
            "relay_ids truncated on encode"
        );
        buf.push(self.relay_ids.len().min(MAX_RELAY_IDS) as u8);
        for r in self.relay_ids.iter().take(MAX_RELAY_IDS) {
            buf.extend_from_slice(r);
        }
        match &self.mlkem_pubkey {
            Some(pk) => {
                debug_assert!(
                    pk.len() <= u16::MAX as usize,
                    "RouteRequest: mlkem_pubkey exceeds u16::MAX bytes"
                );
                buf.extend_from_slice(&(pk.len() as u16).to_be_bytes());
                buf.extend_from_slice(pk);
            }
            None => {
                buf.extend_from_slice(&0u16.to_be_bytes());
            }
        }
        // target_labels are part of the signed body so that
        // intermediate relays cannot forge or strip them. Encoded as a
        // u8 count followed by `count × LABEL_WIDTH` bytes — empty list
        // (count=0) is the on-wire representation when no labels are set
        // matching what an older sender would have produced (no trailing
        // bytes after mlkem_pubkey) only because older verifiers stopped
        // reading before this point. A new verifier reading an old
        // sender's body computes the same signable bytes since the cap
        // is also part of `MAX_TARGET_LABELS = 8`-bound. See decode for
        // the cross-version compat strategy.
        use crate::budget::{LABEL_WIDTH, MAX_TARGET_LABELS};
        debug_assert!(
            self.target_labels.len() <= MAX_TARGET_LABELS,
            "target_labels truncated on encode"
        );
        let lc = self.target_labels.len().min(MAX_TARGET_LABELS);
        buf.push(lc as u8);
        for l in self.target_labels.iter().take(MAX_TARGET_LABELS) {
            debug_assert_eq!(l.len(), LABEL_WIDTH);
            buf.extend_from_slice(l);
        }
        buf
    }

    /// Encode a `RouteResponsePayload` to wire bytes.
    ///
    /// Truncates `transports` / `relay_ids` to their protocol caps; transport
    /// strings are clamped to `MAX_TRANSPORT_STR_LEN`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.target_node_id);
        buf.extend_from_slice(&self.requester_node_id);
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        use crate::budget::{MAX_RELAY_IDS, MAX_TRANSPORT_ADDRS, MAX_TRANSPORT_STR_LEN};
        // Transports
        debug_assert!(
            self.transports.len() <= MAX_TRANSPORT_ADDRS,
            "transports truncated on encode"
        );
        let tc = self.transports.len().min(MAX_TRANSPORT_ADDRS);
        buf.push(tc as u8);
        for t in self.transports.iter().take(MAX_TRANSPORT_ADDRS) {
            let bytes = t.as_bytes();
            debug_assert!(
                bytes.len() <= MAX_TRANSPORT_STR_LEN,
                "transport string truncated on encode"
            );
            let len = bytes.len().min(MAX_TRANSPORT_STR_LEN);
            buf.push(len as u8);
            buf.extend_from_slice(&bytes[..len]);
        }
        // Relay IDs
        debug_assert!(
            self.relay_ids.len() <= MAX_RELAY_IDS,
            "relay_ids truncated on encode"
        );
        buf.push(self.relay_ids.len().min(MAX_RELAY_IDS) as u8);
        for r in self.relay_ids.iter().take(MAX_RELAY_IDS) {
            buf.extend_from_slice(r);
        }
        // ML-KEM pubkey
        match &self.mlkem_pubkey {
            Some(pk) => {
                debug_assert!(
                    pk.len() <= u16::MAX as usize,
                    "RouteResponse: mlkem_pubkey exceeds u16::MAX bytes"
                );
                buf.extend_from_slice(&(pk.len() as u16).to_be_bytes());
                buf.extend_from_slice(pk);
            }
            None => {
                buf.extend_from_slice(&0u16.to_be_bytes());
            }
        }
        // target_labels go BEFORE the signature so they are
        // covered by it. Always encode the u8 count (0 if no labels) so
        // every wire frame has the same field at this offset — there's no
        // "older sender lacks labels" branch to handle since this is a
        // signature-format change (network is intentionally not stable
        // during this transition; see TASKS.md).
        use crate::budget::{LABEL_WIDTH, MAX_TARGET_LABELS};
        debug_assert!(
            self.target_labels.len() <= MAX_TARGET_LABELS,
            "target_labels truncated on encode"
        );
        let lc = self.target_labels.len().min(MAX_TARGET_LABELS);
        buf.push(lc as u8);
        for l in self.target_labels.iter().take(MAX_TARGET_LABELS) {
            debug_assert_eq!(l.len(), LABEL_WIDTH);
            buf.extend_from_slice(l);
        }
        buf.extend_from_slice(&self.signature);
        // ed25519_pubkey appended after signature (not part of signable bytes)
        if let Some(pk) = &self.ed25519_pubkey {
            debug_assert!(
                pk.len() <= u16::MAX as usize,
                "RouteResponse: ed25519_pubkey exceeds u16::MAX bytes"
            );
            buf.extend_from_slice(&(pk.len() as u16).to_be_bytes());
            buf.extend_from_slice(pk);
        }
        buf
    }

    /// Parse from wire bytes; enforces all per-field caps.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::MIN_WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::MIN_WIRE_SIZE,
                got: buf.len(),
            });
        }
        let target_node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let requester_node_id: [u8; 32] = super::read_array::<32>(buf, 32)?;
        let request_id = super::read_u32_be(buf, 64)?;
        let mut offset = 68;

        // Transports
        let transport_count = buf[offset] as usize;
        if transport_count > crate::budget::MAX_TRANSPORT_ADDRS {
            return Err(ProtoError::ValueTooLarge {
                field: "transport_count",
                value: transport_count as u64,
                max: crate::budget::MAX_TRANSPORT_ADDRS as u64,
            });
        }
        offset += 1;
        let mut transports = Vec::with_capacity(transport_count);
        for _ in 0..transport_count {
            if offset >= buf.len() {
                return Err(ProtoError::BufferTooShort {
                    need: offset + 1,
                    got: buf.len(),
                });
            }
            let len = buf[offset] as usize;
            if len > crate::budget::MAX_TRANSPORT_STR_LEN {
                return Err(ProtoError::ValueTooLarge {
                    field: "transport_len",
                    value: len as u64,
                    max: crate::budget::MAX_TRANSPORT_STR_LEN as u64,
                });
            }
            offset += 1;
            if offset + len > buf.len() {
                return Err(ProtoError::BufferTooShort {
                    need: offset + len,
                    got: buf.len(),
                });
            }
            let s = String::from_utf8(buf[offset..offset + len].to_vec())
                .map_err(|_| ProtoError::InvalidUtf8)?;
            transports.push(s);
            offset += len;
        }

        // Relay IDs
        if offset >= buf.len() {
            return Err(ProtoError::BufferTooShort {
                need: offset + 1,
                got: buf.len(),
            });
        }
        let relay_count = buf[offset] as usize;
        if relay_count > crate::budget::MAX_RELAY_IDS {
            return Err(ProtoError::ValueTooLarge {
                field: "relay_count",
                value: relay_count as u64,
                max: crate::budget::MAX_RELAY_IDS as u64,
            });
        }
        offset += 1;
        let mut relay_ids = Vec::with_capacity(relay_count);
        for _ in 0..relay_count {
            if offset + 32 > buf.len() {
                return Err(ProtoError::BufferTooShort {
                    need: offset + 32,
                    got: buf.len(),
                });
            }
            relay_ids.push(super::read_array::<32>(buf, offset)?);
            offset += 32;
        }

        // ML-KEM pubkey
        if offset + 2 > buf.len() {
            return Err(ProtoError::BufferTooShort {
                need: offset + 2,
                got: buf.len(),
            });
        }
        let pk_len = super::read_u16_be(buf, offset)? as usize;
        offset += 2;
        let mlkem_pubkey = if pk_len > 0 {
            let pk = super::read_slice(
                buf,
                offset,
                pk_len,
                crate::budget::MAX_MLKEM_PK_LEN,
                "mlkem_pubkey",
            )?
            .to_vec();
            offset += pk_len;
            Some(pk)
        } else {
            None
        };

        // target_labels — `u8 count` followed by `count × LABEL_WIDTH`
        // bytes. Position is BEFORE the signature so the bytes are covered by it.
        use crate::budget::{LABEL_WIDTH, MAX_TARGET_LABELS};
        if offset + 1 > buf.len() {
            return Err(ProtoError::BufferTooShort {
                need: offset + 1,
                got: buf.len(),
            });
        }
        let label_count = buf[offset] as usize;
        offset += 1;
        if label_count > MAX_TARGET_LABELS {
            return Err(ProtoError::ValueTooLarge {
                field: "target_label_count",
                value: label_count as u64,
                max: MAX_TARGET_LABELS as u64,
            });
        }
        let mut target_labels = Vec::with_capacity(label_count);
        for _ in 0..label_count {
            if offset + LABEL_WIDTH > buf.len() {
                return Err(ProtoError::BufferTooShort {
                    need: offset + LABEL_WIDTH,
                    got: buf.len(),
                });
            }
            let mut label = [0u8; LABEL_WIDTH];
            label.copy_from_slice(&buf[offset..offset + LABEL_WIDTH]);
            target_labels.push(label);
            offset += LABEL_WIDTH;
        }

        // Signature
        if offset + 64 > buf.len() {
            return Err(ProtoError::BufferTooShort {
                need: offset + 64,
                got: buf.len(),
            });
        }
        let signature: [u8; 64] = super::read_array::<64>(buf, offset)?;
        offset += 64;

        // Optional ed25519_pubkey appended after signature (backwards-compatible:
        // older senders omit this field; older receivers stop reading at signature).
        let ed25519_pubkey = if offset + 2 <= buf.len() {
            let pk_len = super::read_u16_be(buf, offset)? as usize;
            offset += 2;
            if pk_len > 0 {
                let pk = super::read_slice(
                    buf,
                    offset,
                    pk_len,
                    crate::budget::MAX_MLKEM_PK_LEN,
                    "ed25519_pubkey",
                )?
                .to_vec();
                offset += pk_len;
                let _ = offset; // suppress unused-assignment warning
                Some(pk)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            target_node_id,
            requester_node_id,
            request_id,
            transports,
            relay_ids,
            mlkem_pubkey,
            signature,
            ed25519_pubkey,
            target_labels,
        })
    }
}

// ── PowChallengePayload ───────────────────────────────────────────────────────

/// PoW challenge issued by the acceptor to the requester.
///
/// Wire layout:
/// ```text
/// [0..32] requester_node_id [u8; 32]
/// [32..64] acceptor_node_id [u8; 32]
/// [64..96] challenge_nonce [u8; 32] — random
/// [96] difficulty u8 — leading-zero bits required
/// [97..161] signature [u8; 64] — ed25519(acceptor_privkey
/// requester||acceptor||nonce||difficulty)
/// ```
///
/// Solution: find `nonce[32]` such that the first `difficulty` bits of
/// `BLAKE3(requester_id || challenge_nonce || nonce)` are zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowChallengePayload {
    /// Requester (challenge target) `node_id`.
    pub requester_node_id: [u8; 32],
    /// Acceptor (challenge issuer) `node_id`.
    pub acceptor_node_id: [u8; 32],
    /// Random per-challenge nonce the solver must include in BLAKE3 input.
    pub challenge_nonce: [u8; 32],
    /// Leading-zero bits required on the hash.
    pub difficulty: u8,
    /// Ed25519 signature over [`Self::signable_bytes`].
    pub signature: [u8; 64],
}

impl PowChallengePayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 32 + 32 + 1 + 64; // 161

    /// Bytes covered by the signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(97);
        buf.extend_from_slice(&self.requester_node_id);
        buf.extend_from_slice(&self.acceptor_node_id);
        buf.extend_from_slice(&self.challenge_nonce);
        buf.push(self.difficulty);
        buf
    }

    /// Encode to the fixed 161-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.requester_node_id);
        buf[32..64].copy_from_slice(&self.acceptor_node_id);
        buf[64..96].copy_from_slice(&self.challenge_nonce);
        buf[96] = self.difficulty;
        buf[97..161].copy_from_slice(&self.signature);
        buf
    }

    /// Parse from a 161-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            requester_node_id: super::read_array::<32>(buf, 0)?,
            acceptor_node_id: super::read_array::<32>(buf, 32)?,
            challenge_nonce: super::read_array::<32>(buf, 64)?,
            difficulty: buf[96],
            signature: super::read_array::<64>(buf, 97)?,
        })
    }
}

// ── PowResponsePayload ────────────────────────────────────────────────────────

/// PoW solution sent by the requester to the acceptor (may be relayed).
///
/// Wire layout:
/// ```text
/// [0..32] requester_node_id [u8; 32]
/// [32..64] acceptor_node_id [u8; 32] — enables multi-hop routing
/// [64..96] challenge_nonce [u8; 32] — echoes the challenge
/// [96..128] solution_nonce [u8; 32] — the found nonce
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowResponsePayload {
    /// Requester's `node_id` (echoed from the challenge).
    pub requester_node_id: [u8; 32],
    /// Acceptor's `node_id` (enables multi-hop routing of the response).
    pub acceptor_node_id: [u8; 32],
    /// Echo of the challenge's `challenge_nonce`.
    pub challenge_nonce: [u8; 32],
    /// Nonce value the solver found.
    pub solution_nonce: [u8; 32],
}

impl PowResponsePayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 32 + 32 + 32; // 128

    /// Encode to the fixed 128-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.requester_node_id);
        buf[32..64].copy_from_slice(&self.acceptor_node_id);
        buf[64..96].copy_from_slice(&self.challenge_nonce);
        buf[96..128].copy_from_slice(&self.solution_nonce);
        buf
    }

    /// Parse from a 128-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            requester_node_id: super::read_array::<32>(buf, 0)?,
            acceptor_node_id: super::read_array::<32>(buf, 32)?,
            challenge_nonce: super::read_array::<32>(buf, 64)?,
            solution_nonce: super::read_array::<32>(buf, 96)?,
        })
    }
}

// ── PowAcceptPayload ──────────────────────────────────────────────────────────

/// PoW accepted; the acceptor provides a transport address for direct connection.
///
/// Wire layout:
/// ```text
/// [0..32] requester_node_id [u8; 32]
/// [32..64] challenge_nonce [u8; 32]
/// [64..66] transport_len u16 BE
/// [66..] transport UTF-8 — e.g. "tcp://1.2.3.4:7001"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowAcceptPayload {
    /// Requester's `node_id`.
    pub requester_node_id: [u8; 32],
    /// Challenge nonce the solver proved against.
    pub challenge_nonce: [u8; 32],
    /// Acceptor's transport address, e.g. `"tcp://1.2.3.4:7001"`.
    pub transport: String,
}

impl PowAcceptPayload {
    /// Minimum wire size (empty transport string).
    pub const MIN_WIRE_SIZE: usize = 32 + 32 + 2; // 66

    /// Encode to wire bytes. Transport is truncated to `MAX_TRANSPORT_STR_LEN`.
    pub fn encode(&self) -> Vec<u8> {
        let tb = self.transport.as_bytes();
        // Truncate to budget limit instead of panicking.
        let tb = &tb[..tb.len().min(crate::budget::MAX_TRANSPORT_STR_LEN)];
        let mut buf = Vec::with_capacity(Self::MIN_WIRE_SIZE + tb.len());
        buf.extend_from_slice(&self.requester_node_id);
        buf.extend_from_slice(&self.challenge_nonce);
        buf.extend_from_slice(&(tb.len() as u16).to_be_bytes());
        buf.extend_from_slice(tb);
        buf
    }

    /// Parse from wire bytes, enforcing `transport_len ≤ MAX_TRANSPORT_STR_LEN`.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::MIN_WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::MIN_WIRE_SIZE,
                got: buf.len(),
            });
        }
        let requester_node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let challenge_nonce: [u8; 32] = super::read_array::<32>(buf, 32)?;
        let tlen = super::read_u16_be(buf, 64)? as usize;
        if tlen > crate::budget::MAX_TRANSPORT_STR_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "transport_len",
                value: tlen as u64,
                max: crate::budget::MAX_TRANSPORT_STR_LEN as u64,
            });
        }
        if buf.len() < 66 + tlen {
            return Err(ProtoError::BufferTooShort {
                need: 66 + tlen,
                got: buf.len(),
            });
        }
        let transport =
            String::from_utf8(buf[66..66 + tlen].to_vec()).map_err(|_| ProtoError::InvalidUtf8)?;
        Ok(Self {
            requester_node_id,
            challenge_nonce,
            transport,
        })
    }
}

// ── RouteAnnounceAliasedPayload ───────────────────────────────────────────────

/// Aliased gossip advertisement.
///
/// Same semantics as `RouteAnnouncePayload` but carries 8-byte session aliases
/// instead of full 32-byte node_ids. Reduces frame size by 48 bytes (138 → 90).
///
/// The signature still covers the full 32-byte node_ids so the receiver must
/// resolve both aliases before verifying.
///
/// Wire layout:
/// ```text
/// [0..8] origin_alias [u8; 8]
/// [8..16] via_alias [u8; 8]
/// [16] hop_count u8
/// [17] ttl u8
/// [18..22] sequence u32 BE
/// [22..26] timestamp u32 BE
/// [26..90] signature [u8; 64]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAnnounceAliasedPayload {
    /// 8-byte session alias of the reachable origin node.
    pub origin_alias: [u8; 8],
    /// 8-byte session alias of the announcing relay node.
    pub via_alias: [u8; 8],
    /// Hops from via to origin.
    pub hop_count: u8,
    /// Remaining propagation TTL.
    pub ttl: u8,
    /// Monotonic counter (origin) pair.
    pub sequence: u32,
    /// Unix-seconds timestamp for freshness check.
    pub timestamp: u32,
    /// ed25519 signature over the **full** `RouteAnnouncePayload::signable_bytes`.
    /// Receiver must resolve aliases → node_ids before verifying.
    pub signature: [u8; 64],
}

impl RouteAnnounceAliasedPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 8 + 8 + 1 + 1 + 4 + 4 + 64; // 90

    /// Encode to the fixed 90-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..8].copy_from_slice(&self.origin_alias);
        buf[8..16].copy_from_slice(&self.via_alias);
        buf[16] = self.hop_count;
        buf[17] = self.ttl;
        buf[18..22].copy_from_slice(&self.sequence.to_be_bytes());
        buf[22..26].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[26..90].copy_from_slice(&self.signature);
        buf
    }

    /// Parse from a 90-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            origin_alias: super::read_array::<8>(buf, 0)?,
            via_alias: super::read_array::<8>(buf, 8)?,
            hop_count: buf[16],
            ttl: buf[17],
            sequence: super::read_u32_be(buf, 18)?,
            timestamp: super::read_u32_be(buf, 22)?,
            signature: super::read_array::<64>(buf, 26)?,
        })
    }
}

// ── RouteWithdrawAliasedPayload ───────────────────────────────────────────────

/// Aliased gossip retraction.
///
/// Same semantics as `RouteWithdrawPayload` but carries 8-byte session aliases
/// instead of full 32-byte node_ids. Reduces frame size by 48 bytes (132 → 84).
///
/// Wire layout:
/// ```text
/// [0..8] origin_alias [u8; 8]
/// [8..16] via_alias [u8; 8]
/// [16..20] sequence u32 BE
/// [20..84] signature [u8; 64]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteWithdrawAliasedPayload {
    /// 8-byte session alias of the origin node.
    pub origin_alias: [u8; 8],
    /// 8-byte session alias of the announcing relay node.
    pub via_alias: [u8; 8],
    /// Must be greater than the last seen Announce sequence.
    pub sequence: u32,
    /// ed25519 signature over `RouteWithdrawPayload::signable_bytes` (full node_ids).
    pub signature: [u8; 64],
    /// Hop counter — incremented by each forwarder.
    pub hop_count: u8,
}

impl RouteWithdrawAliasedPayload {
    /// Fixed wire size including the `hop_count` byte.
    pub const WIRE_SIZE: usize = 8 + 8 + 4 + 64 + 1; // 85

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&self.origin_alias);
        buf.extend_from_slice(&self.via_alias);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf.push(self.hop_count);
        buf
    }

    /// Parse from the fixed 85-byte wire layout.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            origin_alias: super::read_array::<8>(buf, 0)?,
            via_alias: super::read_array::<8>(buf, 8)?,
            sequence: super::read_u32_be(buf, 16)?,
            signature: super::read_array::<64>(buf, 20)?,
            hop_count: buf[84],
        })
    }
}

// ── RecursiveQueryPayload ─────────────────────────────────────────

/// Query type discriminants for `RecursiveQueryPayload`.
/// Query-type discriminants for `RecursiveQueryPayload`.
pub mod recursive_query_type {
    /// Kademlia FIND_NODE — return the closest K nodes to `target_key`.
    pub const FIND_NODE: u8 = 1;
    /// Kademlia FIND_VALUE — return the value at `target_key` or closest nodes.
    pub const FIND_VALUE: u8 = 2;
    /// Kademlia STORE — ask the closest nodes to store `payload` under `target_key`.
    pub const STORE: u8 = 3;
    /// PoW-Gated Rendezvous request relay (Slice 6 of the
    /// PoW-Gated Rendezvous epic; see
    /// `docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`).
    ///
    /// **Routing contract:** initiator builds а `RecursiveQueryPayload`
    /// where:
    ///
    /// * `target_key` = the destination's `node_id` (so existing
    ///   greedy-relay forwarding делivers the query toward the
    ///   stealth-listener target)
    /// * `reply_to` = initiator's own `node_id` (response routes back
    ///   through the same reverse-path machinery used by FIND_NODE)
    /// * `query_type` = `RENDEZVOUS_REQUEST` (this value)
    /// * `payload` = encoded
    ///   [`crate::rendezvous::RequestEphemeralEndpointPayload`] (fixed
    ///   148 bytes incl. PoW + requester sig)
    /// * `reply_port` = 0 — UDP-direct reply NOT supported (target's
    ///   reachable IP is the secret protected by the rendezvous flow;
    ///   reply must travel through veil)
    ///
    /// **Target dispatcher behavior** (см.
    /// `veilcore::node::dispatcher::routing::handle_recursive_query`,
    /// Slice 6b): parses inner
    /// `RequestEphemeralEndpointPayload`, invokes the rendezvous
    /// controller (`dispatcher.rendezvous_weak.upgrade()`), packs the
    /// signed `EphemeralEndpointResponsePayload` bytes into а
    /// `RecursiveResponsePayload` outer envelope, ships it back via
    /// the existing reverse-path resolver.
    ///
    /// **Initiator verification** (Slice 6c): outer envelope's
    /// `responder_pubkey` MUST satisfy
    /// `BLAKE3(responder_pubkey) == target_node_id`; inner
    /// `EphemeralEndpointResponsePayload` then runs through the
    /// existing `verify_ephemeral_endpoint_response()` под the same
    /// pubkey.  Defense-in-depth: inner и outer sigs are domain-
    /// separated, so а passive relay capturing the outer envelope
    /// cannot replay it к а different initiator (inner sig binds
    /// `requester_pubkey`).
    pub const RENDEZVOUS_REQUEST: u8 = 4;
}

/// Recursive DHT query — greedy forwarded toward `target_key` by each
/// intermediate node. The target (or a node that has the answer) sends a
/// `RecursiveResponsePayload` directly to `reply_to` via `reply_addr`.
///
/// Wire layout:
/// ```text
/// [0..16] query_id [u8; 16] dedup
/// [16..48] target_key [u8; 32] what we're looking for
/// [48..80] reply_to [u8; 32] node_id of the initiator
/// [80] ttl u8 hop limit
/// [81] query_type u8 FindNode / FindValue / Store
/// [82..84] reply_port u16 BE UDP port for direct reply
/// [84..88] payload_len u32 BE
/// [88..] payload [u8] query-specific data
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveQueryPayload {
    /// Random query id for dedup.
    pub query_id: [u8; 16],
    /// Kademlia target key being queried.
    pub target_key: [u8; 32],
    /// Initiator's `node_id` — direct replies are sent here.
    pub reply_to: [u8; 32],
    /// Hop budget decremented by each relay.
    pub ttl: u8,
    /// One [`recursive_query_type`] codes.
    pub query_type: u8,
    /// UDP port for direct reply (0 = route via veil).
    pub reply_port: u16,
    /// Query-type-specific payload (e.g. value bytes for STORE).
    pub payload: Vec<u8>,
}

impl RecursiveQueryPayload {
    /// Size of the fixed-width header (before `payload`).
    pub const FIXED_HEADER: usize = 16 + 32 + 32 + 1 + 1 + 2 + 4; // 88

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_HEADER + self.payload.len());
        buf.extend_from_slice(&self.query_id);
        buf.extend_from_slice(&self.target_key);
        buf.extend_from_slice(&self.reply_to);
        buf.push(self.ttl);
        buf.push(self.query_type);
        buf.extend_from_slice(&self.reply_port.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse from wire bytes; enforces `payload_len ≤ MAX_DHT_VALUE_BYTES`.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_HEADER {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_HEADER,
                got: buf.len(),
            });
        }
        let query_id: [u8; 16] = super::read_array::<16>(buf, 0)?;
        let target_key: [u8; 32] = super::read_array::<32>(buf, 16)?;
        let reply_to: [u8; 32] = super::read_array::<32>(buf, 48)?;
        // Clamp `ttl` к `MAX_RECURSIVE_RELAY_HOPS` (canonical spec cap):
        // attacker-controlled `ttl=255` × 2-way fanout would otherwise
        // amplify per-hop bandwidth before the network-wide query_id
        // dedup catches up.  Clamping at decode means every dispatcher
        // sees the same bounded value regardless of input.
        let ttl = buf[80].min(crate::budget::MAX_RECURSIVE_RELAY_HOPS);
        let query_type = buf[81];
        let reply_port = super::read_u16_be(buf, 82)?;
        let payload_len = super::read_u32_be(buf, 84)? as usize;
        if payload_len > crate::budget::MAX_DHT_VALUE_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "RecursiveQuery.payload",
                value: payload_len as u64,
                max: crate::budget::MAX_DHT_VALUE_BYTES as u64,
            });
        }
        // checked_add — 32-bit overflow defence.
        let total =
            Self::FIXED_HEADER
                .checked_add(payload_len)
                .ok_or(ProtoError::BufferTooShort {
                    need: usize::MAX,
                    got: buf.len(),
                })?;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            query_id,
            target_key,
            reply_to,
            ttl,
            query_type,
            reply_port,
            payload: buf[Self::FIXED_HEADER..total].to_vec(),
        })
    }
}

// ── RecursiveResponsePayload ────────────

/// Direct response to a `RecursiveQueryPayload`. Sent to the initiator's
/// `reply_addr` (UDP direct) or via the session layer as fallback.
///
/// the responder binds the payload to its long-term Ed25519 key
/// so passive relays that observe the `query_id` mid-flight cannot forge a
/// response. The initiator verifies `BLAKE3(responder_pubkey)` matches the
/// claimed responder node_id and that the signature covers
/// `query_id || payload`.
///
/// Wire layout:
/// ```text
/// [0..16] query_id [u8; 16] matches the query
/// [16..20] payload_len u32 BE
/// [20..N] payload [u8] result data
/// [N..N+32] responder_pubkey [u8; 32] Ed25519 public key of the replier
/// [N+32..] signature [u8; 64] Ed25519(query_id || payload)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveResponsePayload {
    /// Echo of the query's `query_id`.
    pub query_id: [u8; 16],
    /// Result bytes (type depends on the original query's `query_type`).
    pub payload: Vec<u8>,
    /// Ed25519 public key of the responding node.
    pub responder_pubkey: [u8; 32],
    /// Ed25519 signature over `query_id || payload`.
    pub signature: [u8; 64],
}

impl RecursiveResponsePayload {
    /// Size of the fixed-width header (before `payload`).
    pub const FIXED_HEADER: usize = 16 + 4; // 20
    /// Size of the fixed-width authenticator trailer (pubkey + signature).
    pub const AUTH_SIZE: usize = 32 + 64; // 96

    /// Bytes covered by the signature: `query_id || payload`.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.payload.len());
        buf.extend_from_slice(&self.query_id);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_HEADER + self.payload.len() + Self::AUTH_SIZE);
        buf.extend_from_slice(&self.query_id);
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&self.responder_pubkey);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parse from wire bytes; enforces `payload_len ≤ MAX_DHT_VALUE_BYTES`
    /// and that the authenticator trailer is present.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_HEADER {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_HEADER,
                got: buf.len(),
            });
        }
        let query_id: [u8; 16] = super::read_array::<16>(buf, 0)?;
        let payload_len = super::read_u32_be(buf, 16)? as usize;
        if payload_len > crate::budget::MAX_DHT_VALUE_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "RecursiveResponse.payload",
                value: payload_len as u64,
                max: crate::budget::MAX_DHT_VALUE_BYTES as u64,
            });
        }
        let total = Self::FIXED_HEADER + payload_len + Self::AUTH_SIZE;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        let payload = buf[Self::FIXED_HEADER..Self::FIXED_HEADER + payload_len].to_vec();
        let responder_pubkey: [u8; 32] =
            super::read_array::<32>(buf, Self::FIXED_HEADER + payload_len)?;
        let signature: [u8; 64] =
            super::read_array::<64>(buf, Self::FIXED_HEADER + payload_len + 32)?;
        Ok(Self {
            query_id,
            payload,
            responder_pubkey,
            signature,
        })
    }
}

// ── RouteUpdatePayload ────────────────────────────────────────────

/// Route update actions.
/// Route-update actions for `RouteUpdatePayload::action`.
pub mod route_update_action {
    /// Advertise a new route to `origin` via `via`.
    pub const ADD: u8 = 1;
    /// Retract a previously-advertised route.
    pub const REMOVE: u8 = 2;
}

/// Event-driven route update: pushed on peer connect/disconnect instead of
/// periodic flood. Replaces `RouteAnnounce` + `RouteWithdraw` gossip.
///
/// Wire layout:
/// ```text
/// [0..32] origin_node_id [u8; 32]
/// [32..64] via_node_id [u8; 32]
/// [64] action u8 ADD=1 / REMOVE=2
/// [65..73] version u64 BE monotonic per-origin
/// [73] hop_count u8
/// [74..138] signature [u8; 64]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteUpdatePayload {
    /// Reachable node the update applies to.
    pub origin_node_id: [u8; 32],
    /// Relay node (= signer) announcing the change.
    pub via_node_id: [u8; 32],
    /// One [`route_update_action`] codes.
    pub action: u8,
    /// Monotonic per-origin version for conflict resolution.
    pub version: u64,
    /// Hop counter — incremented by each forwarder.
    pub hop_count: u8,
    /// Ed25519 signature over [`Self::signable_bytes`].
    pub signature: [u8; 64],
}

impl RouteUpdatePayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 32 + 1 + 8 + 1 + 64; // 138

    /// Bytes covered by the signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(73);
        buf.extend_from_slice(&self.origin_node_id);
        buf.extend_from_slice(&self.via_node_id);
        buf.push(self.action);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&self.origin_node_id);
        buf.extend_from_slice(&self.via_node_id);
        buf.push(self.action);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.push(self.hop_count);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parse from a 138-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            origin_node_id: super::read_array::<32>(buf, 0)?,
            via_node_id: super::read_array::<32>(buf, 32)?,
            action: buf[64],
            version: super::read_u64_be(buf, 65)?,
            hop_count: buf[73],
            signature: super::read_array::<64>(buf, 74)?,
        })
    }
}

// ── VersionVectorSyncPayload ──────────────────────────────────────

/// Periodic version-vector exchange for route reconciliation.
/// Each entry is (origin_node_id, max_version_seen). The peer responds with
/// RouteUpdate deltas for entries where peer.version > received.version.
///
/// Wire layout:
/// ```text
/// [0..4] count u32 BE
/// [4..] entries Vec<(node_id[32], version[u64])> = 40 bytes each
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionVectorSyncPayload {
    /// `(origin_node_id, version)` pairs the sender currently holds.
    pub entries: Vec<([u8; 32], u64)>,
}

impl VersionVectorSyncPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let count = self.entries.len().min(u32::MAX as usize) as u32;
        let mut buf = Vec::with_capacity(4 + self.entries.len() * 40);
        buf.extend_from_slice(&count.to_be_bytes());
        for (node_id, version) in self.entries.iter().take(count as usize) {
            buf.extend_from_slice(node_id);
            buf.extend_from_slice(&version.to_be_bytes());
        }
        buf
    }

    /// Parse from wire bytes; enforces `count ≤ 10_000`.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 4 {
            return Err(ProtoError::BufferTooShort {
                need: 4,
                got: buf.len(),
            });
        }
        let count = super::read_u32_be(buf, 0)? as usize;
        if count > 10_000 {
            return Err(ProtoError::ValueTooLarge {
                field: "VersionVectorSync.count",
                value: count as u64,
                max: 10_000,
            });
        }
        let needed = 4 + count * 40;
        if buf.len() < needed {
            return Err(ProtoError::BufferTooShort {
                need: needed,
                got: buf.len(),
            });
        }
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let off = 4 + i * 40;
            let node_id: [u8; 32] = super::read_array::<32>(buf, off)?;
            let version = super::read_u64_be(buf, off + 32)?;
            entries.push((node_id, version));
        }
        Ok(Self { entries })
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_announce_roundtrip() {
        let p = RouteAnnouncePayload {
            origin_node_id: [1u8; 32],
            via_node_id: [2u8; 32],
            hop_count: 1,
            ttl: 7,
            sequence: 42,
            timestamp: 1_700_000_000,
            signature: [0xABu8; 64],
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), RouteAnnouncePayload::WIRE_SIZE);
        let decoded = RouteAnnouncePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn route_announce_too_short() {
        let err = RouteAnnouncePayload::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn route_announce_signable_excludes_sig() {
        let p = RouteAnnouncePayload {
            origin_node_id: [1u8; 32],
            via_node_id: [2u8; 32],
            hop_count: 2,
            ttl: 5,
            sequence: 7,
            timestamp: 100,
            signature: [0u8; 64],
        };
        let sig_bytes = p.signable_bytes();
        assert_eq!(sig_bytes.len(), 74);
        // Changing sig must not affect signable bytes.
        let p2 = RouteAnnouncePayload {
            signature: [0xFFu8; 64],
            ..p.clone()
        };
        assert_eq!(p.signable_bytes(), p2.signable_bytes());
    }

    #[test]
    fn route_withdraw_roundtrip() {
        let p = RouteWithdrawPayload {
            origin_node_id: [3u8; 32],
            via_node_id: [4u8; 32],
            sequence: 99,
            signature: [0xCDu8; 64],
            hop_count: 3,
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), RouteWithdrawPayload::WIRE_SIZE);
        let decoded = RouteWithdrawPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn route_request_roundtrip() {
        let p = RouteRequestPayload {
            target_node_id: [5u8; 32],
            requester_node_id: [6u8; 32],
            request_id: 0xDEAD_BEEF,
            ttl: 6,
            signature: [0x11u8; 64],
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), RouteRequestPayload::WIRE_SIZE);
        let decoded = RouteRequestPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn route_response_roundtrip_empty() {
        let p = RouteResponsePayload {
            target_node_id: [7u8; 32],
            requester_node_id: [8u8; 32],
            request_id: 1,
            transports: vec![],
            relay_ids: vec![],
            mlkem_pubkey: None,
            signature: [0x22u8; 64],
            ed25519_pubkey: None,

            target_labels: Vec::new(),
        };
        let encoded = p.encode();
        let decoded = RouteResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn route_response_roundtrip_full() {
        let p = RouteResponsePayload {
            target_node_id: [7u8; 32],
            requester_node_id: [8u8; 32],
            request_id: 42,
            transports: vec![
                "tcp://127.0.0.1:7001".to_string(),
                "tcp://10.0.0.1:7001".to_string(),
            ],
            relay_ids: vec![[9u8; 32], [10u8; 32]],
            mlkem_pubkey: Some(vec![0xAAu8; 1184]),
            signature: [0x33u8; 64],
            ed25519_pubkey: Some(vec![0xBBu8; 32]),

            target_labels: Vec::new(),
        };
        let encoded = p.encode();
        let decoded = RouteResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded.target_node_id, p.target_node_id);
        assert_eq!(decoded.transports, p.transports);
        assert_eq!(decoded.relay_ids, p.relay_ids);
        assert_eq!(decoded.mlkem_pubkey, p.mlkem_pubkey);
        assert_eq!(decoded.signature, p.signature);
        assert_eq!(decoded.ed25519_pubkey, p.ed25519_pubkey);
    }

    #[test]
    fn route_response_roundtrip_with_target_labels() {
        let p = RouteResponsePayload {
            target_node_id: [7u8; 32],
            requester_node_id: [8u8; 32],
            request_id: 99,
            transports: vec!["tcp://127.0.0.1:7001".to_owned()],
            relay_ids: vec![],
            mlkem_pubkey: None,
            signature: [0x44u8; 64],
            ed25519_pubkey: None,
            target_labels: vec![*b"exit", *b"low\0", *b"qiwi"],
        };
        let encoded = p.encode();
        let decoded = RouteResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded.target_labels, p.target_labels);
        assert_eq!(decoded, p);
    }

    #[test]
    fn route_response_target_labels_in_signable_bytes() {
        // Two responses identical except for target_labels must produce
        // distinct signable_bytes (so the signature actually covers the
        // labels and a relay can't strip them without invalidating sig).
        let mut p1 = RouteResponsePayload {
            target_node_id: [7u8; 32],
            requester_node_id: [8u8; 32],
            request_id: 1,
            transports: vec![],
            relay_ids: vec![],
            mlkem_pubkey: None,
            signature: [0u8; 64],
            ed25519_pubkey: None,
            target_labels: vec![],
        };
        let sig_empty = p1.signable_bytes();
        p1.target_labels = vec![*b"exit"];
        let sig_one = p1.signable_bytes();
        assert_ne!(
            sig_empty, sig_one,
            "target_labels must change signable_bytes — otherwise relays could forge labels"
        );
    }

    #[test]
    fn route_response_rejects_too_many_labels() {
        // Encode 9 labels (cap=8) and verify decode rejects it.
        // Build an over-capacity wire blob by hand.
        let p = RouteResponsePayload {
            target_node_id: [7u8; 32],
            requester_node_id: [8u8; 32],
            request_id: 0,
            transports: vec![],
            relay_ids: vec![],
            mlkem_pubkey: None,
            signature: [0u8; 64],
            ed25519_pubkey: None,
            target_labels: vec![
                *b"l001", *b"l002", *b"l003", *b"l004", *b"l005", *b"l006", *b"l007", *b"l008",
            ],
        };
        let encoded = p.encode();
        // Sanity: at-cap encodes fine.
        assert!(RouteResponsePayload::decode(&encoded).is_ok());
        // Overflow: bump count byte to 9 and re-decode → ValueTooLarge.
        // Find the label_count byte: target(32)+requester(32)+req_id(4)+
        // transport_count(1=0)+relay_count(1=0)+mlkem_len(2=0) = 72.
        let mut bad = encoded.clone();
        bad[72] = 9;
        assert!(matches!(
            RouteResponsePayload::decode(&bad),
            Err(crate::ProtoError::ValueTooLarge { .. })
        ));
    }

    #[test]
    fn pow_challenge_roundtrip() {
        let p = PowChallengePayload {
            requester_node_id: [11u8; 32],
            acceptor_node_id: [12u8; 32],
            challenge_nonce: [0xBBu8; 32],
            difficulty: 16,
            signature: [0x44u8; 64],
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), PowChallengePayload::WIRE_SIZE);
        let decoded = PowChallengePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn pow_response_roundtrip() {
        let p = PowResponsePayload {
            requester_node_id: [13u8; 32],
            acceptor_node_id: [14u8; 32],
            challenge_nonce: [0xCCu8; 32],
            solution_nonce: [0xDDu8; 32],
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), PowResponsePayload::WIRE_SIZE);
        let decoded = PowResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn pow_accept_roundtrip() {
        let p = PowAcceptPayload {
            requester_node_id: [14u8; 32],
            challenge_nonce: [0xEEu8; 32],
            transport: "tcp://192.168.1.1:7777".to_string(),
        };
        let encoded = p.encode();
        let decoded = PowAcceptPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn pow_accept_empty_transport() {
        let p = PowAcceptPayload {
            requester_node_id: [0u8; 32],
            challenge_nonce: [0u8; 32],
            transport: String::new(),
        };
        let encoded = p.encode();
        let decoded = PowAcceptPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.transport, "");
    }

    // ── aliased payload tests ────────────────────────────────────────────────

    #[test]
    fn route_announce_aliased_roundtrip() {
        let p = RouteAnnounceAliasedPayload {
            origin_alias: [0x11u8; 8],
            via_alias: [0x22u8; 8],
            hop_count: 1,
            ttl: 7,
            sequence: 42,
            timestamp: 1_700_000_000,
            signature: [0xABu8; 64],
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), RouteAnnounceAliasedPayload::WIRE_SIZE);
        assert_eq!(RouteAnnounceAliasedPayload::decode(&encoded).unwrap(), p);
    }

    #[test]
    fn route_announce_aliased_too_short() {
        assert!(RouteAnnounceAliasedPayload::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn route_withdraw_aliased_roundtrip() {
        let p = RouteWithdrawAliasedPayload {
            origin_alias: [0x33u8; 8],
            via_alias: [0x44u8; 8],
            sequence: 99,
            signature: [0xCDu8; 64],
            hop_count: 2,
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), RouteWithdrawAliasedPayload::WIRE_SIZE);
        assert_eq!(RouteWithdrawAliasedPayload::decode(&encoded).unwrap(), p);
    }

    #[test]
    fn route_withdraw_aliased_too_short() {
        assert!(RouteWithdrawAliasedPayload::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn aliased_wire_size_smaller_than_full() {
        // Verify the wire size savings are as expected.
        assert_eq!(RouteAnnounceAliasedPayload::WIRE_SIZE, 90);
        assert_eq!(RouteWithdrawAliasedPayload::WIRE_SIZE, 85);
        const { assert!(RouteAnnounceAliasedPayload::WIRE_SIZE < RouteAnnouncePayload::WIRE_SIZE) };
        const { assert!(RouteWithdrawAliasedPayload::WIRE_SIZE < RouteWithdrawPayload::WIRE_SIZE) };
    }
}

// ── RouteDiscoveryPacket ──────────────────────────────────────────────────────

/// Random-walk route discovery packet.
///
/// Sent by a node wanting to discover new routes. Each forwarding node
/// decrements `ttl`; when it reaches 0 the holder responds to the initiator
/// via the discovery directory (gateway lookup).
///
/// Wire layout:
/// ```text
/// [0..32] src_node_id [u8; 32] — initiating node
/// [32..40] timestamp u64 BE — unix seconds (replay guard)
/// [40..72] pow_nonce [u8; 32] — PoW solution nonce
/// [72] ttl u8 — remaining hops
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDiscoveryPacket {
    /// Initiating node's `node_id`.
    pub src_node_id: [u8; 32],
    /// Unix timestamp (seconds) at which the PoW was solved.
    pub timestamp: u64,
    /// PoW solution nonce.
    pub pow_nonce: [u8; 32],
    /// Remaining forwarding hops. Decremented by each relay; 0 → respond.
    pub ttl: u8,
}

impl RouteDiscoveryPacket {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 8 + 32 + 1; // 73

    /// Encode to the fixed 73-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.src_node_id);
        buf[32..40].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[40..72].copy_from_slice(&self.pow_nonce);
        buf[72] = self.ttl;
        buf
    }

    /// Parse from a 73-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            src_node_id: super::read_array::<32>(buf, 0)?,
            timestamp: super::read_u64_be(buf, 32)?,
            pow_nonce: super::read_array::<32>(buf, 40)?,
            ttl: buf[72],
        })
    }
}

// ── RouteDiscoverOfferPayload ─────────────────────────────────────────────────

/// Offer sent from the TTL=0 node back to the discovery initiator.
///
/// Transmitted over an already-established encrypted session (the responder
/// connects to the initiator through the initiator's gateway).
///
/// Wire layout:
/// ```text
/// [0..32] responder_node_id [u8; 32]
/// [32] transport_count u8
/// [33..] transports [len(1) + utf8_bytes...]*
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDiscoverOfferPayload {
    /// Responder's `node_id`.
    pub responder_node_id: [u8; 32],
    /// Transport URIs at which the responder can be reached.
    pub transports: Vec<String>,
}

impl RouteDiscoverOfferPayload {
    /// Minimum wire size (empty transports list).
    pub const MIN_WIRE_SIZE: usize = 32 + 1; // 33

    /// Encode to wire bytes; truncates `transports` / string lengths to caps.
    pub fn encode(&self) -> Vec<u8> {
        use crate::budget::{MAX_TRANSPORT_ADDRS, MAX_TRANSPORT_STR_LEN};
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.responder_node_id);
        let tc = self.transports.len().min(MAX_TRANSPORT_ADDRS);
        buf.push(tc as u8);
        for t in self.transports.iter().take(MAX_TRANSPORT_ADDRS) {
            let bytes = t.as_bytes();
            let len = bytes.len().min(MAX_TRANSPORT_STR_LEN);
            buf.push(len as u8);
            buf.extend_from_slice(&bytes[..len]);
        }
        buf
    }

    /// Parse from wire bytes; enforces all per-field caps.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::MIN_WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::MIN_WIRE_SIZE,
                got: buf.len(),
            });
        }
        use crate::budget::{MAX_TRANSPORT_ADDRS, MAX_TRANSPORT_STR_LEN};
        let responder_node_id = super::read_array::<32>(buf, 0)?;
        let transport_count = buf[32] as usize;
        if transport_count > MAX_TRANSPORT_ADDRS {
            return Err(ProtoError::ValueTooLarge {
                field: "transport_count",
                value: transport_count as u64,
                max: MAX_TRANSPORT_ADDRS as u64,
            });
        }
        let mut offset = 33;
        let mut transports = Vec::with_capacity(transport_count);
        for _ in 0..transport_count {
            if offset >= buf.len() {
                return Err(ProtoError::BufferTooShort {
                    need: offset + 1,
                    got: buf.len(),
                });
            }
            let len = buf[offset] as usize;
            if len > MAX_TRANSPORT_STR_LEN {
                return Err(ProtoError::ValueTooLarge {
                    field: "transport_len",
                    value: len as u64,
                    max: MAX_TRANSPORT_STR_LEN as u64,
                });
            }
            offset += 1;
            if offset + len > buf.len() {
                return Err(ProtoError::BufferTooShort {
                    need: offset + len,
                    got: buf.len(),
                });
            }
            let s = String::from_utf8(buf[offset..offset + len].to_vec())
                .map_err(|_| ProtoError::InvalidUtf8)?;
            transports.push(s);
            offset += len;
        }
        Ok(Self {
            responder_node_id,
            transports,
        })
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    #[test]
    fn route_discovery_packet_roundtrip() {
        let pkt = RouteDiscoveryPacket {
            src_node_id: [0x11u8; 32],
            timestamp: 1_700_000_000,
            pow_nonce: [0x22u8; 32],
            ttl: 16,
        };
        let encoded = pkt.encode();
        assert_eq!(encoded.len(), RouteDiscoveryPacket::WIRE_SIZE);
        let decoded = RouteDiscoveryPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn route_discovery_packet_too_short() {
        assert!(RouteDiscoveryPacket::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn route_discover_offer_roundtrip_no_transports() {
        let offer = RouteDiscoverOfferPayload {
            responder_node_id: [0xAAu8; 32],
            transports: vec![],
        };
        let encoded = offer.encode();
        assert_eq!(encoded.len(), RouteDiscoverOfferPayload::MIN_WIRE_SIZE);
        let decoded = RouteDiscoverOfferPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, offer);
    }

    #[test]
    fn route_discover_offer_roundtrip_with_transports() {
        let offer = RouteDiscoverOfferPayload {
            responder_node_id: [0xBBu8; 32],
            transports: vec![
                "tcp://1.2.3.4:7001".to_owned(),
                "quic://5.6.7.8:7002".to_owned(),
            ],
        };
        let encoded = offer.encode();
        let decoded = RouteDiscoverOfferPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, offer);
    }

    #[test]
    fn route_discover_offer_too_short() {
        assert!(RouteDiscoverOfferPayload::decode(&[0u8; 5]).is_err());
    }

    // ── RecursiveQuery/Response roundtrip ──────────────────────

    #[test]
    fn recursive_query_roundtrip() {
        // Drive-by: ttl set к MAX_RECURSIVE_RELAY_HOPS (was 40 — pre-
        // existing flake after the constant got clamped к 20; decode
        // clamps so the round-trip differs in the ttl field).  Using
        // the canonical maximum makes the test stable.
        let q = RecursiveQueryPayload {
            query_id: [0xAAu8; 16],
            target_key: [0xBBu8; 32],
            reply_to: [0xCCu8; 32],
            ttl: crate::budget::MAX_RECURSIVE_RELAY_HOPS,
            query_type: recursive_query_type::FIND_VALUE,
            reply_port: 9000,
            payload: b"test payload".to_vec(),
        };
        let encoded = q.encode();
        let decoded = RecursiveQueryPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, q);
    }

    #[test]
    fn recursive_query_too_short() {
        assert!(RecursiveQueryPayload::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn recursive_query_payload_too_large() {
        let mut buf = vec![0u8; RecursiveQueryPayload::FIXED_HEADER];
        // Set payload_len to MAX_DHT_VALUE_BYTES + 1
        let too_large = (crate::budget::MAX_DHT_VALUE_BYTES + 1) as u32;
        buf[84..88].copy_from_slice(&too_large.to_be_bytes());
        assert!(RecursiveQueryPayload::decode(&buf).is_err());
    }

    #[test]
    fn recursive_response_roundtrip() {
        let r = RecursiveResponsePayload {
            query_id: [0xDDu8; 16],
            payload: b"result data".to_vec(),
            responder_pubkey: [0x11u8; 32],
            signature: [0x22u8; 64],
        };
        let encoded = r.encode();
        let decoded = RecursiveResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, r);
    }

    // ── PoW-Gated Rendezvous over RecursiveQuery (Slice 6a) ─────

    /// Slice 6a contract: а signed `RequestEphemeralEndpointPayload`
    /// embedded в а `RecursiveQueryPayload::payload` field с
    /// `query_type = RENDEZVOUS_REQUEST` round-trips cleanly through
    /// both layers AND the inner sig + PoW still verify after
    /// decode-from-outer.  This is the on-wire contract что Slice 6b
    /// (target dispatcher arm) + Slice 6c (initiator client) rely
    /// on.
    #[test]
    fn rendezvous_request_round_trips_through_recursive_envelope() {
        use crate::rendezvous::{
            MIN_POW_DIFFICULTY, RequestEphemeralEndpointPayload, mine_pow_nonce,
            sign_request_ephemeral_endpoint, verify_request_ephemeral_endpoint,
        };
        use ed25519_dalek::SigningKey;

        // Build а signed PoW-gated request at minimum difficulty so
        // mining is fast in the test.
        let requester_sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let requester_pk = requester_sk.verifying_key().to_bytes();
        let target_node_id = [0xABu8; 32];
        let timestamp_unix = 1_700_000_000;
        let mut draft = RequestEphemeralEndpointPayload {
            target_node_id,
            requester_pubkey: requester_pk,
            timestamp_unix,
            pow_difficulty: MIN_POW_DIFFICULTY,
            pow_nonce: 0,
            requester_sig: [0u8; 64],
        };
        mine_pow_nonce(&mut draft).unwrap();
        let inner = sign_request_ephemeral_endpoint(
            target_node_id,
            requester_pk,
            timestamp_unix,
            MIN_POW_DIFFICULTY,
            draft.pow_nonce,
            &requester_sk,
        );
        let inner_bytes = inner.encode().to_vec();

        // Wrap в the recursive envelope.  Use canonical max-hops так
        // round-trip is stable (decode clamps к MAX_RECURSIVE_RELAY_HOPS).
        let query = RecursiveQueryPayload {
            query_id: [0xC0u8; 16],
            target_key: target_node_id,
            reply_to: [0xC1u8; 32],
            ttl: crate::budget::MAX_RECURSIVE_RELAY_HOPS,
            query_type: recursive_query_type::RENDEZVOUS_REQUEST,
            reply_port: 0, // veil reverse-path, not UDP-direct
            payload: inner_bytes.clone(),
        };

        // Wire round-trip: encode → decode → recover inner.
        let outer_bytes = query.encode();
        let outer_decoded = RecursiveQueryPayload::decode(&outer_bytes).unwrap();
        assert_eq!(outer_decoded, query);
        assert_eq!(
            outer_decoded.query_type,
            recursive_query_type::RENDEZVOUS_REQUEST
        );
        assert_eq!(outer_decoded.reply_port, 0);

        // Inner payload still decodes + verifies against initial
        // difficulty + timestamp window.
        let inner_recovered =
            RequestEphemeralEndpointPayload::decode(&outer_decoded.payload).unwrap();
        assert_eq!(inner_recovered, inner);
        verify_request_ephemeral_endpoint(
            &inner_recovered,
            MIN_POW_DIFFICULTY,
            timestamp_unix + 60,
        )
        .expect("inner sig + PoW must still verify after outer round-trip");
    }

    /// Slice 6a contract: а signed `EphemeralEndpointResponsePayload`
    /// embedded в а `RecursiveResponsePayload::payload` field
    /// round-trips и still verifies under the inner's target pubkey.
    /// The OUTER sig (recursive response level) binds к the responder's
    /// long-term key; the INNER sig binds к the per-request canonical.
    /// Both must verify independently — domain-separation guarantees
    /// disjointness.
    #[test]
    fn rendezvous_response_round_trips_through_recursive_envelope() {
        use crate::rendezvous::{
            EphemeralEndpointResponsePayload, sign_ephemeral_endpoint_response,
            verify_ephemeral_endpoint_response,
        };
        use ed25519_dalek::SigningKey;

        let target_sk = SigningKey::from_bytes(&[0x55u8; 32]);
        let target_pk = target_sk.verifying_key().to_bytes();
        let target_node_id = *blake3::hash(&target_pk).as_bytes();
        let requester_pk = SigningKey::from_bytes(&[0x66u8; 32])
            .verifying_key()
            .to_bytes();
        let inner = sign_ephemeral_endpoint_response(
            target_node_id,
            requester_pk,
            1_700_000_300,
            "obfs4-tcp://example.com:51234".to_owned(),
            [0xCDu8; 32],
            &target_sk,
        )
        .unwrap();
        let inner_bytes = inner.encode();

        let outer = RecursiveResponsePayload {
            query_id: [0xC0u8; 16],
            payload: inner_bytes.clone(),
            responder_pubkey: target_pk,
            signature: [0x99u8; 64], // outer sig — fake; tested separately
        };
        let outer_bytes = outer.encode();
        let outer_decoded = RecursiveResponsePayload::decode(&outer_bytes).unwrap();
        assert_eq!(outer_decoded, outer);

        // Inner still verifies against target's pubkey.
        let inner_recovered =
            EphemeralEndpointResponsePayload::decode(&outer_decoded.payload).unwrap();
        verify_ephemeral_endpoint_response(
            &inner_recovered,
            &target_pk,
            &requester_pk,
            1_700_000_100,
        )
        .expect("inner response sig must still verify after outer round-trip");
    }

    // ── RouteUpdate + VersionVectorSync roundtrip ─────────────

    #[test]
    fn route_update_roundtrip() {
        let p = RouteUpdatePayload {
            origin_node_id: [0x11u8; 32],
            via_node_id: [0x22u8; 32],
            action: route_update_action::ADD,
            version: 42,
            hop_count: 3,
            signature: [0xEEu8; 64],
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), RouteUpdatePayload::WIRE_SIZE);
        let decoded = RouteUpdatePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn version_vector_sync_roundtrip() {
        let vv = VersionVectorSyncPayload {
            entries: vec![
                ([0xAAu8; 32], 100),
                ([0xBBu8; 32], 200),
                ([0xCCu8; 32], 300),
            ],
        };
        let encoded = vv.encode();
        let decoded = VersionVectorSyncPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, vv);
    }

    #[test]
    fn version_vector_sync_empty() {
        let vv = VersionVectorSyncPayload { entries: vec![] };
        let encoded = vv.encode();
        let decoded = VersionVectorSyncPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.entries.len(), 0);
    }

    #[test]
    fn version_vector_sync_count_limit() {
        let mut buf = vec![0u8; 4];
        // count = 10001 > 10000 limit
        buf[0..4].copy_from_slice(&10001u32.to_be_bytes());
        assert!(VersionVectorSyncPayload::decode(&buf).is_err());
    }
}
