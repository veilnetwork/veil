//! Receiver-signed capability tokens that gate access to the mailbox
//! PUT endpoint.
//!
//! ## Threat model
//!
//! Pre-fix the mailbox PUT endpoint was open: anyone holding a receiver's
//! `node_id` could deposit blobs at any of its replica relays, gated only
//! by per-receiver byte quota and rate limit. An attacker grinding random
//! `(receiver_id, content_id)` tuples could drive a relay's per-receiver
//! byte counter against the quota cap, displacing legitimate blobs via
//! the global eviction path (the eviction-age guard in
//! [`crate::lib::MIN_EVICTION_AGE_SECS`] caps that, but the attacker
//! still wastes the receiver's quota slot).
//!
//! Capability tokens turn the PUT endpoint from open to "receiver-authorised":
//! the receiver mints a signed token, distributes it out-of-band (e.g.
//! alongside the `RendezvousAd.auth_cookie` already published in DHT)
//! senders attach the token to each PUT, and the relay verifies the
//! signature and time-window before storing.
//!
//! ## Why receiver-signed (not relay-issued)
//!
//! The relay does not know **which** senders the receiver wants to accept
//! deposits from. Only the receiver knows that. Pushing the policy
//! decision to the receiver — sender holds a token = receiver said "yes" —
//! keeps the relay stateless with regard to sender identity. Same shape as
//! the existing `RendezvousAd.auth_cookie` in `veil-anonymity`.
//!
//! ## What this slice ships
//!
//! 1. [`MailboxCapabilityToken`] type + encode/decode wire format.
//! 2. Sign (test/internal use) + verify primitives.
//! 3. Time-window enforcement (skew tolerant within ±60 s).
//! 4. Receiver-id binding via `BLAKE3(issuer_pubkey)`.
//!
//! ## Landed since this module's first slice
//!
//! * Receiver-side mint API: `MailboxCapabilityToken::mint_unbound_ed25519` /
//!   `mint_bound_ed25519` (and the `sign_token` / `sign_token_v2` primitives);
//!   the daemon mints into `RendezvousAd.capability_token`.
//! * Trust-class eviction pools: `TrustClass::{Identified, Anonymous}` keep
//!   tokenless deposits in a separately-evicted pool.
//! * Relay-binding (v2): tokens carry a signed `relay_node_id`
//!   (`SIGN_CONTEXT_V2`); the verifier rejects a v2 token presented at the
//!   wrong relay, closing the cross-replica replay vector described above.
//!
//! ## Per-sender quota key (audit A6 — resolved)
//!
//! The per-sender byte quota (`TABLE_SENDER_BYTES`) is charged against the
//! `sender` argument passed to [`crate::Mailbox::put_with_capability`], NOT
//! against the wire-supplied, unauthenticated `MailboxPutPayload.sender_id`
//! hint. On the network-facing deposit path the runtime passes the
//! **authenticated OVL1 session source** (`src_node_id`, bound by the
//! handshake) as that argument — so an attacker can neither rotate a claimed
//! `sender_id` to evade their own quota slice nor spoof a victim's id to
//! exhaust theirs (see `veil-node-runtime` `builtin::mailbox::handle_put_message`
//! and commit "mailbox per-sender quota keyed on authenticated src_node_id").
//!
//! The original proposal was a separate explicit `quota_key` parameter
//! (distinct from the logical sender) threaded through the put methods; it is
//! intentionally NOT implemented, because using the authenticated source as
//! `sender` is strictly safer than storing the spoofable hint, and the
//! local-IPC deposit path has no authenticated per-deposit identity distinct
//! from the (already-trusted, UID+token-gated) local app to charge against.
//!
//! ## Wire format
//!
//! ```text
//! [0] version: u8 = 1
//! [1] issuer_algo: u8 — 0 = Ed25519, 1 = Falcon-512
//! [2..10] valid_from_unix: u64 BE
//! [10..18] valid_until_unix: u64 BE
//! [18..20] issuer_pk_len: u16 BE
//! [20..20+pk_len] issuer_pk
//! [20+pk_len..+2] sig_len: u16 BE
//! [22+pk_len..] sig
//! ```
//!
//! Signed bytes (the message that `sig` is a signature):
//!
//! ```text
//! b"veil:v1:mailbox-cap"
//! || version (1 B)
//! || issuer_algo (1 B)
//! || valid_from_unix (8 B BE)
//! || valid_until_unix (8 B BE)
//! || issuer_pk (raw bytes)
//! ```
//!
//! Note: `receiver_id` is NOT signed. Relay computes
//! `BLAKE3(issuer_pk)` and checks equality with the `MailboxPutPayload.receiver_id`
//! field. Token is reusable across all replicas of the same receiver
//! while it remains within its time window.

use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, VerificationError};

/// Wire-format version byte for **v1 (unbound)** capability tokens.
/// V1 tokens may be presented to ANY of the receiver's mailbox replicas;
/// a malicious relay observing a v1 PUT can replay the token to other
/// replicas. Kept readable for backward compat (existing senders).
pub const TOKEN_VERSION: u8 = 1;

/// Wire-format version byte for **v2 (relay-bound)** capability tokens.
/// V2 adds a `relay_node_id` field signed by the issuer; relay verifies
/// `expected_relay_id == token.relay_node_id` before accepting. Closes
/// the cross-replica replay vector. Receivers mint one token per replica
/// they want senders to use.
pub const TOKEN_VERSION_V2: u8 = 2;

/// Algorithm byte `0` = Ed25519 (32-byte pubkey, 64-byte sig).
pub const ALGO_ED25519: u8 = 0;
/// Algorithm byte `1` = Falcon-512 (897-byte pubkey, ≤666-byte sig).
pub const ALGO_FALCON512: u8 = 1;

/// Domain-separation tag for the **v1** signed message. Distinct from any
/// other signing context in the project so a signature minted under another
/// purpose (identity proof, rendezvous ad, etc.) cannot be replayed here.
pub const SIGN_CONTEXT: &[u8] = b"veil:v1:mailbox-cap";

/// Domain-separation tag for the **v2** signed message. Distinct from
/// [`SIGN_CONTEXT`] so a v1 token bytes cannot be reinterpreted as v2 OR
/// vice-versa even at byte-level overlap.
pub const SIGN_CONTEXT_V2: &[u8] = b"veil:v2:mailbox-cap-bound";

/// Maximum total token size on the wire. Falcon-512 worst case:
/// 22 fixed-header B + 897 pk B + 666 sig B + slack ≈ 1600 B. 2 KiB
/// keeps headroom for a future algo with ~1 KiB pubkey. Bounded to prevent
/// pathological-size deserialisation attacks.
pub const MAX_TOKEN_BYTES: usize = 2048;

/// Header size before the variable-length pubkey for **v1**: ver(1) +
/// algo(1) + from(8) + until(8) + pk_len(2) = 20 B.
const FIXED_HEADER_SIZE: usize = 1 + 1 + 8 + 8 + 2;

/// Header size before the variable-length pubkey for **v2**: v1 header
/// + relay_node_id(32) = 52 B.
const FIXED_HEADER_SIZE_V2: usize = FIXED_HEADER_SIZE + 32;

/// Allowed clock skew between sender and relay for the time-window
/// check.
///
/// **Interactive tier** (60 s) — central policy in
/// `veil-proto::time_validity::INTERACTIVE_SKEW_SECS`.  Cannot import
/// directly (veil-mailbox is leaf, no veil-proto dep) so the
/// constant is duplicated.  **Pinned by the `interactive_tier_is_60_seconds`
/// test in `veil-proto::time_validity`** — that test fails if a
/// future refactor flips the central tier without updating this site.
///
/// Why this tier: stops the most common cause of legitimate-token
/// rejection (NTP drift in low-end mobile clients).
pub const SKEW_SECS: u64 = 60;

/// Decoded capability token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxCapabilityToken {
    /// Either [`TOKEN_VERSION`] (v1, unbound) or [`TOKEN_VERSION_V2`]
    /// (v2, relay-bound).
    pub version: u8,
    /// One [`ALGO_ED25519`] / [`ALGO_FALCON512`].
    pub issuer_algo: u8,
    /// Unix-seconds; relay rejects tokens with `now + SKEW_SECS < valid_from`.
    pub valid_from_unix: u64,
    /// Unix-seconds; relay rejects tokens with `now > valid_until + SKEW_SECS`.
    pub valid_until_unix: u64,
    /// **v2 only**: the receiver-chosen relay node_id this token is valid
    /// at. `None` for v1 (unbound) tokens; `Some(...)` for v2 (relay-bound).
    /// Verifier rejects v2 tokens whose `relay_node_id` doesn't match the
    /// local relay's own node_id — closes the cross-replica replay vector.
    pub relay_node_id: Option<[u8; 32]>,
    /// Raw issuer public key bytes. Length depends on `issuer_algo`.
    pub issuer_pk: Vec<u8>,
    /// Detached signature over [`signed_message_for`] using `issuer_pk`.
    pub sig: Vec<u8>,
}

/// Errors from token decode + verify.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapTokenError {
    /// Buffer ended before the fixed-header / pubkey / sig section
    /// could be read.
    #[error("token bytes too short: need {need}, got {got}")]
    TooShort {
        /// Bytes required to continue parsing.
        need: usize,
        /// Bytes actually present.
        got: usize,
    },
    /// Buffer length exceeds [`MAX_TOKEN_BYTES`] — almost certainly
    /// an attacker probing the parser with oversized inputs.
    #[error("token bytes too long: max {max}, got {got}")]
    TooLong {
        /// Cap that was violated.
        max: usize,
        /// Actual buffer length.
        got: usize,
    },
    /// First byte is not [`TOKEN_VERSION`] (1) or [`TOKEN_VERSION_V2`] (2).
    #[error("unsupported wire version: {version}")]
    BadVersion {
        /// Version byte read off the wire.
        version: u8,
    },
    /// v2 token's `relay_node_id` does not match the expected relay id
    /// the verifier was told to check. Either the token was minted for a
    /// different replica (malicious relay replay scenario) or the
    /// verifier was misconfigured.
    #[error("v2 relay-binding mismatch: token={token_hex}.. expected={expected_hex}..")]
    RelayMismatch {
        /// First 8 bytes of token's `relay_node_id`, hex-encoded.
        token_hex: String,
        /// First 8 bytes of expected relay node_id, hex-encoded.
        expected_hex: String,
    },
    /// v2 token presented but verifier wasn't given an `expected_relay_id`.
    /// Inconsistent caller state — either upgrade the caller to pass its
    /// node_id or downgrade to v1 tokens.
    #[error("v2 token requires expected_relay_id at verify but caller passed None")]
    RelayBindingRequired,
    /// `issuer_algo` byte not one of the known values
    /// [`ALGO_ED25519`] / [`ALGO_FALCON512`].
    #[error("unsupported algo byte: {algo}")]
    BadAlgo {
        /// Algo byte read off the wire.
        algo: u8,
    },
    /// `issuer_pk_len` does not match the size required by the
    /// declared algo (Ed25519 = 32 B, Falcon-512 = 897 B).
    #[error("issuer_pk length {got} mismatches algo {algo} expected {expected}")]
    BadPubkeyLen {
        /// Declared algo.
        algo: u8,
        /// Required pubkey bytes for that algo.
        expected: usize,
        /// `issuer_pk_len` read off the wire.
        got: usize,
    },
    /// Wire shape is internally inconsistent (e.g.
    /// `valid_from > valid_until`).
    #[error("malformed wire: {reason}")]
    Malformed {
        /// Specific malformedness reason.
        reason: &'static str,
    },
    /// `now + SKEW_SECS < valid_from_unix`.
    #[error("token not yet valid: now={now} < valid_from={valid_from}")]
    NotYetValid {
        /// Caller-supplied current unix time.
        now: u64,
        /// Token's `valid_from_unix`.
        valid_from: u64,
    },
    /// `now > valid_until_unix + SKEW_SECS`.
    #[error("token expired: now={now} > valid_until={valid_until}")]
    Expired {
        /// Caller-supplied current unix time.
        now: u64,
        /// Token's `valid_until_unix`.
        valid_until: u64,
    },
    /// `BLAKE3(issuer_pk)!= expected_receiver_id`. Token was minted
    /// for a different receiver — sender either misrouted either replayed
    /// a stolen token to a wrong target.
    #[error("issuer_pk does not hash to expected receiver_id")]
    ReceiverIdMismatch,
    /// Cryptographic signature verification failed. Folds in both
    /// "unparseable signature bytes" and "valid bytes but mismatched key"
    /// to avoid leaking distinguishability to a probing attacker.
    #[error("signature verification failed")]
    BadSignature,
}

impl MailboxCapabilityToken {
    /// Build the canonical signed-message bytes. The signer signs these
    /// the verifier reconstructs the same bytes from the decoded token
    /// fields and checks the signature against `issuer_pk`.
    pub fn signed_message(&self) -> Vec<u8> {
        signed_message_for_versioned(
            self.version,
            self.issuer_algo,
            self.valid_from_unix,
            self.valid_until_unix,
            self.relay_node_id.as_ref(),
            &self.issuer_pk,
        )
    }

    /// Encode to wire bytes. Caller must ensure `issuer_pk` and `sig`
    /// match the algo's expected sizes; encode does not validate (decode
    /// does).
    pub fn encode(&self) -> Vec<u8> {
        let pk_len = self.issuer_pk.len();
        let sig_len = self.sig.len();
        let header_size = match self.version {
            TOKEN_VERSION_V2 => FIXED_HEADER_SIZE_V2,
            _ => FIXED_HEADER_SIZE,
        };
        let mut buf = Vec::with_capacity(header_size + pk_len + 2 + sig_len);
        buf.push(self.version);
        buf.push(self.issuer_algo);
        buf.extend_from_slice(&self.valid_from_unix.to_be_bytes());
        buf.extend_from_slice(&self.valid_until_unix.to_be_bytes());
        // v2 only: relay_node_id slot.  If version==2 the field MUST be
        // Some — encode without value would corrupt downstream sig offset
        // verification.  v1 skips this entirely.
        if self.version == TOKEN_VERSION_V2
            && let Some(relay_id) = &self.relay_node_id
        {
            buf.extend_from_slice(relay_id);
        }
        buf.extend_from_slice(&(pk_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.issuer_pk);
        buf.extend_from_slice(&(sig_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.sig);
        buf
    }

    /// Decode wire bytes to a structured token. Validates wire shape
    /// and known algo; does NOT verify signature or time-window — call
    /// [`Self::verify`] for the full check.
    pub fn decode(buf: &[u8]) -> Result<Self, CapTokenError> {
        if buf.len() > MAX_TOKEN_BYTES {
            return Err(CapTokenError::TooLong {
                max: MAX_TOKEN_BYTES,
                got: buf.len(),
            });
        }
        if buf.len() < FIXED_HEADER_SIZE {
            return Err(CapTokenError::TooShort {
                need: FIXED_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let version = buf[0];
        let (header_size, relay_node_id) = match version {
            TOKEN_VERSION => (FIXED_HEADER_SIZE, None),
            TOKEN_VERSION_V2 => {
                if buf.len() < FIXED_HEADER_SIZE_V2 {
                    return Err(CapTokenError::TooShort {
                        need: FIXED_HEADER_SIZE_V2,
                        got: buf.len(),
                    });
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&buf[18..50]);
                (FIXED_HEADER_SIZE_V2, Some(id))
            }
            _ => return Err(CapTokenError::BadVersion { version }),
        };
        let issuer_algo = buf[1];
        let valid_from_unix = u64::from_be_bytes(buf[2..10].try_into().unwrap());
        let valid_until_unix = u64::from_be_bytes(buf[10..18].try_into().unwrap());
        if valid_from_unix > valid_until_unix {
            return Err(CapTokenError::Malformed {
                reason: "valid_from_unix > valid_until_unix",
            });
        }
        // pk_len byte offset depends on version: v1 at [18..20], v2 at [50..52].
        let pk_len_offset = header_size - 2;
        let pk_len =
            u16::from_be_bytes(buf[pk_len_offset..pk_len_offset + 2].try_into().unwrap()) as usize;
        let pk_end = header_size
            .checked_add(pk_len)
            .ok_or(CapTokenError::Malformed {
                reason: "issuer_pk_len overflow",
            })?;
        if buf.len() < pk_end + 2 {
            return Err(CapTokenError::TooShort {
                need: pk_end + 2,
                got: buf.len(),
            });
        }
        // validate algo + pk_len consistency at decode time.
        // Catches malformed wire early before signature attempts.
        match issuer_algo {
            ALGO_ED25519 => {
                if pk_len != 32 {
                    return Err(CapTokenError::BadPubkeyLen {
                        algo: issuer_algo,
                        expected: 32,
                        got: pk_len,
                    });
                }
            }
            ALGO_FALCON512 => {
                if pk_len != falcon512::public_key_bytes() {
                    return Err(CapTokenError::BadPubkeyLen {
                        algo: issuer_algo,
                        expected: falcon512::public_key_bytes(),
                        got: pk_len,
                    });
                }
            }
            other => return Err(CapTokenError::BadAlgo { algo: other }),
        }
        let issuer_pk = buf[header_size..pk_end].to_vec();
        let sig_len = u16::from_be_bytes(buf[pk_end..pk_end + 2].try_into().unwrap()) as usize;
        let sig_end = pk_end + 2 + sig_len;
        if buf.len() < sig_end {
            return Err(CapTokenError::TooShort {
                need: sig_end,
                got: buf.len(),
            });
        }
        let sig = buf[pk_end + 2..sig_end].to_vec();
        Ok(Self {
            version,
            issuer_algo,
            valid_from_unix,
            valid_until_unix,
            relay_node_id,
            issuer_pk,
            sig,
        })
    }

    /// Verify a decoded token against an expected receiver and a point in
    /// time. Combines: time-window check, receiver-id binding,
    /// **relay binding** (v2 only) and signature verification.
    ///
    /// `expected_relay_id` semantics:
    /// * `Some(local)` + v1 token → relay-binding ignored (backward compat).
    /// * `Some(local)` + v2 token → must match `token.relay_node_id`.
    /// * `None` + v1 token → OK.
    /// * `None` + v2 token → reject ([`CapTokenError::RelayBindingRequired`]):
    ///   token requests relay-binding but caller didn't supply local id.
    pub fn verify(
        &self,
        expected_receiver_id: &[u8; 32],
        expected_relay_id: Option<&[u8; 32]>,
        now_unix: u64,
    ) -> Result<(), CapTokenError> {
        // Time window — apply skew tolerance both ways.
        if now_unix + SKEW_SECS < self.valid_from_unix {
            return Err(CapTokenError::NotYetValid {
                now: now_unix,
                valid_from: self.valid_from_unix,
            });
        }
        if now_unix > self.valid_until_unix.saturating_add(SKEW_SECS) {
            return Err(CapTokenError::Expired {
                now: now_unix,
                valid_until: self.valid_until_unix,
            });
        }
        // Receiver binding: issuer_pk MUST hash to the receiver_id the
        // sender's PUT claims to target.
        let computed_receiver_id = *blake3::hash(&self.issuer_pk).as_bytes();
        if &computed_receiver_id != expected_receiver_id {
            return Err(CapTokenError::ReceiverIdMismatch);
        }
        // Relay binding (v2): if token claims a bound relay, verifier MUST
        // be told its own node_id and that id MUST match. Closes the
        // malicious-relay-replay vector where R captures a valid token
        // observed during legitimate deposit and replays it to other replicas.
        match (self.relay_node_id.as_ref(), expected_relay_id) {
            (Some(token_relay), Some(local_relay)) if token_relay != local_relay => {
                return Err(CapTokenError::RelayMismatch {
                    token_hex: hex_short(token_relay),
                    expected_hex: hex_short(local_relay),
                });
            }
            (Some(_), None) => return Err(CapTokenError::RelayBindingRequired),
            // (Some, Some) matching, or (None, _) — accept (v1 unbound or
            // v2 bound with matching local id).
            _ => {}
        }
        // Signature verify.
        let msg = self.signed_message();
        match self.issuer_algo {
            ALGO_ED25519 => verify_ed25519(&self.issuer_pk, &msg, &self.sig),
            ALGO_FALCON512 => verify_falcon512(&self.issuer_pk, &msg, &self.sig),
            other => Err(CapTokenError::BadAlgo { algo: other }),
        }
    }

    /// **Mint helper (v1, unbound)**: high-level convenience wrapper over
    /// [`sign_token`] for Ed25519 receivers. Returns the encoded token
    /// bytes ready to publish in `RendezvousAd.capability_token`.
    pub fn mint_unbound_ed25519(
        signing_key: &ed25519_dalek::SigningKey,
        valid_from_unix: u64,
        valid_until_unix: u64,
    ) -> Result<Vec<u8>, CapTokenError> {
        use ed25519_dalek::Signer;
        let issuer_pk = signing_key.verifying_key().to_bytes();
        sign_token(
            ALGO_ED25519,
            &issuer_pk,
            valid_from_unix,
            valid_until_unix,
            |msg| signing_key.sign(msg).to_bytes().to_vec(),
        )
    }

    /// **Mint helper (v2, relay-bound)**: high-level convenience wrapper
    /// over [`sign_token_v2`] for Ed25519 receivers. `relay_node_id` is
    /// the specific replica node_id this token authorises deposit to —
    /// receivers mint one token per replica and publish the full list in
    /// `RendezvousAd`.
    pub fn mint_bound_ed25519(
        signing_key: &ed25519_dalek::SigningKey,
        relay_node_id: [u8; 32],
        valid_from_unix: u64,
        valid_until_unix: u64,
    ) -> Result<Vec<u8>, CapTokenError> {
        use ed25519_dalek::Signer;
        let issuer_pk = signing_key.verifying_key().to_bytes();
        sign_token_v2(
            ALGO_ED25519,
            &issuer_pk,
            relay_node_id,
            valid_from_unix,
            valid_until_unix,
            |msg| signing_key.sign(msg).to_bytes().to_vec(),
        )
    }
}

/// Short hex (8 bytes / 16 chars) for log messages.
fn hex_short(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for byte in &b[..8] {
        use std::fmt::Write as _;
        let _ = write!(s, "{:02x}", byte);
    }
    s
}

/// mint a capability token by composing
/// the canonical signed-message and delegating signing to a caller-supplied
/// closure. Returns the encoded token wire bytes ready to stash in
/// `RendezvousAd.capability_token`.
///
/// The closure pattern keeps `veil-mailbox` from needing a dep on
/// `veil-crypto` (which would pull in the full PQ stack for what is
/// functionally a 1-line `vk.sign(msg)` call). Callers that already
/// have an `veil_crypto::sign_message` or `IdentitySigningKey::sign`
/// in scope just wrap it.
///
/// `issuer_algo` must be one [`ALGO_ED25519`] / [`ALGO_FALCON512`].
/// Hybrid sigs are not supported in; pass a tokenless ad if the
/// receiver uses a hybrid identity.
pub fn sign_token(
    issuer_algo: u8,
    issuer_pk: &[u8],
    valid_from_unix: u64,
    valid_until_unix: u64,
    sign_fn: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>, CapTokenError> {
    let expected_pk_len = match issuer_algo {
        ALGO_ED25519 => 32,
        ALGO_FALCON512 => falcon512::public_key_bytes(),
        other => return Err(CapTokenError::BadAlgo { algo: other }),
    };
    if issuer_pk.len() != expected_pk_len {
        return Err(CapTokenError::BadPubkeyLen {
            algo: issuer_algo,
            expected: expected_pk_len,
            got: issuer_pk.len(),
        });
    }
    if valid_from_unix > valid_until_unix {
        return Err(CapTokenError::Malformed {
            reason: "valid_from_unix > valid_until_unix",
        });
    }
    let msg = signed_message_for(
        TOKEN_VERSION,
        issuer_algo,
        valid_from_unix,
        valid_until_unix,
        issuer_pk,
    );
    let sig = sign_fn(&msg);
    let token = MailboxCapabilityToken {
        version: TOKEN_VERSION,
        issuer_algo,
        valid_from_unix,
        valid_until_unix,
        relay_node_id: None,
        issuer_pk: issuer_pk.to_vec(),
        sig,
    };
    let bytes = token.encode();
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(CapTokenError::TooLong {
            max: MAX_TOKEN_BYTES,
            got: bytes.len(),
        });
    }
    Ok(bytes)
}

/// **v2 (relay-bound)** variant of [`sign_token`]. Token includes the
/// receiver-chosen `relay_node_id`; only that replica accepts the token.
/// Same closure-signing pattern as v1 so callers stay decoupled from
/// crypto-stack details.
pub fn sign_token_v2(
    issuer_algo: u8,
    issuer_pk: &[u8],
    relay_node_id: [u8; 32],
    valid_from_unix: u64,
    valid_until_unix: u64,
    sign_fn: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>, CapTokenError> {
    let expected_pk_len = match issuer_algo {
        ALGO_ED25519 => 32,
        ALGO_FALCON512 => falcon512::public_key_bytes(),
        other => return Err(CapTokenError::BadAlgo { algo: other }),
    };
    if issuer_pk.len() != expected_pk_len {
        return Err(CapTokenError::BadPubkeyLen {
            algo: issuer_algo,
            expected: expected_pk_len,
            got: issuer_pk.len(),
        });
    }
    if valid_from_unix > valid_until_unix {
        return Err(CapTokenError::Malformed {
            reason: "valid_from_unix > valid_until_unix",
        });
    }
    let msg = signed_message_for_versioned(
        TOKEN_VERSION_V2,
        issuer_algo,
        valid_from_unix,
        valid_until_unix,
        Some(&relay_node_id),
        issuer_pk,
    );
    let sig = sign_fn(&msg);
    let token = MailboxCapabilityToken {
        version: TOKEN_VERSION_V2,
        issuer_algo,
        valid_from_unix,
        valid_until_unix,
        relay_node_id: Some(relay_node_id),
        issuer_pk: issuer_pk.to_vec(),
        sig,
    };
    let bytes = token.encode();
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(CapTokenError::TooLong {
            max: MAX_TOKEN_BYTES,
            got: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Build canonical signed-message bytes, version-aware. Picks
/// [`SIGN_CONTEXT_V2`] for v2 tokens (different domain so v1↔v2 byte
/// overlap can't enable cross-version replay), else [`SIGN_CONTEXT`].
pub fn signed_message_for_versioned(
    version: u8,
    issuer_algo: u8,
    valid_from_unix: u64,
    valid_until_unix: u64,
    relay_node_id: Option<&[u8; 32]>,
    issuer_pk: &[u8],
) -> Vec<u8> {
    let context: &[u8] = if version == TOKEN_VERSION_V2 {
        SIGN_CONTEXT_V2
    } else {
        SIGN_CONTEXT
    };
    let mut msg = Vec::with_capacity(context.len() + 64 + issuer_pk.len());
    msg.extend_from_slice(context);
    msg.push(version);
    msg.push(issuer_algo);
    msg.extend_from_slice(&valid_from_unix.to_be_bytes());
    msg.extend_from_slice(&valid_until_unix.to_be_bytes());
    if version == TOKEN_VERSION_V2
        && let Some(rid) = relay_node_id
    {
        msg.extend_from_slice(rid);
    }
    msg.extend_from_slice(issuer_pk);
    msg
}

/// Build the canonical signed-message bytes without a decoded token —
/// used by signers who construct the token field-by-field.
pub fn signed_message_for(
    version: u8,
    issuer_algo: u8,
    valid_from_unix: u64,
    valid_until_unix: u64,
    issuer_pk: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGN_CONTEXT.len() + FIXED_HEADER_SIZE + issuer_pk.len());
    msg.extend_from_slice(SIGN_CONTEXT);
    msg.push(version);
    msg.push(issuer_algo);
    msg.extend_from_slice(&valid_from_unix.to_be_bytes());
    msg.extend_from_slice(&valid_until_unix.to_be_bytes());
    msg.extend_from_slice(issuer_pk);
    msg
}

fn verify_ed25519(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CapTokenError> {
    let pk_arr: &[u8; 32] = pk.try_into().map_err(|_| CapTokenError::BadPubkeyLen {
        algo: ALGO_ED25519,
        expected: 32,
        got: pk.len(),
    })?;
    let vk = VerifyingKey::from_bytes(pk_arr).map_err(|_| CapTokenError::BadSignature)?;
    let sig = Ed25519Signature::from_slice(sig).map_err(|_| CapTokenError::BadSignature)?;
    vk.verify(msg, &sig)
        .map_err(|_| CapTokenError::BadSignature)
}

fn verify_falcon512(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CapTokenError> {
    let pk = falcon512::PublicKey::from_bytes(pk).map_err(|_| CapTokenError::BadSignature)?;
    let sig =
        falcon512::DetachedSignature::from_bytes(sig).map_err(|_| CapTokenError::BadSignature)?;
    falcon512::verify_detached_signature(&sig, msg, &pk)
        .map_err(|_: VerificationError| CapTokenError::BadSignature)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pqcrypto_traits::sign::SecretKey as _;

    /// Mint a valid Ed25519 token signed by a freshly-generated key.
    /// Returns the issuer's public key bytes (so test code can derive
    /// the expected receiver_id) and the encoded token bytes.
    fn mint_ed25519_token(
        valid_from_unix: u64,
        valid_until_unix: u64,
    ) -> (Vec<u8>, MailboxCapabilityToken) {
        let mut seed = [0u8; 32];
        seed[0] = 0x42;
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let msg = signed_message_for(
            TOKEN_VERSION,
            ALGO_ED25519,
            valid_from_unix,
            valid_until_unix,
            &pk,
        );
        let sig = sk.sign(&msg).to_bytes().to_vec();
        let token = MailboxCapabilityToken {
            version: TOKEN_VERSION,
            issuer_algo: ALGO_ED25519,
            valid_from_unix,
            valid_until_unix,
            relay_node_id: None,
            issuer_pk: pk.clone(),
            sig,
        };
        (pk, token)
    }

    fn mint_falcon512_token(
        valid_from_unix: u64,
        valid_until_unix: u64,
    ) -> (Vec<u8>, MailboxCapabilityToken) {
        let (pk, sk) = falcon512::keypair();
        let pk_bytes = pk.as_bytes().to_vec();
        let msg = signed_message_for(
            TOKEN_VERSION,
            ALGO_FALCON512,
            valid_from_unix,
            valid_until_unix,
            &pk_bytes,
        );
        let sig = falcon512::detached_sign(&msg, &sk);
        // Force-pad/truncate the SK on stack as in identity::signing_key.
        let _: &[u8] = sk.as_bytes();
        let token = MailboxCapabilityToken {
            version: TOKEN_VERSION,
            issuer_algo: ALGO_FALCON512,
            valid_from_unix,
            valid_until_unix,
            relay_node_id: None,
            issuer_pk: pk_bytes.clone(),
            sig: <falcon512::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::as_bytes(&sig).to_vec(),
        };
        (pk_bytes, token)
    }

    fn receiver_id_of(pk: &[u8]) -> [u8; 32] {
        *blake3::hash(pk).as_bytes()
    }

    #[test]
    fn encode_decode_roundtrip_ed25519() {
        let (_, token) = mint_ed25519_token(1000, 2000);
        let bytes = token.encode();
        let decoded = MailboxCapabilityToken::decode(&bytes).expect("decode");
        assert_eq!(token, decoded);
    }

    #[test]
    fn encode_decode_roundtrip_falcon512() {
        let (_, token) = mint_falcon512_token(1000, 2000);
        let bytes = token.encode();
        assert!(bytes.len() <= MAX_TOKEN_BYTES, "falcon token must fit");
        let decoded = MailboxCapabilityToken::decode(&bytes).expect("decode");
        assert_eq!(token, decoded);
    }

    #[test]
    fn verify_ed25519_happy_path() {
        let (pk, token) = mint_ed25519_token(1000, 2000);
        let rid = receiver_id_of(&pk);
        token.verify(&rid, None, 1500).expect("verify");
    }

    #[test]
    fn verify_falcon512_happy_path() {
        let (pk, token) = mint_falcon512_token(1000, 2000);
        let rid = receiver_id_of(&pk);
        token.verify(&rid, None, 1500).expect("verify");
    }

    #[test]
    fn verify_rejects_expired() {
        let (pk, token) = mint_ed25519_token(1000, 2000);
        let rid = receiver_id_of(&pk);
        let err = token.verify(&rid, None, 2000 + SKEW_SECS + 1).unwrap_err();
        assert!(matches!(err, CapTokenError::Expired { .. }));
    }

    #[test]
    fn verify_accepts_within_skew_after_expiry() {
        // now == valid_until + SKEW_SECS exactly should still accept.
        let (pk, token) = mint_ed25519_token(1000, 2000);
        let rid = receiver_id_of(&pk);
        token
            .verify(&rid, None, 2000 + SKEW_SECS)
            .expect("within skew");
    }

    #[test]
    fn verify_rejects_not_yet_valid() {
        let (pk, token) = mint_ed25519_token(1000, 2000);
        let rid = receiver_id_of(&pk);
        // now + SKEW_SECS < valid_from = 1000 → now < 1000 - SKEW_SECS
        let now = 1000u64.saturating_sub(SKEW_SECS).saturating_sub(1);
        let err = token.verify(&rid, None, now).unwrap_err();
        assert!(matches!(err, CapTokenError::NotYetValid { .. }));
    }

    #[test]
    fn verify_accepts_within_skew_before_valid_from() {
        let (pk, token) = mint_ed25519_token(1000, 2000);
        let rid = receiver_id_of(&pk);
        // now = valid_from - SKEW_SECS → just inside skew window.
        token
            .verify(&rid, None, 1000 - SKEW_SECS)
            .expect("within skew");
    }

    #[test]
    fn verify_rejects_wrong_receiver_id() {
        let (_, token) = mint_ed25519_token(1000, 2000);
        let rogue_rid = [0xAAu8; 32];
        let err = token.verify(&rogue_rid, None, 1500).unwrap_err();
        assert_eq!(err, CapTokenError::ReceiverIdMismatch);
    }

    #[test]
    fn verify_rejects_corrupted_signature() {
        let (pk, mut token) = mint_ed25519_token(1000, 2000);
        token.sig[0] ^= 0xFF;
        let rid = receiver_id_of(&pk);
        let err = token.verify(&rid, None, 1500).unwrap_err();
        assert_eq!(err, CapTokenError::BadSignature);
    }

    #[test]
    fn verify_rejects_signature_over_different_validity_window() {
        // Take a valid token, change valid_until, and keep the old sig:
        // verify must fail because the signed bytes no longer match.
        let (pk, mut token) = mint_ed25519_token(1000, 2000);
        token.valid_until_unix = 5000;
        let rid = receiver_id_of(&pk);
        let err = token.verify(&rid, None, 1500).unwrap_err();
        assert_eq!(err, CapTokenError::BadSignature);
    }

    #[test]
    fn decode_rejects_too_short() {
        let buf = vec![0u8; FIXED_HEADER_SIZE - 1];
        let err = MailboxCapabilityToken::decode(&buf).unwrap_err();
        assert!(matches!(err, CapTokenError::TooShort { .. }));
    }

    #[test]
    fn decode_rejects_too_long() {
        let buf = vec![0u8; MAX_TOKEN_BYTES + 1];
        let err = MailboxCapabilityToken::decode(&buf).unwrap_err();
        assert!(matches!(err, CapTokenError::TooLong { .. }));
    }

    #[test]
    fn decode_rejects_bad_version() {
        let (_, token) = mint_ed25519_token(1000, 2000);
        let mut bytes = token.encode();
        bytes[0] = 99;
        let err = MailboxCapabilityToken::decode(&bytes).unwrap_err();
        assert!(matches!(err, CapTokenError::BadVersion { .. }));
    }

    #[test]
    fn decode_rejects_bad_algo() {
        let (_, token) = mint_ed25519_token(1000, 2000);
        let mut bytes = token.encode();
        bytes[1] = 99;
        let err = MailboxCapabilityToken::decode(&bytes).unwrap_err();
        assert!(matches!(err, CapTokenError::BadAlgo { .. }));
    }

    #[test]
    fn decode_rejects_swapped_validity_window() {
        let (_, mut token) = mint_ed25519_token(1000, 2000);
        std::mem::swap(&mut token.valid_from_unix, &mut token.valid_until_unix);
        let bytes = token.encode();
        let err = MailboxCapabilityToken::decode(&bytes).unwrap_err();
        assert!(matches!(err, CapTokenError::Malformed { .. }));
    }

    #[test]
    fn decode_rejects_pk_len_mismatch_for_ed25519() {
        let (_, token) = mint_ed25519_token(1000, 2000);
        // Corrupt pk_len bytes to something other than 32.
        let mut bytes = token.encode();
        bytes[18] = 0;
        bytes[19] = 99; // pk_len = 99, not 32 → must reject for Ed25519.
        // Need to also extend pk and sig regions to keep buffer at the
        // declared length so we hit the algo-vs-len validator not the
        // length-buffer check.
        let extra = 99usize.saturating_sub(32);
        for _ in 0..extra {
            bytes.insert(FIXED_HEADER_SIZE, 0);
        }
        let err = MailboxCapabilityToken::decode(&bytes).unwrap_err();
        assert!(matches!(err, CapTokenError::BadPubkeyLen { algo: 0, .. }));
    }

    #[test]
    fn signed_message_is_deterministic() {
        let m1 = signed_message_for(1, 0, 1000, 2000, b"pk-bytes-here");
        let m2 = signed_message_for(1, 0, 1000, 2000, b"pk-bytes-here");
        assert_eq!(m1, m2);
    }

    #[test]
    fn sign_token_roundtrip_ed25519() {
        let mut seed = [0u8; 32];
        seed[0] = 0x99;
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let bytes = sign_token(ALGO_ED25519, &pk, 1000, 2000, |msg| {
            sk.sign(msg).to_bytes().to_vec()
        })
        .expect("sign_token");
        let decoded = MailboxCapabilityToken::decode(&bytes).expect("decode");
        let receiver_id = receiver_id_of(&pk);
        decoded
            .verify(&receiver_id, None, 1500)
            .expect("verify minted token");
    }

    #[test]
    fn sign_token_roundtrip_falcon512() {
        let (pk, sk) = falcon512::keypair();
        let pk_bytes = pk.as_bytes().to_vec();
        let bytes = sign_token(ALGO_FALCON512, &pk_bytes, 1000, 2000, |msg| {
            <falcon512::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::as_bytes(
                &falcon512::detached_sign(msg, &sk),
            )
            .to_vec()
        })
        .expect("sign_token falcon");
        let decoded = MailboxCapabilityToken::decode(&bytes).expect("decode");
        let receiver_id = receiver_id_of(&pk_bytes);
        decoded
            .verify(&receiver_id, None, 1500)
            .expect("verify minted falcon token");
    }

    #[test]
    fn sign_token_rejects_bad_algo() {
        let pk = vec![0u8; 32];
        let err = sign_token(99, &pk, 1000, 2000, |_| vec![]).unwrap_err();
        assert!(matches!(err, CapTokenError::BadAlgo { algo: 99 }));
    }

    #[test]
    fn sign_token_rejects_bad_pubkey_len() {
        let pk = vec![0u8; 16]; // Ed25519 expects 32.
        let err = sign_token(ALGO_ED25519, &pk, 1000, 2000, |_| vec![]).unwrap_err();
        assert!(matches!(
            err,
            CapTokenError::BadPubkeyLen {
                algo: 0,
                expected: 32,
                got: 16
            }
        ));
    }

    #[test]
    fn sign_token_rejects_inverted_validity() {
        let pk = vec![0u8; 32];
        let err = sign_token(ALGO_ED25519, &pk, 2000, 1000, |_| vec![0; 64]).unwrap_err();
        assert!(matches!(err, CapTokenError::Malformed { .. }));
    }

    #[test]
    fn signed_message_changes_on_any_field() {
        let base = signed_message_for(1, 0, 1000, 2000, b"pk");
        assert_ne!(base, signed_message_for(2, 0, 1000, 2000, b"pk"));
        assert_ne!(base, signed_message_for(1, 1, 1000, 2000, b"pk"));
        assert_ne!(base, signed_message_for(1, 0, 1001, 2000, b"pk"));
        assert_ne!(base, signed_message_for(1, 0, 1000, 2001, b"pk"));
        assert_ne!(base, signed_message_for(1, 0, 1000, 2000, b"qk"));
    }

    // ────────────────────────────── v2 (relay-bound) ──────────────────────────

    fn signing_key(seed_byte: u8) -> SigningKey {
        let mut seed = [0u8; 32];
        seed[0] = seed_byte;
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn v2_mint_unbound_helper_decodes_as_v1() {
        let sk = signing_key(0x11);
        let bytes = MailboxCapabilityToken::mint_unbound_ed25519(&sk, 1000, 2000)
            .expect("mint_unbound_ed25519");
        let decoded = MailboxCapabilityToken::decode(&bytes).expect("decode");
        assert_eq!(decoded.version, TOKEN_VERSION);
        assert!(decoded.relay_node_id.is_none());
        let rid = receiver_id_of(&decoded.issuer_pk);
        decoded
            .verify(&rid, None, 1500)
            .expect("v1 unbound verifies w/o expected_relay_id");
        decoded
            .verify(&rid, Some(&[0xAB; 32]), 1500)
            .expect("v1 unbound ignores expected_relay_id");
    }

    #[test]
    fn v2_mint_bound_roundtrip_and_verify() {
        let sk = signing_key(0x22);
        let relay = [0xCDu8; 32];
        let bytes = MailboxCapabilityToken::mint_bound_ed25519(&sk, relay, 1000, 2000)
            .expect("mint_bound_ed25519");
        let decoded = MailboxCapabilityToken::decode(&bytes).expect("decode");
        assert_eq!(decoded.version, TOKEN_VERSION_V2);
        assert_eq!(decoded.relay_node_id, Some(relay));
        let rid = receiver_id_of(&decoded.issuer_pk);
        decoded
            .verify(&rid, Some(&relay), 1500)
            .expect("v2 bound verifies with matching expected_relay_id");
    }

    #[test]
    fn v2_bound_token_rejects_cross_relay_replay() {
        let sk = signing_key(0x33);
        let issuer_relay = [0x10u8; 32];
        let other_relay = [0x20u8; 32];
        let bytes =
            MailboxCapabilityToken::mint_bound_ed25519(&sk, issuer_relay, 1000, 2000).unwrap();
        let decoded = MailboxCapabilityToken::decode(&bytes).unwrap();
        let rid = receiver_id_of(&decoded.issuer_pk);
        let err = decoded.verify(&rid, Some(&other_relay), 1500).unwrap_err();
        assert!(matches!(err, CapTokenError::RelayMismatch { .. }));
    }

    #[test]
    fn v2_bound_token_rejects_when_verifier_has_no_local_id() {
        let sk = signing_key(0x44);
        let relay = [0x77u8; 32];
        let bytes = MailboxCapabilityToken::mint_bound_ed25519(&sk, relay, 1000, 2000).unwrap();
        let decoded = MailboxCapabilityToken::decode(&bytes).unwrap();
        let rid = receiver_id_of(&decoded.issuer_pk);
        let err = decoded.verify(&rid, None, 1500).unwrap_err();
        assert_eq!(err, CapTokenError::RelayBindingRequired);
    }

    #[test]
    fn v2_signed_message_differs_from_v1_for_same_window() {
        // Even with same issuer/algo/window, v2 must produce a different
        // signed message than v1 — domain separation prevents cross-version
        // signature reuse.
        let pk = vec![0u8; 32];
        let relay = [0xEEu8; 32];
        let v1 = signed_message_for(TOKEN_VERSION, ALGO_ED25519, 1000, 2000, &pk);
        let v2 = signed_message_for_versioned(
            TOKEN_VERSION_V2,
            ALGO_ED25519,
            1000,
            2000,
            Some(&relay),
            &pk,
        );
        assert_ne!(v1, v2);
    }

    #[test]
    fn v2_decode_rejects_truncated_header() {
        // Mint a valid v2 token, truncate one byte below v2 header size.
        let sk = signing_key(0x55);
        let bytes =
            MailboxCapabilityToken::mint_bound_ed25519(&sk, [0x01; 32], 1000, 2000).unwrap();
        let truncated = &bytes[..FIXED_HEADER_SIZE_V2 - 1];
        let err = MailboxCapabilityToken::decode(truncated).unwrap_err();
        assert!(matches!(err, CapTokenError::TooShort { .. }));
    }

    #[test]
    fn v2_encoded_size_includes_relay_id() {
        let sk = signing_key(0x66);
        let v1_bytes = MailboxCapabilityToken::mint_unbound_ed25519(&sk, 1000, 2000).unwrap();
        let v2_bytes =
            MailboxCapabilityToken::mint_bound_ed25519(&sk, [0xAB; 32], 1000, 2000).unwrap();
        // v2 wire form carries an extra 32-byte relay_node_id, so it must
        // be exactly 32 bytes larger than v1 (same algo, same pk/sig lens).
        assert_eq!(v2_bytes.len(), v1_bytes.len() + 32);
    }

    #[test]
    fn v2_corrupted_relay_id_breaks_signature() {
        // Flip a byte inside the relay_node_id region of an encoded v2
        // token — decode still succeeds (it's not a structural field)
        // but verify must fail because the signature covered the bound
        // relay_id.
        let sk = signing_key(0x77);
        let relay = [0x42u8; 32];
        let mut bytes = MailboxCapabilityToken::mint_bound_ed25519(&sk, relay, 1000, 2000).unwrap();
        // relay_node_id sits at bytes 18..50 (after the v1 fixed header).
        bytes[18] ^= 0x01;
        let decoded = MailboxCapabilityToken::decode(&bytes).expect("decode still parses");
        let rid = receiver_id_of(&decoded.issuer_pk);
        // The decoded relay_id has the flipped byte; verify w/ that exact id
        // passes the equality check but fails signature verify.
        let local = decoded.relay_node_id.unwrap();
        let err = decoded.verify(&rid, Some(&local), 1500).unwrap_err();
        assert_eq!(err, CapTokenError::BadSignature);
    }

    #[test]
    fn v2_token_signed_with_v1_context_fails_verify() {
        // Construct a v2-shaped token whose signature was made with the
        // v1 SIGN_CONTEXT instead of SIGN_CONTEXT_V2. verify must reject.
        let sk = signing_key(0x88);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let relay = [0x55u8; 32];
        // Forge: sign as if v1 (wrong context) but ship as v2.
        let wrong_msg = signed_message_for(TOKEN_VERSION, ALGO_ED25519, 1000, 2000, &pk);
        let sig = sk.sign(&wrong_msg).to_bytes().to_vec();
        let forged = MailboxCapabilityToken {
            version: TOKEN_VERSION_V2,
            issuer_algo: ALGO_ED25519,
            valid_from_unix: 1000,
            valid_until_unix: 2000,
            relay_node_id: Some(relay),
            issuer_pk: pk.clone(),
            sig,
        };
        let bytes = forged.encode();
        let decoded = MailboxCapabilityToken::decode(&bytes).expect("decode");
        let rid = receiver_id_of(&pk);
        let err = decoded.verify(&rid, Some(&relay), 1500).unwrap_err();
        assert_eq!(err, CapTokenError::BadSignature);
    }
}
