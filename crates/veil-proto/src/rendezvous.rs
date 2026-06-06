//! PoW-gated rendezvous wire frames + primitives — Slice 1 of the
//! PoW-Gated Rendezvous epic ([`docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`]).
//!
//! Two payload types live in this module:
//!
//! * [`RequestEphemeralEndpointPayload`] — initiator's request that
//!   a target node provision an ephemeral listener for one-shot dial.
//!   Carries a PoW proof + Ed25519 signature from the requester.
//! * [`EphemeralEndpointResponsePayload`] — target's signed response
//!   with the freshly-bound URI + per-request PSK + TTL.
//!
//! Domain-separated signatures + PoW canonicalisation prevent a
//! cross-purpose replay: signing material for request and response are
//! disjoint, and a PoW solution for one cannot be reused for the other.
//!
//! Threat model and full lifecycle described in the linked plan doc; this
//! module ships only the wire-level primitives (Slice 1 scope) and does
//! NOT perform live network dispatch (that's Slice 3+ work).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::ProtoError;
use crate::discovery::MAX_TRANSPORT_URI_LEN;

// ── Public constants ────────────────────────────────────────────────

/// Domain separation tag for the request's signature input.  Prepended
/// before `signable_bytes` so a sig from one purpose cannot be replayed
/// against a message of another type.  Versioned (`v1`) so future wire
/// format bumps stay disjoint.
pub const REQUEST_SIG_DOMAIN: &[u8] = b"veil-rendezvous-request:v1\0";

/// Domain separation tag for the response's signature input.  Disjoint
/// from [`REQUEST_SIG_DOMAIN`] so a valid request signature cannot pass
/// response verification and vice versa.
pub const RESPONSE_SIG_DOMAIN: &[u8] = b"veil-rendezvous-response:v1\0";

/// Domain separation tag for the request's PoW canonical form.
/// Distinct from signature domains so a PoW solution computed against
/// the request body cannot be re-applied to (say) identity-mining
/// that shares the BLAKE3 primitive.
pub const POW_DOMAIN: &[u8] = b"veil-rendezvous-pow:v1\0";

/// Replay-tolerance window (seconds).  Requests with `|now - timestamp|`
/// outside this window are silently dropped — anti-replay protection
/// for long-captured PoW solutions.  Symmetric around `now` to be
/// robust to minor clock skew (~5 min in both directions).
pub const REPLAY_WINDOW_SECS: u64 = 300;

/// Maximum allowed PoW difficulty in leading-zero-bits.  Bound prevents
/// a malicious requester from claiming an unverifiable difficulty (e.g.
/// 2^32 — verifier would still pass but the value is meaningless).
/// 64 bits = ~10^19 hashes, far beyond practical compute budgets.
pub const MAX_POW_DIFFICULTY: u32 = 64;

/// Minimum sensible PoW difficulty.  Set to 8 bits (256 expected
/// attempts) so even minimal "demonstration" deployments require some
/// CPU expenditure.  Production defaults run higher (24-28 bits per
/// the PLAN doc).
pub const MIN_POW_DIFFICULTY: u32 = 8;

// ── RequestEphemeralEndpointPayload ─────────────────────────────────

/// Initiator's signed request asking a target node to bind an ephemeral
/// listener.  Routed to the target through the existing OVL1 session
/// fabric (typically relayed by a mediator with whom both initiator and
/// target have active sessions).
///
/// Wire layout:
/// ```text
/// [0..32]    target_node_id      [u8; 32]
/// [32..64]   requester_pubkey    [u8; 32]   (Ed25519 verifying key)
/// [64..72]   timestamp_unix      u64 BE     (anti-replay anchor)
/// [72..76]   pow_difficulty      u32 BE     (claimed; verifier re-checks)
/// [76..84]   pow_nonce           u64 BE     (such that BLAKE3(POW_DOMAIN ||
///                                            signable_bytes) has >=
///                                            pow_difficulty leading zero bits)
/// [84..148]  requester_sig       [u8; 64]   (Ed25519 sig over REQUEST_SIG_DOMAIN
///                                            || signable_bytes() under
///                                            requester_pubkey)
/// ```
///
/// `signable_bytes()` covers: `target_node_id || requester_pubkey ||
/// timestamp_be || difficulty_be || nonce_be`.
///
/// Wire size: 148 bytes (fixed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEphemeralEndpointPayload {
    /// Identity of the node the initiator wants to dial.  Equals
    /// `BLAKE3(target_identity_pubkey)`.
    pub target_node_id: [u8; 32],
    /// Initiator's Ed25519 verifying key.  Identifies the requester
    /// and binds the PoW solution to this specific entity (PoW cannot
    /// be transferred to another requester).
    pub requester_pubkey: [u8; 32],
    /// Unix timestamp when the request was issued — anchors the
    /// replay-window check.  Verifier rejects requests with
    /// `|now - timestamp| > REPLAY_WINDOW_SECS`.
    pub timestamp_unix: u64,
    /// Claimed PoW difficulty in leading-zero-bits over
    /// `BLAKE3(POW_DOMAIN || signable_bytes())`.  Verifier re-counts
    /// the actual leading zeros and rejects if below operator-configured
    /// minimum (separate from this self-declared value, which is included
    /// in the signable surface so a stripping mediator cannot
    /// downgrade it).
    pub pow_difficulty: u32,
    /// PoW nonce — varied by the miner until
    /// `pow_leading_zeros(BLAKE3(POW_DOMAIN || signable_bytes())) >=
    /// pow_difficulty`.
    pub pow_nonce: u64,
    /// Ed25519 signature over `REQUEST_SIG_DOMAIN || signable_bytes()`
    /// under `requester_pubkey`.  Prevents another node from replaying
    /// somebody else's PoW solution with a forged requester_pubkey.
    pub requester_sig: [u8; 64],
}

/// Fixed wire size of a serialized [`RequestEphemeralEndpointPayload`].
pub const REQUEST_WIRE_SIZE: usize = 32 + 32 + 8 + 4 + 8 + 64;

impl RequestEphemeralEndpointPayload {
    /// Bytes covered by both the signature and the PoW canonical form.
    /// Excludes `requester_sig` itself (sig signs the rest).  PoW input
    /// is `POW_DOMAIN || signable_bytes()`; signature input is
    /// `REQUEST_SIG_DOMAIN || signable_bytes()`.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 4 + 8);
        buf.extend_from_slice(&self.target_node_id);
        buf.extend_from_slice(&self.requester_pubkey);
        buf.extend_from_slice(&self.timestamp_unix.to_be_bytes());
        buf.extend_from_slice(&self.pow_difficulty.to_be_bytes());
        buf.extend_from_slice(&self.pow_nonce.to_be_bytes());
        buf
    }

    /// Encode to the fixed-size wire format.
    pub fn encode(&self) -> [u8; REQUEST_WIRE_SIZE] {
        let mut buf = [0u8; REQUEST_WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.target_node_id);
        buf[32..64].copy_from_slice(&self.requester_pubkey);
        buf[64..72].copy_from_slice(&self.timestamp_unix.to_be_bytes());
        buf[72..76].copy_from_slice(&self.pow_difficulty.to_be_bytes());
        buf[76..84].copy_from_slice(&self.pow_nonce.to_be_bytes());
        buf[84..148].copy_from_slice(&self.requester_sig);
        buf
    }

    /// Decode wire bytes with structural validation only.  Caller MUST
    /// separately invoke [`verify_request_ephemeral_endpoint`] before
    /// trusting the payload — decode does NOT check sig, PoW,
    /// timestamp window, or any policy.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < REQUEST_WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: REQUEST_WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            target_node_id: super::read_array::<32>(buf, 0)?,
            requester_pubkey: super::read_array::<32>(buf, 32)?,
            timestamp_unix: super::read_u64_be(buf, 64)?,
            pow_difficulty: super::read_u32_be(buf, 72)?,
            pow_nonce: super::read_u64_be(buf, 76)?,
            requester_sig: super::read_array::<64>(buf, 84)?,
        })
    }
}

// ── EphemeralEndpointResponsePayload ────────────────────────────────

/// Target's signed response carrying the freshly-bound ephemeral URI
/// + per-request PSK + TTL.  Routed back to the initiator through the
///   same path the request arrived on.
///
/// Wire layout:
/// ```text
/// [0..32]    target_node_id      [u8; 32]   (target's own node_id; echoed)
/// [32..64]   requester_pubkey    [u8; 32]   (echoes the request's requester
///                                            field — verifier checks this
///                                            matches its own pubkey so a
///                                            response intended for another
///                                            peer cannot be replayed to it)
/// [64..72]   valid_until_unix    u64 BE     (URI expiry; after this the
///                                            target's listener is gone)
/// [72..74]   transport_len       u16 BE     (≤ MAX_TRANSPORT_URI_LEN)
/// [74..L]    transport_uri       utf8       (e.g. "obfs4-tcp://1.2.3.4:51237")
/// [L..L+32]  psk                 [u8; 32]   (one-shot PSK for this dial)
/// [L+32..L+96] sig               [u8; 64]   (Ed25519 sig over RESPONSE_SIG_DOMAIN
///                                            || signable_bytes() under
///                                            target's identity_pk)
/// ```
///
/// Wire size: 170 + transport_len bytes (170 = 32+32+8+2+32+64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralEndpointResponsePayload {
    /// Target's node_id — equals `BLAKE3(target_identity_pubkey)`.
    /// Echoed so the initiator can quickly cross-check it received a
    /// response from the intended node before signature verify.
    pub target_node_id: [u8; 32],
    /// Echoes the request's `requester_pubkey` field.  Initiator MUST
    /// check this matches its own pubkey on receive — prevents
    /// a malicious mediator from replaying a response originally signed
    /// for a different requester.
    pub requester_pubkey: [u8; 32],
    /// Unix timestamp at which the ephemeral listener will be guaranteed
    /// dropped.  Initiator MUST dial before this time.
    pub valid_until_unix: u64,
    /// Transport URI to dial.  UTF-8 string, capped at
    /// [`MAX_TRANSPORT_URI_LEN`].
    pub transport_uri: String,
    /// One-shot PSK for the obfs4/wireformat handshake against the
    /// ephemeral listener.  Unique per request; verifier on the target
    /// side wires this PSK into the on-demand listener's
    /// `TransportContext` during bind.
    pub psk: [u8; 32],
    /// Ed25519 signature over `RESPONSE_SIG_DOMAIN || signable_bytes()`
    /// under target's identity_pk.  Verifier MUST resolve the target's
    /// pubkey separately (e.g. by `BLAKE3(pubkey) == target_node_id`)
    /// and validate against it.
    pub sig: [u8; 64],
}

impl EphemeralEndpointResponsePayload {
    /// Bytes covered by the signature.  Excludes `sig` itself.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let uri_bytes = self.transport_uri.as_bytes();
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 2 + uri_bytes.len() + 32);
        buf.extend_from_slice(&self.target_node_id);
        buf.extend_from_slice(&self.requester_pubkey);
        buf.extend_from_slice(&self.valid_until_unix.to_be_bytes());
        buf.extend_from_slice(&(uri_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(uri_bytes);
        buf.extend_from_slice(&self.psk);
        buf
    }

    /// Encode to wire bytes.  Variable length (depends on URI length).
    pub fn encode(&self) -> Vec<u8> {
        let uri_bytes = self.transport_uri.as_bytes();
        let total = 32 + 32 + 8 + 2 + uri_bytes.len() + 32 + 64;
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&self.target_node_id);
        buf.extend_from_slice(&self.requester_pubkey);
        buf.extend_from_slice(&self.valid_until_unix.to_be_bytes());
        buf.extend_from_slice(&(uri_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(uri_bytes);
        buf.extend_from_slice(&self.psk);
        buf.extend_from_slice(&self.sig);
        buf
    }

    /// Decode wire bytes with structural validation.  Caller MUST
    /// separately invoke [`verify_ephemeral_endpoint_response`] before
    /// trusting it.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        const HEADER: usize = 32 + 32 + 8 + 2;
        const TAIL: usize = 32 + 64;
        if buf.len() < HEADER + TAIL {
            return Err(ProtoError::BufferTooShort {
                need: HEADER + TAIL,
                got: buf.len(),
            });
        }
        let target_node_id = super::read_array::<32>(buf, 0)?;
        let requester_pubkey = super::read_array::<32>(buf, 32)?;
        let valid_until_unix = super::read_u64_be(buf, 64)?;
        let transport_len = super::read_u16_be(buf, 72)? as usize;
        if transport_len > MAX_TRANSPORT_URI_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "EphemeralEndpointResponse.transport_len",
                value: transport_len as u64,
                max: MAX_TRANSPORT_URI_LEN as u64,
            });
        }
        let needed = HEADER + transport_len + TAIL;
        if buf.len() < needed {
            return Err(ProtoError::BufferTooShort {
                need: needed,
                got: buf.len(),
            });
        }
        let uri_bytes = &buf[74..74 + transport_len];
        let transport_uri = std::str::from_utf8(uri_bytes)
            .map_err(|_| ProtoError::InvalidUtf8)?
            .to_owned();
        let psk_start = 74 + transport_len;
        let psk = super::read_array::<32>(buf, psk_start)?;
        let sig_start = psk_start + 32;
        let sig = super::read_array::<64>(buf, sig_start)?;
        Ok(Self {
            target_node_id,
            requester_pubkey,
            valid_until_unix,
            transport_uri,
            psk,
            sig,
        })
    }
}

// ── PoW primitives ──────────────────────────────────────────────────

/// Count leading-zero **bits** in a 32-byte BLAKE3 hash.  Used as the
/// PoW difficulty measurement.  An empty / all-zero hash returns 256;
/// a hash starting with `0x80` returns 0; etc.
pub fn pow_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut zeros = 0u32;
    for &byte in hash {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    zeros
}

/// Compute the PoW hash for a request payload's canonical form.
/// Returns the BLAKE3 hash bytes; caller uses [`pow_leading_zero_bits`]
/// to derive the difficulty measurement.
///
/// Input shape: `POW_DOMAIN || signable_bytes()`.  Domain prefix
/// prevents a PoW computed for one purpose from satisfying a different
/// difficulty target elsewhere in the protocol.
pub fn pow_hash(canonical: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(POW_DOMAIN.len() + canonical.len());
    input.extend_from_slice(POW_DOMAIN);
    input.extend_from_slice(canonical);
    *blake3::hash(&input).as_bytes()
}

/// Check whether `payload`'s embedded `pow_nonce` solves a PoW puzzle
/// at the declared difficulty.  Verifier-side primitive — called as
/// step (a) of [`verify_request_ephemeral_endpoint`].
pub fn pow_solution_satisfies(payload: &RequestEphemeralEndpointPayload) -> bool {
    let canonical = payload.signable_bytes();
    let hash = pow_hash(&canonical);
    pow_leading_zero_bits(&hash) >= payload.pow_difficulty
}

/// Mine a `pow_nonce` such that [`pow_solution_satisfies`] returns true
/// for the resulting payload.  Mutates `payload.pow_nonce` in-place.
/// Returns the number of attempts taken (useful for observability).
///
/// **Hot loop** — caller should be prepared for CPU-bound work
/// proportional to `2^pow_difficulty` expected attempts.  At difficulty
/// 24 expect ~16M tries (~0.5 seconds on typical 2-vCPU VPS); above 28
/// the cost grows fast enough to notice.
///
/// Refuses if `pow_difficulty` exceeds [`MAX_POW_DIFFICULTY`] — a
/// guard so honest miners don't accidentally spin forever on a garbage
/// difficulty value.
pub fn mine_pow_nonce(payload: &mut RequestEphemeralEndpointPayload) -> Result<u64, ProtoError> {
    mine_pow_nonce_with_progress(payload, u64::MAX, |_| {})
}

/// Same as [`mine_pow_nonce`] but invokes `progress(attempts_so_far)`
/// every `report_every` attempts.  Useful for UI spinners during long
/// mining sessions at production-grade difficulties (24-28 bits ⇒
/// 0.5–10 s wall-clock on a 2-vCPU VPS).  Pass `u64::MAX` to disable
/// reporting (matches [`mine_pow_nonce`] behaviour).
///
/// The callback runs synchronously inside the mining hot-loop — keep
/// it cheap (atomic stores, log lines).  Heavy work (UI redraws,
/// network calls) should debounce on the caller side.
pub fn mine_pow_nonce_with_progress<F: FnMut(u64)>(
    payload: &mut RequestEphemeralEndpointPayload,
    report_every: u64,
    mut progress: F,
) -> Result<u64, ProtoError> {
    if payload.pow_difficulty > MAX_POW_DIFFICULTY {
        return Err(ProtoError::ValueTooLarge {
            field: "pow_difficulty",
            value: payload.pow_difficulty as u64,
            max: MAX_POW_DIFFICULTY as u64,
        });
    }
    let mut attempts = 0u64;
    let report_every = report_every.max(1);
    loop {
        attempts = attempts.saturating_add(1);
        if pow_solution_satisfies(payload) {
            return Ok(attempts);
        }
        if attempts.is_multiple_of(report_every) {
            progress(attempts);
        }
        payload.pow_nonce = payload.pow_nonce.wrapping_add(1);
    }
}

/// Number of mining attempts between `cancel`-flag polls in
/// [`mine_pow_nonce_cancellable`]. 4096 BLAKE3 hashes is on the order of
/// microseconds, so cancellation is observed near-instantly while the poll
/// adds negligible overhead to the hot loop.
const POW_CANCEL_CHECK_INTERVAL: u64 = 4096;

/// Cancellable variant of [`mine_pow_nonce`]: identical mining, but every
/// [`POW_CANCEL_CHECK_INTERVAL`] attempts it checks `cancel` and, if set,
/// abandons the search and returns `Ok(None)`.
///
/// This exists so an async caller can run the (CPU-bound) miner on a blocking
/// thread and stop it when an operation deadline elapses — without it, a
/// timed-out mine would orphan a thread that keeps hashing until it happens to
/// find a solution. `Ok(Some(attempts))` on success, `Ok(None)` if cancelled,
/// `Err` if `pow_difficulty` exceeds [`MAX_POW_DIFFICULTY`] (same guard as
/// [`mine_pow_nonce`]).
pub fn mine_pow_nonce_cancellable(
    payload: &mut RequestEphemeralEndpointPayload,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<Option<u64>, ProtoError> {
    if payload.pow_difficulty > MAX_POW_DIFFICULTY {
        return Err(ProtoError::ValueTooLarge {
            field: "pow_difficulty",
            value: payload.pow_difficulty as u64,
            max: MAX_POW_DIFFICULTY as u64,
        });
    }
    let mut attempts = 0u64;
    loop {
        attempts = attempts.saturating_add(1);
        if pow_solution_satisfies(payload) {
            return Ok(Some(attempts));
        }
        if attempts.is_multiple_of(POW_CANCEL_CHECK_INTERVAL)
            && cancel.load(std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(None);
        }
        payload.pow_nonce = payload.pow_nonce.wrapping_add(1);
    }
}

// ── Sign / verify helpers ───────────────────────────────────────────

/// Build + sign a request payload with the given PoW solution.  Caller
/// is responsible for mining the PoW first (use [`mine_pow_nonce`])
/// or supplying a pre-computed `pow_nonce`.
///
/// Does NOT validate the PoW solution itself — callers can either
/// (a) mine before calling this, or (b) sign a draft payload then
/// run [`mine_pow_nonce`] AFTER (but note that mining mutates `pow_nonce`
/// which IS included in signable_bytes — so sig must be recomputed
/// after mining).  For simplicity, mine-then-sign is the recommended
/// order.
pub fn sign_request_ephemeral_endpoint(
    target_node_id: [u8; 32],
    requester_pubkey: [u8; 32],
    timestamp_unix: u64,
    pow_difficulty: u32,
    pow_nonce: u64,
    signing_key: &SigningKey,
) -> RequestEphemeralEndpointPayload {
    let mut draft = RequestEphemeralEndpointPayload {
        target_node_id,
        requester_pubkey,
        timestamp_unix,
        pow_difficulty,
        pow_nonce,
        requester_sig: [0u8; 64],
    };
    let mut to_sign = Vec::with_capacity(REQUEST_SIG_DOMAIN.len() + 84);
    to_sign.extend_from_slice(REQUEST_SIG_DOMAIN);
    to_sign.extend_from_slice(&draft.signable_bytes());
    let sig: Signature = signing_key.sign(&to_sign);
    draft.requester_sig = sig.to_bytes();
    draft
}

/// Verify a request payload.  Returns `Ok(())` iff:
/// 1. `requester_pubkey` is a valid Ed25519 pubkey.
/// 2. `requester_sig` valid under `REQUEST_SIG_DOMAIN || signable_bytes()`
///    under `requester_pubkey`.
/// 3. `pow_difficulty` is in `[min_difficulty, MAX_POW_DIFFICULTY]`.
/// 4. `pow_solution_satisfies(payload)` — PoW hash has at least
///    `pow_difficulty` leading zeros.
/// 5. `|now_unix - timestamp_unix| <= REPLAY_WINDOW_SECS`.
///
/// `min_difficulty` is a **policy** parameter set by the verifier
/// (typically from `[listen.on_demand].pow_difficulty` config); included
/// here so the wire-layer primitive can be called with different policies
/// per-listener.
pub fn verify_request_ephemeral_endpoint(
    payload: &RequestEphemeralEndpointPayload,
    min_difficulty: u32,
    now_unix: u64,
) -> Result<(), ProtoError> {
    // 1+2: Ed25519 sig verify under requester_pubkey.
    let vk = VerifyingKey::from_bytes(&payload.requester_pubkey)
        .map_err(|e| ProtoError::Malformed(format!("bad requester_pubkey: {e}")))?;
    let mut to_verify = Vec::with_capacity(REQUEST_SIG_DOMAIN.len() + 84);
    to_verify.extend_from_slice(REQUEST_SIG_DOMAIN);
    to_verify.extend_from_slice(&payload.signable_bytes());
    let sig = Signature::from_bytes(&payload.requester_sig);
    vk.verify(&to_verify, &sig)
        .map_err(|_| ProtoError::Malformed("rendezvous request: sig verify failed".to_owned()))?;

    // 3: difficulty bounds.
    if payload.pow_difficulty < min_difficulty {
        return Err(ProtoError::Malformed(format!(
            "rendezvous request: pow_difficulty={} below operator min={}",
            payload.pow_difficulty, min_difficulty,
        )));
    }
    if payload.pow_difficulty > MAX_POW_DIFFICULTY {
        return Err(ProtoError::ValueTooLarge {
            field: "pow_difficulty",
            value: payload.pow_difficulty as u64,
            max: MAX_POW_DIFFICULTY as u64,
        });
    }

    // 4: PoW solution.
    if !pow_solution_satisfies(payload) {
        return Err(ProtoError::Malformed(
            "rendezvous request: PoW solution does not meet declared difficulty".to_owned(),
        ));
    }

    // 5: replay window.
    let skew = now_unix.abs_diff(payload.timestamp_unix);
    if skew > REPLAY_WINDOW_SECS {
        return Err(ProtoError::Malformed(format!(
            "rendezvous request replay: timestamp skew {}s > {}s window",
            skew, REPLAY_WINDOW_SECS,
        )));
    }

    Ok(())
}

/// Build + sign a response payload.  Validates the transport URI
/// length up-front so callers cannot accidentally produce wire-invalid
/// frames.
pub fn sign_ephemeral_endpoint_response(
    target_node_id: [u8; 32],
    requester_pubkey: [u8; 32],
    valid_until_unix: u64,
    transport_uri: String,
    psk: [u8; 32],
    signing_key: &SigningKey,
) -> Result<EphemeralEndpointResponsePayload, ProtoError> {
    if transport_uri.len() > MAX_TRANSPORT_URI_LEN {
        return Err(ProtoError::ValueTooLarge {
            field: "transport_uri",
            value: transport_uri.len() as u64,
            max: MAX_TRANSPORT_URI_LEN as u64,
        });
    }
    let mut draft = EphemeralEndpointResponsePayload {
        target_node_id,
        requester_pubkey,
        valid_until_unix,
        transport_uri,
        psk,
        sig: [0u8; 64],
    };
    let mut to_sign = Vec::with_capacity(RESPONSE_SIG_DOMAIN.len() + 256);
    to_sign.extend_from_slice(RESPONSE_SIG_DOMAIN);
    to_sign.extend_from_slice(&draft.signable_bytes());
    let sig: Signature = signing_key.sign(&to_sign);
    draft.sig = sig.to_bytes();
    Ok(draft)
}

/// Verify a response payload.  Returns `Ok(())` iff:
/// 1. `target_pubkey` valid Ed25519 key.
/// 2. `BLAKE3(target_pubkey) == payload.target_node_id` — identity binding.
/// 3. `payload.requester_pubkey == expected_requester_pubkey` — anti-
///    replay-for-someone-else (verifier supplies its own pubkey).
/// 4. `payload.sig` valid under `RESPONSE_SIG_DOMAIN || signable_bytes()`
///    under `target_pubkey`.
/// 5. `now_unix < payload.valid_until_unix` — endpoint not expired.
pub fn verify_ephemeral_endpoint_response(
    payload: &EphemeralEndpointResponsePayload,
    target_pubkey: &[u8; 32],
    expected_requester_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<(), ProtoError> {
    // 1: pubkey shape.
    let vk = VerifyingKey::from_bytes(target_pubkey)
        .map_err(|e| ProtoError::Malformed(format!("bad target_pubkey: {e}")))?;

    // 2: identity binding (target_node_id == BLAKE3(target_pubkey)).
    let expected_node_id = *blake3::hash(target_pubkey).as_bytes();
    if expected_node_id != payload.target_node_id {
        return Err(ProtoError::Malformed(
            "rendezvous response: target_node_id != BLAKE3(target_pubkey)".to_owned(),
        ));
    }

    // 3: requester binding.
    if &payload.requester_pubkey != expected_requester_pubkey {
        return Err(ProtoError::Malformed(
            "rendezvous response: requester_pubkey echo does not match expected".to_owned(),
        ));
    }

    // 4: sig verify.
    let mut to_verify = Vec::with_capacity(RESPONSE_SIG_DOMAIN.len() + 256);
    to_verify.extend_from_slice(RESPONSE_SIG_DOMAIN);
    to_verify.extend_from_slice(&payload.signable_bytes());
    let sig = Signature::from_bytes(&payload.sig);
    vk.verify(&to_verify, &sig)
        .map_err(|_| ProtoError::Malformed("rendezvous response: sig verify failed".to_owned()))?;

    // 5: TTL check.
    if now_unix >= payload.valid_until_unix {
        return Err(ProtoError::Malformed(format!(
            "rendezvous response: endpoint expired at {} (now={})",
            payload.valid_until_unix, now_unix,
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ────────────────────────────────────────────────────

    fn test_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn build_request_with_low_difficulty(
        target_sk_seed: u8,
        requester_sk_seed: u8,
        difficulty: u32,
        timestamp: u64,
    ) -> (RequestEphemeralEndpointPayload, SigningKey, [u8; 32]) {
        let target_sk = test_sk(target_sk_seed);
        let target_pk = target_sk.verifying_key().to_bytes();
        let target_node_id = *blake3::hash(&target_pk).as_bytes();
        let requester_sk = test_sk(requester_sk_seed);
        let requester_pk = requester_sk.verifying_key().to_bytes();

        // Build draft with pow_nonce=0, mine, then sign.  Difficulty kept
        // low (8 bits) so the test mines quickly.
        let mut draft = RequestEphemeralEndpointPayload {
            target_node_id,
            requester_pubkey: requester_pk,
            timestamp_unix: timestamp,
            pow_difficulty: difficulty,
            pow_nonce: 0,
            requester_sig: [0u8; 64],
        };
        mine_pow_nonce(&mut draft).unwrap();
        // Re-sign after mining (mining mutates pow_nonce which is in
        // signable bytes).
        let signed = sign_request_ephemeral_endpoint(
            target_node_id,
            requester_pk,
            timestamp,
            difficulty,
            draft.pow_nonce,
            &requester_sk,
        );
        (signed, requester_sk, target_node_id)
    }

    // ── pow_leading_zero_bits ──────────────────────────────────────

    #[test]
    fn pow_leading_zero_bits_basic() {
        let zero = [0u8; 32];
        assert_eq!(pow_leading_zero_bits(&zero), 256);

        let mut one_at_byte_0 = [0u8; 32];
        one_at_byte_0[0] = 0x80;
        assert_eq!(pow_leading_zero_bits(&one_at_byte_0), 0);

        let mut high_bit_at_byte_1 = [0u8; 32];
        high_bit_at_byte_1[1] = 0x80;
        assert_eq!(pow_leading_zero_bits(&high_bit_at_byte_1), 8);

        let mut three_zeros_in_byte_0 = [0u8; 32];
        three_zeros_in_byte_0[0] = 0x10; // 0b0001_0000 → 3 leading zeros
        assert_eq!(pow_leading_zero_bits(&three_zeros_in_byte_0), 3);
    }

    #[test]
    fn pow_solution_satisfies_at_zero_difficulty_always_true() {
        let (req, _, _) = build_request_with_low_difficulty(1, 2, 0, 1_000);
        // With difficulty=0 ANY hash satisfies it.
        assert!(pow_solution_satisfies(&req));
    }

    #[test]
    fn pow_solution_satisfies_after_mining_at_8_bits() {
        let (req, _, _) = build_request_with_low_difficulty(3, 4, 8, 1_000);
        assert_eq!(req.pow_difficulty, 8);
        assert!(pow_solution_satisfies(&req));
        let hash = pow_hash(&req.signable_bytes());
        assert!(pow_leading_zero_bits(&hash) >= 8);
    }

    /// Build a fresh unmined draft (pow_nonce = 0) for the cancellable-miner
    /// tests — mirrors the first half of `build_request_with_low_difficulty`
    /// but stops before mining so the caller controls the search.
    fn unmined_draft(difficulty: u32) -> RequestEphemeralEndpointPayload {
        let target_sk = test_sk(11);
        let target_pk = target_sk.verifying_key().to_bytes();
        RequestEphemeralEndpointPayload {
            target_node_id: *blake3::hash(&target_pk).as_bytes(),
            requester_pubkey: test_sk(12).verifying_key().to_bytes(),
            timestamp_unix: 1_700_000_000,
            pow_difficulty: difficulty,
            pow_nonce: 0,
            requester_sig: [0u8; 64],
        }
    }

    #[test]
    fn mine_cancellable_finds_solution_when_not_cancelled() {
        use std::sync::atomic::AtomicBool;
        let mut draft = unmined_draft(8);
        let cancel = AtomicBool::new(false);
        let attempts = mine_pow_nonce_cancellable(&mut draft, &cancel)
            .expect("difficulty within cap")
            .expect("must find a solution when not cancelled");
        assert!(attempts >= 1);
        assert!(pow_solution_satisfies(&draft));
    }

    #[test]
    fn mine_cancellable_bails_when_cancel_preset() {
        use std::sync::atomic::AtomicBool;
        // Difficulty 40: P(solving within one cancel-check interval of 4096
        // attempts) ≈ 4096 / 2^40 ≈ 4e-9, so with cancel pre-set the miner
        // deterministically gives up at the first poll and returns None.
        let mut draft = unmined_draft(40);
        let cancel = AtomicBool::new(true);
        let result = mine_pow_nonce_cancellable(&mut draft, &cancel)
            .expect("difficulty within cap (40 <= MAX_POW_DIFFICULTY)");
        assert!(result.is_none(), "pre-set cancel must abandon the search");
    }

    #[test]
    fn mine_cancellable_rejects_difficulty_above_cap() {
        use std::sync::atomic::AtomicBool;
        let mut draft = unmined_draft(MAX_POW_DIFFICULTY + 1);
        let cancel = AtomicBool::new(false);
        let err = mine_pow_nonce_cancellable(&mut draft, &cancel).unwrap_err();
        assert!(matches!(err, ProtoError::ValueTooLarge { .. }));
    }

    // ── Request encode/decode round-trip ───────────────────────────

    #[test]
    fn request_round_trip_through_encode_decode() {
        let (req, _, _) = build_request_with_low_difficulty(5, 6, 8, 1_700_000_000);
        let bytes = req.encode();
        assert_eq!(bytes.len(), REQUEST_WIRE_SIZE);
        let decoded = RequestEphemeralEndpointPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_decode_truncated_buffer_rejected() {
        let (req, _, _) = build_request_with_low_difficulty(7, 8, 8, 1_700_000_000);
        let bytes = req.encode();
        let err =
            RequestEphemeralEndpointPayload::decode(&bytes[..REQUEST_WIRE_SIZE - 1]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    // ── Request verify ─────────────────────────────────────────────

    #[test]
    fn request_verify_happy_path() {
        let (req, _, _) = build_request_with_low_difficulty(9, 10, 8, 1_700_000_000);
        assert!(verify_request_ephemeral_endpoint(&req, 8, 1_700_000_010).is_ok());
    }

    #[test]
    fn request_verify_rejects_below_min_difficulty() {
        let (req, _, _) = build_request_with_low_difficulty(11, 12, 8, 1_700_000_000);
        let err = verify_request_ephemeral_endpoint(&req, 16, 1_700_000_010).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("below operator min"),
            "want min-difficulty rejection, got: {msg}",
        );
    }

    #[test]
    fn request_verify_rejects_excess_max_difficulty() {
        // Construct a draft with pow_difficulty > MAX (e.g. 100) — signed
        // properly but verify must refuse.
        let target_sk = test_sk(13);
        let target_pk = target_sk.verifying_key().to_bytes();
        let target_node_id = *blake3::hash(&target_pk).as_bytes();
        let requester_sk = test_sk(14);
        let requester_pk = requester_sk.verifying_key().to_bytes();
        let signed = sign_request_ephemeral_endpoint(
            target_node_id,
            requester_pk,
            1_700_000_000,
            MAX_POW_DIFFICULTY + 1,
            0,
            &requester_sk,
        );
        let err = verify_request_ephemeral_endpoint(&signed, 8, 1_700_000_010).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::ValueTooLarge {
                field: "pow_difficulty",
                ..
            }
        ));
    }

    #[test]
    fn request_verify_rejects_bad_sig() {
        let (mut req, _, _) = build_request_with_low_difficulty(15, 16, 8, 1_700_000_000);
        req.requester_sig[0] ^= 0x01; // tamper
        let err = verify_request_ephemeral_endpoint(&req, 8, 1_700_000_010).unwrap_err();
        assert!(format!("{err}").contains("sig verify failed"));
    }

    #[test]
    fn request_verify_rejects_tampered_pow_nonce() {
        let (mut req, _, _) = build_request_with_low_difficulty(17, 18, 8, 1_700_000_000);
        // Bump pow_nonce — invalidates PoW solution AND sig.
        req.pow_nonce = req.pow_nonce.wrapping_add(1);
        let err = verify_request_ephemeral_endpoint(&req, 8, 1_700_000_010).unwrap_err();
        // Sig fails first (signable bytes include pow_nonce).
        assert!(format!("{err}").contains("sig verify failed"));
    }

    #[test]
    fn request_verify_rejects_replay_outside_window() {
        let (req, _, _) = build_request_with_low_difficulty(19, 20, 8, 1_700_000_000);
        // now > timestamp + REPLAY_WINDOW_SECS.
        let stale_now = 1_700_000_000 + REPLAY_WINDOW_SECS + 1;
        let err = verify_request_ephemeral_endpoint(&req, 8, stale_now).unwrap_err();
        assert!(format!("{err}").contains("replay"));
    }

    #[test]
    fn request_verify_rejects_pow_failure_without_sig_tamper() {
        // Build a valid sig but stick a PoW solution that doesn't meet the
        // difficulty.  Hard to do honestly — we need a payload where sig is
        // valid but PoW fails.  Trick: difficulty=0 satisfies any hash;
        // raise difficulty in the verify call.  Actually we already cover
        // this via `request_verify_rejects_below_min_difficulty`.  Here
        // we test the OPPOSITE: claim high difficulty with sig valid but PoW
        // nonce not actually mined.
        let target_sk = test_sk(21);
        let target_pk = target_sk.verifying_key().to_bytes();
        let target_node_id = *blake3::hash(&target_pk).as_bytes();
        let requester_sk = test_sk(22);
        let requester_pk = requester_sk.verifying_key().to_bytes();
        // Claim difficulty=24 but use pow_nonce=0 (~almost certainly
        // doesn't satisfy 24 leading zeros).
        let signed = sign_request_ephemeral_endpoint(
            target_node_id,
            requester_pk,
            1_700_000_000,
            24,
            0,
            &requester_sk,
        );
        let err = verify_request_ephemeral_endpoint(&signed, 8, 1_700_000_010).unwrap_err();
        // PoW failure (sig is genuine since we just signed it).
        assert!(format!("{err}").contains("PoW solution"));
    }

    // ── Domain separation ──────────────────────────────────────────

    #[test]
    fn request_and_response_sig_domains_disjoint() {
        // A signed request must NOT verify when treated as a response
        // and vice versa — domain prefix bytes differ.
        assert_ne!(REQUEST_SIG_DOMAIN, RESPONSE_SIG_DOMAIN);
        assert_ne!(REQUEST_SIG_DOMAIN, POW_DOMAIN);
        assert_ne!(RESPONSE_SIG_DOMAIN, POW_DOMAIN);
    }

    // ── Response encode/decode + verify ────────────────────────────

    fn build_signed_response(
        target_sk_seed: u8,
        requester_pk: [u8; 32],
        valid_until: u64,
        uri: &str,
    ) -> (EphemeralEndpointResponsePayload, [u8; 32]) {
        let target_sk = test_sk(target_sk_seed);
        let target_pk = target_sk.verifying_key().to_bytes();
        let target_node_id = *blake3::hash(&target_pk).as_bytes();
        let psk = [0xCD; 32];
        let signed = sign_ephemeral_endpoint_response(
            target_node_id,
            requester_pk,
            valid_until,
            uri.to_owned(),
            psk,
            &target_sk,
        )
        .unwrap();
        (signed, target_pk)
    }

    #[test]
    fn response_round_trip_through_encode_decode() {
        let requester_pk = test_sk(30).verifying_key().to_bytes();
        let (resp, _) =
            build_signed_response(31, requester_pk, 1_700_000_300, "obfs4-tcp://1.2.3.4:51234");
        let bytes = resp.encode();
        let decoded = EphemeralEndpointResponsePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, resp);
        assert_eq!(decoded.transport_uri, "obfs4-tcp://1.2.3.4:51234");
    }

    #[test]
    fn response_verify_happy_path() {
        let requester_pk = test_sk(40).verifying_key().to_bytes();
        let (resp, target_pk) =
            build_signed_response(41, requester_pk, 1_700_000_300, "obfs4-tcp://1.2.3.4:51234");
        assert!(
            verify_ephemeral_endpoint_response(&resp, &target_pk, &requester_pk, 1_700_000_100,)
                .is_ok()
        );
    }

    #[test]
    fn response_verify_rejects_node_id_mismatch() {
        let requester_pk = test_sk(50).verifying_key().to_bytes();
        let (mut resp, target_pk) =
            build_signed_response(51, requester_pk, 1_700_000_300, "obfs4-tcp://1.2.3.4:51234");
        // Tamper with target_node_id so the BLAKE3(target_pk) check fails.
        resp.target_node_id[0] ^= 0x01;
        let err =
            verify_ephemeral_endpoint_response(&resp, &target_pk, &requester_pk, 1_700_000_100)
                .unwrap_err();
        assert!(format!("{err}").contains("target_node_id"));
    }

    #[test]
    fn response_verify_rejects_replay_to_different_requester() {
        // A response signed for requester_A is sent to requester_B (B
        // tries to verify it under its own pubkey).  Must reject.
        let requester_a_pk = test_sk(60).verifying_key().to_bytes();
        let requester_b_pk = test_sk(61).verifying_key().to_bytes();
        let (resp, target_pk) = build_signed_response(
            62,
            requester_a_pk,
            1_700_000_300,
            "obfs4-tcp://1.2.3.4:51234",
        );
        let err =
            verify_ephemeral_endpoint_response(&resp, &target_pk, &requester_b_pk, 1_700_000_100)
                .unwrap_err();
        assert!(format!("{err}").contains("requester_pubkey echo"));
    }

    #[test]
    fn response_verify_rejects_expired_endpoint() {
        let requester_pk = test_sk(70).verifying_key().to_bytes();
        let (resp, target_pk) = build_signed_response(
            71,
            requester_pk,
            1_700_000_100, // valid_until
            "obfs4-tcp://1.2.3.4:51234",
        );
        let err = verify_ephemeral_endpoint_response(
            &resp,
            &target_pk,
            &requester_pk,
            1_700_000_300, // now > valid_until
        )
        .unwrap_err();
        assert!(format!("{err}").contains("expired"));
    }

    #[test]
    fn response_verify_rejects_tampered_uri() {
        let requester_pk = test_sk(80).verifying_key().to_bytes();
        let (mut resp, target_pk) =
            build_signed_response(81, requester_pk, 1_700_000_300, "obfs4-tcp://1.2.3.4:51234");
        resp.transport_uri = "obfs4-tcp://9.9.9.9:51234".to_owned();
        let err =
            verify_ephemeral_endpoint_response(&resp, &target_pk, &requester_pk, 1_700_000_100)
                .unwrap_err();
        assert!(format!("{err}").contains("sig verify"));
    }

    #[test]
    fn response_signs_refuses_oversized_uri() {
        let target_sk = test_sk(90);
        let target_pk = target_sk.verifying_key().to_bytes();
        let target_node_id = *blake3::hash(&target_pk).as_bytes();
        let requester_pk = test_sk(91).verifying_key().to_bytes();
        let huge_uri = "x".repeat(MAX_TRANSPORT_URI_LEN + 1);
        let err = sign_ephemeral_endpoint_response(
            target_node_id,
            requester_pk,
            1_700_000_300,
            huge_uri,
            [0xAA; 32],
            &target_sk,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProtoError::ValueTooLarge {
                field: "transport_uri",
                ..
            }
        ));
    }

    #[test]
    fn response_decode_truncated_buffer_rejected() {
        let requester_pk = test_sk(100).verifying_key().to_bytes();
        let (resp, _) = build_signed_response(
            101,
            requester_pk,
            1_700_000_300,
            "obfs4-tcp://1.2.3.4:51234",
        );
        let bytes = resp.encode();
        let err = EphemeralEndpointResponsePayload::decode(&bytes[..bytes.len() - 1]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn pow_domain_prevents_cross_replay_to_response() {
        // A PoW solution mined against the request canonical (with
        // POW_DOMAIN prefix) must NOT satisfy ANY response-canonical PoW
        // (if we were to ever add one — a domain-separation
        // sanity check).  Here we just confirm domain bytes differ and
        // hashes therefore disjoint in expectation.
        let canonical = b"shared canonical bytes";
        let pow = pow_hash(canonical);
        // Compute what the hash WOULD be with RESPONSE_SIG_DOMAIN prefix
        // — should differ.
        let mut response_input = Vec::new();
        response_input.extend_from_slice(RESPONSE_SIG_DOMAIN);
        response_input.extend_from_slice(canonical);
        let response_hash = *blake3::hash(&response_input).as_bytes();
        assert_ne!(pow, response_hash);
    }
}
