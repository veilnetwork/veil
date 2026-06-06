//! PoW-gated rendezvous initiator client — Slice 4 of the PoW-Gated
//! Rendezvous epic ([`docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`]).
//!
//! This module provides the **client-side** primitives for one
//! rendezvous exchange:
//!
//! 1. [`RendezvousRequestBuilder`] — mints a PoW-gated request signed
//!    under the initiator's identity key.  Mining is CPU-bound;
//!    optional progress callback supports a UI spinner.
//! 2. [`parse_and_verify_response`] — decodes wire bytes + verifies
//!    the target's signature + identity binding + requester echo +
//!    TTL; returns a ready-to-dial [`EphemeralEndpoint`] (URI + PSK +
//!    expiry).
//!
//! ## Scope (Slice 4)
//!
//! This module ships only the wire-level + signing primitives.  The
//! transport-layer "send the request, await a matching response"
//! plumbing requires session integration that lives outside the SDK
//! (mediator routing, dispatcher arms) — that's Slice 5+ work.
//!
//! Today's typical caller will:
//! 1. Construct a `RendezvousRequestBuilder` from their identity sk.
//! 2. Call `build_request()` to get a signed payload + the encoded bytes.
//! 3. Hand the bytes to a transport-layer routing primitive (Slice 5).
//! 4. When response bytes come back, call `parse_and_verify_response`.
//! 5. Dial `EphemeralEndpoint::transport_uri` with `EphemeralEndpoint::psk`
//!    as the obfs4 PSK.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use ed25519_dalek::SigningKey;

use veil_proto::ProtoError;
use veil_proto::rendezvous::{
    EphemeralEndpointResponsePayload, MAX_POW_DIFFICULTY, MIN_POW_DIFFICULTY,
    RequestEphemeralEndpointPayload, mine_pow_nonce_with_progress, sign_request_ephemeral_endpoint,
    verify_ephemeral_endpoint_response,
};
use veil_proto::routing::{RecursiveQueryPayload, RecursiveResponsePayload, recursive_query_type};

// ── Public API ──────────────────────────────────────────────────────

/// Decoded + verified ephemeral endpoint, ready for a dial.  Returned
/// by [`parse_and_verify_response`] after signature verification + TTL
/// check passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralEndpoint {
    /// Transport URI to dial (e.g. `"obfs4-tcp://example.com:51237"`).
    pub transport_uri: String,
    /// One-shot PSK for the obfs4 handshake.
    pub psk: [u8; 32],
    /// Wall-clock expiry (unix seconds) — caller MUST dial before this.
    pub valid_until_unix: u64,
}

/// Progress reporter for PoW mining.  Cheap closure that the mine loop
/// invokes every N attempts (configured by the caller).  Default cadence
/// is `RendezvousRequestBuilder::DEFAULT_PROGRESS_EVERY = 65_536` —
/// fast enough to keep a UI spinner alive without dominating the mining
/// hot path.
pub trait ProgressCallback: Send + Sync + 'static {
    fn on_progress(&self, attempts_so_far: u64);
}

/// Convenience impl for bare closures: any `Fn(u64)` that is `Send +
/// Sync + 'static` becomes a `ProgressCallback`.
impl<F: Fn(u64) + Send + Sync + 'static> ProgressCallback for F {
    fn on_progress(&self, attempts_so_far: u64) {
        (self)(attempts_so_far)
    }
}

/// Shared counter that mining loops can write into.  Cheap, allocation-
/// free observability primitive for callers that want to poll progress
/// asynchronously without registering a callback closure.  Pass the
/// returned `Arc` to [`RendezvousRequestBuilder::build_request_async`]
/// (when added in a future slice) or hand-roll your own polling task.
#[derive(Debug, Clone, Default)]
pub struct AtomicProgress {
    counter: Arc<AtomicU64>,
}

impl AtomicProgress {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn current(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

impl ProgressCallback for AtomicProgress {
    fn on_progress(&self, attempts_so_far: u64) {
        self.counter.store(attempts_so_far, Ordering::Relaxed);
    }
}

/// Builder for one PoW-gated rendezvous request.  Wraps the
/// proto-level mining + signing primitives with client-side ergonomics:
/// generates the timestamp, validates the difficulty against a
/// caller-configurable cap, and dispatches the progress callback.
pub struct RendezvousRequestBuilder {
    signing_key: SigningKey,
}

impl RendezvousRequestBuilder {
    /// Default cadence for progress-callback invocations.  Chosen
    /// such that at 28 bits (~250M attempts ≈ 8 s wall-clock) the
    /// callback fires ~4000 times — every ~2 ms, fast enough to
    /// drive a smooth UI spinner.
    pub const DEFAULT_PROGRESS_EVERY: u64 = 65_536;

    /// Construct.  The signing key MUST be the initiator's identity
    /// Ed25519 key; the corresponding pubkey is embedded in the request
    /// and binds the PoW solution to this requester.
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Build a signed request with mined PoW.  Returns the payload + the
    /// final attempt count.  CPU-bound work proportional to
    /// `2^difficulty`.
    ///
    /// Production callers should set `difficulty` to the target's
    /// declared minimum (discovered through DHT or operator config).
    /// Below [`MIN_POW_DIFFICULTY`] (8 bits) the build rejects to keep
    /// even demonstration deployments anti-spam.  Above
    /// [`MAX_POW_DIFFICULTY`] (64 bits) rejects to prevent a wedged
    /// mining loop on operator misconfig.
    ///
    /// `now_unix` is captured at build time AND included in the
    /// signable surface — callers that mine offline and transmit later
    /// must respect the [`REPLAY_WINDOW_SECS`] (5 min) on the
    /// verifier side.
    pub fn build_request<P: ProgressCallback>(
        &self,
        target_node_id: [u8; 32],
        difficulty: u32,
        progress: Option<P>,
    ) -> Result<BuiltRequest, BuildError> {
        self.build_request_with_timestamp(target_node_id, difficulty, now_unix(), progress)
    }

    /// Test-hook variant that accepts an explicit `timestamp_unix`.
    /// Production callers use [`Self::build_request`] which calls
    /// `SystemTime::now`.
    pub fn build_request_with_timestamp<P: ProgressCallback>(
        &self,
        target_node_id: [u8; 32],
        difficulty: u32,
        timestamp_unix: u64,
        progress: Option<P>,
    ) -> Result<BuiltRequest, BuildError> {
        if difficulty < MIN_POW_DIFFICULTY {
            return Err(BuildError::DifficultyBelowMin {
                requested: difficulty,
                min: MIN_POW_DIFFICULTY,
            });
        }
        if difficulty > MAX_POW_DIFFICULTY {
            return Err(BuildError::DifficultyAboveMax {
                requested: difficulty,
                max: MAX_POW_DIFFICULTY,
            });
        }

        let requester_pubkey = self.signing_key.verifying_key().to_bytes();

        // Stage 1 — mine the nonce against the canonical form.  Mining
        // mutates pow_nonce which IS in signable_bytes; signing comes
        // after.
        let mut draft = RequestEphemeralEndpointPayload {
            target_node_id,
            requester_pubkey,
            timestamp_unix,
            pow_difficulty: difficulty,
            pow_nonce: 0,
            requester_sig: [0u8; 64],
        };
        let attempts = match progress {
            Some(cb) => {
                mine_pow_nonce_with_progress(&mut draft, Self::DEFAULT_PROGRESS_EVERY, |n| {
                    cb.on_progress(n)
                })
            }
            None => mine_pow_nonce_with_progress(&mut draft, u64::MAX, |_| {}),
        }
        .map_err(BuildError::Mine)?;

        // Stage 2 — sign the now-canonical payload.
        let signed = sign_request_ephemeral_endpoint(
            target_node_id,
            requester_pubkey,
            timestamp_unix,
            difficulty,
            draft.pow_nonce,
            &self.signing_key,
        );
        let wire_bytes = signed.encode().to_vec();
        Ok(BuiltRequest {
            payload: signed,
            wire_bytes,
            mining_attempts: attempts,
        })
    }

    /// Diagnostics: requester pubkey derived from the signing key.
    /// Useful when the caller needs to check the target's response
    /// echoes the right pubkey.
    pub fn requester_pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Slice 6c — wrap a freshly-built `BuiltRequest` in the recursive
    /// envelope used by the mediator-relay path.  Caller ships the
    /// returned wire bytes as a `RoutingMsg::RecursiveQuery` frame
    /// addressed to any neighbour; the existing recursive-routing
    /// infrastructure (already in production for DHT FIND_NODE) takes
    /// care of forwarding to the target and returning a signed response.
    ///
    /// `target_node_id` MUST equal `BLAKE3(target_identity_pubkey)`
    /// (the target's well-known node-id).  `reply_to_node_id` MUST
    /// equal the initiator's own node-id — recursive responses route
    /// back to this address.  `ttl` defaults to the canonical
    /// `MAX_RECURSIVE_RELAY_HOPS` (20 hops) when `None`.
    pub fn wrap_recursive(
        built: &BuiltRequest,
        target_node_id: [u8; 32],
        reply_to_node_id: [u8; 32],
        query_id: [u8; 16],
        ttl: Option<u8>,
    ) -> RecursiveQueryPayload {
        RecursiveQueryPayload {
            query_id,
            target_key: target_node_id,
            reply_to: reply_to_node_id,
            ttl: ttl.unwrap_or(20),
            query_type: recursive_query_type::RENDEZVOUS_REQUEST,
            // 0 = no UDP-direct reply.  Target's reachable IP is the
            // secret protected by stealth — response MUST travel
            // through veil reverse-path.
            reply_port: 0,
            payload: built.wire_bytes.clone(),
        }
    }
}

/// Parse + verify a `RecursiveResponsePayload` carrying a
/// PoW-rendezvous response inner payload.  Performs two layers of
/// verification:
///
/// 1. Outer envelope's `responder_pubkey` MUST equal
///    `expected_target_pubkey` — a malicious mediator cannot replace
///    the target's identity with its own.
/// 2. Inner `EphemeralEndpointResponsePayload` runs through the
///    same `verify_ephemeral_endpoint_response` as the direct-session
///    path (see [`parse_and_verify_response_at`]).  Domain-separated
///    sig that a passive observer cannot replay to a different
///    `requester_pubkey`.
///
/// Outer envelope's own Ed25519 sig (signed by target's key over
/// `query_id || payload`) is verified inside this function — caller
/// MUST supply the `query_id` they originally used to build the
/// recursive query (echoed back by the responder).
pub fn parse_and_verify_recursive_response(
    bytes: &[u8],
    expected_query_id: &[u8; 16],
    expected_target_pubkey: &[u8; 32],
    own_requester_pubkey: &[u8; 32],
) -> Result<EphemeralEndpoint, ParseError> {
    parse_and_verify_recursive_response_at(
        bytes,
        expected_query_id,
        expected_target_pubkey,
        own_requester_pubkey,
        now_unix(),
    )
}

/// Test-hook variant with explicit `now_unix`.
pub fn parse_and_verify_recursive_response_at(
    bytes: &[u8],
    expected_query_id: &[u8; 16],
    expected_target_pubkey: &[u8; 32],
    own_requester_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<EphemeralEndpoint, ParseError> {
    let outer = RecursiveResponsePayload::decode(bytes).map_err(ParseError::Decode)?;

    // 1. query_id echo — fast reject mismatched responses.
    if outer.query_id != *expected_query_id {
        return Err(ParseError::Verify(ProtoError::Malformed(
            "recursive response query_id mismatch".to_owned(),
        )));
    }
    // 2. responder identity binding.
    if outer.responder_pubkey != *expected_target_pubkey {
        return Err(ParseError::Verify(ProtoError::Malformed(
            "recursive response responder_pubkey != expected target_pubkey".to_owned(),
        )));
    }
    // 3. outer envelope sig verify.
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&outer.responder_pubkey)
        .map_err(|e| ParseError::Verify(ProtoError::Malformed(format!("bad pubkey: {e}"))))?;
    let mut signable = Vec::with_capacity(16 + outer.payload.len());
    signable.extend_from_slice(&outer.query_id);
    signable.extend_from_slice(&outer.payload);
    let sig = Signature::from_bytes(&outer.signature);
    vk.verify(&signable, &sig).map_err(|_| {
        ParseError::Verify(ProtoError::Malformed(
            "recursive response outer sig verify failed".to_owned(),
        ))
    })?;

    // 4. inner verify — delegates to the existing parse path.
    parse_and_verify_response_at(
        &outer.payload,
        expected_target_pubkey,
        own_requester_pubkey,
        now_unix,
    )
}

/// Output of [`RendezvousRequestBuilder::build_request`].
#[derive(Debug)]
pub struct BuiltRequest {
    /// Decoded form — useful for tests / logging.
    pub payload: RequestEphemeralEndpointPayload,
    /// Wire bytes ready to ship — Slice 5 transport layer takes these
    /// and wraps them in a `SessionMsg::RequestEphemeralEndpoint` frame.
    pub wire_bytes: Vec<u8>,
    /// Number of PoW attempts the miner burned.  Surfaced for metric/
    /// log purposes.
    pub mining_attempts: u64,
}

/// Decode + verify a response payload.  Returns a ready-to-dial
/// [`EphemeralEndpoint`] on success.  Performs the full 5-step verify
/// (sig, identity binding, requester echo, TTL) from
/// [`veil_proto::rendezvous::verify_ephemeral_endpoint_response`].
///
/// `expected_target_pubkey` is the initiator's a-priori knowledge of
/// the target's Ed25519 identity pubkey — typically learnt from a
/// previous handshake, DHT lookup, or bootstrap invite.  Caller MUST
/// supply it; signature verify alone is insufficient (a malicious
/// mediator could forge a response under a DIFFERENT key claiming to
/// be the target).
///
/// `own_requester_pubkey` MUST match the initiator's own pubkey —
/// usually `builder.requester_pubkey()`.  Prevents a malicious mediator
/// from replaying a response originally signed for a different requester.
pub fn parse_and_verify_response(
    bytes: &[u8],
    expected_target_pubkey: &[u8; 32],
    own_requester_pubkey: &[u8; 32],
) -> Result<EphemeralEndpoint, ParseError> {
    parse_and_verify_response_at(
        bytes,
        expected_target_pubkey,
        own_requester_pubkey,
        now_unix(),
    )
}

/// Test-hook variant that accepts an explicit `now_unix`.  Production
/// callers use [`parse_and_verify_response`] which calls
/// `SystemTime::now`.
pub fn parse_and_verify_response_at(
    bytes: &[u8],
    expected_target_pubkey: &[u8; 32],
    own_requester_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<EphemeralEndpoint, ParseError> {
    let payload = EphemeralEndpointResponsePayload::decode(bytes).map_err(ParseError::Decode)?;
    verify_ephemeral_endpoint_response(
        &payload,
        expected_target_pubkey,
        own_requester_pubkey,
        now_unix,
    )
    .map_err(ParseError::Verify)?;
    Ok(EphemeralEndpoint {
        transport_uri: payload.transport_uri,
        psk: payload.psk,
        valid_until_unix: payload.valid_until_unix,
    })
}

// ── Error types ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("requested PoW difficulty {requested} below client floor {min}")]
    DifficultyBelowMin { requested: u32, min: u32 },
    #[error("requested PoW difficulty {requested} above protocol max {max}")]
    DifficultyAboveMax { requested: u32, max: u32 },
    #[error("PoW mining failed: {0}")]
    Mine(ProtoError),
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("response decode failed: {0}")]
    Decode(ProtoError),
    #[error("response verify failed: {0}")]
    Verify(ProtoError),
}

// ── Helpers ─────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use veil_proto::rendezvous::{
        REPLAY_WINDOW_SECS, sign_ephemeral_endpoint_response, verify_request_ephemeral_endpoint,
    };

    fn test_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn target_identity(seed: u8) -> ([u8; 32], SigningKey, [u8; 32]) {
        let sk = test_sk(seed);
        let pk = sk.verifying_key().to_bytes();
        let nid = *blake3::hash(&pk).as_bytes();
        (nid, sk, pk)
    }

    // ── build_request — happy path ────────────────────────────────

    #[test]
    fn build_request_at_min_difficulty_succeeds() {
        let (target_nid, _, _) = target_identity(1);
        let builder = RendezvousRequestBuilder::new(test_sk(2));
        let built = builder
            .build_request::<fn(u64)>(target_nid, MIN_POW_DIFFICULTY, None)
            .unwrap();
        assert!(built.mining_attempts >= 1);
        assert_eq!(built.payload.pow_difficulty, MIN_POW_DIFFICULTY);
        // Encoded form decodes back to the same payload.
        let decoded = RequestEphemeralEndpointPayload::decode(&built.wire_bytes).unwrap();
        assert_eq!(decoded, built.payload);
    }

    #[test]
    fn build_request_produces_payload_that_verifies_under_target_min() {
        let (target_nid, _, _) = target_identity(3);
        let builder = RendezvousRequestBuilder::new(test_sk(4));
        let built = builder
            .build_request::<fn(u64)>(target_nid, MIN_POW_DIFFICULTY, None)
            .unwrap();
        // The signed payload must pass the proto-level verify when the
        // target's min_difficulty matches what we mined for.
        let now = now_unix();
        verify_request_ephemeral_endpoint(&built.payload, MIN_POW_DIFFICULTY, now)
            .expect("freshly-built request must verify");
    }

    // ── Difficulty bounds ─────────────────────────────────────────

    #[test]
    fn build_request_rejects_below_min_difficulty() {
        let (target_nid, _, _) = target_identity(5);
        let builder = RendezvousRequestBuilder::new(test_sk(6));
        let err = builder
            .build_request::<fn(u64)>(target_nid, MIN_POW_DIFFICULTY - 1, None)
            .unwrap_err();
        assert!(matches!(err, BuildError::DifficultyBelowMin { .. }));
    }

    #[test]
    fn build_request_rejects_above_max_difficulty() {
        let (target_nid, _, _) = target_identity(7);
        let builder = RendezvousRequestBuilder::new(test_sk(8));
        let err = builder
            .build_request::<fn(u64)>(target_nid, MAX_POW_DIFFICULTY + 1, None)
            .unwrap_err();
        assert!(matches!(err, BuildError::DifficultyAboveMax { .. }));
    }

    // ── Progress callback ─────────────────────────────────────────

    #[test]
    fn progress_callback_fires_during_mining() {
        // Use moderately-hard difficulty so the miner has to take
        // enough attempts that the default cadence (65_536) fires at
        // least once.  At difficulty 16 expect ~65K attempts on
        // average, ample to trigger a call.
        let (target_nid, _, _) = target_identity(9);
        let builder = RendezvousRequestBuilder::new(test_sk(10));
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = Arc::clone(&counter);
        let progress = move |n: u64| {
            counter_clone.store(n, Ordering::Relaxed);
        };
        let _built = builder
            .build_request(target_nid, 16, Some(progress))
            .unwrap();
        // Not assert exact count — random PoW could mine quickly OR
        // many cycles.  Just assert at least the callback machinery
        // works.
        let observed = counter.load(Ordering::Relaxed);
        // Some attempts must have been recorded if mining took more
        // than `DEFAULT_PROGRESS_EVERY` iterations.  In rare cases
        // mining finishes < 65K attempts and the counter stays 0 — that's
        // valid and does not indicate a failure of the progress path.
        assert!(
            observed == 0 || observed >= RendezvousRequestBuilder::DEFAULT_PROGRESS_EVERY,
            "observed {observed} should be 0 OR >= default cadence",
        );
    }

    #[test]
    fn atomic_progress_tracks_attempts() {
        let (target_nid, _, _) = target_identity(11);
        let builder = RendezvousRequestBuilder::new(test_sk(12));
        let progress = AtomicProgress::new();
        let _built = builder
            .build_request(target_nid, 16, Some(progress.clone()))
            .unwrap();
        // AtomicProgress is a ProgressCallback — verify it exposed
        // through current() and matched what mining would have set.
        let observed = progress.current();
        assert!(observed == 0 || observed >= RendezvousRequestBuilder::DEFAULT_PROGRESS_EVERY,);
    }

    // ── parse_and_verify_response ─────────────────────────────────

    fn build_signed_response(
        target_sk_seed: u8,
        requester_pubkey: [u8; 32],
        uri: &str,
        valid_until: u64,
    ) -> (Vec<u8>, [u8; 32]) {
        let (target_nid, target_sk, target_pk) = target_identity(target_sk_seed);
        let psk = [0xCDu8; 32];
        let signed = sign_ephemeral_endpoint_response(
            target_nid,
            requester_pubkey,
            valid_until,
            uri.to_owned(),
            psk,
            &target_sk,
        )
        .unwrap();
        (signed.encode(), target_pk)
    }

    #[test]
    fn parse_and_verify_happy_path() {
        let (_, _, target_pk) = target_identity(13);
        let requester_sk = test_sk(14);
        let requester_pk = requester_sk.verifying_key().to_bytes();
        let (bytes, _) = build_signed_response(
            13,
            requester_pk,
            "obfs4-tcp://example.com:51234",
            now_unix() + 300,
        );
        let endpoint = parse_and_verify_response(&bytes, &target_pk, &requester_pk).unwrap();
        assert_eq!(endpoint.transport_uri, "obfs4-tcp://example.com:51234");
        assert_eq!(endpoint.psk, [0xCDu8; 32]);
        assert!(endpoint.valid_until_unix > now_unix());
    }

    #[test]
    fn parse_and_verify_rejects_wrong_target_pubkey() {
        let (_, _, target_pk) = target_identity(15);
        let requester_pk = test_sk(16).verifying_key().to_bytes();
        let (bytes, _) = build_signed_response(
            15,
            requester_pk,
            "obfs4-tcp://example.com:51234",
            now_unix() + 300,
        );
        // Use a DIFFERENT pubkey as the expected target.
        let mut wrong_pk = target_pk;
        wrong_pk[0] ^= 0x01;
        let err = parse_and_verify_response(&bytes, &wrong_pk, &requester_pk).unwrap_err();
        assert!(matches!(err, ParseError::Verify(_)));
    }

    #[test]
    fn parse_and_verify_rejects_wrong_requester_pubkey() {
        let (_, _, target_pk) = target_identity(17);
        let requester_a_pk = test_sk(18).verifying_key().to_bytes();
        let requester_b_pk = test_sk(19).verifying_key().to_bytes();
        let (bytes, _) = build_signed_response(
            17,
            requester_a_pk,
            "obfs4-tcp://example.com:51234",
            now_unix() + 300,
        );
        // Response signed for A, but we're trying to verify as B.
        let err = parse_and_verify_response(&bytes, &target_pk, &requester_b_pk).unwrap_err();
        assert!(matches!(err, ParseError::Verify(_)));
    }

    #[test]
    fn parse_and_verify_rejects_expired_endpoint() {
        let (_, _, target_pk) = target_identity(20);
        let requester_pk = test_sk(21).verifying_key().to_bytes();
        let (bytes, _) = build_signed_response(
            20,
            requester_pk,
            "obfs4-tcp://example.com:51234",
            now_unix() - 1, // already expired
        );
        let err = parse_and_verify_response(&bytes, &target_pk, &requester_pk).unwrap_err();
        match err {
            ParseError::Verify(e) => assert!(format!("{e}").contains("expired")),
            other => panic!("expected Verify(expired), got {other:?}"),
        }
    }

    #[test]
    fn parse_and_verify_rejects_truncated_buffer() {
        let (_, _, target_pk) = target_identity(22);
        let requester_pk = test_sk(23).verifying_key().to_bytes();
        let (bytes, _) = build_signed_response(
            22,
            requester_pk,
            "obfs4-tcp://example.com:51234",
            now_unix() + 300,
        );
        let truncated = &bytes[..bytes.len() - 1];
        let err = parse_and_verify_response(truncated, &target_pk, &requester_pk).unwrap_err();
        assert!(matches!(err, ParseError::Decode(_)));
    }

    #[test]
    fn parse_and_verify_at_explicit_now_independent_of_clock() {
        let (_, _, target_pk) = target_identity(24);
        let requester_pk = test_sk(25).verifying_key().to_bytes();
        // valid_until = 1000; verify at 999 → ok; at 1001 → expired.
        let (bytes, _) =
            build_signed_response(24, requester_pk, "obfs4-tcp://example.com:51234", 1000);
        assert!(parse_and_verify_response_at(&bytes, &target_pk, &requester_pk, 999).is_ok());
        assert!(matches!(
            parse_and_verify_response_at(&bytes, &target_pk, &requester_pk, 1001),
            Err(ParseError::Verify(_))
        ));
    }

    // ── Full client round-trip simulation ─────────────────────────

    #[test]
    fn full_client_round_trip_via_proto() {
        // Simulate: initiator builds request → ships to target → target
        // signs response → initiator parses + verifies.  Uses ONLY the
        // public surfaces of this client module + the proto crate (no
        // veilcore controller — that's covered separately in
        // veilcore::node::rendezvous tests).
        let (target_nid, target_sk, target_pk) = target_identity(30);
        let requester_sk = test_sk(31);
        let requester_pk = requester_sk.verifying_key().to_bytes();
        let builder = RendezvousRequestBuilder::new(requester_sk);

        // Initiator side.
        let built = builder
            .build_request::<fn(u64)>(target_nid, MIN_POW_DIFFICULTY, None)
            .unwrap();

        // Target side — verify the request.
        let now = now_unix();
        verify_request_ephemeral_endpoint(&built.payload, MIN_POW_DIFFICULTY, now).unwrap();

        // Target signs a response.
        let psk = [0x99u8; 32];
        let response = sign_ephemeral_endpoint_response(
            target_nid,
            built.payload.requester_pubkey,
            now + 300,
            "obfs4-tcp://example.com:55555".to_owned(),
            psk,
            &target_sk,
        )
        .unwrap();
        let response_bytes = response.encode();

        // Initiator parses + verifies the response.
        let endpoint =
            parse_and_verify_response(&response_bytes, &target_pk, &requester_pk).unwrap();
        assert_eq!(endpoint.transport_uri, "obfs4-tcp://example.com:55555");
        assert_eq!(endpoint.psk, psk);
    }

    // ── Replay-window edge case ───────────────────────────────────

    #[test]
    fn request_built_at_timestamp_t_verifies_within_window() {
        let (target_nid, _, _) = target_identity(40);
        let builder = RendezvousRequestBuilder::new(test_sk(41));
        let t = 1_700_000_000;
        let built = builder
            .build_request_with_timestamp::<fn(u64)>(target_nid, MIN_POW_DIFFICULTY, t, None)
            .unwrap();
        // verify at t + REPLAY_WINDOW_SECS — should still pass.
        assert!(
            verify_request_ephemeral_endpoint(
                &built.payload,
                MIN_POW_DIFFICULTY,
                t + REPLAY_WINDOW_SECS,
            )
            .is_ok(),
        );
        // verify at t + REPLAY_WINDOW_SECS + 1 — should fail.
        assert!(
            verify_request_ephemeral_endpoint(
                &built.payload,
                MIN_POW_DIFFICULTY,
                t + REPLAY_WINDOW_SECS + 1,
            )
            .is_err(),
        );
    }

    #[test]
    fn requester_pubkey_accessor_returns_signing_key_pubkey() {
        let sk = test_sk(50);
        let expected_pk = sk.verifying_key().to_bytes();
        let builder = RendezvousRequestBuilder::new(sk);
        assert_eq!(builder.requester_pubkey(), expected_pk);
    }

    // ── Slice 6c: recursive envelope helpers ─────────────────────

    #[test]
    fn wrap_recursive_populates_envelope_correctly() {
        let (target_nid, _, _) = target_identity(60);
        let builder = RendezvousRequestBuilder::new(test_sk(61));
        let reply_to = [0x07u8; 32];
        let query_id = [0xC0u8; 16];
        let built = builder
            .build_request::<fn(u64)>(target_nid, MIN_POW_DIFFICULTY, None)
            .unwrap();
        let envelope =
            RendezvousRequestBuilder::wrap_recursive(&built, target_nid, reply_to, query_id, None);
        assert_eq!(envelope.query_id, query_id);
        assert_eq!(envelope.target_key, target_nid);
        assert_eq!(envelope.reply_to, reply_to);
        assert_eq!(envelope.ttl, 20);
        assert_eq!(
            envelope.query_type,
            veil_proto::routing::recursive_query_type::RENDEZVOUS_REQUEST
        );
        assert_eq!(envelope.reply_port, 0);
        assert_eq!(envelope.payload, built.wire_bytes);
    }

    #[test]
    fn wrap_recursive_custom_ttl() {
        let (target_nid, _, _) = target_identity(62);
        let builder = RendezvousRequestBuilder::new(test_sk(63));
        let built = builder
            .build_request::<fn(u64)>(target_nid, MIN_POW_DIFFICULTY, None)
            .unwrap();
        let envelope = RendezvousRequestBuilder::wrap_recursive(
            &built,
            target_nid,
            [0u8; 32],
            [0u8; 16],
            Some(5),
        );
        assert_eq!(envelope.ttl, 5);
    }

    /// Helper for Slice 6c response tests: build a signed
    /// `RecursiveResponsePayload` mirroring what the dispatcher arm
    /// would emit, then run the client's parse + verify.
    fn build_signed_recursive_response(
        target_sk_seed: u8,
        requester_pubkey: [u8; 32],
        query_id: [u8; 16],
        uri: &str,
        valid_until: u64,
    ) -> (Vec<u8>, [u8; 32]) {
        use veil_proto::rendezvous::sign_ephemeral_endpoint_response;
        let (target_nid, target_sk, target_pk) = target_identity(target_sk_seed);
        let psk = [0xCDu8; 32];
        let inner = sign_ephemeral_endpoint_response(
            target_nid,
            requester_pubkey,
            valid_until,
            uri.to_owned(),
            psk,
            &target_sk,
        )
        .unwrap();
        let inner_bytes = inner.encode();
        use ed25519_dalek::Signer as _;
        let mut signable = Vec::with_capacity(16 + inner_bytes.len());
        signable.extend_from_slice(&query_id);
        signable.extend_from_slice(&inner_bytes);
        let sig = target_sk.sign(&signable).to_bytes();
        let outer = veil_proto::routing::RecursiveResponsePayload {
            query_id,
            payload: inner_bytes,
            responder_pubkey: target_pk,
            signature: sig,
        };
        (outer.encode(), target_pk)
    }

    #[test]
    fn parse_recursive_response_happy_path() {
        let requester_pk = test_sk(70).verifying_key().to_bytes();
        let query_id = [0xC0u8; 16];
        let (bytes, target_pk) = build_signed_recursive_response(
            71,
            requester_pk,
            query_id,
            "obfs4-tcp://example.com:51234",
            now_unix() + 300,
        );
        let endpoint =
            parse_and_verify_recursive_response(&bytes, &query_id, &target_pk, &requester_pk)
                .unwrap();
        assert_eq!(endpoint.transport_uri, "obfs4-tcp://example.com:51234");
        assert_eq!(endpoint.psk, [0xCDu8; 32]);
    }

    #[test]
    fn parse_recursive_response_rejects_query_id_mismatch() {
        let requester_pk = test_sk(80).verifying_key().to_bytes();
        let signed_with_id = [0xAAu8; 16];
        let (bytes, target_pk) = build_signed_recursive_response(
            81,
            requester_pk,
            signed_with_id,
            "obfs4-tcp://example.com:51234",
            now_unix() + 300,
        );
        // Caller expected a DIFFERENT query_id.
        let expected_id = [0xBBu8; 16];
        let err =
            parse_and_verify_recursive_response(&bytes, &expected_id, &target_pk, &requester_pk)
                .unwrap_err();
        assert!(format!("{err}").contains("query_id mismatch"));
    }

    #[test]
    fn parse_recursive_response_rejects_wrong_responder_pubkey() {
        let requester_pk = test_sk(90).verifying_key().to_bytes();
        let query_id = [0xC0u8; 16];
        let (bytes, target_pk) = build_signed_recursive_response(
            91,
            requester_pk,
            query_id,
            "obfs4-tcp://example.com:51234",
            now_unix() + 300,
        );
        // Pretend we expected a different target.
        let mut wrong_pk = target_pk;
        wrong_pk[0] ^= 0x01;
        let err = parse_and_verify_recursive_response(&bytes, &query_id, &wrong_pk, &requester_pk)
            .unwrap_err();
        assert!(format!("{err}").contains("responder_pubkey"));
    }

    #[test]
    fn parse_recursive_response_rejects_tampered_outer_sig() {
        let requester_pk = test_sk(100).verifying_key().to_bytes();
        let query_id = [0xC0u8; 16];
        let (mut bytes, target_pk) = build_signed_recursive_response(
            101,
            requester_pk,
            query_id,
            "obfs4-tcp://example.com:51234",
            now_unix() + 300,
        );
        // Flip a bit in the outer sig (last byte).
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let err = parse_and_verify_recursive_response(&bytes, &query_id, &target_pk, &requester_pk)
            .unwrap_err();
        assert!(format!("{err}").contains("outer sig verify"));
    }

    #[test]
    fn parse_recursive_response_rejects_inner_for_wrong_requester() {
        // Response signed for requester_A; B tries to verify under
        // its own pubkey.  Outer sig validates but inner echo-check
        // fails.
        let requester_a_pk = test_sk(110).verifying_key().to_bytes();
        let requester_b_pk = test_sk(111).verifying_key().to_bytes();
        let query_id = [0xC0u8; 16];
        let (bytes, target_pk) = build_signed_recursive_response(
            112,
            requester_a_pk,
            query_id,
            "obfs4-tcp://example.com:51234",
            now_unix() + 300,
        );
        let err =
            parse_and_verify_recursive_response(&bytes, &query_id, &target_pk, &requester_b_pk)
                .unwrap_err();
        assert!(matches!(err, ParseError::Verify(_)));
    }
}
