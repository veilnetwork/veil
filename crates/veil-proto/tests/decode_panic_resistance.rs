//! panic-resistance for every wire-decode path.
//!
//! In an authoritarian threat-model the network is full of hostile
//! peers who control the bytes they send. If a single `decode` on
//! any wire-frame payload can be made to panic by hand-crafted input
//! that's a one-shot DoS per victim — drop a hostile peer in front of
//! a target, wait for them to handshake, send the trigger frame
//! target's process aborts. Repeat across the network for a coordinated
//! kill of every node a sybil cluster can reach.
//!
//! This test sweeps every public `Payload::decode(&[u8])` entry in
//! `veil-proto` against a fixed set of adversarial byte inputs:
//! * empty buffer
//! * 1 byte
//! * 4 bytes (smaller than most fixed-size payloads)
//! * 1 KiB pseudo-random
//! * 64 KiB pseudo-random
//! * 4 KiB of 0xFF (matches DHT_VALUE_BYTES; max-size lengths everywhere)
//! * truncated length-prefix patterns: `u16::MAX` / `u32::MAX` / `u64::MAX`
//!   in the leading bytes followed by zero or near-zero remainder
//!
//! For each input × decoder combination, the test asserts that the
//! call returns a `Result` (whatever variant) without panicking.
//! `decode` is allowed to return `Ok(_)` for *some* random inputs;
//! all that matters is that the process keeps running.
//!
//! `proptest` adds a randomized layer: 256 cases per decoder × random
//! length 0..=4 KiB × random bytes. Combined coverage stays under a
//! second on a fast machine; the test runs on every `cargo test`.
//!
//! Adding a new wire-decode path: append it to `DECODERS` below. CI
//! will then sweep it under the full adversarial battery automatically.
//!
//! Strategic context: the dispatcher's `dispatch` function calls
//! `*Payload::decode(body)` for every routed family/msg_type combination
//! (see `veilcore/src/node/dispatcher/`). This registry aims to cover EVERY
//! remote-peer-reachable wire decoder so the dispatcher cannot be panic'd by a
//! hostile body. It is a maintained allow-list, NOT an automatic guarantee:
//! a decoder that exists but is missing from `decoders()` is NOT swept, so the
//! coverage holds only as far as the list is kept in sync. When you add a new
//! `decode(&[u8])` on a remote-peer payload, append it below. Out of scope:
//! `ipc::*` decoders (local, uid-gated loopback — not remote-peer bytes) and
//! signature-verify paths (covered by their own crates' tests).

use veil_proto as p;

/// Type-erased decoder: takes a byte slice, returns whether the call
/// completed without panicking. All real decoders return `Result<T
/// ProtoError>`; we discard the success/error variant — only "did the
/// process survive" matters for this test.
type DecoderFn = fn(&[u8]);

macro_rules! decoder {
    ($payload:path) => {
        |buf: &[u8]| {
            let _ = <$payload>::decode(buf);
        }
    };
}

/// Registry of every `decode(&[u8]) -> Result<_, ProtoError>` entry
/// that processes remote-peer bytes. Names are stringified for
/// failure-mode diagnostics; if an assertion fires under proptest
/// shrinking will surface (decoder_name, byte_pattern).
fn decoders() -> Vec<(&'static str, DecoderFn)> {
    vec![
        // ── anycast ────────────────────────────────────────────────────
        ("AnycastRecord", decoder!(p::anycast::AnycastRecord)),
        ("AnycastList", decoder!(p::anycast::AnycastList)),
        (
            "AnycastResolvePayload",
            decoder!(p::anycast::AnycastResolvePayload),
        ),
        (
            "AnycastResultPayload",
            decoder!(p::anycast::AnycastResultPayload),
        ),
        (
            "AnycastAdvertisePayload",
            decoder!(p::anycast::AnycastAdvertisePayload),
        ),
        (
            "AnycastWithdrawPayload",
            decoder!(p::anycast::AnycastWithdrawPayload),
        ),
        // ── app (LocalApp / veil App frames) ────────────────────────
        ("AppOpenPayload", decoder!(p::app::AppOpenPayload)),
        ("AppDataPayload", decoder!(p::app::AppDataPayload)),
        ("AppClosePayload", decoder!(p::app::AppClosePayload)),
        ("AppSendPayload", decoder!(p::app::AppSendPayload)),
        // ── control (live in `control.rs`, not `routing.rs`) ──────────
        (
            "NeighborOfferPayload",
            decoder!(p::control::NeighborOfferPayload),
        ),
        ("RouteProbePayload", decoder!(p::control::RouteProbePayload)),
        ("RouteReplyPayload", decoder!(p::control::RouteReplyPayload)),
        (
            "NatProbeRequestPayload",
            decoder!(p::control::NatProbeRequestPayload),
        ),
        (
            "NatProbeReplyPayload",
            decoder!(p::control::NatProbeReplyPayload),
        ),
        (
            "NatRelayRequestPayload",
            decoder!(p::control::NatRelayRequestPayload),
        ),
        // ── delivery ───────────────────────────────────────────────────
        ("ForwardPayload", decoder!(p::delivery::ForwardPayload)),
        (
            "DeliveryStatusPayload",
            decoder!(p::delivery::DeliveryStatusPayload),
        ),
        // ── discovery (signed DHT records + IPC payloads) ─────────────
        (
            "AnnounceAttachmentPayload",
            decoder!(p::discovery::AnnounceAttachmentPayload),
        ),
        (
            "GetAttachmentPayload",
            decoder!(p::discovery::GetAttachmentPayload),
        ),
        (
            "GetAppEndpointPayload",
            decoder!(p::discovery::GetAppEndpointPayload),
        ),
        (
            "FindNodeV2Payload",
            decoder!(p::discovery::FindNodeV2Payload),
        ),
        (
            "ResolveTransportPayload",
            decoder!(p::discovery::ResolveTransportPayload),
        ),
        ("FindValuePayload", decoder!(p::discovery::FindValuePayload)),
        ("StorePayload", decoder!(p::discovery::StorePayload)),
        ("DeletePayload", decoder!(p::discovery::DeletePayload)),
        // ── routing ────────────────────────────────────────────────────
        (
            "RouteAnnouncePayload",
            decoder!(p::routing::RouteAnnouncePayload),
        ),
        (
            "RouteWithdrawPayload",
            decoder!(p::routing::RouteWithdrawPayload),
        ),
        (
            "RouteRequestPayload",
            decoder!(p::routing::RouteRequestPayload),
        ),
        (
            "RouteResponsePayload",
            decoder!(p::routing::RouteResponsePayload),
        ),
        (
            "RouteUpdatePayload",
            decoder!(p::routing::RouteUpdatePayload),
        ),
        (
            "PowChallengePayload",
            decoder!(p::routing::PowChallengePayload),
        ),
        (
            "PowResponsePayload",
            decoder!(p::routing::PowResponsePayload),
        ),
        ("PowAcceptPayload", decoder!(p::routing::PowAcceptPayload)),
        (
            "RecursiveQueryPayload",
            decoder!(p::routing::RecursiveQueryPayload),
        ),
        (
            "RecursiveResponsePayload",
            decoder!(p::routing::RecursiveResponsePayload),
        ),
        (
            "VersionVectorSyncPayload",
            decoder!(p::routing::VersionVectorSyncPayload),
        ),
        (
            "RouteDiscoverOfferPayload",
            decoder!(p::routing::RouteDiscoverOfferPayload),
        ),
        (
            "RouteAnnounceAliasedPayload",
            decoder!(p::routing::RouteAnnounceAliasedPayload),
        ),
        (
            "RouteWithdrawAliasedPayload",
            decoder!(p::routing::RouteWithdrawAliasedPayload),
        ),
        // ── identity / sovereign-identity wire types ───────────────────
        (
            "IdentityDocument",
            decoder!(p::identity_document::IdentityDocument),
        ),
        (
            "InstanceRegistry",
            decoder!(p::instance_registry::InstanceRegistry),
        ),
        ("NameClaim", decoder!(p::name_claim_v2::NameClaim)),
        ("IdentityProof", decoder!(p::identity_proof::IdentityProof)),
        ("PairingInvite", decoder!(p::pairing_invite::PairingInvite)),
        ("MlKemKeyCert", decoder!(p::mlkem_cert::MlKemKeyCert)),
        // ── e2e / mailbox / pex / mesh / epidemic ──────────────────────
        ("EpidemicPayload", decoder!(p::epidemic::EpidemicPayload)),
        ("E2eEnvelope", decoder!(p::e2e::E2eEnvelope)),
        ("RelayChainHop", decoder!(p::relay_chain::RelayChainHop)),
        // ── pex (random-walk peer exchange) ────────────────────────────
        ("PexWalk", decoder!(p::pex::PexWalk)),
        ("PexChallenge", decoder!(p::pex::PexChallenge)),
        ("PexResponse", decoder!(p::pex::PexResponse)),
        ("PexPeer", decoder!(p::pex::PexPeer)),
        ("PexResult", decoder!(p::pex::PexResult)),
        // ── delivery (nested relay/transit/chunk payloads) ─────────────
        ("DeliveryEnvelope", decoder!(p::delivery::DeliveryEnvelope)),
        (
            "ChunkedEnvelopePayload",
            decoder!(p::delivery::ChunkedEnvelopePayload),
        ),
        (
            "TransitFramePayload",
            decoder!(p::delivery::TransitFramePayload),
        ),
        (
            "RecursiveRelayPayload",
            decoder!(p::delivery::RecursiveRelayPayload),
        ),
        ("RelayPathPayload", decoder!(p::delivery::RelayPathPayload)),
        // ── mesh (realm beacon/ack/frame) ──────────────────────────────
        ("MeshFrame", decoder!(p::mesh::MeshFrame)),
        ("MeshBeaconPayload", decoder!(p::mesh::MeshBeaconPayload)),
        ("MeshAckPayload", decoder!(p::mesh::MeshAckPayload)),
        // ── rendezvous (ephemeral endpoint) ────────────────────────────
        (
            "RequestEphemeralEndpointPayload",
            decoder!(p::rendezvous::RequestEphemeralEndpointPayload),
        ),
        (
            "EphemeralEndpointResponsePayload",
            decoder!(p::rendezvous::EphemeralEndpointResponsePayload),
        ),
        // ── diag (ping/trace) ──────────────────────────────────────────
        ("DiagPingPayload", decoder!(p::diag::DiagPingPayload)),
        ("DiagPongPayload", decoder!(p::diag::DiagPongPayload)),
        (
            "DiagTraceProbePayload",
            decoder!(p::diag::DiagTraceProbePayload),
        ),
        (
            "DiagTraceHopPayload",
            decoder!(p::diag::DiagTraceHopPayload),
        ),
        // ── recipient (offset-based decode_from) ───────────────────────
        ("Recipient::decode_from", |buf: &[u8]| {
            let mut pos = 0usize;
            let _ = p::recipient::Recipient::decode_from(buf, &mut pos);
        }),
        ("Recipient::decode_fixed_from", |buf: &[u8]| {
            let mut pos = 0usize;
            let _ = p::recipient::Recipient::decode_fixed_from(buf, &mut pos);
        }),
    ]
}

/// Adversarial fixed byte patterns covering corner cases that random
/// fuzzing would only hit by accident: zero length, length-1 (smaller
/// than every fixed-size header), maximally-large length-prefix
/// values that could overflow naive `pos + len` arithmetic, all-`0xFF`
/// (worst-case for unsigned-decoded-as-signed bugs).
fn adversarial_inputs() -> Vec<(&'static str, Vec<u8>)> {
    let mut out = vec![
        ("empty", Vec::new()),
        ("one_byte_zero", vec![0u8]),
        ("one_byte_ff", vec![0xFFu8]),
        ("four_zeros", vec![0u8; 4]),
        ("four_ffs", vec![0xFFu8; 4]),
        ("max_dht_value", vec![0xFFu8; 4096]),
    ];

    // Length-prefix-overflow patterns: an attacker who controls the
    // first 2/4/8 bytes can claim u16/u32/u64::MAX worth of payload
    // follows. Naive `pos + len` arithmetic on a `usize` of that size
    // overflows in debug builds; release builds wrap and `get(..)`
    // returns None safely — but we still want a regression test that
    // catches a future inversion.
    let mut u16_max_len = vec![0u8; 16];
    u16_max_len[0..2].copy_from_slice(&u16::MAX.to_be_bytes());
    out.push(("u16_max_length_prefix", u16_max_len));

    let mut u32_max_len = vec![0u8; 32];
    u32_max_len[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
    out.push(("u32_max_length_prefix", u32_max_len));

    let mut u64_max_len = vec![0u8; 64];
    u64_max_len[0..8].copy_from_slice(&u64::MAX.to_be_bytes());
    out.push(("u64_max_length_prefix", u64_max_len));

    // Random bytes (deterministic seed for reproducibility).
    let mut rng_state: u64 = 0xDEAD_BEEF_CAFE_F00D_u64;
    let mut next = || {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        rng_state
    };
    for (label, len) in &[
        ("rand_64B", 64usize),
        ("rand_1KB", 1024),
        ("rand_64KB", 65_536),
    ] {
        let mut buf = Vec::with_capacity(*len);
        while buf.len() < *len {
            let v = next();
            buf.extend_from_slice(&v.to_be_bytes());
        }
        buf.truncate(*len);
        out.push((label, buf));
    }

    out
}

#[test]
fn no_decoder_panics_on_adversarial_inputs() {
    let decoders = decoders();
    let inputs = adversarial_inputs();
    let mut total = 0usize;

    for (name, dec) in &decoders {
        for (label, bytes) in &inputs {
            // Wrap each call in a catch_unwind so a panic in ONE decoder
            // doesn't abort the whole sweep — we want to surface every
            // panic site at once, not the first one.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dec(bytes);
            }));
            assert!(
                result.is_ok(),
                "decoder `{name}` panicked on adversarial input \
                 `{label}` ({} bytes).  This is a one-shot DoS attack \
                 surface — any remote peer who can guess the right framing \
                 sends this body and the receiving node aborts.  Investigate \
                 and replace the panicking unwrap/expect with a Result error.",
                bytes.len(),
            );
            total += 1;
        }
    }
    eprintln!("swept {} decoder × adversarial-input combos cleanly", total);
}

// ── Property-test layer: random length × random bytes per decoder ────────────

use proptest::prelude::*;

proptest! {
    /// Random-bytes fuzz: 256 cases per decoder, length uniform 0..=4096.
    /// Catches surprising panics that fixed adversarial inputs miss
    /// (e.g. specific bit patterns in length-prefix fields, narrow ranges
    /// that confuse parser state machines).
    #[test]
    fn decoders_dont_panic_on_random_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..=4096),
    ) {
        for (name, dec) in decoders() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dec(&bytes);
            }));
            prop_assert!(
                result.is_ok(),
                "decoder `{name}` panicked on {} random bytes",
                bytes.len(),
            );
        }
    }
}
