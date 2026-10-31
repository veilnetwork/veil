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
//! Adding a new wire-decode path: append it to `decoders()` below. CI
//! will then sweep it under the full adversarial battery automatically.
//!
//! Strategic context: the dispatcher's `dispatch` function calls
//! `*Payload::decode(body)` for every routed family/msg_type combination
//! (see `veilcore/src/node/dispatcher/`). This registry aims to cover EVERY
//! remote-peer-reachable wire decoder so the dispatcher cannot be panic'd by a
//! hostile body. It is a maintained allow-list, NOT an automatic guarantee:
//! a decoder that exists but is missing from `decoders()` is NOT swept. A
//! source-inventory guard now detects public inherent `decode` omissions;
//! macro-generated and nonstandard entrypoints still require review. When you add a new
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
        (
            stringify!($payload),
            (|buf: &[u8]| {
                let _ = <$payload>::decode(buf);
            }) as DecoderFn,
        )
    };
}

/// Registry of every `decode(&[u8]) -> Result<_, ProtoError>` entry
/// that processes remote-peer bytes. Names are stringified for
/// failure-mode diagnostics; if an assertion fires under proptest
/// shrinking will surface (decoder_name, byte_pattern).
fn decoders() -> Vec<(&'static str, DecoderFn)> {
    vec![
        // Session negotiation is reachable before peer authentication.
        decoder!(p::session::HelloPayload),
        decoder!(p::session::IdentityPayload),
        decoder!(p::session::CapabilitiesPayload),
        decoder!(p::session::KeyAgreementPayload),
        decoder!(p::session::SessionConfirmPayload),
        decoder!(p::session::AttachPayload),
        decoder!(p::session::DetachPayload),
        decoder!(p::session::SleepAdvertisementPayload),
        decoder!(p::session::TransportMigrationNotifyPayload),
        decoder!(p::session::KeepalivePayload),
        decoder!(p::session::RekeyPayload),
        decoder!(p::session::MlKemRekeyEkPayload),
        decoder!(p::session::HybridKexCtPayload),
        decoder!(p::session::HandoffInitPayload),
        decoder!(p::session::HandoffAckPayload),
        decoder!(p::session::HandoffAttachPayload),
        decoder!(p::session::HandoffChallengePayload),
        decoder!(p::session::HandoffResponsePayload),
        // ── anycast ────────────────────────────────────────────────────
        decoder!(p::anycast::AnycastRecord),
        decoder!(p::anycast::AnycastList),
        decoder!(p::anycast::AnycastResolvePayload),
        decoder!(p::anycast::AnycastResultPayload),
        decoder!(p::anycast::AnycastAdvertisePayload),
        decoder!(p::anycast::AnycastWithdrawPayload),
        // ── app (LocalApp / veil App frames) ────────────────────────
        decoder!(p::app::AppOpenPayload),
        decoder!(p::app::AppDataPayload),
        decoder!(p::app::AppClosePayload),
        decoder!(p::app::AppSendPayload),
        // ── control (live in `control.rs`, not `routing.rs`) ──────────
        decoder!(p::control::NeighborOfferPayload),
        decoder!(p::control::RouteProbePayload),
        decoder!(p::control::RouteReplyPayload),
        decoder!(p::control::NatProbeRequestPayload),
        decoder!(p::control::NatProbeReplyPayload),
        decoder!(p::control::NatRelayRequestPayload),
        // ── delivery ───────────────────────────────────────────────────
        decoder!(p::delivery::ForwardPayload),
        decoder!(p::delivery::DeliveryStatusPayload),
        // ── discovery (signed DHT records + IPC payloads) ─────────────
        decoder!(p::discovery::AnnounceAttachmentPayload),
        decoder!(p::discovery::GetAttachmentPayload),
        decoder!(p::discovery::GetAppEndpointPayload),
        decoder!(p::discovery::FindNodeV2Payload),
        decoder!(p::discovery::ResolveTransportPayload),
        decoder!(p::discovery::FindValuePayload),
        decoder!(p::discovery::StorePayload),
        decoder!(p::discovery::DeletePayload),
        // ── routing ────────────────────────────────────────────────────
        decoder!(p::routing::RouteAnnouncePayload),
        decoder!(p::routing::RouteWithdrawPayload),
        decoder!(p::routing::RouteRequestPayload),
        decoder!(p::routing::RouteResponsePayload),
        decoder!(p::routing::PowChallengePayload),
        decoder!(p::routing::PowResponsePayload),
        decoder!(p::routing::PowAcceptPayload),
        decoder!(p::routing::RecursiveQueryPayload),
        decoder!(p::routing::RecursiveResponsePayload),
        decoder!(p::routing::RouteDiscoverOfferPayload),
        decoder!(p::routing::RouteAnnounceAliasedPayload),
        decoder!(p::routing::RouteWithdrawAliasedPayload),
        // ── identity / sovereign-identity wire types ───────────────────
        decoder!(p::identity_document::IdentityDocument),
        decoder!(p::instance_registry::InstanceRegistry),
        decoder!(p::name_claim_v2::NameClaim),
        decoder!(p::identity_proof::IdentityProof),
        decoder!(p::pairing_invite::PairingInvite),
        decoder!(p::mlkem_cert::MlKemKeyCert),
        // ── e2e / mailbox / pex / mesh / epidemic ──────────────────────
        decoder!(p::epidemic::EpidemicPayload),
        decoder!(p::e2e::E2eEnvelope),
        decoder!(p::relay_chain::RelayChainHop),
        // ── pex (random-walk peer exchange) ────────────────────────────
        decoder!(p::pex::PexWalk),
        decoder!(p::pex::PexChallenge),
        decoder!(p::pex::PexResponse),
        decoder!(p::pex::PexPeer),
        decoder!(p::pex::PexResult),
        // ── delivery (nested relay/transit/chunk payloads) ─────────────
        decoder!(p::delivery::DeliveryEnvelope),
        decoder!(p::delivery::ChunkedEnvelopePayload),
        decoder!(p::delivery::TransitFramePayload),
        decoder!(p::delivery::RecursiveRelayPayload),
        decoder!(p::delivery::RelayPathPayload),
        // ── mesh (realm beacon/ack/frame) ──────────────────────────────
        decoder!(p::mesh::MeshFrame),
        decoder!(p::mesh::MeshBeaconPayload),
        decoder!(p::mesh::MeshAckPayload),
        // ── rendezvous (ephemeral endpoint) ────────────────────────────
        decoder!(p::rendezvous::RequestEphemeralEndpointPayload),
        decoder!(p::rendezvous::EphemeralEndpointResponsePayload),
        // ── diag (ping/trace) ──────────────────────────────────────────
        decoder!(p::diag::DiagPingPayload),
        decoder!(p::diag::DiagPongPayload),
        decoder!(p::diag::DiagTraceProbePayload),
        decoder!(p::diag::DiagTraceHopPayload),
        decoder!(p::anycast::AnycastReportFailurePayload),
        decoder!(p::app::AppReceiptPayload),
        decoder!(p::app::AppWindowUpdatePayload),
        decoder!(p::app::AppRtDataPayload),
        decoder!(p::discovery::EpochDifficultyRecord),
        decoder!(p::discovery::GatewayRef),
        decoder!(p::discovery::AttachmentResponse),
        decoder!(p::discovery::AppEndpointResponse),
        decoder!(p::discovery::NodeContact),
        decoder!(p::discovery::FindNodeResponse),
        decoder!(p::discovery::FindNodeV2Response),
        decoder!(p::discovery::SignedTransportAnnouncement),
        decoder!(p::discovery::ResolveTransportResponse),
        decoder!(p::discovery::FindValueResponse),
        decoder!(p::discovery::DhtValue),
        decoder!(p::introducer::IntroduceRequest),
        decoder!(p::pair_session::PairingHello),
        decoder!(p::pair_session::PairingCert),
        decoder!(p::pair_session::PairingConfirm),
        decoder!(p::prekey_bundle::PrekeyBundle),
        decoder!(p::recipient::Recipient),
        decoder!(p::relay_key::RelayKeyRecord),
        decoder!(p::routing::RouteDiscoveryPacket),
        decoder!(p::session::SessionTicket),
        decoder!(p::transport_hints::TransportHintResultPayload),
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

/// Catch registry drift without a fragile count or hand-written second list.
/// Parse inherent public decode methods from production source. The only
/// module exemptions are local IPC, whose authenticated-host scope is stated
/// above; every other one-slice decoder must be executable in the sweep.
#[test]
fn every_public_wire_decode_is_registered() {
    use std::collections::BTreeSet;
    fn collect(items: &[syn::Item], prefix: &str, found: &mut BTreeSet<String>) {
        for item in items {
            match item {
                syn::Item::Mod(module) => {
                    if module.attrs.iter().any(|a| {
                        a.path().is_ident("cfg")
                            && a.parse_args::<syn::Path>()
                                .is_ok_and(|p| p.is_ident("test"))
                    }) {
                        continue;
                    }
                    if let Some((_, items)) = &module.content {
                        collect(items, &format!("{prefix}::{}", module.ident), found);
                    }
                }
                syn::Item::Impl(implementation) if implementation.trait_.is_none() => {
                    let syn::Type::Path(ty) = implementation.self_ty.as_ref() else {
                        continue;
                    };
                    for item in &implementation.items {
                        let syn::ImplItem::Fn(method) = item else {
                            continue;
                        };
                        if method.sig.ident != "decode"
                            || !matches!(method.vis, syn::Visibility::Public(_))
                        {
                            continue;
                        }
                        assert_eq!(
                            method.sig.inputs.len(),
                            1,
                            "classify new decoder signature explicitly"
                        );
                        let name = ty.path.segments.last().unwrap().ident.to_string();
                        found.insert(format!("p::{prefix}::{name}"));
                    }
                }
                _ => {}
            }
        }
    }
    let mut source = BTreeSet::new();
    for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let module = path.file_stem().unwrap().to_str().unwrap();
        if matches!(module, "ipc" | "ipc_lossy_batch") {
            continue;
        }
        let parsed = syn::parse_file(&std::fs::read_to_string(&path).unwrap()).unwrap();
        collect(&parsed.items, module, &mut source);
    }
    let registry: BTreeSet<_> = decoders()
        .into_iter()
        .map(|(name, _)| name.to_owned())
        .collect();
    let missing: Vec<_> = source.difference(&registry).collect();
    assert!(
        missing.is_empty(),
        "wire decoders absent from executable panic sweep: {missing:?}"
    );
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
