//! Fuzz target for protocol-decoder robustness against untrusted bytes.
//!
//! Every decoder below parses bytes that originate from a REMOTE peer, so an
//! arbitrary byte slice must never panic, abort, over-allocate, or produce
//! undefined behaviour — decoders may only return `Err` / `None`.
//!
//! Coverage (expanded in audit cycle-1 from the original 4 decoders):
//! * Epics 243-246: `RelayChainHop`, `AnnounceAttachmentPayload` (+ optional
//!   `EphemeralEndpoint` TLV), `EphemeralEndpoint::decode_from_tlv`, `MeshFrame`.
//! * Gossip / E2E: `EpidemicPayload`, `E2eEnvelope`.
//! * Routing / recursive-DHT plane: `RouteAnnouncePayload`,
//!   `RouteResponsePayload`, `RecursiveQueryPayload`, `RecursiveResponsePayload`.
//! * DHT store/find plane (the cache-poison surface — see the ML-KEM resolver
//!   validated-fast-path fix): `StorePayload`, `DhtValue`, `FindValuePayload`,
//!   `FindNodeResponse`.
#![no_main]
use libfuzzer_sys::fuzz_target;

use veilcore::proto::{
    discovery::{
        AnnounceAttachmentPayload, DhtValue, EphemeralEndpoint, FindNodeResponse, FindValuePayload,
        StorePayload,
    },
    e2e::E2eEnvelope,
    epidemic::EpidemicPayload,
    mesh::MeshFrame,
    relay_chain::RelayChainHop,
    routing::{
        RecursiveQueryPayload, RecursiveResponsePayload, RouteAnnouncePayload, RouteResponsePayload,
    },
};

fuzz_target!(|data: &[u8]| {
    // ── Epics 243-246 (original coverage) ──────────────────────────────
    let _ = RelayChainHop::decode(data);
    let _ = AnnounceAttachmentPayload::decode(data);
    let _ = EphemeralEndpoint::decode_from_tlv(data);
    let _ = MeshFrame::decode(data);

    // ── Gossip + end-to-end envelopes ──────────────────────────────────
    let _ = EpidemicPayload::decode(data);
    let _ = E2eEnvelope::decode(data);

    // ── Routing / recursive-DHT plane (attacker-reachable frames) ───────
    let _ = RouteAnnouncePayload::decode(data);
    let _ = RouteResponsePayload::decode(data);
    let _ = RecursiveQueryPayload::decode(data);
    let _ = RecursiveResponsePayload::decode(data);

    // ── DHT store/find plane — the cache-poison surface ────────────────
    let _ = StorePayload::decode(data);
    let _ = DhtValue::decode(data);
    let _ = FindValuePayload::decode(data);
    let _ = FindNodeResponse::decode(data);
});
