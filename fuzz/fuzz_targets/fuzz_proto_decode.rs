//! Fuzz target for protocol conformance.
//!
//! Covers proto types introduced in Epics 243-246:
//! * `RelayChainHop`
//! * `AnnounceAttachmentPayload` with optional `EphemeralEndpoint` TLV
//! * `EphemeralEndpoint::decode_from_tlv`
//! * `MeshFrame`
//!
//! No arbitrary byte slice must cause a panic — decoders may return `Err` / `None`
//! but must never panic, abort, or produce undefined behaviour.
#![no_main]
use libfuzzer_sys::fuzz_target;

use veilcore::proto::{
    discovery::{AnnounceAttachmentPayload, EphemeralEndpoint},
    mesh::MeshFrame,
    relay_chain::RelayChainHop,
};

fuzz_target!(|data: &[u8]| {
    // RelayChainHop — must never panic on arbitrary input.
    let _ = RelayChainHop::decode(data);

    // AnnounceAttachmentPayload — includes optional TLV.
    let _ = AnnounceAttachmentPayload::decode(data);

    // EphemeralEndpoint TLV scanner — parses arbitrary TLV blocks.
    let _ = EphemeralEndpoint::decode_from_tlv(data);

    // MeshFrame — realm-scoped mesh packet.
    let _ = MeshFrame::decode(data);
});
