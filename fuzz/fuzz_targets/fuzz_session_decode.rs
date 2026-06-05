//! Fuzz target for session-plane payload decode functions.
//!
//! Verifies that no arbitrary byte slice causes a panic in any session
//! payload decoder. Only the `Err` / `Ok` distinction matters — panics
//! are bugs.
#![no_main]
use libfuzzer_sys::fuzz_target;

use veilcore::proto::session::{
    CapabilitiesPayload, DetachPayload, HelloPayload,
    IdentityPayload, KeepalivePayload, KeyAgreementPayload, RekeyPayload,
    SessionConfirmPayload,
};

fuzz_target!(|data: &[u8]| {
    // None of these must panic — they may return Err but never panic.
    let _ = HelloPayload::decode(data);
    let _ = IdentityPayload::decode(data);
    let _ = CapabilitiesPayload::decode(data);
    let _ = KeyAgreementPayload::decode(data);
    let _ = SessionConfirmPayload::decode(data);
    let _ = DetachPayload::decode(data);
    let _ = KeepalivePayload::decode(data);
    let _ = RekeyPayload::decode(data);
});
