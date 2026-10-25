//! The CALL SITE, guarded from outside the file it guards.
//!
//! `app.rs`'s own unit tests prove that `sovereign_sender_of` decides
//! correctly. They cannot prove that the ratchet is ASKED with what it
//! returned — and that gap is exactly how the defect survived: the peer's
//! identity was available in the same function all along, and the call passed
//! the other name.
//!
//! This lives in `tests/` rather than beside the code deliberately. The first
//! version of this guard read the file it was written in, so its own needle
//! satisfied it — a guard that measures nothing. Reading a DIFFERENT file makes
//! the match mean something.

const APP_RS: &str = include_str!("../src/app.rs");

/// The sealed-frame path must open the conversation under the resolved sender.
#[test]
fn the_sealed_path_opens_under_the_resolved_sender() {
    let needle = "ratchet.open_payload(&sender,";
    assert_eq!(
        APP_RS.matches(needle).count(),
        1,
        "expected exactly one sealed-frame open, under the resolved sender",
    );
}

/// Opening under the SESSION PEER is the defect. A peer's device is not the
/// address the ratchet keys conversations by.
#[test]
fn the_sealed_path_does_not_open_under_the_session_peer() {
    assert!(
        !APP_RS.contains("ratchet.open_payload(node_id"),
        "opening under the session peer drops every sealed frame that arrives \
         over a direct session — see app.ratchet.open_failed",
    );
}

/// Keep the resolved identity, but scope the reset to the physical session
/// endpoint. A broad identity reset would discard healthy sibling chains.
#[test]
fn forgetting_a_conversation_uses_the_resolved_identity_and_reporting_device() {
    assert!(
        APP_RS.contains("ratchet.forget_peer_device(&sender, node_id.as_bytes())"),
        "reset must use the resolved identity and authenticated physical endpoint",
    );
    assert!(
        !APP_RS.contains("ratchet.forget_peer(&sender)"),
        "one device's reset must not discard every sibling's conversation",
    );
}

/// Call signalling rides `AppRtData`, and the app registers its realtime
/// endpoint under the CONTACT. Routing that by the session peer drops every
/// `XVSG` frame — the callee answers, the caller never learns it.
#[test]
fn realtime_frames_route_under_the_resolved_sender() {
    assert!(
        APP_RS.contains("route_rt_data(sender, payload)"),
        "realtime frames must route under the resolved sender",
    );
    assert!(
        !APP_RS.contains("route_rt_data(*node_id"),
        "routing realtime frames by the session peer drops call signalling",
    );
}
