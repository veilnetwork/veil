//! The ratchet's `local_node_id` must be the IDENTITY, not this device.
//!
//! It is not a label. It goes into the AEAD associated data
//! (`associated_data(sender, sender_instance, recipient, recipient_instance)`),
//! and the SENDER fills the recipient half from the certificate it resolved —
//! whose `node_id` is the identity. Adopt the device here and the two ends
//! compute different associated data, the tag never verifies, and every sealed
//! frame over a direct session is dropped while the mailbox path keeps working
//! because it seals by another route entirely.
//!
//! Guarded from outside the file it guards: a source check that reads itself
//! finds its own needle and proves nothing.

const LIFECYCLE: &str = include_str!("../src/runtime/lifecycle.rs");

/// The value handed to `adopt_identity` must come from the sovereign document.
#[test]
fn the_ratchet_adopts_the_sovereign_node_id() {
    assert_eq!(
        LIFECYCLE
            .matches("ratchet.adopt_identity(ratchet_node_id")
            .count(),
        1,
        "the ratchet must adopt the resolved sovereign node id",
    );
    assert!(
        LIFECYCLE.contains(".map(|sov| *sov.node_id())"),
        "the resolved id must be read off the sovereign document",
    );
}

/// Adopting this device's own id is the defect. A sovereign install's device
/// id is never what a peer seals to.
#[test]
fn the_ratchet_does_not_adopt_the_device_id() {
    assert!(
        !LIFECYCLE.contains("ratchet.adopt_identity(\n                *self.identity.local_identity.node_id.as_bytes(),"),
        "adopting the device id puts the two ends on different associated data",
    );
}

/// A node with no sovereign document IS its own identity, and must keep
/// working — the fallback is the compatibility half of this change.
#[test]
fn a_node_without_a_document_falls_back_to_its_own_id() {
    assert!(
        LIFECYCLE.contains(".unwrap_or(*self.identity.local_identity.node_id.as_bytes())"),
        "a legacy node must still adopt its own id",
    );
}
