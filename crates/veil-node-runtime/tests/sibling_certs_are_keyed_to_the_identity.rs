//! A sibling device's certificate is looked up under the IDENTITY.
//!
//! Structural, and in `tests/` rather than beside the code: the call it guards
//! sits inside an async method on a runtime handle that a unit test cannot
//! build, and a source-reading assertion placed in the same file would match
//! its own needle and pass for ever.
//!
//! The defect it pins, measured on a two-device stand 2026-09-20: the publisher
//! writes each certificate at `dht_key(cert.node_id, instance_id)` where
//! `cert.node_id` is the IDENTITY, while this call asked under
//! `self.local_node_id` — THIS DEVICE. The two keys differ on exactly the
//! multi-device case the branch exists to serve (on a master they coincide,
//! which is why it never showed), so every deposit to a sibling failed
//! `PeerUnresolved` and the second device never received anything. Every other
//! caller, this resolver's own tests included, passes the document's node id.

#[test]
fn the_my_devices_branch_resolves_under_the_identity() {
    let src = include_str!("../src/runtime/offline_seal.rs");
    // Vacuity guard: a moved or renamed file must redden here rather than
    // satisfy the absence check below by being empty.
    assert!(
        src.len() > 10_000,
        "offline_seal.rs is unexpectedly small — did the file move?"
    );

    let call = src
        .split("certs_for_instances(")
        .nth(1)
        .expect("offline_seal.rs no longer resolves instance certificates — re-point this guard");
    let first_arg = call
        .split(',')
        .next()
        .expect("certs_for_instances call has no arguments")
        .trim();

    assert_eq!(
        first_arg, "identity",
        "the sibling lookup must be keyed to the identity the publisher used; \
         `{first_arg}` computes a DHT key nobody ever wrote to"
    );
}
