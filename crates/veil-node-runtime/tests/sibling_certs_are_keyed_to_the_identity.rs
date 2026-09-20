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

/// A device our document names but that has NOT adopted the identity yet must
/// still be sealable — as itself.
///
/// The link ceremony amends the document BEFORE the new device adopts, so from
/// that moment its certificate is sought under OUR identity, where it is not
/// and cannot be: until it adopts, the device publishes under its own. The
/// thing that lets it adopt is the snapshot being sealed.
///
/// Measured end to end: `1 device(s) of the recipient were asked about and none
/// has a certificate on the network`, every deposit suppressed in
/// `unresolved-peer backoff` so nothing was ever re-driven, and the snapshot's
/// thirteen live chunks arriving as nine — the receiver held 9/13 and answered
/// `no bundle` twelve times over.
///
/// Structural, like the guard above and like this file's neighbours: the branch
/// sits several awaits deep inside `seal_for` and what is pinned is that the
/// empty my-devices resolution is retried against the recipient's own identity.
#[test]
fn a_device_that_has_not_adopted_yet_is_sealed_to_as_itself() {
    let src = include_str!("../src/runtime/offline_seal.rs");
    assert!(
        src.len() > 10_000,
        "offline_seal.rs is unexpectedly small — did the file move?"
    );

    let at = src
        .find("if resolved.is_empty()")
        .expect("the empty-resolution branch is gone — re-point this guard");
    // Bounded to the fallback, so this reads the branch and not the file.
    let arm = &src[at..at + 1600.min(src.len() - at)];

    assert!(
        arm.contains("fetch_verified_certs(recipient_node_id)"),
        "an empty my-devices resolution no longer retries the recipient as \
         itself, so a device that has not adopted yet cannot be sealed to"
    );
    // CONTROL: the fallback must re-sign, or the opener reconstructs a `dst`
    // the blob was not bound to and every honest open fails.
    assert!(
        arm.contains("sign_auth_deliver("),
        "the fallback changes the binding without re-signing the auth"
    );
    // CONTROL: and it must not fire for a stranger, or every unresolvable
    // recipient costs a second full resolve on a path that already failed.
    assert!(
        arm.contains("addressed_to_us"),
        "the fallback is not gated on the recipient being one of our devices"
    );
}
