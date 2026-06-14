//! Well-known constants for the mailbox built-in app service
//!
//!
//! The mailbox-relay role exposes a single veil app endpoint that
//! senders use to deposit blobs for offline receivers. Both sides
//! agree on the same `(MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)`
//! tuple — receivers' RendezvousAd carries push envelopes sealed for
//! the relay's X25519 key, senders publish to this endpoint.
//!
//! ## Why fire-and-forget put (no reply)
//!
//! The mailbox is a best-effort wake-up channel. Sender doesn't
//! need a synchronous "stored" confirmation to make progress —
//! peer-sync (P4) handles eventual delivery if the put silently
//! failed. Avoiding a reply keeps the wire path single-frame and
//! sidesteps streams / correlation-id machinery.
//!
//! ## Why deterministic app_id
//!
//! `MAILBOX_APP_ID = BLAKE3("veil.mailbox.v1").as_bytes` —
//! every node computes the same value without coordination. The
//! `v1` suffix lets us version the app id (different mailbox
//! protocols → different app id → no cross-version confusion).
//! The hardcoded byte array below is the precomputed value;
//! [`tests::mailbox_app_id_matches_blake3_of_name`] verifies the
//! hardcoding stays in sync if anyone touches `MAILBOX_APP_NAME`.

/// Well-known service name input to BLAKE3. Bumping the version
/// suffix mints a new `MAILBOX_APP_ID` and effectively soft-forks
/// the protocol; old and new clients won't see each other's puts.
pub const MAILBOX_APP_NAME: &str = "veil.mailbox.v1";

/// `MAILBOX_APP_ID = BLAKE3("veil.mailbox.v1")` — 32 bytes.
pub const MAILBOX_APP_ID: [u8; 32] = [
    0xd4, 0x17, 0xcf, 0x22, 0x72, 0x89, 0x07, 0x40, 0xe2, 0xe1, 0xb6, 0xb1, 0xb5, 0x74, 0x12, 0x95,
    0x6b, 0x3e, 0xfc, 0xc6, 0xfd, 0xd4, 0x95, 0x4f, 0xc4, 0xd4, 0x9b, 0x1c, 0xee, 0x36, 0xf5, 0xbb,
];

/// Endpoint id for the put operation. Senders address
/// `(relay_node_id, MAILBOX_APP_ID, MAILBOX_PUT_ENDPOINT_ID)`.
pub const MAILBOX_PUT_ENDPOINT_ID: u32 = 1;

/// mpsc channel buffer depth for the PUT endpoint. Sized to absorb
/// the realistic put-rate burst per relay (~tens/sec from many
/// senders) without blocking the dispatcher's incoming-frame path
/// when the service is briefly slow. At 256 × ~1 KB per put = 256
/// KiB worst-case transient memory.
pub const MAILBOX_PUT_ENDPOINT_CAPACITY: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard against accidentally desynchronising the hardcoded
    /// `MAILBOX_APP_ID` from the BLAKE3 of `MAILBOX_APP_NAME`.
    /// Anyone changing one without the other will see this fail.
    #[test]
    fn t1_4_p5b_mailbox_app_id_matches_blake3_of_name() {
        let hash = blake3::hash(MAILBOX_APP_NAME.as_bytes());
        assert_eq!(
            *hash.as_bytes(),
            MAILBOX_APP_ID,
            "hardcoded MAILBOX_APP_ID drifted from BLAKE3({MAILBOX_APP_NAME:?})",
        );
    }
}
