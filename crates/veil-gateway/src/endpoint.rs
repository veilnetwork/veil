//! Ephemeral endpoint rotation.
//!
//! Each node announces a short-lived `endpoint_id` alongside its attachment
//! record. The identifier is a 16-byte CSPRNG token that rotates every
//! `rotation_interval` seconds. To avoid disrupting in-flight connections
//! the **previous** endpoint remains valid for an additional `grace_period`.
//!
//! # Usage
//!
//! ```ignore
//! use std::time::Duration;
//! let mut table = EndpointTable::new(Duration::from_secs(300), Duration::from_secs(60));
//! let current = table.current;
//! //... announce current.endpoint_id in AnnounceAttachmentPayload...
//!
//! // Later, on the rotation timer:
//! table.rotate(unix_now_secs);
//! //... re-announce with the new endpoint_id...
//! ```

use std::time::Duration;

use veil_proto::discovery::EphemeralEndpoint;

// ── EndpointTable ─────────────────────────────────────────────────────────────

/// Manages current and previous ephemeral endpoint identifiers.
///
/// Thread-safety: wrap in `Mutex` / `RwLock` at the call site.
pub struct EndpointTable {
    current: EphemeralEndpoint,
    previous: Option<EphemeralEndpoint>,
    rotation_interval: Duration,
    grace_period: Duration,
}

impl EndpointTable {
    /// Default rotation interval: 5 minutes.
    pub const DEFAULT_ROTATION: Duration = Duration::from_secs(300);
    /// Default grace period for the previous endpoint: 60 seconds.
    pub const DEFAULT_GRACE: Duration = Duration::from_secs(60);

    /// Create a new table. Generates the first `endpoint_id` from `now_secs`
    /// (Unix seconds) and the system CSPRNG.
    pub fn new(rotation_interval: Duration, grace_period: Duration, now_secs: u64) -> Self {
        let endpoint_id = random_endpoint_id();
        let valid_until = now_secs + rotation_interval.as_secs();
        Self {
            current: EphemeralEndpoint {
                endpoint_id,
                valid_until,
            },
            previous: None,
            rotation_interval,
            grace_period,
        }
    }

    /// Create with default intervals.
    pub fn with_defaults(now_secs: u64) -> Self {
        Self::new(Self::DEFAULT_ROTATION, Self::DEFAULT_GRACE, now_secs)
    }

    /// Returns a reference to the currently-active ephemeral endpoint.
    pub fn current(&self) -> &EphemeralEndpoint {
        &self.current
    }

    /// Returns the previous endpoint if it is still within its grace period.
    pub fn previous_if_alive(&self, now_secs: u64) -> Option<&EphemeralEndpoint> {
        self.previous
            .as_ref()
            .filter(|ep| ep.valid_until > now_secs)
    }

    /// Rotate to a new endpoint.
    ///
    /// The old current becomes the `previous` entry and is valid for an
    /// additional `grace_period` seconds. The new endpoint's `valid_until`
    /// is set to `now_secs + rotation_interval`.
    ///
    /// Returns the new `endpoint_id` so the caller can trigger a re-announce.
    pub fn rotate(&mut self, now_secs: u64) -> [u8; 16] {
        let new_id = random_endpoint_id();
        let new_valid_until = now_secs + self.rotation_interval.as_secs();
        // The old current survives for grace_period more seconds.
        let mut retiring = self.current.clone();
        retiring.valid_until = now_secs + self.grace_period.as_secs();
        self.previous = Some(retiring);
        self.current = EphemeralEndpoint {
            endpoint_id: new_id,
            valid_until: new_valid_until,
        };
        new_id
    }

    /// Returns `true` if `endpoint_id` matches either the current or a
    /// still-valid previous endpoint.
    pub fn is_valid(&self, endpoint_id: &[u8; 16], now_secs: u64) -> bool {
        if &self.current.endpoint_id == endpoint_id {
            return true;
        }
        self.previous_if_alive(now_secs)
            .is_some_and(|ep| &ep.endpoint_id == endpoint_id)
    }

    /// Returns `true` if the current endpoint has passed its `valid_until`.
    /// Call from the maintenance loop to decide whether to call `rotate`.
    pub fn is_due_for_rotation(&self, now_secs: u64) -> bool {
        self.current.valid_until <= now_secs
    }

    /// Convenience: rotate if due, returning the new `endpoint_id` if rotation
    /// occurred (so the caller knows to re-announce to its gateways).
    ///
    /// Returns `Some(new_endpoint_id)` when rotation happened, `None` otherwise.
    ///
    /// Typical usage in a maintenance loop:
    /// ```ignore
    /// if let Some(_new_id) = table.check_and_rotate(unix_now_secs) {
    /// node.reannounce_attachment.await;
    /// }
    /// ```
    pub fn check_and_rotate(&mut self, now_secs: u64) -> Option<[u8; 16]> {
        if self.is_due_for_rotation(now_secs) {
            Some(self.rotate(now_secs))
        } else {
            None
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Generate a 16-byte cryptographically-random endpoint identifier.
fn random_endpoint_id() -> [u8; 16] {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    buf
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn new_table_has_no_previous() {
        let table = EndpointTable::new(Duration::from_secs(300), Duration::from_secs(60), NOW);
        assert!(table.previous_if_alive(NOW).is_none());
    }

    #[test]
    fn current_endpoint_is_valid() {
        let table = EndpointTable::with_defaults(NOW);
        assert!(table.is_valid(&table.current().endpoint_id, NOW));
    }

    #[test]
    fn rotate_creates_new_current() {
        let mut table = EndpointTable::with_defaults(NOW);
        let old_id = table.current().endpoint_id;
        let new_id = table.rotate(NOW + 300);
        assert_ne!(
            old_id, new_id,
            "rotation must yield a different endpoint_id"
        );
        assert_eq!(table.current().endpoint_id, new_id);
    }

    #[test]
    fn old_endpoint_valid_during_grace_period() {
        let mut table = EndpointTable::new(Duration::from_secs(300), Duration::from_secs(60), NOW);
        let old_id = table.current().endpoint_id;
        table.rotate(NOW + 300);
        // Within grace period — old_id still accepted.
        assert!(
            table.is_valid(&old_id, NOW + 300 + 30),
            "old endpoint must work within grace period"
        );
    }

    #[test]
    fn old_endpoint_invalid_after_grace_period() {
        let mut table = EndpointTable::new(Duration::from_secs(300), Duration::from_secs(60), NOW);
        let old_id = table.current().endpoint_id;
        table.rotate(NOW + 300);
        // Past grace period — old_id must be rejected.
        let after_grace = NOW + 300 + 61;
        assert!(
            !table.is_valid(&old_id, after_grace),
            "old endpoint must expire after grace period"
        );
    }

    #[test]
    fn unknown_endpoint_id_rejected() {
        let table = EndpointTable::with_defaults(NOW);
        assert!(!table.is_valid(&[0xFFu8; 16], NOW));
    }

    #[test]
    fn is_due_for_rotation_triggers_correctly() {
        let table = EndpointTable::new(Duration::from_secs(300), Duration::from_secs(60), NOW);
        // Before rotation_interval expires.
        assert!(!table.is_due_for_rotation(NOW + 299));
        // At or past valid_until.
        assert!(table.is_due_for_rotation(NOW + 300));
    }

    #[test]
    fn rotate_updates_valid_until() {
        let mut table = EndpointTable::new(Duration::from_secs(300), Duration::from_secs(60), NOW);
        table.rotate(NOW + 300);
        assert_eq!(table.current().valid_until, NOW + 300 + 300);
    }

    // ── re-announce hook ─────────────────────────────────────────

    /// `check_and_rotate` returns `None` before the rotation interval expires.
    #[test]
    fn check_and_rotate_no_op_before_due() {
        let mut table = EndpointTable::new(Duration::from_secs(300), Duration::from_secs(60), NOW);
        assert!(table.check_and_rotate(NOW + 299).is_none());
    }

    /// `check_and_rotate` returns the new id when the endpoint is overdue.
    #[test]
    fn check_and_rotate_triggers_when_due() {
        let mut table = EndpointTable::new(Duration::from_secs(300), Duration::from_secs(60), NOW);
        let old_id = table.current().endpoint_id;
        let result = table.check_and_rotate(NOW + 300);
        assert!(
            result.is_some(),
            "check_and_rotate must return Some when due"
        );
        let new_id = result.unwrap();
        assert_ne!(old_id, new_id);
        assert_eq!(table.current().endpoint_id, new_id);
    }

    /// After `check_and_rotate` the old endpoint lives for `grace_period`.
    #[test]
    fn check_and_rotate_grace_period_survives() {
        let mut table = EndpointTable::new(Duration::from_secs(300), Duration::from_secs(60), NOW);
        let old_id = table.current().endpoint_id;
        table.check_and_rotate(NOW + 300);
        // Within grace period: old endpoint still accepted.
        assert!(table.is_valid(&old_id, NOW + 300 + 30));
        // After grace period: old endpoint rejected.
        assert!(!table.is_valid(&old_id, NOW + 300 + 61));
    }

    /// Also test the EphemeralEndpoint TLV encode/decode roundtrip (244.1).
    #[test]
    fn ephemeral_endpoint_tlv_roundtrip() {
        use veil_proto::discovery::EphemeralEndpoint;
        let ep = EphemeralEndpoint {
            endpoint_id: [0xABu8; 16],
            valid_until: 1_700_001_234,
        };
        let encoded = ep.encode_tlv();
        let decoded = EphemeralEndpoint::decode_from_tlv(&encoded);
        assert_eq!(decoded, Some(ep));
    }

    /// Unknown TLV tag before the endpoint tag must be skipped.
    #[test]
    fn ephemeral_endpoint_tlv_skips_unknown_tag() {
        use veil_proto::discovery::{EPHEMERAL_ENDPOINT_TLV_TAG, EphemeralEndpoint};
        // Build a buffer: [unknown tag | len=2 | 0x00 0x00] + [ep tag | len=24 | ep bytes]
        let ep = EphemeralEndpoint {
            endpoint_id: [0xCCu8; 16],
            valid_until: 42,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0099u16.to_be_bytes()); // unknown tag
        buf.extend_from_slice(&2u16.to_be_bytes()); // len=2
        buf.extend_from_slice(&[0u8; 2]);
        buf.extend_from_slice(&EPHEMERAL_ENDPOINT_TLV_TAG.to_be_bytes());
        buf.extend_from_slice(&(EphemeralEndpoint::VALUE_SIZE as u16).to_be_bytes());
        buf.extend_from_slice(&ep.endpoint_id);
        buf.extend_from_slice(&ep.valid_until.to_be_bytes());
        let decoded = EphemeralEndpoint::decode_from_tlv(&buf);
        assert_eq!(decoded, Some(ep));
    }
}
