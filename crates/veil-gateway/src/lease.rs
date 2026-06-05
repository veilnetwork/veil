//! Attachment lease model.
//!
//! A lease represents a leaf (or relay/gateway) node's current attachment to
//! this gateway/core node. It has a finite lifetime and can be renewed by
//! receiving a `KEEPALIVE` from the attached peer.

use std::time::{Duration, Instant};

use veil_cfg::NodeId;
use veil_proto::session::{AttachPayload, VisibilityScope};

// ── AttachLease ───────────────────────────────────────────────────────────────

/// A single attachment lease.
///
/// Created when a peer sends an `ATTACH` message and renewed on each
/// subsequent `KEEPALIVE`. Expires if no renewal arrives before `expires_at`.
#[derive(Debug, Clone)]
pub struct AttachLease {
    /// 32-byte node identifier of the attached peer.
    pub node_id: NodeId,
    /// Role byte as declared in the `ATTACH` message.
    pub role: u8,
    /// Realm the peer belongs to.
    pub realm_id: u32,
    /// Epoch at the time of attachment (monotonically increasing per node).
    pub attach_epoch: u32,
    /// Mailbox preference count declared by the peer.
    pub mailbox_preference_count: u8,
    /// Gateway preference count declared by the peer.
    pub gateway_preference_count: u8,
    /// When this lease expires unless renewed.
    pub expires_at: Instant,
    /// Visibility scope declared by the peer.
    pub visibility_scope: VisibilityScope,
    /// Custom TTL in seconds requested by the peer (0 = use gateway default).
    pub custom_ttl_secs: u32,
}

impl AttachLease {
    /// Default lease duration: 60 seconds.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

    /// Upper bound on a peer-requested `custom_ttl_secs`: 1 day.
    ///
    /// The lease model is keepalive-driven (a live peer renews well within
    /// `DEFAULT_TTL`; `handle_keepalive` rejects keepalives beyond a 300 s
    /// clock-skew window). `custom_ttl_secs` rides the `CUSTOM_TTL_TLV_TAG`
    /// wire extension, so it is remote-attacker-controllable; without a
    /// ceiling a single `ATTACH` could pin a lease for up to ~136 years and
    /// defeat reclaim. 1 day is generous versus the 60 s default yet keeps
    /// the invariant `effective_ttl <= MAX_ATTACH_TTL_SECS` bounded.
    pub const MAX_ATTACH_TTL_SECS: u64 = 86_400;

    /// Create a new lease from an `ATTACH` payload using the default TTL.
    pub fn new(node_id: NodeId, payload: &AttachPayload) -> Self {
        Self::with_ttl(
            node_id,
            payload,
            Self::DEFAULT_TTL,
            VisibilityScope::Public,
            0,
        )
    }

    /// Create a new lease with full TLV-extended fields.
    ///
    /// If `custom_ttl_secs > 0` it is used instead of `ttl`.
    pub fn with_ttl(
        node_id: NodeId,
        payload: &AttachPayload,
        ttl: Duration,
        visibility_scope: VisibilityScope,
        custom_ttl_secs: u32,
    ) -> Self {
        let effective_ttl = if custom_ttl_secs > 0 {
            // `custom_ttl_secs` is wire-exposed (CUSTOM_TTL_TLV_TAG); clamp to
            // MAX_ATTACH_TTL_SECS so a remote peer cannot pin a lease past the
            // reclaim horizon.
            Duration::from_secs((custom_ttl_secs as u64).min(Self::MAX_ATTACH_TTL_SECS))
        } else {
            ttl
        };
        Self {
            node_id,
            role: payload.role,
            realm_id: payload.realm_id,
            attach_epoch: payload.attach_epoch,
            mailbox_preference_count: payload.mailbox_preference_count,
            gateway_preference_count: payload.gateway_preference_count,
            expires_at: Instant::now() + effective_ttl,
            visibility_scope,
            custom_ttl_secs,
        }
    }

    /// Renew the lease, resetting the expiry to `now + ttl`.
    pub fn renew(&mut self, ttl: Duration) {
        self.expires_at = Instant::now() + ttl;
    }

    /// Returns `true` if the lease has not yet expired relative to `now`.
    pub fn is_alive(&self, now: Instant) -> bool {
        self.expires_at > now
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::session::{AttachPayload, VisibilityScope};

    fn sample_payload() -> AttachPayload {
        AttachPayload {
            role: 1,
            realm_id: 42,
            attach_epoch: 7,
            mailbox_preference_count: 1,
            gateway_preference_count: 2,
            flags: 0,
        }
    }

    #[test]
    fn new_lease_is_alive() {
        let lease = AttachLease::new(NodeId::from([1u8; 32]), &sample_payload());
        assert!(lease.is_alive(Instant::now()));
    }

    #[test]
    fn expired_lease_is_dead() {
        let lease = AttachLease::with_ttl(
            NodeId::from([1u8; 32]),
            &sample_payload(),
            Duration::from_nanos(1),
            VisibilityScope::Public,
            0,
        );
        // Wait for expiry
        std::thread::sleep(Duration::from_millis(5));
        assert!(!lease.is_alive(Instant::now()));
    }

    #[test]
    fn renew_extends_lifetime() {
        let mut lease = AttachLease::with_ttl(
            NodeId::from([1u8; 32]),
            &sample_payload(),
            Duration::from_nanos(1),
            VisibilityScope::Public,
            0,
        );
        // Renew before checking expiry
        lease.renew(Duration::from_secs(60));
        assert!(lease.is_alive(Instant::now()));
    }

    #[test]
    fn huge_custom_ttl_is_clamped() {
        let before = Instant::now();
        let lease = AttachLease::with_ttl(
            NodeId::from([1u8; 32]),
            &sample_payload(),
            AttachLease::DEFAULT_TTL,
            VisibilityScope::Public,
            u32::MAX, // attacker-supplied, ~136 years if unclamped
        );
        let after = Instant::now();
        // expires_at must sit no later than `now + MAX_ATTACH_TTL_SECS`,
        // proving the clamp held rather than honoring u32::MAX seconds.
        let ceiling = Duration::from_secs(AttachLease::MAX_ATTACH_TTL_SECS);
        assert!(
            lease.expires_at <= after + ceiling,
            "custom_ttl must be clamped to MAX_ATTACH_TTL_SECS"
        );
        // ...and it must actually use the full ceiling (not the 60 s default).
        assert!(
            lease.expires_at >= before + ceiling - Duration::from_secs(1),
            "clamped TTL should equal the ceiling, not the default"
        );
    }

    #[test]
    fn lease_fields_match_payload() {
        let payload = sample_payload();
        let lease = AttachLease::new(NodeId::from([9u8; 32]), &payload);
        assert_eq!(lease.node_id, NodeId::from([9u8; 32]));
        assert_eq!(lease.role, payload.role);
        assert_eq!(lease.realm_id, payload.realm_id);
        assert_eq!(lease.attach_epoch, payload.attach_epoch);
    }
}
