//! Gateway service — handles ATTACH, DETACH, and KEEPALIVE session messages.
//!
//! # Role enforcement
//!
//! Only `NodeRole::Core` is permitted to act as an attachment host.
//! Calls on a service with role `Leaf` return `GatewayError::NotAllowed`.
//!
//! # Thread safety
//!
//! `GatewayService` is `Clone` and cheap to clone — the inner
//! `AttachmentTable` is behind an `Arc<Mutex<_>>`.

use veil_util::lock;

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use veil_cfg::NodeRole;
use veil_proto::session::{AttachPayload, DetachPayload, KeepalivePayload};
use veil_routing::probe::RttTable;
use veil_routing::score::NeighborScorer;

use crate::attachment::AttachmentTable;

// ── GatewayError ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    /// This node's role does not permit acting as an attachment gateway.
    NotAllowed,
    /// The peer is not currently attached.
    NotAttached,
    /// The gateway attachment table is full (`MAX_GATEWAY_ATTACHMENTS`).
    CapacityFull,
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed => write!(f, "node role does not allow gateway attachment hosting"),
            Self::NotAttached => write!(f, "peer is not attached"),
            Self::CapacityFull => write!(f, "gateway attachment table is full"),
        }
    }
}

// ── GatewayService ────────────────────────────────────────────────────────────

/// Gateway attachment service.
///
/// Clone-cheap: the inner table is behind an `Arc<Mutex<_>>`.
#[derive(Clone, Debug)]
pub struct GatewayService {
    pub table: Arc<Mutex<AttachmentTable>>,
    role: NodeRole,
}

impl GatewayService {
    pub fn new(role: NodeRole) -> Self {
        Self {
            table: Arc::new(Mutex::new(AttachmentTable::new())),
            role,
        }
    }

    /// Create a new `GatewayService` with a specific attachment lease TTL.
    ///
    /// Leases expire after `lease_ttl` without a `KEEPALIVE` renewal.
    pub fn new_with_lease_ttl(role: NodeRole, lease_ttl: std::time::Duration) -> Self {
        Self {
            table: Arc::new(Mutex::new(AttachmentTable::with_ttl(lease_ttl))),
            role,
        }
    }

    fn can_host(&self) -> bool {
        matches!(self.role, NodeRole::Core)
    }

    // ── handlers ─────────────────────────────────────────────────────────

    /// Handle an `ATTACH` message from a peer.
    pub fn handle_attach(
        &self,
        node_id: [u8; 32],
        payload: &AttachPayload,
    ) -> Result<(), GatewayError> {
        if !self.can_host() {
            return Err(GatewayError::NotAllowed);
        }
        if !lock!(self.table).attach(node_id, payload) {
            return Err(GatewayError::CapacityFull);
        }
        Ok(())
    }

    /// Handle a `DETACH` message from a peer.
    pub fn handle_detach(
        &self,
        node_id: &[u8; 32],
        payload: &DetachPayload,
    ) -> Result<(), GatewayError> {
        if !self.can_host() {
            return Err(GatewayError::NotAllowed);
        }
        log::info!(
            "gateway.detach node_id={} reason={}",
            veil_util::hex_short(node_id),
            payload.reason,
        );
        lock!(self.table).detach(node_id);
        Ok(())
    }

    /// Handle a `KEEPALIVE` from a peer (renew their lease).
    ///
    /// Returns `Err(GatewayError::NotAttached)` if the peer is not found in
    /// the table (e.g., after a gateway restart).
    pub fn handle_keepalive(
        &self,
        node_id: &[u8; 32],
        payload: &KeepalivePayload,
    ) -> Result<(), GatewayError> {
        if !self.can_host() {
            return Err(GatewayError::NotAllowed);
        }
        // Reject keepalives with implausible timestamps (>5 min clock skew)
        // to prevent replay of stale keepalives from extending leases.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let skew = payload.timestamp_secs.abs_diff(now_secs);
        if skew > 300 {
            return Err(GatewayError::NotAllowed);
        }
        if lock!(self.table).renew(node_id) {
            Ok(())
        } else {
            Err(GatewayError::NotAttached)
        }
    }

    // ── maintenance ───────────────────────────────────────────────────────

    /// Remove expired leases. Call from a background task.
    pub fn cleanup_expired(&self, now: Instant) {
        lock!(self.table).cleanup_expired(now);
    }

    // ── queries ───────────────────────────────────────────────────────────

    pub fn is_attached(&self, node_id: &[u8; 32]) -> bool {
        lock!(self.table).is_attached(node_id)
    }

    pub fn attachment_count(&self) -> usize {
        lock!(self.table).len()
    }

    pub fn attached_nodes(&self) -> Vec<[u8; 32]> {
        lock!(self.table).attached_nodes()
    }

    /// Select the preferred upstream gateway from `candidates`.
    ///
    /// Uses `NeighborScorer::preferred_gateway` to rank candidates by RTT and
    /// reachability. Returns `None` when `candidates` is empty.
    ///
    /// This is called by leaf-side logic when multiple gateway choices are
    /// available (e.g. from discovery results).
    pub fn preferred_gateway<'a>(
        candidates: &'a [[u8; 32]],
        scorer: &NeighborScorer,
        rtt_table: &RttTable,
    ) -> Option<&'a [u8; 32]> {
        scorer.preferred_gateway(candidates, rtt_table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::session::{AttachPayload, DetachPayload, KeepalivePayload, detach_reason};

    // ── tests ─────────────────────────────────────────────────────────

    /// — gateway evicts an expired lease when `cleanup_expired` is
    /// called after the TTL elapses.
    #[test]
    fn gateway_eviction_removes_expired_lease() {
        // Use a very short TTL so the test doesn't sleep long.
        let short_ttl = std::time::Duration::from_millis(5);
        let svc = GatewayService::new_with_lease_ttl(NodeRole::Core, short_ttl);
        let node_id = [0xABu8; 32];
        let payload = AttachPayload {
            role: 1,
            realm_id: 1,
            attach_epoch: 1,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        };

        svc.handle_attach(node_id, &payload).unwrap();
        assert!(svc.is_attached(&node_id));

        // Wait past the TTL.
        std::thread::sleep(short_ttl + std::time::Duration::from_millis(5));

        svc.cleanup_expired(std::time::Instant::now());

        assert!(!svc.is_attached(&node_id), "expired lease must be evicted");
        assert_eq!(svc.attachment_count(), 0);
    }

    /// Keepalive renews the lease so it survives past the original TTL.
    ///
    /// cleanup: original test used a 15ms TTL +
    /// `std::thread::sleep(7.5ms)` twice. Under load `std::thread::sleep`
    /// returned 30+ms late and the lease's renewed deadline lapsed before
    /// the post-keepalive `cleanup_expired(Instant::now)` call — flake.
    /// Rewrite uses a 60-second TTL + a `cfg(test)` helper to force the
    /// lease's `expires_at` to a synthetic short deadline, so the
    /// cleanup-vs-deadline race is replaced with deterministic Instant
    /// arithmetic.
    #[test]
    fn keepalive_prevents_eviction() {
        let ttl = std::time::Duration::from_secs(60);
        let svc = GatewayService::new_with_lease_ttl(NodeRole::Core, ttl);
        let node_id = [0xCDu8; 32];
        let payload = AttachPayload {
            role: 1,
            realm_id: 1,
            attach_epoch: 1,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        };

        svc.handle_attach(node_id, &payload).unwrap();

        // Force the lease to a synthetic short deadline 100ms in the past.
        // Without keepalive a subsequent cleanup_expired(now) would evict.
        let synthetic_short_deadline =
            std::time::Instant::now() - std::time::Duration::from_millis(100);
        assert!(
            lock!(svc.table).force_expires_at(&node_id, synthetic_short_deadline),
            "test fixture: lease must exist after attach",
        );

        // Renew via the real handle_keepalive path. After this the lease's
        // expires_at = Instant::now + 60s, strictly later than the
        // synthetic short deadline above (since Instant::now is monotonic
        // and moves forward of synthetic_short_deadline = now-100ms).
        svc.handle_keepalive(
            &node_id,
            &KeepalivePayload {
                timestamp_secs: veil_util::unix_secs_now_u64(),
            },
        )
        .unwrap();

        let renewed_deadline = lock!(svc.table)
            .expires_at(&node_id)
            .expect("lease still attached");
        assert!(
            renewed_deadline > synthetic_short_deadline,
            "keepalive must move deadline forward of the synthetic short one",
        );

        // Cleanup at synthetic_short_deadline + 1ms — past the synthetic
        // short deadline but well before the renewed (now+60s) deadline.
        // Without keepalive the lease would be evicted; with keepalive it must
        // survive.
        svc.cleanup_expired(synthetic_short_deadline + std::time::Duration::from_millis(1));

        assert!(
            svc.is_attached(&node_id),
            "renewed lease must survive cleanup past the original deadline",
        );
    }

    fn attach_payload() -> AttachPayload {
        AttachPayload {
            role: 1,
            realm_id: 10,
            attach_epoch: 1,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        }
    }

    #[test]
    fn leaf_role_rejects_attach() {
        let svc = GatewayService::new(NodeRole::Leaf);
        let err = svc.handle_attach([1u8; 32], &attach_payload()).unwrap_err();
        assert_eq!(err, GatewayError::NotAllowed);
    }

    #[test]
    fn gateway_accepts_attach() {
        let svc = GatewayService::new(NodeRole::Core);
        svc.handle_attach([1u8; 32], &attach_payload()).unwrap();
        assert!(svc.is_attached(&[1u8; 32]));
        assert_eq!(svc.attachment_count(), 1);
    }

    #[test]
    fn core_accepts_attach() {
        let svc = GatewayService::new(NodeRole::Core);
        svc.handle_attach([2u8; 32], &attach_payload()).unwrap();
        assert!(svc.is_attached(&[2u8; 32]));
    }

    #[test]
    fn detach_removes_attachment() {
        let svc = GatewayService::new(NodeRole::Core);
        svc.handle_attach([3u8; 32], &attach_payload()).unwrap();
        svc.handle_detach(
            &[3u8; 32],
            &DetachPayload {
                reason: detach_reason::NORMAL,
            },
        )
        .unwrap();
        assert!(!svc.is_attached(&[3u8; 32]));
    }

    #[test]
    fn keepalive_renews_attachment() {
        let svc = GatewayService::new(NodeRole::Core);
        svc.handle_attach([4u8; 32], &attach_payload()).unwrap();
        let result = svc.handle_keepalive(
            &[4u8; 32],
            &KeepalivePayload {
                timestamp_secs: veil_util::unix_secs_now_u64(),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn keepalive_on_unknown_peer_returns_not_attached() {
        let svc = GatewayService::new(NodeRole::Core);
        let err = svc
            .handle_keepalive(
                &[99u8; 32],
                &KeepalivePayload {
                    timestamp_secs: veil_util::unix_secs_now_u64(),
                },
            )
            .unwrap_err();
        assert_eq!(err, GatewayError::NotAttached);
    }

    #[test]
    fn relay_role_rejects_attach() {
        let svc = GatewayService::new(NodeRole::Leaf);
        let err = svc.handle_attach([1u8; 32], &attach_payload()).unwrap_err();
        assert_eq!(err, GatewayError::NotAllowed);
    }

    // ── duplicate ATTACH from same peer is upsert, not duplicate ──────

    /// Second ATTACH from the same `peer_id` must update (upsert) the existing
    /// lease — not create a second entry. The total attachment count must
    /// remain 1.
    #[test]
    fn duplicate_attach_is_upsert_not_duplicate() {
        let svc = GatewayService::new(NodeRole::Core);
        let node_id = [0x42u8; 32];

        svc.handle_attach(node_id, &attach_payload()).unwrap();
        assert_eq!(
            svc.attachment_count(),
            1,
            "first ATTACH should create one entry"
        );

        // Second ATTACH from the same node_id — must not create a second entry.
        svc.handle_attach(node_id, &attach_payload()).unwrap();
        assert_eq!(
            svc.attachment_count(),
            1,
            "duplicate ATTACH must upsert, not append — count must still be 1",
        );
        assert!(
            svc.is_attached(&node_id),
            "node must still be attached after upsert"
        );
    }
}
