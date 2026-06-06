//! Attachment table for gateway/core nodes.
//!
//! Stores the set of currently attached peers as `AttachLease` records, keyed
//! by the 32-byte `node_id` of the attached peer. Supports attach, detach
//! keepalive renewal, and TTL-based expiry cleanup.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use veil_proto::session::{AttachPayload, VisibilityScope};

use crate::lease::AttachLease;

// ── AttachmentTable ───────────────────────────────────────────────────────────

/// In-memory store of active attachment leases.
///
/// `NodeRole` enforcement (only gateway/core may maintain an attachment table)
/// is the responsibility of the caller; this struct is role-agnostic.
#[derive(Debug, Default)]
pub struct AttachmentTable {
    leases: HashMap<[u8; 32], AttachLease>,
    /// TTL applied to new leases and renewals.
    pub lease_ttl: Duration,
}

impl AttachmentTable {
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
            lease_ttl: AttachLease::DEFAULT_TTL,
        }
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            leases: HashMap::new(),
            lease_ttl: ttl,
        }
    }

    // ── mutations ─────────────────────────────────────────────────────────

    /// Record a new attachment (or refresh an existing one) from `ATTACH`.
    ///
    /// Returns `true` if the attachment was accepted, `false` if the table is
    /// at capacity (`MAX_GATEWAY_ATTACHMENTS`) and `node_id` is not already
    /// attached. Re-attach (lease renewal for an existing `node_id`) is always
    /// accepted regardless of the cap.
    pub fn attach(&mut self, node_id: [u8; 32], payload: &AttachPayload) -> bool {
        self.attach_with_scope(node_id, payload, VisibilityScope::Public, 0)
    }

    /// Like `attach` but also stores visibility scope and custom TTL.
    pub fn attach_with_scope(
        &mut self,
        node_id: [u8; 32],
        payload: &AttachPayload,
        visibility_scope: VisibilityScope,
        custom_ttl_secs: u32,
    ) -> bool {
        if !self.leases.contains_key(&node_id)
            && self.leases.len() >= veil_proto::budget::MAX_GATEWAY_ATTACHMENTS
        {
            return false;
        }
        let lease = AttachLease::with_ttl(
            node_id.into(),
            payload,
            self.lease_ttl,
            visibility_scope,
            custom_ttl_secs,
        );
        self.leases.insert(node_id, lease);
        true
    }

    /// Remove a lease when a `DETACH` is received.
    ///
    /// Returns `true` if the lease was present.
    pub fn detach(&mut self, node_id: &[u8; 32]) -> bool {
        self.leases.remove(node_id).is_some()
    }

    /// Renew the lease for `node_id` on receipt of a `KEEPALIVE`.
    ///
    /// Returns `true` if the lease existed and was renewed.
    pub fn renew(&mut self, node_id: &[u8; 32]) -> bool {
        if let Some(lease) = self.leases.get_mut(node_id) {
            lease.renew(self.lease_ttl);
            true
        } else {
            false
        }
    }

    /// Remove all leases that have expired relative to `now`.
    ///
    /// Call this periodically from a background task.
    pub fn cleanup_expired(&mut self, now: Instant) {
        self.leases.retain(|_, lease| lease.is_alive(now));
    }

    // ── queries ───────────────────────────────────────────────────────────

    pub fn get(&self, node_id: &[u8; 32]) -> Option<&AttachLease> {
        self.leases.get(node_id)
    }

    /// Look up a lease visible to `requester`.
    ///
    /// `Public` leases are always returned.
    /// `FriendsOnly` leases are returned only if `requester` is in `friend_list`.
    /// `InviteOnly` / `Private` leases are never returned by this method
    /// (InviteOnly requires a separate invite-token check not handled here).
    ///
    /// `friend_list` is the set of node_ids that the attached peer has approved.
    pub fn get_visible<'a>(
        &'a self,
        target_id: &[u8; 32],
        requester: &[u8; 32],
        friend_list: &[[u8; 32]],
    ) -> Option<&'a AttachLease> {
        let lease = self.leases.get(target_id)?;
        match lease.visibility_scope {
            VisibilityScope::Public => Some(lease),
            VisibilityScope::FriendsOnly => {
                if friend_list.contains(requester) {
                    Some(lease)
                } else {
                    None
                }
            }
            VisibilityScope::InviteOnly | VisibilityScope::Private => None,
        }
    }

    pub fn is_attached(&self, node_id: &[u8; 32]) -> bool {
        self.leases.contains_key(node_id)
    }

    /// cleanup test helper: read a lease's `expires_at`
    /// without exposing the internal HashMap. Used by sleep-free flake-fix
    /// rewrites of `keepalive_prevents_eviction`-style tests.
    #[cfg(test)]
    pub fn expires_at(&self, node_id: &[u8; 32]) -> Option<Instant> {
        self.leases.get(node_id).map(|l| l.expires_at)
    }

    /// cleanup test helper: forcibly set a lease's
    /// `expires_at` to a synthetic instant. Lets tests verify
    /// cleanup_expired / keepalive interactions through explicit Instant
    /// arithmetic instead of `std::thread::sleep` (which was scheduler-bound
    /// and produced timing-flakes). Returns `true` if the lease existed.
    #[cfg(test)]
    pub fn force_expires_at(&mut self, node_id: &[u8; 32], instant: Instant) -> bool {
        if let Some(lease) = self.leases.get_mut(node_id) {
            lease.expires_at = instant;
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.leases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    /// Return all currently alive lease node_ids (for diagnostics/admin).
    pub fn attached_nodes(&self) -> Vec<[u8; 32]> {
        self.leases.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::session::AttachPayload;

    fn payload(role: u8) -> AttachPayload {
        AttachPayload {
            role,
            realm_id: 1,
            attach_epoch: 1,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        }
    }

    #[test]
    fn attach_stores_lease() {
        let mut table = AttachmentTable::new();
        table.attach([1u8; 32], &payload(1));
        assert!(table.is_attached(&[1u8; 32]));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn detach_removes_lease() {
        let mut table = AttachmentTable::new();
        table.attach([1u8; 32], &payload(1));
        assert!(table.detach(&[1u8; 32]));
        assert!(!table.is_attached(&[1u8; 32]));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn detach_unknown_returns_false() {
        let mut table = AttachmentTable::new();
        assert!(!table.detach(&[99u8; 32]));
    }

    #[test]
    fn renew_updates_expiry() {
        let mut table = AttachmentTable::with_ttl(Duration::from_millis(10));
        table.attach([2u8; 32], &payload(1));
        assert!(table.renew(&[2u8; 32]));
        // After renew the lease should be alive even a moment later
        assert!(table.is_attached(&[2u8; 32]));
    }

    #[test]
    fn renew_unknown_returns_false() {
        let mut table = AttachmentTable::new();
        assert!(!table.renew(&[0u8; 32]));
    }

    #[test]
    fn cleanup_removes_expired_leases() {
        let mut table = AttachmentTable::with_ttl(Duration::from_nanos(1));
        table.attach([3u8; 32], &payload(1));
        // Long TTL — should survive
        table.lease_ttl = Duration::from_secs(60);
        table.attach([4u8; 32], &payload(2));

        std::thread::sleep(Duration::from_millis(5));
        table.cleanup_expired(Instant::now());

        // [3u8;32] expired, [4u8;32] alive
        assert!(!table.is_attached(&[3u8; 32]));
        assert!(table.is_attached(&[4u8; 32]));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn re_attach_replaces_lease() {
        let mut table = AttachmentTable::new();
        table.attach([5u8; 32], &payload(1)); // role=1
        table.attach([5u8; 32], &payload(2)); // role=2 — re-attach
        assert_eq!(table.get(&[5u8; 32]).unwrap().role, 2);
    }

    #[test]
    fn attached_nodes_returns_all_keys() {
        let mut table = AttachmentTable::new();
        table.attach([1u8; 32], &payload(1));
        table.attach([2u8; 32], &payload(1));
        let mut nodes = table.attached_nodes();
        nodes.sort();
        assert_eq!(nodes.len(), 2);
    }

    // ── visibility scope tests ─────────────────────────────────────

    const REQUESTER: [u8; 32] = [0xBB; 32];
    const TARGET: [u8; 32] = [0xAA; 32];
    const STRANGER: [u8; 32] = [0xCC; 32];

    #[test]
    fn test_private_attach_not_visible() {
        let mut table = AttachmentTable::new();
        table.attach_with_scope(TARGET, &payload(1), VisibilityScope::Private, 0);
        // Nobody can see a private attachment.
        assert!(
            table
                .get_visible(&TARGET, &REQUESTER, &[REQUESTER])
                .is_none()
        );
        assert!(table.get_visible(&TARGET, &STRANGER, &[]).is_none());
    }

    #[test]
    fn test_public_attach_visible_to_all() {
        let mut table = AttachmentTable::new();
        table.attach_with_scope(TARGET, &payload(1), VisibilityScope::Public, 0);
        assert!(table.get_visible(&TARGET, &REQUESTER, &[]).is_some());
        assert!(table.get_visible(&TARGET, &STRANGER, &[]).is_some());
    }

    #[test]
    fn test_friends_only_scope() {
        let mut table = AttachmentTable::new();
        table.attach_with_scope(TARGET, &payload(1), VisibilityScope::FriendsOnly, 0);
        // Friend can see; stranger cannot.
        assert!(
            table
                .get_visible(&TARGET, &REQUESTER, &[REQUESTER])
                .is_some()
        );
        assert!(
            table
                .get_visible(&TARGET, &STRANGER, &[REQUESTER])
                .is_none()
        );
    }

    #[test]
    fn test_invite_only_not_visible_via_get_visible() {
        let mut table = AttachmentTable::new();
        table.attach_with_scope(TARGET, &payload(1), VisibilityScope::InviteOnly, 0);
        // InviteOnly requires a separate token check — always None from get_visible.
        assert!(
            table
                .get_visible(&TARGET, &REQUESTER, &[REQUESTER])
                .is_none()
        );
    }

    #[test]
    fn test_custom_ttl_applied() {
        // custom_ttl_secs=1s — lease should live at least 1s.
        let mut table = AttachmentTable::with_ttl(Duration::from_millis(50));
        table.attach_with_scope(TARGET, &payload(1), VisibilityScope::Public, 1);
        let lease = table.get(&TARGET).unwrap();
        // expires_at should be at least 900ms in the future.
        assert!(lease.expires_at > Instant::now() + Duration::from_millis(900));
    }
}
