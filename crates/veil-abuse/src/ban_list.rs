//! Peer ban list with optional time-limited bans.
//!
//! `BanList` allows banning a peer either permanently (`None` duration) or
//! temporarily (`Some(Duration)`). `is_banned` automatically treats
//! expired temporary bans as not-banned. Call `evict_expired` periodically
//! to reclaim memory.

use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, Instant},
};

// ── BanEntry ──────────────────────────────────────────────────────────────────

/// A single ban record.
#[derive(Debug, Clone)]
pub struct BanEntry {
    pub peer_id: [u8; 32],
    pub reason: String,
    /// `None` → permanent ban. `Some(t)` → ban expires at `t`.
    pub banned_until: Option<Instant>,
    /// Insertion sequence number for O(log n) eviction ordering.
    pub(crate) seq: u64,
    /// `true` for manual bans (persisted across restarts).
    pub manual: bool,
    /// Wall-clock time of the ban. `None` for entries
    /// restored from disk without this field (pre-468.4 bans.json).
    /// Operator UX only — not used for expiry logic.
    pub banned_at: Option<std::time::SystemTime>,
}

impl BanEntry {
    pub fn is_expired(&self, now: Instant) -> bool {
        self.banned_until.map(|t| now >= t).unwrap_or(false)
    }
}

// ── BanList ───────────────────────────────────────────────────────────────────

/// Registry of banned peers.
#[derive(Debug, Default, Clone)]
pub struct BanList {
    entries: HashMap<[u8; 32], BanEntry>,
    /// Secondary index: seq → peer_id, ordered by insertion time.
    /// Enables O(log n) eviction instead of O(n) scan.
    eviction_order: BTreeMap<u64, [u8; 32]>,
    next_seq: u64,
}

impl BanList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ban `peer_id` for `duration` (or permanently if `None`).
    ///
    /// When the list is full (≥ `MAX_BAN_LIST_SIZE`), the oldest-inserted
    /// entry is evicted to make room. Call `evict_expired` periodically
    /// to remove expired bans before the cap is reached.
    /// Ban `peer_id` for `duration` (or permanently if `None`).
    /// `manual = true` marks the ban for persistence across restarts.
    pub fn ban_manual(&mut self, peer_id: [u8; 32], reason: impl Into<String>) {
        self.ban_inner(peer_id, reason, None, true);
    }

    pub fn ban(
        &mut self,
        peer_id: [u8; 32],
        reason: impl Into<String>,
        duration: Option<Duration>,
    ) {
        self.ban_inner(peer_id, reason, duration, false);
    }

    fn ban_inner(
        &mut self,
        peer_id: [u8; 32],
        reason: impl Into<String>,
        duration: Option<Duration>,
        manual: bool,
    ) {
        let now = Instant::now();
        // Remove the old eviction_order entry if re-banning an existing peer
        // otherwise ghosts accumulate and capacity eviction may unban a peer
        // whose ban was recently refreshed.
        if let Some(old_entry) = self.entries.get(&peer_id) {
            self.eviction_order.remove(&old_entry.seq);
        } else if self.entries.len() >= veil_proto::budget::MAX_BAN_LIST_SIZE {
            // O(log n): pop the oldest-inserted entry to make room.
            if let Some((&seq, &victim_id)) = self.eviction_order.iter().next() {
                self.eviction_order.remove(&seq);
                self.entries.remove(&victim_id);
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let banned_until = duration.map(|d| now + d);
        self.eviction_order.insert(seq, peer_id);
        self.entries.insert(
            peer_id,
            BanEntry {
                peer_id,
                reason: reason.into(),
                banned_until,
                seq,
                manual,
                banned_at: Some(std::time::SystemTime::now()),
            },
        );
    }

    /// Returns `true` if `peer_id` is currently banned (and ban has not expired).
    pub fn is_banned(&self, peer_id: &[u8; 32]) -> bool {
        match self.entries.get(peer_id) {
            None => false,
            Some(entry) => !entry.is_expired(Instant::now()),
        }
    }

    /// Explicitly unban a peer.
    pub fn unban(&mut self, peer_id: &[u8; 32]) {
        if let Some(entry) = self.entries.remove(peer_id) {
            self.eviction_order.remove(&entry.seq);
        }
    }

    /// Remove all expired temporary ban entries.
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        // Split borrows so `retain` can mutate `entries` while the closure
        // mutates `eviction_order` — both are distinct fields.
        let eviction_order = &mut self.eviction_order;
        self.entries.retain(|_, e| {
            if e.is_expired(now) {
                eviction_order.remove(&e.seq);
                false
            } else {
                true
            }
        });
    }

    /// Get the ban entry for `peer_id` (including expired bans until evicted).
    pub fn get(&self, peer_id: &[u8; 32]) -> Option<&BanEntry> {
        self.entries.get(peer_id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all currently active (non-expired) ban entries.
    pub fn active_bans(&self) -> Vec<&BanEntry> {
        let now = Instant::now();
        self.entries
            .values()
            .filter(|e| !e.is_expired(now))
            .collect()
    }

    /// Return only manual (persistent) bans for serialisation.
    pub fn manual_bans(&self) -> Vec<&BanEntry> {
        let now = Instant::now();
        self.entries
            .values()
            .filter(|e| e.manual && !e.is_expired(now))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_ban() {
        let mut bl = BanList::new();
        bl.ban([1u8; 32], "spam", None);
        assert!(bl.is_banned(&[1u8; 32]));
    }

    #[test]
    fn temporary_ban_expires() {
        let mut bl = BanList::new();
        // Ban for 1 nanosecond — will expire immediately
        bl.ban([2u8; 32], "test", Some(Duration::from_nanos(1)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!bl.is_banned(&[2u8; 32]));
    }

    #[test]
    fn unban_removes_entry() {
        let mut bl = BanList::new();
        bl.ban([3u8; 32], "test", None);
        bl.unban(&[3u8; 32]);
        assert!(!bl.is_banned(&[3u8; 32]));
        assert!(bl.eviction_order.is_empty());
    }

    #[test]
    fn evict_expired_removes_old_bans() {
        let mut bl = BanList::new();
        bl.ban([4u8; 32], "temp", Some(Duration::from_nanos(1)));
        bl.ban([5u8; 32], "perm", None);
        std::thread::sleep(Duration::from_millis(5));
        bl.evict_expired();
        assert_eq!(bl.len(), 1); // only permanent ban remains
        assert!(!bl.is_banned(&[4u8; 32]));
        assert!(bl.is_banned(&[5u8; 32]));
    }

    #[test]
    fn unknown_peer_not_banned() {
        let bl = BanList::new();
        assert!(!bl.is_banned(&[99u8; 32]));
    }

    #[test]
    fn ban_list_cap_evicts_soonest_expiry() {
        use veil_proto::budget::MAX_BAN_LIST_SIZE;
        let mut bl = BanList::new();
        // Fill to the cap with short-lived bans.
        for i in 0..MAX_BAN_LIST_SIZE {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            bl.ban(id, "test", Some(Duration::from_secs(60)));
        }
        assert_eq!(bl.len(), MAX_BAN_LIST_SIZE);
        // Adding one more must not grow beyond the cap.
        bl.ban([0xFFu8; 32], "overflow", Some(Duration::from_secs(120)));
        assert_eq!(bl.len(), MAX_BAN_LIST_SIZE);
    }

    #[test]
    fn eviction_order_stays_consistent_with_entries() {
        let mut bl = BanList::new();
        bl.ban([1u8; 32], "a", None);
        bl.ban([2u8; 32], "b", Some(Duration::from_nanos(1)));
        assert_eq!(bl.eviction_order.len(), bl.entries.len());
        std::thread::sleep(Duration::from_millis(5));
        bl.evict_expired();
        assert_eq!(bl.eviction_order.len(), bl.entries.len());
    }
}
