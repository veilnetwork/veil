//! Relay-side registry of receivers' **private** mailbox fetch cookies.
//!
//! This is the authorization gate for mailbox `fetch`/`ack`, kept SEPARATE from
//! the onion rendezvous-publisher registry on purpose: the rendezvous cookie is
//! published in the receiver's resolvable `RendezvousAd`, so authorizing mailbox
//! fetch against it would let any contact who resolved the ad drain the
//! receiver's mailbox. Mailbox fetch is instead authorized against the private,
//! per-relay/per-epoch cookie the receiver registers here (see
//! [`crate::fetch_cookie`]) and never publishes.
//!
//! Each receiver keeps up to [`MAX_COOKIES_PER_RECEIVER`] most-recent cookies so
//! a fetch straddling an epoch rotation (receiver registered the new cookie but
//! a request with the previous one is still in flight) still authorizes. The map
//! is bounded ([`MailboxCookieRegistry::new`] cap) with LRU eviction, and stale
//! receivers can be [`prune`](MailboxCookieRegistry::prune)d by last-registration
//! time.

use std::collections::HashMap;

use crate::fetch_cookie::MAILBOX_COOKIE_LEN;

/// How many recent cookies a receiver may have valid at once (current +
/// previous epoch).
pub const MAX_COOKIES_PER_RECEIVER: usize = 2;

type Cookie = [u8; MAILBOX_COOKIE_LEN];

/// Constant-time equality for cookies — never early-exits, so a probing
/// attacker can't learn a correct prefix from timing.
fn ct_eq(a: &Cookie, b: &Cookie) -> bool {
    let mut diff = 0u8;
    for i in 0..MAILBOX_COOKIE_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Per-receiver state: up to [`MAX_COOKIES_PER_RECEIVER`] cookies, newest first,
/// each with the unix-secs it was last (re)registered.
#[derive(Default)]
struct Entry {
    cookies: Vec<(Cookie, u64)>,
}

impl Entry {
    fn newest_registered_at(&self) -> u64 {
        self.cookies.first().map(|(_, t)| *t).unwrap_or(0)
    }
}

/// Bounded registry of receivers' private mailbox fetch cookies.
pub struct MailboxCookieRegistry {
    entries: HashMap<[u8; 32], Entry>,
    max_receivers: usize,
}

impl MailboxCookieRegistry {
    /// New registry holding at most `max_receivers` receivers (LRU-evicted by
    /// last registration when full).
    #[must_use]
    pub fn new(max_receivers: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_receivers: max_receivers.max(1),
        }
    }

    /// Register `cookie` for `receiver` at `now` (unix secs). Re-registering an
    /// existing cookie just refreshes its timestamp + moves it to newest. A new
    /// cookie is prepended and the list trimmed to [`MAX_COOKIES_PER_RECEIVER`].
    /// If a brand-new receiver would exceed the cap, the least-recently-active
    /// receiver is evicted first.
    pub fn register(&mut self, receiver: [u8; 32], cookie: Cookie, now: u64) {
        if !self.entries.contains_key(&receiver) && self.entries.len() >= self.max_receivers {
            self.evict_lru();
        }
        let entry = self.entries.entry(receiver).or_default();
        // Dedup: drop any existing copy of this cookie, then prepend fresh.
        entry.cookies.retain(|(c, _)| !ct_eq(c, &cookie));
        entry.cookies.insert(0, (cookie, now));
        entry.cookies.truncate(MAX_COOKIES_PER_RECEIVER);
    }

    /// True iff `cookie` is one of `receiver`'s currently-valid cookies.
    /// Constant-time over the (≤2) stored cookies.
    #[must_use]
    pub fn is_authorised(&self, receiver: &[u8; 32], cookie: &Cookie) -> bool {
        let Some(entry) = self.entries.get(receiver) else {
            return false;
        };
        // Check ALL stored cookies (no early exit) to avoid a timing signal on
        // which slot matched.
        let mut ok = false;
        for (c, _) in &entry.cookies {
            ok |= ct_eq(c, cookie);
        }
        ok
    }

    /// Drop receivers whose newest cookie was registered before `now - ttl`.
    pub fn prune(&mut self, now: u64, ttl: u64) {
        let cutoff = now.saturating_sub(ttl);
        self.entries
            .retain(|_, e| e.newest_registered_at() >= cutoff);
    }

    /// Number of receivers currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_lru(&mut self) {
        if let Some(victim) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.newest_registered_at())
            .map(|(id, _)| *id)
        {
            self.entries.remove(&victim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1: [u8; 32] = [1; 32];
    const R2: [u8; 32] = [2; 32];
    fn ck(b: u8) -> Cookie {
        [b; MAILBOX_COOKIE_LEN]
    }

    #[test]
    fn register_then_authorise() {
        let mut reg = MailboxCookieRegistry::new(16);
        reg.register(R1, ck(0xAA), 100);
        assert!(reg.is_authorised(&R1, &ck(0xAA)));
        assert!(!reg.is_authorised(&R1, &ck(0xBB)), "wrong cookie rejected");
        assert!(!reg.is_authorised(&R2, &ck(0xAA)), "wrong receiver rejected");
    }

    #[test]
    fn keeps_current_and_previous_then_drops_older() {
        let mut reg = MailboxCookieRegistry::new(16);
        reg.register(R1, ck(1), 100); // epoch E-1
        reg.register(R1, ck(2), 200); // epoch E   -> {2,1} valid
        assert!(reg.is_authorised(&R1, &ck(2)));
        assert!(reg.is_authorised(&R1, &ck(1)), "previous epoch still valid");
        reg.register(R1, ck(3), 300); // epoch E+1 -> {3,2}, 1 dropped
        assert!(reg.is_authorised(&R1, &ck(3)));
        assert!(reg.is_authorised(&R1, &ck(2)));
        assert!(!reg.is_authorised(&R1, &ck(1)), "two-epochs-old cookie invalid");
    }

    #[test]
    fn re_register_same_cookie_dedups() {
        let mut reg = MailboxCookieRegistry::new(16);
        reg.register(R1, ck(7), 100);
        reg.register(R1, ck(7), 150); // same cookie refreshed
        // Still only the one cookie; a second distinct one still leaves room.
        reg.register(R1, ck(8), 200);
        assert!(reg.is_authorised(&R1, &ck(7)));
        assert!(reg.is_authorised(&R1, &ck(8)));
    }

    #[test]
    fn lru_eviction_at_cap() {
        let mut reg = MailboxCookieRegistry::new(2);
        reg.register([10; 32], ck(1), 100);
        reg.register([11; 32], ck(2), 200);
        reg.register([12; 32], ck(3), 300); // evicts [10] (oldest)
        assert_eq!(reg.len(), 2);
        assert!(!reg.is_authorised(&[10; 32], &ck(1)), "LRU receiver evicted");
        assert!(reg.is_authorised(&[11; 32], &ck(2)));
        assert!(reg.is_authorised(&[12; 32], &ck(3)));
    }

    #[test]
    fn prune_drops_stale() {
        let mut reg = MailboxCookieRegistry::new(16);
        reg.register(R1, ck(1), 100);
        reg.register(R2, ck(2), 1000);
        reg.prune(1100, 200); // cutoff = 900 -> R1 (100) dropped, R2 (1000) kept
        assert!(!reg.is_authorised(&R1, &ck(1)));
        assert!(reg.is_authorised(&R2, &ck(2)));
    }
}
