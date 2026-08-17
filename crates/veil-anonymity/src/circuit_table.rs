//! Relay-side circuit state table (onion-registration epic b6-core). See
//! `docs/internal/PLAN_ANON_SERVICE_ONION_REGISTRATION.md` + `PLAN_STATEFUL_CIRCUITS_482_7.md` §5.
//!
//! After b2 [`crate::circuit_setup::peel_circuit_setup`] yields a
//! [`crate::circuit_setup::CircuitInstall`], a relay records it here so later
//! data/teardown cells can be re-tagged + forwarded with the cached key (b3).
//! Cells route in BOTH directions, so the table is dual-indexed:
//!
//! * FORWARD cell (originator→terminus) arrives on the PREV link tagged
//!   `circuit_id_in` → looked up by `(prev_link, circuit_id_in)`.
//! * RETURN cell (terminus→originator) arrives on the NEXT link tagged
//!   `circuit_id_out` → looked up by `(next_link, circuit_id_out)`.
//!
//! Both keys resolve to the same [`CircuitState`]. A relay never learns the
//! originator or terminus — only its two immediate neighbours.
//!
//! Bounded like the rendezvous registry (`MAX_CIRCUITS` total, per-link cap) so
//! a peer cannot exhaust relay memory by asking it to allocate circuit state
//! (the DoS surface 482.7 §5 flags). Reject-on-full — but only after an inline
//! reclaim pass over the affected bucket: a LIVE circuit is never evicted to
//! admit a new one, while an entry the periodic gc would reap anyway (idle past
//! the TTL) or a one-shot reply binding that already delivered its reply (see
//! [`SERVED_LINGER_SECS`]) does not get to starve admissions just because the
//! maintenance tick hasn't come round yet.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::circuit_data::ReplayWindow;
use crate::circuit_setup::{CIRCUIT_KEY_LEN, CircuitInstall};
use crate::circuit_wire::CircuitId;

/// Global cap on concurrently-held circuits at one relay (mirrors the rendezvous
/// registry's `MAX_REGISTRATIONS`).
pub const MAX_CIRCUITS: usize = 10_000;
/// Per-previous-link cap (mirrors `MAX_COOKIES_PER_PEER`): bounds how much state
/// a single neighbour can make this relay allocate.
pub const MAX_CIRCUITS_PER_LINK: usize = 64;
/// Default idle TTL: a circuit with no cell in this window is GC'd.
pub const DEFAULT_CIRCUIT_TTL_SECS: u64 = 300;
/// Grace after the LAST introduce forwarded down a terminus circuit before its
/// slot may be reclaimed under install pressure.
///
/// The funnel this exists for: on a small topology a terminus has only a
/// handful of possible prev_links — with 3 relays, every 2-hop circuit funnels
/// into 6 directed 64-slot buckets. One ephemeral reply circuit is built per
/// chat send / mailbox FETCH poll, its cookie answers a single reply, and
/// nothing ever tears it down (no originator sends CircuitTeardown) — so each
/// one held its bucket slot for the full 300 s idle TTL. 64 slots × 300 s hold
/// × one circuit per SEND per link = buckets permanently full, and ~98.6% of
/// live introduces died at `cookie_unknown` because the NEXT registration
/// could not be installed. A binding that has already forwarded its reply is
/// the one thing safe to reclaim early.
///
/// Why a grace and not immediate teardown: the relay cannot tell a one-shot
/// reply binding from a long-lived hosted-service registration (the signed
/// `CircuitRegisterPayload` carries no such marker), and a single logical
/// reply may ride SEVERAL introduces down the same binding (sliced mailbox
/// FETCH responses; `auth_deliver` fragments). Each forwarded introduce
/// re-arms the grace, so a multi-part reply in flight is never cut; a binding
/// quiet for `SERVED_LINGER_SECS` after its last forward is reclaimable —
/// and even then only when a bucket is actually under pressure.
pub const SERVED_LINGER_SECS: u64 = 30;

type Link = [u8; 32];

/// One relay's view of a circuit passing through it.
#[derive(Debug)]
pub struct CircuitState {
    /// Cached symmetric key for this hop's data-cell layer (b3).
    pub circuit_key: [u8; CIRCUIT_KEY_LEN],
    /// Neighbour the FORWARD cell arrived from / RETURN cell is sent to.
    pub prev_link: Link,
    /// Circuit id on the `prev_link` side.
    pub circuit_id_in: CircuitId,
    /// Neighbour to FORWARD toward; `None` ⇒ this relay is the terminus (R).
    pub next_link: Option<Link>,
    /// Circuit id on the `next_link` side.
    pub circuit_id_out: CircuitId,
    /// Last-activity timestamp (unix secs) for idle GC.
    pub last_seen_unix: Mutex<u64>,
    /// Anti-replay window for forward-direction cells.
    pub replay_fwd: Mutex<ReplayWindow>,
    /// Anti-replay window for return-direction cells.
    pub replay_ret: Mutex<ReplayWindow>,
    /// Monotonic seq for return cells THIS node ORIGINATES (only meaningful at
    /// the terminus, which seals the first return layer — see b4b). Starts at 1
    /// (0 is reserved by [`ReplayWindow`]).
    next_return_seq: AtomicU32,
    /// Cookie this circuit is registered under in the circuit-rendezvous registry
    /// (terminus only), so teardown can immediately drop the orphaned
    /// subscription instead of waiting for its TTL. `None` until a registration
    /// binds it (b4a `register`).
    registered_cookie: Mutex<Option<[u8; 16]>>,
    /// Unix secs of the LAST introduce forwarded DOWN this (terminus) circuit;
    /// 0 = never served. Set by the dispatcher when
    /// `try_forward_introduce_via_circuit` sends a reply cell, re-armed on every
    /// forward so a multi-part reply keeps its binding. A served binding past
    /// [`SERVED_LINGER_SECS`] is reclaimable under install pressure — the
    /// escape valve for one-shot reply circuits that otherwise squat their
    /// bucket slot for the whole idle TTL (see the const's funnel arithmetic).
    last_served_unix: AtomicU64,
}

impl Drop for CircuitState {
    fn drop(&mut self) {
        // diff-audit Δ2-j: scrub the per-circuit symmetric key on drop so it does
        // not linger in freed memory for the circuit's whole lifetime.
        use zeroize::Zeroize;
        self.circuit_key.zeroize();
    }
}

impl CircuitState {
    fn from_install(
        install: &CircuitInstall,
        prev_link: Link,
        next_link: Option<Link>,
        now: u64,
    ) -> Self {
        Self {
            circuit_key: install.circuit_key,
            prev_link,
            circuit_id_in: install.circuit_id_in,
            next_link,
            circuit_id_out: install.circuit_id_out,
            last_seen_unix: Mutex::new(now),
            replay_fwd: Mutex::new(ReplayWindow::new()),
            replay_ret: Mutex::new(ReplayWindow::new()),
            next_return_seq: AtomicU32::new(1),
            registered_cookie: Mutex::new(None),
            last_served_unix: AtomicU64::new(0),
        }
    }

    /// Bump the idle-GC clock; call on every accepted cell.
    pub fn touch(&self, now: u64) {
        *self
            .last_seen_unix
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = now;
    }

    /// Record the rendezvous cookie this (terminus) circuit is registered under,
    /// so teardown can evict the subscription eagerly.
    pub fn set_registered_cookie(&self, cookie: [u8; 16]) {
        *self
            .registered_cookie
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(cookie);
    }

    /// The registered cookie, if any.
    pub fn registered_cookie(&self) -> Option<[u8; 16]> {
        *self
            .registered_cookie
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Record that an introduce was forwarded DOWN this circuit (the reply
    /// travelling to the originator). Re-armed on every forward: a sliced
    /// FETCH response or fragmented reply is several introduces on ONE
    /// binding, and only the LAST one starts the [`SERVED_LINGER_SECS`]
    /// clock. `fetch_max` so a stale clock can't rewind the marker.
    pub fn mark_served(&self, now: u64) {
        self.last_served_unix.fetch_max(now, Ordering::Relaxed);
    }

    /// Unix secs of the last forwarded introduce; 0 = never served.
    pub fn last_served_unix(&self) -> u64 {
        self.last_served_unix.load(Ordering::Relaxed)
    }

    /// Allocate the next return-direction seq for a cell this node originates.
    /// Returns `None` when the seq space is EXHAUSTED (diff-audit D5).
    ///
    /// The cell keystream is `keystream(circuit_key, Return, seq)`. Wrapping the
    /// seq back to 1 would reuse a (key, dir, seq) triple and hence reuse
    /// keystream — an XOR/two-time-pad leak. Instead we SATURATE: once the space
    /// is used up we refuse to allocate (the caller drops the cell; the circuit
    /// idle-GCs and is rebuilt with a fresh key). 2^32 return cells on ONE
    /// circuit is far beyond any real lifetime (the idle TTL tears it down long
    /// first), so this is a belt-and-braces guard, not a hot path. Never returns
    /// 0 (reserved by [`ReplayWindow`]).
    pub fn alloc_return_seq(&self) -> Option<u32> {
        let mut cur = self.next_return_seq.load(Ordering::Relaxed);
        loop {
            if cur == u32::MAX {
                return None; // exhausted — refuse rather than wrap + reuse
            }
            match self.next_return_seq.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(cur),
                Err(actual) => cur = actual,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn set_return_seq_for_test(&self, v: u32) {
        self.next_return_seq.store(v, Ordering::Relaxed);
    }
}

/// Why an install was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallError {
    /// Global `MAX_CIRCUITS` reached.
    TableFull,
    /// `MAX_CIRCUITS_PER_LINK` reached for this `prev_link`.
    PerLinkFull,
    /// `(prev_link, circuit_id_in)` already in use (collision / replay).
    Duplicate,
}

/// Bounded, dual-indexed circuit table. Cheap to clone the `Arc<CircuitTable>`;
/// internally `Mutex`-guarded.
pub struct CircuitTable {
    inner: Mutex<Inner>,
    max_total: usize,
    max_per_link: usize,
    ttl_secs: u64,
}

#[derive(Default)]
struct Inner {
    /// `(prev_link, circuit_id_in)` → state (forward lookup).
    fwd: HashMap<(Link, CircuitId), std::sync::Arc<CircuitState>>,
    /// `(next_link, circuit_id_out)` → state (return lookup); only for non-termini.
    bwd: HashMap<(Link, CircuitId), std::sync::Arc<CircuitState>>,
    /// Per-prev-link bucket membership (`circuit_id_in`s) for the per-link cap.
    /// Ids, not a bare count, so the install-pressure reclaim can sweep ONE
    /// bucket in O(bucket) instead of filtering the whole `fwd` map. Bounded by
    /// `max_per_link` (64), so the linear scans stay trivial.
    per_link: HashMap<Link, Vec<CircuitId>>,
}

impl Inner {
    /// Occupancy of one prev_link's bucket.
    fn bucket_len(&self, prev_link: &Link) -> usize {
        self.per_link.get(prev_link).map_or(0, Vec::len)
    }

    /// Unlink one circuit from ALL indices. The single removal path — explicit
    /// teardown, periodic gc and install-pressure reclaim all go through it so
    /// the three indices can never drift apart.
    fn detach(&mut self, prev_link: &Link, cid_in: CircuitId) -> Option<std::sync::Arc<CircuitState>> {
        let state = self.fwd.remove(&(*prev_link, cid_in))?;
        if let Some(nl) = state.next_link {
            self.bwd.remove(&(nl, state.circuit_id_out));
        }
        if let Some(ids) = self.per_link.get_mut(prev_link) {
            if let Some(pos) = ids.iter().position(|c| *c == cid_in) {
                ids.swap_remove(pos);
            }
            if ids.is_empty() {
                self.per_link.remove(prev_link);
            }
        }
        Some(state)
    }
}

impl CircuitTable {
    pub fn new() -> Self {
        Self::with_params(
            MAX_CIRCUITS,
            MAX_CIRCUITS_PER_LINK,
            DEFAULT_CIRCUIT_TTL_SECS,
        )
    }

    pub fn with_params(max_total: usize, max_per_link: usize, ttl_secs: u64) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            max_total: max_total.max(1),
            max_per_link: max_per_link.max(1),
            ttl_secs,
        }
    }

    /// Install a peeled circuit. `prev_link` is the authenticated neighbour the
    /// setup arrived from; `next_link` is `Some` for an intermediate relay,
    /// `None` for the terminus.
    pub fn install(
        &self,
        install: &CircuitInstall,
        prev_link: Link,
        next_link: Option<Link>,
        now: u64,
    ) -> Result<std::sync::Arc<CircuitState>, InstallError> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let fwd_key = (prev_link, install.circuit_id_in);
        if g.fwd.contains_key(&fwd_key) {
            return Err(InstallError::Duplicate);
        }
        // Inline reclaim on a would-be refusal (small-topology starvation fix):
        // the periodic gc lives on the runtime maintenance tick, so between
        // ticks a full bucket refused EVERY registration even when most of its
        // occupants were idle-expired or already-served reply bindings. On a
        // 3-relay network — 6 directed 64-slot buckets, one 300 s-held circuit
        // per SEND — that meant buckets sat permanently full and admissions
        // only happened in the brief post-tick windows (~98.6% of live
        // introduces starved). Reclaim what the gc would reap anyway, then
        // re-check; a bucket full of genuinely live circuits still refuses.
        if g.fwd.len() >= self.max_total {
            self.reclaim_table(&mut g, now);
            if g.fwd.len() >= self.max_total {
                return Err(InstallError::TableFull);
            }
        }
        if g.bucket_len(&prev_link) >= self.max_per_link {
            self.reclaim_bucket(&mut g, &prev_link, now);
            if g.bucket_len(&prev_link) >= self.max_per_link {
                return Err(InstallError::PerLinkFull);
            }
        }
        // Backward-index dedup (diff-audit S1/M1): `bwd` is the ONLY index used to
        // route RETURN cells. `circuit_id_out` is an originator-chosen u32, so two
        // circuits through this relay toward the same `next_link` can collide. A
        // silent overwrite (the old behaviour) would (a) misroute the first
        // circuit's return traffic to the second's state, and (b) let EITHER
        // circuit's teardown delete the shared `(nl, cid_out)` key, breaking the
        // survivor's return path. Reject the collision instead — checked before
        // any mutation so `install` stays atomic.
        if let Some(nl) = next_link
            && g.bwd.contains_key(&(nl, install.circuit_id_out))
        {
            return Err(InstallError::Duplicate);
        }
        let state = std::sync::Arc::new(CircuitState::from_install(
            install, prev_link, next_link, now,
        ));
        g.fwd.insert(fwd_key, std::sync::Arc::clone(&state));
        if let Some(nl) = next_link {
            g.bwd
                .insert((nl, install.circuit_id_out), std::sync::Arc::clone(&state));
        }
        g.per_link
            .entry(prev_link)
            .or_default()
            .push(install.circuit_id_in);
        Ok(state)
    }

    /// Install-pressure reclaim for ONE bucket, O(bucket) and allocation-light
    /// (a single ≤bucket-sized id Vec). Two passes, second only if the first
    /// left the bucket full:
    ///
    /// 1. idle past the TTL — exactly the periodic gc's criterion, run inline
    ///    because the dispatcher never calls `gc` between maintenance ticks;
    /// 2. served reply bindings quiet for [`SERVED_LINGER_SECS`] — a terminus
    ///    circuit whose registration already answered (introduce forwarded
    ///    down it, nothing since). Its table slot is the scarce resource; the
    ///    cookie subscription is NOT touched — the rendezvous registry holds
    ///    its own `Arc` to this state and return-forwarding never consults the
    ///    table, so a late slice of a multi-part reply (or a hosted service we
    ///    can't distinguish on the wire) keeps flowing after the slot frees.
    fn reclaim_bucket(&self, g: &mut Inner, prev_link: &Link, now: u64) {
        let ttl = self.ttl_secs;
        let Some(ids) = g.per_link.get(prev_link) else {
            return;
        };
        let idle: Vec<CircuitId> = ids
            .iter()
            .filter(|cid| {
                g.fwd.get(&(*prev_link, **cid)).is_some_and(|s| {
                    let last = *s.last_seen_unix.lock().unwrap_or_else(|p| p.into_inner());
                    now.saturating_sub(last) >= ttl
                })
            })
            .copied()
            .collect();
        for cid in idle {
            g.detach(prev_link, cid);
        }
        if g.bucket_len(prev_link) < self.max_per_link {
            return;
        }
        let Some(ids) = g.per_link.get(prev_link) else {
            return;
        };
        let served: Vec<CircuitId> = ids
            .iter()
            .filter(|cid| {
                g.fwd.get(&(*prev_link, **cid)).is_some_and(|s| {
                    let served = s.last_served_unix();
                    served != 0 && now.saturating_sub(served) >= SERVED_LINGER_SECS
                })
            })
            .copied()
            .collect();
        for cid in served {
            g.detach(prev_link, cid);
        }
    }

    /// Whole-table analogue of [`Self::reclaim_bucket`] for a `TableFull`
    /// verdict: pass 1 is the periodic gc inline; pass 2 (only if still full)
    /// frees served-and-quiet reply bindings across all buckets.
    fn reclaim_table(&self, g: &mut Inner, now: u64) {
        let ttl = self.ttl_secs;
        let idle: Vec<(Link, CircuitId)> = g
            .fwd
            .iter()
            .filter(|(_, s)| {
                let last = *s.last_seen_unix.lock().unwrap_or_else(|p| p.into_inner());
                now.saturating_sub(last) >= ttl
            })
            .map(|(k, _)| *k)
            .collect();
        for (link, cid) in idle {
            g.detach(&link, cid);
        }
        if g.fwd.len() < self.max_total {
            return;
        }
        let served: Vec<(Link, CircuitId)> = g
            .fwd
            .iter()
            .filter(|(_, s)| {
                let served = s.last_served_unix();
                served != 0 && now.saturating_sub(served) >= SERVED_LINGER_SECS
            })
            .map(|(k, _)| *k)
            .collect();
        for (link, cid) in served {
            g.detach(&link, cid);
        }
    }

    /// Look up by the FORWARD key (cell arriving from `prev_link`).
    pub fn lookup_forward(
        &self,
        prev_link: &Link,
        cid_in: CircuitId,
    ) -> Option<std::sync::Arc<CircuitState>> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.fwd.get(&(*prev_link, cid_in)).cloned()
    }

    /// Look up by the RETURN key (cell arriving from `next_link`).
    pub fn lookup_backward(
        &self,
        next_link: &Link,
        cid_out: CircuitId,
    ) -> Option<std::sync::Arc<CircuitState>> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.bwd.get(&(*next_link, cid_out)).cloned()
    }

    /// Remove a circuit (teardown). Idempotent.
    pub fn remove(&self, prev_link: &Link, cid_in: CircuitId) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.detach(prev_link, cid_in);
    }

    /// Evict circuits idle past the TTL. Returns the number removed.
    pub fn gc(&self, now: u64) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let ttl = self.ttl_secs;
        let stale: Vec<(Link, CircuitId)> = g
            .fwd
            .iter()
            .filter(|(_, s)| {
                let last = *s.last_seen_unix.lock().unwrap_or_else(|p| p.into_inner());
                now.saturating_sub(last) >= ttl
            })
            .map(|(k, _)| *k)
            .collect();
        for (prev_link, cid_in) in &stale {
            g.detach(prev_link, *cid_in);
        }
        stale.len()
    }

    /// Occupancy of one prev_link's bucket (for the dispatcher's refusal log).
    pub fn link_occupancy(&self, prev_link: &Link) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .bucket_len(prev_link)
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .fwd
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CircuitTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst(cid_in: u32, cid_out: u32, key: u8) -> CircuitInstall {
        CircuitInstall {
            circuit_id_in: cid_in,
            circuit_id_out: cid_out,
            circuit_key: [key; CIRCUIT_KEY_LEN],
        }
    }

    #[test]
    fn install_and_dual_lookup() {
        let t = CircuitTable::new();
        let prev = [1u8; 32];
        let next = [2u8; 32];
        t.install(&inst(10, 11, 0xAA), prev, Some(next), 1000)
            .unwrap();

        // Forward: arrives from prev tagged 10.
        let f = t.lookup_forward(&prev, 10).unwrap();
        assert_eq!(f.circuit_id_out, 11);
        assert_eq!(f.next_link, Some(next));
        assert_eq!(f.circuit_key, [0xAA; CIRCUIT_KEY_LEN]);
        // Return: arrives from next tagged 11.
        let b = t.lookup_backward(&next, 11).unwrap();
        assert_eq!(b.circuit_id_in, 10);
        // Misses.
        assert!(t.lookup_forward(&prev, 99).is_none());
        assert!(t.lookup_backward(&next, 99).is_none());
    }

    #[test]
    fn alloc_return_seq_saturates_no_wrap_d5() {
        let t = CircuitTable::new();
        let c = t.install(&inst(1, 2, 0x11), [3u8; 32], None, 0).unwrap();
        // Normal allocation: nonzero, increasing.
        let a = c.alloc_return_seq().unwrap();
        let b = c.alloc_return_seq().unwrap();
        assert_ne!(a, 0);
        assert!(b > a);
        // diff-audit D5: at the top of the space, hand out the last seq then
        // SATURATE to None — never wrap back to a reused (key, dir, seq).
        c.set_return_seq_for_test(u32::MAX - 1);
        assert_eq!(c.alloc_return_seq(), Some(u32::MAX - 1));
        assert_eq!(
            c.alloc_return_seq(),
            None,
            "exhausted — must not wrap + reuse"
        );
        assert_eq!(c.alloc_return_seq(), None, "stays exhausted");
    }

    #[test]
    fn terminus_has_no_backward_entry() {
        let t = CircuitTable::new();
        let prev = [1u8; 32];
        t.install(&inst(7, 0, 1), prev, None, 1).unwrap();
        assert!(t.lookup_forward(&prev, 7).is_some());
        // No next_link → no backward index entry anywhere.
        assert!(t.lookup_backward(&[0u8; 32], 0).is_none());
    }

    #[test]
    fn rejects_duplicate_and_caps() {
        let t = CircuitTable::with_params(3, 2, 300);
        let prev = [1u8; 32];
        t.install(&inst(1, 1, 1), prev, Some([9u8; 32]), 0).unwrap();
        // Duplicate (prev, cid_in).
        assert!(matches!(
            t.install(&inst(1, 2, 1), prev, Some([9u8; 32]), 0),
            Err(InstallError::Duplicate)
        ));
        // Per-link cap = 2.
        t.install(&inst(2, 2, 1), prev, Some([9u8; 32]), 0).unwrap();
        assert!(matches!(
            t.install(&inst(3, 3, 1), prev, Some([9u8; 32]), 0),
            Err(InstallError::PerLinkFull)
        ));
        // A different link still works until the GLOBAL cap (3) is hit.
        // Distinct cid_out (3) so it doesn't collide on the backward index with
        // the (next=[9], cid_out=1) circuit installed above — the cap, not a
        // bwd collision, is what this asserts.
        t.install(&inst(1, 3, 1), [2u8; 32], Some([9u8; 32]), 0)
            .unwrap();
        assert!(matches!(
            t.install(&inst(1, 4, 1), [3u8; 32], Some([9u8; 32]), 0),
            Err(InstallError::TableFull)
        ));
    }

    #[test]
    fn rejects_backward_index_collision() {
        // Two circuits through this relay toward the SAME next_link with the SAME
        // originator-chosen circuit_id_out, but distinct (prev_link, cid_in). The
        // forward dedup does NOT catch this; the backward-index dedup must — else
        // the first circuit's return route is silently overwritten and a later
        // teardown of either breaks the survivor (diff-audit S1/M1).
        let t = CircuitTable::new();
        let next = [9u8; 32];
        t.install(&inst(10, 50, 0xAA), [1u8; 32], Some(next), 0)
            .unwrap();
        // Same (next, cid_out=50), different (prev, cid_in) → rejected, not
        // silently overwritten.
        assert!(matches!(
            t.install(&inst(20, 50, 0xBB), [2u8; 32], Some(next), 0),
            Err(InstallError::Duplicate)
        ));
        // The first circuit's return route is intact and still its OWN state.
        let b = t.lookup_backward(&next, 50).unwrap();
        assert_eq!(b.circuit_id_in, 10);
        assert_eq!(b.circuit_key, [0xAA; CIRCUIT_KEY_LEN]);
        // A distinct (next, cid_out) still installs fine.
        t.install(&inst(30, 51, 0xCC), [3u8; 32], Some(next), 0)
            .unwrap();
        assert_eq!(t.lookup_backward(&next, 51).unwrap().circuit_id_in, 30);
        // And tearing it down leaves the first circuit's return route untouched.
        t.remove(&[3u8; 32], 30);
        assert!(t.lookup_backward(&next, 50).is_some());
    }

    #[test]
    fn remove_clears_both_indices_and_count() {
        let t = CircuitTable::new();
        let prev = [1u8; 32];
        let next = [2u8; 32];
        t.install(&inst(10, 11, 1), prev, Some(next), 0).unwrap();
        t.remove(&prev, 10);
        assert!(t.lookup_forward(&prev, 10).is_none());
        assert!(t.lookup_backward(&next, 11).is_none());
        assert!(t.is_empty());
        // Per-link freed → can install again up to cap.
        t.install(&inst(10, 11, 1), prev, Some(next), 0).unwrap();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn full_bucket_with_idle_expired_admits_after_inline_gc() {
        // The small-topology starvation regression: a bucket full of
        // idle-expired one-shot circuits must not refuse a new registration
        // just because the periodic gc tick hasn't run — install itself
        // reclaims what the gc would reap and retries.
        let t = CircuitTable::with_params(100, 2, 300);
        let prev = [1u8; 32];
        t.install(&inst(1, 0, 1), prev, None, 1000).unwrap();
        t.install(&inst(2, 0, 1), prev, None, 1000).unwrap();
        // Both occupants idle past the TTL → the new install evicts + lands.
        let s = t.install(&inst(3, 0, 1), prev, None, 1000 + 300).unwrap();
        assert_eq!(s.circuit_id_in, 3);
        assert!(t.lookup_forward(&prev, 1).is_none(), "expired occupant evicted");
        assert!(t.lookup_forward(&prev, 2).is_none(), "expired occupant evicted");
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn full_bucket_all_fresh_still_refuses() {
        // Reject-on-full is intact for LIVE circuits: nothing idle-expired,
        // nothing served → the inline reclaim finds no victim and the verdict
        // stays PerLinkFull.
        let t = CircuitTable::with_params(100, 2, 300);
        let prev = [1u8; 32];
        t.install(&inst(1, 0, 1), prev, None, 1000).unwrap();
        t.install(&inst(2, 0, 1), prev, None, 1000).unwrap();
        assert!(matches!(
            t.install(&inst(3, 0, 1), prev, None, 1000 + 299),
            Err(InstallError::PerLinkFull)
        ));
        assert_eq!(t.len(), 2, "no live occupant was evicted");
    }

    #[test]
    fn table_full_with_idle_expired_admits_after_inline_gc() {
        // Same relief for the GLOBAL cap: expired entries anywhere in the
        // table are reclaimed before a TableFull refusal.
        let t = CircuitTable::with_params(2, 64, 300);
        t.install(&inst(1, 0, 1), [1u8; 32], None, 0).unwrap();
        t.install(&inst(2, 0, 1), [2u8; 32], None, 0).unwrap();
        // Fresh entries at t=299 → still refused.
        assert!(matches!(
            t.install(&inst(3, 0, 1), [3u8; 32], None, 299),
            Err(InstallError::TableFull)
        ));
        // Expired at t=300 → reclaimed, install lands.
        t.install(&inst(3, 0, 1), [3u8; 32], None, 300).unwrap();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn served_reply_binding_freed_under_install_pressure() {
        // A one-shot reply binding that already forwarded its introduce frees
        // its bucket slot under pressure once SERVED_LINGER_SECS have passed —
        // while an unserved, fresh sibling is never touched.
        let t = CircuitTable::with_params(100, 2, 300);
        let prev = [1u8; 32];
        let served = t.install(&inst(1, 0, 1), prev, None, 1000).unwrap();
        t.install(&inst(2, 0, 1), prev, None, 1000).unwrap();
        served.mark_served(1005);
        // Linger not yet elapsed (and nothing idle-expired) → still refused.
        assert!(matches!(
            t.install(&inst(3, 0, 1), prev, None, 1005 + SERVED_LINGER_SECS - 1),
            Err(InstallError::PerLinkFull)
        ));
        // Linger elapsed → the SERVED circuit is evicted, the fresh unserved
        // one survives, and the install lands.
        t.install(&inst(3, 0, 1), prev, None, 1005 + SERVED_LINGER_SECS)
            .unwrap();
        assert!(t.lookup_forward(&prev, 1).is_none(), "served slot reclaimed");
        assert!(
            t.lookup_forward(&prev, 2).is_some(),
            "unserved live circuit must never be pressure-evicted"
        );
        assert!(t.lookup_forward(&prev, 3).is_some());
    }

    #[test]
    fn remark_served_rearms_linger_for_multi_slice_replies() {
        // A sliced reply is several introduces down ONE binding; every forward
        // re-arms the linger clock, so only quiet-since-the-LAST-slice bindings
        // are reclaimable — an in-flight multi-part reply is never cut.
        let t = CircuitTable::with_params(100, 1, 300);
        let prev = [1u8; 32];
        let s = t.install(&inst(1, 0, 1), prev, None, 1000).unwrap();
        s.mark_served(1000); // slice 1
        s.mark_served(1020); // slice 2 re-arms the clock
        assert!(matches!(
            t.install(&inst(2, 0, 1), prev, None, 1020 + SERVED_LINGER_SECS - 1),
            Err(InstallError::PerLinkFull)
        ));
        t.install(&inst(2, 0, 1), prev, None, 1020 + SERVED_LINGER_SECS)
            .unwrap();
        assert!(t.lookup_forward(&prev, 2).is_some());
    }

    #[test]
    fn gc_evicts_idle() {
        let t = CircuitTable::with_params(100, 64, 300);
        let prev = [1u8; 32];
        let s = t
            .install(&inst(10, 11, 1), prev, Some([2u8; 32]), 1000)
            .unwrap();
        // Still fresh at +299.
        assert_eq!(t.gc(1000 + 299), 0);
        // touch advances the clock.
        s.touch(1500);
        assert_eq!(t.gc(1500 + 299), 0);
        // Idle past TTL → evicted.
        assert_eq!(t.gc(1500 + 300), 1);
        assert!(t.is_empty());
    }
}
