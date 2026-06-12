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
//! (the DoS surface 482.7 §5 flags). Reject-on-full (never evict an honest
//! circuit to admit a new one).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

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

    /// Allocate the next return-direction seq for a cell this node originates.
    /// Wraps past `u32::MAX` back to 1 (never returns 0).
    pub fn alloc_return_seq(&self) -> u32 {
        let s = self.next_return_seq.fetch_add(1, Ordering::Relaxed);
        if s == 0 { 1 } else { s }
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
    /// Per-prev-link live count for the per-link cap.
    per_link: HashMap<Link, usize>,
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
        if g.fwd.len() >= self.max_total {
            return Err(InstallError::TableFull);
        }
        if g.per_link.get(&prev_link).copied().unwrap_or(0) >= self.max_per_link {
            return Err(InstallError::PerLinkFull);
        }
        let state = std::sync::Arc::new(CircuitState::from_install(
            install, prev_link, next_link, now,
        ));
        g.fwd.insert(fwd_key, std::sync::Arc::clone(&state));
        if let Some(nl) = next_link {
            g.bwd
                .insert((nl, install.circuit_id_out), std::sync::Arc::clone(&state));
        }
        *g.per_link.entry(prev_link).or_insert(0) += 1;
        Ok(state)
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
        if let Some(state) = g.fwd.remove(&(*prev_link, cid_in)) {
            if let Some(nl) = state.next_link {
                g.bwd.remove(&(nl, state.circuit_id_out));
            }
            if let Some(c) = g.per_link.get_mut(prev_link) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    g.per_link.remove(prev_link);
                }
            }
        }
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
            if let Some(state) = g.fwd.remove(&(*prev_link, *cid_in)) {
                if let Some(nl) = state.next_link {
                    g.bwd.remove(&(nl, state.circuit_id_out));
                }
                if let Some(c) = g.per_link.get_mut(prev_link) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        g.per_link.remove(prev_link);
                    }
                }
            }
        }
        stale.len()
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
        t.install(&inst(1, 1, 1), [2u8; 32], Some([9u8; 32]), 0)
            .unwrap();
        assert!(matches!(
            t.install(&inst(1, 1, 1), [3u8; 32], Some([9u8; 32]), 0),
            Err(InstallError::TableFull)
        ));
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
