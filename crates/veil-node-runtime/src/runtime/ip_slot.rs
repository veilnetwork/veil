//! Per-source-IP session-slot accounting.
//!
//! [`check_and_reserve_ip_slot`][] performs the atomic check-and-increment
//! step at session accept time; [`IpSlotGuard`][] wraps the resulting slot
//! in RAII so a future cancellation (async drop) between accept and
//! `SessionGuard` construction cannot leak the counter.
//!
//! Two limits are enforced when the source IP is non-loopback:
//!
//! - `max_per_ip` — sessions from a single IP
//! - `max_per_subnet` — sessions from a single /24 (IPv4) or /48 (IPv6)
//!   prefix, to bound eclipse / flood attempts from a CIDR-block adversary
//!
//! Loopback peers bypass both limits — sim/devnet topologies inevitably
//! share `127.0.0.1` across all nodes and would trip the production cap at
//! mesh size > 5.
//!
//! # Implementation note — O(1) subnet count
//!
//! Earlier versions kept a single `HashMap<IpAddr, usize>` and computed the
//! subnet count by iterating ALL keys on every accept (O(N) under a lock,
//! N = unique IPs). Under a scattered-IP flood the lock-held scan blocked
//! all inbound accepts for the duration. The current design keeps a
//! parallel `HashMap<SubnetKey, usize>` so subnet count is a direct lookup
//! (O(1)). The two maps update atomically under the same `Mutex`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::error::{NodeError, Result};
use crate::types::LinkId;

use super::SessionRuntimeContext;

/// /24 (IPv4) or /48 (IPv6) subnet prefix, used as a HashMap key for
/// per-subnet collision counting.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum SubnetKey {
    V4([u8; 3]),
    V6([u16; 3]),
}

impl SubnetKey {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Self::V4([o[0], o[1], o[2]])
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                Self::V6([s[0], s[1], s[2]])
            }
        }
    }
}

/// Per-source-IP and per-subnet session-slot accounting table.
///
/// Two maps live under a single `Mutex` so reserve / release are atomic
/// across both dimensions. The per-subnet map is a direct lookup (O(1))
/// rather than the earlier O(N) scan of all unique-IP keys.
pub struct IpSlotTable {
    inner: Mutex<IpSlotInner>,
}

pub struct IpSlotInner {
    per_ip: HashMap<IpAddr, usize>,
    per_subnet: HashMap<SubnetKey, usize>,
}

impl IpSlotTable {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(IpSlotInner {
                per_ip: HashMap::new(),
                per_subnet: HashMap::new(),
            }),
        }
    }

    /// Atomically check both per-IP and per-subnet caps and increment
    /// counters on success. Returns `Err` if either limit would be
    /// breached; in that case no mutation occurs (caller's reject path
    /// doesn't need cleanup). A cap value of `0` disables that check.
    fn reserve(
        &self,
        ip: IpAddr,
        max_per_ip: usize,
        max_per_subnet: usize,
    ) -> std::result::Result<(), ReserveError> {
        let subnet = SubnetKey::from_ip(ip);
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let ip_count = inner.per_ip.get(&ip).copied().unwrap_or(0);
        if max_per_ip != 0 && ip_count >= max_per_ip {
            return Err(ReserveError::PerIpExceeded);
        }
        let subnet_count = inner.per_subnet.get(&subnet).copied().unwrap_or(0);
        if max_per_subnet != 0 && subnet_count >= max_per_subnet {
            return Err(ReserveError::PerSubnetExceeded {
                count: subnet_count,
            });
        }
        *inner.per_ip.entry(ip).or_insert(0) += 1;
        *inner.per_subnet.entry(subnet).or_insert(0) += 1;
        Ok(())
    }

    /// Release a previously-reserved slot. Decrements both per-IP and
    /// per-subnet counters; removes a map entry when its count drops to
    /// zero. Defensive — does nothing on count=0 (matches pre-refactor).
    pub fn release(&self, ip: IpAddr) {
        let subnet = SubnetKey::from_ip(ip);
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = inner.per_ip.get_mut(&ip) {
            if *c <= 1 {
                inner.per_ip.remove(&ip);
            } else {
                *c -= 1;
            }
        }
        if let Some(c) = inner.per_subnet.get_mut(&subnet) {
            if *c <= 1 {
                inner.per_subnet.remove(&subnet);
            } else {
                *c -= 1;
            }
        }
    }

    /// Number of distinct source IPs currently held. Used by tests and
    /// admin introspection. Not on the accept hot path.
    #[cfg(test)]
    pub fn ip_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .per_ip
            .len()
    }

    /// Reset both maps to empty. Used by [`NodeRuntime::stop_tasks`] when
    /// all sessions have already been torn down — the per-IP / per-subnet
    /// counters could remain stale from aborted runner tasks that didn't
    /// run their RAII drop. Cheap O(1) — just `.clear()` on both maps.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.per_ip.clear();
        inner.per_subnet.clear();
    }
}

impl Default for IpSlotTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum ReserveError {
    PerIpExceeded,
    PerSubnetExceeded { count: usize },
}

/// RAII guard for the per-IP slot increment.  Constructed RIGHT AFTER
/// [`check_and_reserve_ip_slot`][] succeeds; on drop (including async-
/// future cancellation between awaits) the slot is decremented.  Call
/// [`disarm`](IpSlotGuard::disarm) once `SessionGuard` adopts ownership
/// to suppress the destructor decrement.
///
/// Closes the async-cancellation leak where the legacy manual
/// `decrement_ip_slot(...)` calls scattered across the error-return
/// sites of `register_connection_session` could miss a decrement when
/// the future was dropped between a reserve and a manual undo site.
pub struct IpSlotGuard {
    ip: Option<IpAddr>,
    table: Arc<IpSlotTable>,
}

impl IpSlotGuard {
    /// Wrap an already-incremented slot.  Caller must have just
    /// successfully called [`check_and_reserve_ip_slot`][].
    pub fn arm(ip: IpAddr, table: Arc<IpSlotTable>) -> Self {
        Self {
            ip: Some(ip),
            table,
        }
    }

    /// Suppress the destructor decrement — typically called once
    /// `SessionGuard` has adopted responsibility for the slot.
    pub fn disarm(&mut self) {
        self.ip = None;
    }
}

impl Drop for IpSlotGuard {
    fn drop(&mut self) {
        if let Some(ip) = self.ip {
            self.table.release(ip);
        }
    }
}

/// Atomically enforce per-IP and per-/24-subnet session caps before
/// handshake bytes are exchanged.
///
/// The check-and-increment is one atomic operation under
/// `runtime.sessions_per_ip`; any error path after this point must
/// decrement (either through [`IpSlotTable::release`], [`IpSlotGuard`][]'s
/// destructor, or `SessionGuard`'s).  Logs + returns a
/// `NodeError::Handshake` on limit breach so the TCP socket is closed
/// without sending data.
pub fn check_and_reserve_ip_slot(
    runtime: &SessionRuntimeContext,
    ip: IpAddr,
    link_id: LinkId,
) -> Result<()> {
    // Auto-disable both limits for loopback peers.  On devnet/sim every
    // node binds 127.0.0.1 and they all share the one IP bucket; the
    // production-facing limits trip instantly under any mesh size > 5.
    // The check remains fully active for routable peers so eclipse /
    // flood attacks are still mitigated.
    if ip.is_loopback() {
        runtime
            .sessions_per_ip
            .reserve(ip, 0, 0)
            .expect("reserve with 0/0 caps never rejects");
        return Ok(());
    }
    match runtime.sessions_per_ip.reserve(
        ip,
        runtime.defaults.max_per_ip,
        runtime.defaults.max_per_subnet,
    ) {
        Ok(()) => Ok(()),
        Err(ReserveError::PerIpExceeded) => {
            runtime.logger.warn(
                "session.per_ip_limit",
                format!(
                    "link_id={} ip={} limit={} — inbound connection rejected",
                    link_id, ip, runtime.defaults.max_per_ip,
                ),
            );
            Err(NodeError::Handshake(format!(
                "per-IP session limit reached ({} sessions from {}); rejecting link_id={}",
                runtime.defaults.max_per_ip, ip, link_id,
            )))
        }
        Err(ReserveError::PerSubnetExceeded { count }) => {
            runtime.logger.warn(
                "session.per_subnet_limit",
                format!(
                    "link_id={} ip={} subnet_count={} limit={} — inbound connection rejected",
                    link_id, ip, count, runtime.defaults.max_per_subnet,
                ),
            );
            Err(NodeError::Handshake(format!(
                "per-subnet session limit reached ({} from subnet); rejecting link_id={}",
                runtime.defaults.max_per_subnet, link_id,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn reserve_then_release_returns_to_empty() {
        let t = IpSlotTable::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        t.reserve(ip, 10, 10).unwrap();
        assert_eq!(t.ip_count(), 1);
        t.release(ip);
        assert_eq!(t.ip_count(), 0);
    }

    #[test]
    fn per_ip_cap_rejects_when_exceeded() {
        let t = IpSlotTable::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // cap = 2 → 2 successes, 3rd rejects.
        t.reserve(ip, 2, 0).unwrap();
        t.reserve(ip, 2, 0).unwrap();
        assert!(matches!(
            t.reserve(ip, 2, 0),
            Err(ReserveError::PerIpExceeded)
        ));
    }

    #[test]
    fn per_subnet_cap_rejects_when_exceeded() {
        let t = IpSlotTable::new();
        // Three different IPs in /24 10.0.0.0/24.
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        // per_ip large, per_subnet=2 → first 2 OK, 3rd rejects on subnet.
        t.reserve(a, 100, 2).unwrap();
        t.reserve(b, 100, 2).unwrap();
        assert!(matches!(
            t.reserve(c, 100, 2),
            Err(ReserveError::PerSubnetExceeded { count: 2 })
        ));
    }

    #[test]
    fn different_subnets_dont_interfere() {
        let t = IpSlotTable::new();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        // per_subnet=1 — both succeed because they're in different /24s.
        t.reserve(a, 100, 1).unwrap();
        t.reserve(b, 100, 1).unwrap();
    }

    #[test]
    fn ipv6_uses_48_prefix() {
        let t = IpSlotTable::new();
        // Same /48: 2001:db8:1:* should collide.
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0xffff, 0, 0, 0, 2));
        let c = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x0002, 0, 0, 0, 0, 1));
        t.reserve(a, 100, 2).unwrap();
        t.reserve(b, 100, 2).unwrap();
        // Same /48 as a and b — rejected on subnet cap.
        let d = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0xeeee, 0, 0, 0, 3));
        assert!(matches!(
            t.reserve(d, 100, 2),
            Err(ReserveError::PerSubnetExceeded { .. })
        ));
        // Different /48 — succeeds.
        t.reserve(c, 100, 2).unwrap();
    }

    #[test]
    fn release_decrements_both_dimensions() {
        let t = IpSlotTable::new();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        t.reserve(a, 100, 100).unwrap();
        t.reserve(a, 100, 100).unwrap();
        t.reserve(b, 100, 100).unwrap();
        // a: 2, b: 1; subnet 10.0.0.0/24: 3.
        t.release(a);
        // a: 1, b: 1; subnet: 2.
        t.release(a);
        // a: 0 → removed; b: 1; subnet: 1.
        assert_eq!(t.ip_count(), 1);
        t.release(b);
        assert_eq!(t.ip_count(), 0);
    }

    #[test]
    fn reject_does_not_mutate_state() {
        let t = IpSlotTable::new();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        t.reserve(a, 100, 1).unwrap();
        // per_subnet=1 already saturated — reject must not increment b's counters.
        let _ = t.reserve(b, 100, 1);
        // ip_count still 1; if b had incremented and then rolled back manually,
        // ip_count would be > 1.
        assert_eq!(t.ip_count(), 1);
    }

    #[test]
    fn zero_cap_disables_check() {
        let t = IpSlotTable::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // Both caps = 0 → unlimited; reserve always succeeds.
        for _ in 0..1000 {
            t.reserve(ip, 0, 0).unwrap();
        }
    }
}
