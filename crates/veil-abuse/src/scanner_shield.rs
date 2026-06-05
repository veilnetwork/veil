//! Per-source-IP shield against pre-protocol garbage handshakes.
//!
//! Internet-facing veil listeners receive a steady stream of port-scanner
//! and HTTP-probe traffic that opens a TCP connection, sends a few garbage
//! bytes, then drops. Each such connection costs an inbound-session task
//! spawn, a buffer alloc, an OVL1-frame parse, a `WARN handshake.failure`
//! log line, and a metric increment — all to reject obviously-not-our-protocol
//! traffic.
//!
//! `ScannerShield` tracks per-source-IP counts of "pre-protocol" handshake
//! failures (currently: `ProtoError::InvalidMagic`, i.e. the first 4 bytes
//! were not OVL1). After `MAX_GARBAGE_FAILURES_PER_WINDOW` failures within
//! `WINDOW`, the IP is soft-banned for `BAN_DURATION` and new TCP connections
//! from it are dropped at the listener's accept loop without spawning a
//! handshake task.
//!
//! Bounded at `MAX_TRACKED_IPS` to prevent unbounded growth from spoofed
//! sources.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Pre-protocol handshake failures from a single source IP within `WINDOW`
/// before that IP is soft-banned.
pub const MAX_GARBAGE_FAILURES_PER_WINDOW: u32 = 5;

/// Sliding window during which `MAX_GARBAGE_FAILURES_PER_WINDOW` failures
/// trip the soft-ban.
pub const WINDOW: Duration = Duration::from_secs(60);

/// How long a soft-banned IP stays banned after tripping the threshold.
pub const BAN_DURATION: Duration = Duration::from_secs(300);

/// Maximum number of IPs tracked simultaneously. Capped to prevent unbounded
/// memory growth from spoofed source IPs.
pub const MAX_TRACKED_IPS: usize = 8192;

#[derive(Debug, Clone, Copy)]
struct FailureRecord {
    count: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct ScannerShield {
    inner: Mutex<HashMap<IpAddr, FailureRecord>>,
}

impl ScannerShield {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Record a pre-protocol handshake failure from `ip` (e.g. invalid magic).
    /// Returns `true` iff this failure pushed the IP over the threshold and it
    /// is now banned.
    pub fn record_garbage_failure(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if !map.contains_key(&ip) && map.len() >= MAX_TRACKED_IPS {
            evict_stale(&mut map, now);
            if map.len() >= MAX_TRACKED_IPS {
                // Still full after eviction: fail open (no ban) rather than
                // silently dropping the record.
                return false;
            }
        }
        let entry = map.entry(ip).or_insert(FailureRecord {
            count: 0,
            window_start: now,
            banned_until: None,
        });
        if entry.banned_until.is_some_and(|t| now < t) {
            // Already banned — keep the ban as-is.
            return true;
        }
        if now.duration_since(entry.window_start) >= WINDOW {
            // Window rolled over: reset.
            entry.count = 0;
            entry.window_start = now;
            entry.banned_until = None;
        }
        entry.count += 1;
        if entry.count >= MAX_GARBAGE_FAILURES_PER_WINDOW {
            entry.banned_until = Some(now + BAN_DURATION);
            true
        } else {
            false
        }
    }

    /// Returns `true` iff `ip` is currently soft-banned and new connections
    /// from it should be dropped.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match map.get(&ip) {
            Some(entry) => match entry.banned_until {
                Some(t) if now < t => true,
                Some(_) => {
                    // Ban expired: reset the record so the IP starts fresh.
                    map.remove(&ip);
                    false
                }
                None => false,
            },
            None => false,
        }
    }
}

fn evict_stale(map: &mut HashMap<IpAddr, FailureRecord>, now: Instant) {
    map.retain(|_, rec| {
        if let Some(t) = rec.banned_until {
            now < t
        } else {
            now.duration_since(rec.window_start) < WINDOW
        }
    });
}

/// Detect whether a `NodeError::Handshake(msg)` corresponds to pre-protocol
/// garbage (port-scanner / wrong-protocol traffic) versus a real OVL1
/// handshake-protocol problem.
///
/// We pattern-match the message text because `NodeError::Handshake` flattens
/// the underlying `ProtoError` into a string before reaching the metrics
/// site. The substrings below correspond to `ProtoError::InvalidMagic`
/// and the related "decode … frame header" prefix used by every OVL1
/// header decoder.
pub fn is_pre_protocol_garbage(msg: &str) -> bool {
    msg.contains("invalid magic") || msg.contains("unsupported version")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn under_threshold_does_not_ban() {
        let shield = ScannerShield::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..(MAX_GARBAGE_FAILURES_PER_WINDOW - 1) {
            assert!(!shield.record_garbage_failure(ip));
        }
        assert!(!shield.is_banned(ip));
    }

    #[test]
    fn at_threshold_bans_ip() {
        let shield = ScannerShield::new();
        let ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        for i in 0..MAX_GARBAGE_FAILURES_PER_WINDOW {
            let banned = shield.record_garbage_failure(ip);
            if i + 1 < MAX_GARBAGE_FAILURES_PER_WINDOW {
                assert!(!banned);
            } else {
                assert!(banned);
            }
        }
        assert!(shield.is_banned(ip));
    }

    #[test]
    fn other_ips_unaffected() {
        let shield = ScannerShield::new();
        let scanner = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        let legit = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..MAX_GARBAGE_FAILURES_PER_WINDOW {
            shield.record_garbage_failure(scanner);
        }
        assert!(shield.is_banned(scanner));
        assert!(!shield.is_banned(legit));
    }

    #[test]
    fn classifier_recognises_invalid_magic() {
        assert!(is_pre_protocol_garbage(
            "decode OVL1 frame header: invalid magic: expected OVL1, got [71, 69, 84, 32]"
        ));
        assert!(is_pre_protocol_garbage("unsupported version: 99"));
        assert!(!is_pre_protocol_garbage(
            "peer signature verification failed"
        ));
        assert!(!is_pre_protocol_garbage("ML-KEM decapsulation failed"));
    }
}
