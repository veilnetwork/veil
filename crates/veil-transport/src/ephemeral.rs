//! Ephemeral port binder with collision retry.
//!
//! Picks a random port from the configured range; if `EADDRINUSE` (some
//! other process on the host bound it first), retries with a fresh random
//! pick up to `bind_retries` times.  Use case: snowflake-style anti-port-
//! clustering — each node in the fleet listens on a different port
//! within the same range, so DPI / scanner can't recognize "all veil
//! nodes listen on 5556" cluster signal.
//!
//! ## What's IN scope (Phase 5a)
//!
//! - Pure binding helper: input = (host, port range, retry count);
//!   output = a bound `TcpListener` or error.
//! - Pure functions, no runtime state.  Caller decides when to call
//!   (initial boot, rotation event, etc.).
//!
//! ## What's deferred (Phase 5b/5c)
//!
//! - **Rotation scheduler**: periodic re-bind with grace period for in-
//!   flight sessions — needs integration with the runtime task-spawner.
//! - **Peer-notify wire frame** (`TransportMigrationNotify`): broadcasting
//!   the new URI to active peers before the old port closes — needs
//!   a new proto family member + dispatcher arm.
//! - **Invite-bundle CLI**: out-of-band distribution for trusted listener
//!   URIs — needs CLI scaffolding + CBOR + base32.

use std::ops::RangeInclusive;

use rand::Rng;
use tokio::net::TcpListener;

use super::error::{Result, TransportError};

/// Maximum sensible retry count.  Tuned for typical 50k-port ranges
/// under typical load — `(1 - p_collision)^64 > 0.999999` for 1000
/// occupied ports.
pub const DEFAULT_BIND_RETRIES: u32 = 64;

/// Pick a random port in `port_range` and attempt `TcpListener::bind`
/// on `(host, port)`.  Retry up to `bind_retries` times on `EADDRINUSE`
/// (per RFC; on Linux this `errno=98`).  Other errors fail immediately
/// (no point retrying if, e.g., the host isn't bindable).
///
/// Returns the bound `TcpListener` AND the random port chosen so the
/// caller can advertise/publish that port.
///
/// # Arguments
/// - `host`: bind host (e.g. `"0.0.0.0"`).
/// - `port_range`: inclusive port range (e.g. `10000..=60000`).  Empty
///   range (start > end) errors immediately.
/// - `bind_retries`: max attempts.  0 = single-shot (no retry).
pub async fn bind_random_port(
    host: &str,
    port_range: RangeInclusive<u16>,
    bind_retries: u32,
) -> Result<(TcpListener, u16)> {
    let (low, high) = (*port_range.start(), *port_range.end());
    if low > high {
        return Err(TransportError::Unsupported(format!(
            "ephemeral port range invalid: {low}..={high}"
        )));
    }
    let mut last_err: Option<std::io::Error> = None;
    let total_attempts = bind_retries.saturating_add(1);
    for _ in 0..total_attempts {
        let port: u16 = rand::rng().random_range(low..=high);
        match TcpListener::bind((host, port)).await {
            Ok(listener) => return Ok((listener, port)),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(TransportError::Io(e)),
        }
    }
    Err(TransportError::Io(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrInUse, "all bind attempts exhausted")
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Single-shot bind succeeds for a wide range on localhost.
    #[tokio::test]
    async fn bind_random_succeeds_wide_range() {
        let (listener, port) = bind_random_port("127.0.0.1", 30000..=60000, 64)
            .await
            .expect("bind should succeed");
        assert!((30000..=60000).contains(&port), "port {port} not in range");
        let local = listener.local_addr().unwrap();
        assert_eq!(local.port(), port);
    }

    /// Invalid range (start > end) errors immediately.
    #[tokio::test]
    #[allow(clippy::reversed_empty_ranges)] // intentional — verifies negative-path validation rejects inverted range
    async fn bind_random_rejects_invalid_range() {
        let err = bind_random_port("127.0.0.1", 50000..=10000, 64)
            .await
            .expect_err("invalid range must error");
        let msg = format!("{err}");
        assert!(msg.contains("invalid"), "got: {msg}");
    }

    /// Single-port range (low == high) works iff that port is free.
    #[tokio::test]
    async fn bind_random_single_port_range() {
        // Bind two listeners ON a single-port range — first succeeds,
        // second must fail (with retry exhausted).
        let (_first, port) = bind_random_port("127.0.0.1", 40000..=50000, 64)
            .await
            .expect("first bind ok");
        let single = port..=port;
        // Now retry-bind on the same port; first attempt collides,
        // 64 retries also collide (single-port range), so eventually fails.
        let err = bind_random_port("127.0.0.1", single, 5)
            .await
            .expect_err("collision must fail after retries");
        let msg = format!("{err}").to_lowercase();
        // Linux/macOS phrase WSAEADDRINUSE as "address already in use";
        // Windows phrases it "only one usage of each socket address …
        // (os error 10048)". Accept either so the assertion is portable.
        assert!(
            msg.contains("in use")
                || msg.contains("addrinuse")
                || msg.contains("usage of each socket address")
                || msg.contains("10048"),
            "got: {msg}"
        );
    }

    /// Two simultaneous binds on a wide range produce different ports.
    #[tokio::test]
    async fn bind_random_diversity() {
        let (_l1, p1) = bind_random_port("127.0.0.1", 30000..=60000, 64)
            .await
            .unwrap();
        let (_l2, p2) = bind_random_port("127.0.0.1", 30000..=60000, 64)
            .await
            .unwrap();
        // 30000-port range; collision probability is 1/30000 ≈ 0.003%.
        // If they're equal, either bad luck either bug.  Re-run if spurious.
        assert_ne!(
            p1, p2,
            "two ephemeral binds picked the same port (re-run if spurious)"
        );
    }

    /// Zero retries = single-shot.
    #[tokio::test]
    async fn bind_random_zero_retries_single_shot() {
        // Pre-bind a port to force collision.
        let (_l1, port) = bind_random_port("127.0.0.1", 40000..=50000, 64)
            .await
            .unwrap();
        // Now try to bind same port with zero retries.
        let result = bind_random_port("127.0.0.1", port..=port, 0).await;
        assert!(result.is_err(), "zero retries should fail on collision");
    }
}
