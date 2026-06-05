//! On-demand listener controller — Slice 2 of the PoW-Gated
//! Rendezvous epic ([`docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`]).
//!
//! Provides the primitive that converts а valid PoW-gated rendezvous
//! request into а short-lived listener slot.  Lifecycle:
//!
//! 1. **Port reservation** — caller invokes [`bind_on_demand`], which
//!    calls [`super::ephemeral::bind_random_port`] к probe-bind а free
//!    port в the configured range, then drops the listener (caller
//!    rebinds через `TransportRegistry` so the actual obfs4/wss/quic
//!    wrapping happens uniformly).
//! 2. **Lifecycle tracking** — [`OnDemandLifecycle`] tracks two
//!    independent exit conditions: TTL expiry (wall-clock deadline)
//!    AND remaining accept count (after `max_accepts` handshakes the
//!    slot retires).  Either condition triggers exit.
//! 3. **Caller-driven accept loop** — Slice 3's rendezvous-server
//!    controller spawns its own accept task using the lifecycle handle
//!    в а `tokio::select!` arm; the accept task awaits the lifecycle
//!    OR а `listener.accept()` future и breaks out cleanly когда
//!    lifecycle fires.
//!
//! ## Why split bind from accept-loop
//!
//! Phase 5f's `spawn_listeners` accept loop assumes а persistent
//! listener (replaceable mid-flight via swap-channel, but always
//! present).  On-demand semantics are different: the listener is
//! ephemeral, single-purpose, и cleans up after itself — owning а
//! complete short-lived task lifecycle is cleaner than retro-fitting
//! "remove listener" semantics onto the Phase 5f swap channel.
//!
//! Slice 3 (rendezvous controller server) spawns the dedicated task
//! using this primitive's outputs.

use std::ops::RangeInclusive;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use super::error::{Result, TransportError};

// ── Configuration ───────────────────────────────────────────────────

/// Operator-visible knobs для one PoW-gated rendezvous request.
///
/// Typical production values:
/// * `ttl = Duration::from_secs(300)` — 5-minute window for the
///   initiator к dial back; balances "too short ⇒ legitimate clients
///   miss the window" с "too long ⇒ DPI scanner с captured token
///   has more time".
/// * `max_accepts = 1` — one-shot.  Higher values are valid for
///   multi-device pairing flows что land several connections в quick
///   succession.
/// * `bind_retries = 64` — matches the Phase 5а rotator default.
#[derive(Debug, Clone)]
pub struct OnDemandConfig {
    /// Bind host, e.g. `"0.0.0.0"` или а specific local IP.
    pub host: String,
    /// Inclusive random-port range.
    pub port_range: RangeInclusive<u16>,
    /// Retries on `EADDRINUSE` during port probing.
    pub bind_retries: u32,
    /// Lifetime of the slot от bind moment.  Must be > 0.
    pub ttl: Duration,
    /// Maximum accepted sessions before slot retires.  Must be > 0.
    /// 1 = one-shot rendezvous; higher = "open для N dials of the
    /// same requester within the TTL" (rare).
    pub max_accepts: usize,
}

// ── Lifecycle handle ────────────────────────────────────────────────

/// Tracks the two exit conditions для an on-demand slot: TTL deadline
/// + remaining accept budget.  Shared between the rendezvous-server
///   controller (which decrements `accepts_remaining` after each
///   successful handshake) и the slot's dedicated accept task (which
///   awaits the lifecycle в а `select!` arm).
///
/// All fields are `Arc`-shareable; instances are cheap к clone.  Both
/// fields use atomic / channel-based concurrency primitives so the
/// shared handle does not require external locking.
#[derive(Debug)]
pub struct OnDemandLifecycle {
    /// Wall-clock instant after which the slot is invalid.  Captured
    /// от `Instant::now() + ttl` at bind time.
    expires_at: Instant,
    /// Decremented on each successful accept.  Reaching 0 retires the
    /// slot regardless of TTL.
    accepts_remaining: AtomicUsize,
    /// Used к forcibly retire the slot (e.g. когда the controller
    /// fails к ship the EphemeralEndpointResponse и wants к release
    /// the port immediately rather than waiting для TTL).
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl OnDemandLifecycle {
    /// Record one accepted handshake.  Returns the **previous** count
    /// of `accepts_remaining`.  Caller decides what к do based на the
    /// return value:
    /// * `prev == 1` ⇒ this was the last allowed accept — caller
    ///   should stop listening на the next iteration.
    /// * `prev == 0` (already retired) ⇒ caller should reject this
    ///   connection (race between `should_exit()` check и acceptance).
    /// * `prev > 1` ⇒ slot remains open для more accepts within TTL.
    pub fn note_accept(&self) -> usize {
        // Saturating-sub semantics: we don't want to underflow,
        // even в the rare race где multiple accept-loops call this
        // против а fully-spent slot.
        loop {
            let prev = self.accepts_remaining.load(Ordering::SeqCst);
            if prev == 0 {
                return 0;
            }
            if self
                .accepts_remaining
                .compare_exchange(prev, prev - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return prev;
            }
        }
    }

    /// Returns true iff the slot has retired — either TTL elapsed или
    /// accept budget exhausted.  Cheap к call (no syscall, no lock).
    pub fn should_exit(&self) -> bool {
        if Instant::now() >= self.expires_at {
            return true;
        }
        if self.accepts_remaining.load(Ordering::SeqCst) == 0 {
            return true;
        }
        if *self.shutdown_rx.borrow() {
            return true;
        }
        false
    }

    /// Async wait until either (a) TTL deadline reached, (b) explicit
    /// shutdown signalled.  Note this does NOT track the accept-budget
    /// path — accept-task implementations check `note_accept()` после
    /// each handshake и break out of their loop manually когда the
    /// returned `prev` indicates the slot is now retired.
    ///
    /// Designed для use в а `tokio::select!` arm alongside
    /// `listener.accept()` so the accept-task wakes promptly when
    /// the slot retires.
    pub async fn await_ttl_or_shutdown(&self) {
        let until = tokio::time::Instant::from_std(self.expires_at);
        let mut rx = self.shutdown_rx.clone();
        tokio::select! {
            _ = tokio::time::sleep_until(until) => {}
            _ = rx.changed() => {}
        }
    }

    /// Force-retire the slot.  Wakes any task awaiting
    /// `await_ttl_or_shutdown` immediately.  Idempotent: calling twice
    /// has the same effect as calling once.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Remaining accept budget.  Useful для diagnostics / metrics.
    pub fn accepts_remaining(&self) -> usize {
        self.accepts_remaining.load(Ordering::SeqCst)
    }

    /// Wall-clock expiry instant.  Useful для diagnostics / metrics.
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

// ── Bind result ─────────────────────────────────────────────────────

/// Output of а successful [`bind_on_demand`] call.  Caller uses
/// `port` to compose the transport URI (typically `obfs4-tcp://host:port`)
/// и then calls `TransportRegistry::bind(uri, ctx)` к get а real
/// `Box<dyn TransportListener>`.  The `lifecycle` handle is shared
/// между the controller и the spawned accept task.
#[derive(Debug)]
pub struct OnDemandSlot {
    /// Bind host that the probe used (echoes config — useful когда the
    /// caller has multiple slots в flight и needs к keep track).
    pub host: String,
    /// Random port chosen by [`super::ephemeral::bind_random_port`].
    /// Verified-free at bind time; small race vs caller's actual rebind
    /// is acceptable (handled by `TransportRegistry::bind` returning
    /// an error → controller retries или fails the request).
    pub port: u16,
    /// Shared lifecycle handle.  Cloneable cheaply.
    pub lifecycle: Arc<OnDemandLifecycle>,
}

// ── Public API ──────────────────────────────────────────────────────

/// Probe-bind а free port from the configured range и build а
/// lifecycle handle для the slot.  Returns immediately после the
/// probe drops; caller is responsible for invoking
/// `TransportRegistry::bind(uri, ctx)` к actually open the listener.
///
/// Failures:
/// * `OnDemandConfig::ttl == 0` ⇒ refused
/// * `OnDemandConfig::max_accepts == 0` ⇒ refused
/// * Port range inverted ⇒ delegated к `bind_random_port`'s validation
/// * All `bind_retries` attempts collide ⇒ delegated к `bind_random_port`
pub async fn bind_on_demand(config: OnDemandConfig) -> Result<OnDemandSlot> {
    if config.ttl.is_zero() {
        return Err(TransportError::Unsupported(
            "on-demand: ttl must be > 0".to_owned(),
        ));
    }
    if config.max_accepts == 0 {
        return Err(TransportError::Unsupported(
            "on-demand: max_accepts must be > 0".to_owned(),
        ));
    }

    // Probe-bind к verify а free port.  We drop the listener immediately
    // — caller rebinds через TransportRegistry (which composes obfs4 /
    // TLS / etc. wrapping that this primitive doesn't know about).
    let (probe, port) =
        super::ephemeral::bind_random_port(&config.host, config.port_range, config.bind_retries)
            .await?;
    drop(probe);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let lifecycle = Arc::new(OnDemandLifecycle {
        expires_at: Instant::now() + config.ttl,
        accepts_remaining: AtomicUsize::new(config.max_accepts),
        shutdown_tx,
        shutdown_rx,
    });

    Ok(OnDemandSlot {
        host: config.host,
        port,
        lifecycle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(ttl: Duration, max_accepts: usize) -> OnDemandConfig {
        OnDemandConfig {
            host: "127.0.0.1".to_owned(),
            port_range: 30000..=60000,
            bind_retries: 64,
            ttl,
            max_accepts,
        }
    }

    fn make_lifecycle(ttl: Duration, max_accepts: usize) -> Arc<OnDemandLifecycle> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Arc::new(OnDemandLifecycle {
            expires_at: Instant::now() + ttl,
            accepts_remaining: AtomicUsize::new(max_accepts),
            shutdown_tx,
            shutdown_rx,
        })
    }

    // ── Configuration validation ──────────────────────────────────

    #[tokio::test]
    async fn bind_rejects_zero_ttl() {
        let err = bind_on_demand(cfg(Duration::ZERO, 1)).await.unwrap_err();
        assert!(format!("{err}").contains("ttl must be > 0"));
    }

    #[tokio::test]
    async fn bind_rejects_zero_max_accepts() {
        let err = bind_on_demand(cfg(Duration::from_secs(60), 0))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("max_accepts must be > 0"));
    }

    #[tokio::test]
    async fn bind_happy_path_returns_port_in_range() {
        let slot = bind_on_demand(cfg(Duration::from_secs(60), 1))
            .await
            .expect("bind должен succeed");
        assert!((30000..=60000).contains(&slot.port));
        assert_eq!(slot.host, "127.0.0.1");
        assert_eq!(slot.lifecycle.accepts_remaining(), 1);
    }

    #[tokio::test]
    async fn bind_dropped_listener_releases_port() {
        // After bind_on_demand returns, the probe listener is dropped
        // and the port is free to be rebound by the caller (or by а
        // second call к bind_on_demand).  Verify by binding the same
        // port-range again и asserting no error.
        let _slot1 = bind_on_demand(cfg(Duration::from_secs(60), 1))
            .await
            .unwrap();
        let _slot2 = bind_on_demand(cfg(Duration::from_secs(60), 1))
            .await
            .unwrap();
        // Both succeed — ports are diverse due к random pick over а
        // 30k-port range.
    }

    // ── note_accept ────────────────────────────────────────────────

    #[test]
    fn note_accept_decrements_counter() {
        let l = make_lifecycle(Duration::from_secs(60), 3);
        assert_eq!(l.note_accept(), 3);
        assert_eq!(l.accepts_remaining(), 2);
        assert_eq!(l.note_accept(), 2);
        assert_eq!(l.accepts_remaining(), 1);
        // Last accept — returns 1.  Slot is now retired.
        assert_eq!(l.note_accept(), 1);
        assert_eq!(l.accepts_remaining(), 0);
    }

    #[test]
    fn note_accept_after_exhaustion_returns_zero() {
        let l = make_lifecycle(Duration::from_secs(60), 1);
        assert_eq!(l.note_accept(), 1);
        // Already retired — subsequent calls return 0 без underflow.
        assert_eq!(l.note_accept(), 0);
        assert_eq!(l.note_accept(), 0);
        assert_eq!(l.accepts_remaining(), 0);
    }

    #[test]
    fn note_accept_concurrent_does_not_underflow() {
        // Hammer note_accept от 16 threads against а budget of 8.
        // Final accepts_remaining must be 0 (not negative), и exactly
        // 8 of the 16 calls should have returned non-zero prev.
        let l = make_lifecycle(Duration::from_secs(60), 8);
        let l_arc = Arc::clone(&l);
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let l = Arc::clone(&l_arc);
                std::thread::spawn(move || l.note_accept())
            })
            .collect();
        let results: Vec<usize> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(l.accepts_remaining(), 0);
        let granted = results.iter().filter(|&&p| p > 0).count();
        assert_eq!(granted, 8, "exactly 8 grants for а budget of 8");
    }

    // ── should_exit ────────────────────────────────────────────────

    #[test]
    fn should_exit_false_before_ttl_with_budget() {
        let l = make_lifecycle(Duration::from_secs(60), 1);
        assert!(!l.should_exit());
    }

    #[test]
    fn should_exit_true_when_accepts_exhausted() {
        let l = make_lifecycle(Duration::from_secs(60), 1);
        l.note_accept();
        assert!(l.should_exit());
    }

    #[tokio::test]
    async fn should_exit_true_after_ttl() {
        let l = make_lifecycle(Duration::from_millis(10), 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(l.should_exit());
    }

    #[test]
    fn should_exit_true_after_explicit_shutdown() {
        let l = make_lifecycle(Duration::from_secs(60), 1);
        assert!(!l.should_exit());
        l.shutdown();
        assert!(l.should_exit());
    }

    // ── await_ttl_or_shutdown ──────────────────────────────────────

    #[tokio::test]
    async fn await_ttl_or_shutdown_returns_on_ttl() {
        let l = make_lifecycle(Duration::from_millis(50), 1);
        let start = Instant::now();
        l.await_ttl_or_shutdown().await;
        let elapsed = start.elapsed();
        // Should resolve after ~50ms, well before а generous timeout.
        assert!(
            elapsed >= Duration::from_millis(40) && elapsed < Duration::from_millis(500),
            "elapsed was {elapsed:?}",
        );
    }

    #[tokio::test]
    async fn await_ttl_or_shutdown_returns_on_explicit_shutdown() {
        let l = make_lifecycle(Duration::from_secs(60), 1);
        let l_arc = Arc::clone(&l);
        let waiter = tokio::spawn(async move { l_arc.await_ttl_or_shutdown().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        l.shutdown();
        // Should resolve promptly (< TTL of 60s).
        let result = tokio::time::timeout(Duration::from_secs(1), waiter).await;
        assert!(result.is_ok(), "waiter должен resolve после shutdown");
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let l = make_lifecycle(Duration::from_secs(60), 1);
        l.shutdown();
        l.shutdown();
        l.shutdown();
        assert!(l.should_exit());
    }

    // ── Accept-loop integration pattern ────────────────────────────

    /// Demonstrates the canonical accept-loop pattern that Slice 3's
    /// rendezvous server will use.  This integration test simulates
    /// 2 accept-loop iterations on а budget of 2, then verifies the
    /// loop exits cleanly after the budget is spent.
    #[tokio::test]
    async fn canonical_accept_loop_exits_when_budget_spent() {
        let lifecycle = make_lifecycle(Duration::from_secs(60), 2);

        // Pretend the actual listener.accept() returns immediately
        // by yielding к tokio.  Real accept loop has а listener.accept()
        // future в the select! arm alongside lifecycle.await_ttl_or_shutdown().
        let mut accepts = 0;
        loop {
            if lifecycle.should_exit() {
                break;
            }
            // Simulate accept landing.
            let prev = lifecycle.note_accept();
            if prev == 0 {
                // Race: should_exit said budget but note_accept also
                // sees 0 — bail.  Should be unreachable here но кодом
                // должен handle it gracefully.
                break;
            }
            accepts += 1;
            if prev == 1 {
                // That was the last allowed accept.
                break;
            }
        }

        assert_eq!(accepts, 2);
        assert_eq!(lifecycle.accepts_remaining(), 0);
        assert!(lifecycle.should_exit());
    }

    #[tokio::test]
    async fn canonical_accept_loop_exits_on_ttl() {
        let lifecycle = make_lifecycle(Duration::from_millis(30), 100);

        // Sleep longer than the TTL — accept loop's
        // await_ttl_or_shutdown resolves before any "accept" lands.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(lifecycle.should_exit());

        // Budget remains untouched (no accepts happened).
        assert_eq!(lifecycle.accepts_remaining(), 100);
    }

    // ── Diagnostics getters ────────────────────────────────────────

    #[test]
    fn lifecycle_exposes_expiry_and_remaining() {
        let l = make_lifecycle(Duration::from_secs(60), 5);
        assert!(l.expires_at() > Instant::now());
        assert_eq!(l.accepts_remaining(), 5);
        l.note_accept();
        assert_eq!(l.accepts_remaining(), 4);
    }
}
