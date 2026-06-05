//! Ephemeral-port rotation primitives — Phase 5f.
//!
//! Builds on top of [`super::ephemeral::bind_random_port`] (Phase 5а)
//! и pairs with the wire-frame from `veil-proto::session::
//! TransportMigrationNotify` (Phase 5b) + the dispatcher arm in
//! `veilcore::node::session::runner::handle_transport_migration_
//! notify_arm` (Phase 5e).
//!
//! ## Two layers
//!
//! [`RotationSpec`]: parsed snapshot of the operator's per-listener
//! `[listen.ephemeral]` config (range, interval, grace period).
//! Construction is fallible — invalid duration strings, inverted port
//! ranges, и zero rotation intervals are caught up-front so the loop
//! never spins on garbage.
//!
//! [`run_rotation_loop`]: а generic async task primitive that drives
//! the rotation lifecycle. Caller injects the bind closure (typically
//! [`super::ephemeral::bind_random_port`]) и the broadcast closure
//! (sign + send `TransportMigrationNotify` к active sessions); the loop
//! handles the timing + grace-period choreography.
//!
//! The split — primitives in `veil-transport`, runtime integration в
//! `veilcore` — keeps signing key и session-registry concerns out
//! of this crate (which avoids а cyclic dep на veil-proto + crypto
//! material that veil-transport must not know about).

use std::ops::RangeInclusive;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;

use super::error::{Result, TransportError};

// ── duration parsing ────────────────────────────────────────────────

/// Parse а compact duration spec accepted в the `[listen.ephemeral]`
/// section: `"30s"`, `"5m"`, `"3h"`, `"7d"`.  Trailing whitespace is
/// trimmed; leading whitespace и signs are NOT.
///
/// Numeric part must be а decimal integer ≥ 0 fitting в `u64`; suffix
/// must be exactly one of `s / m / h / d`.  Returns а `Duration` saturated
/// at `Duration::MAX` if а wildly large value would overflow seconds.
///
/// # Examples
///
/// ```
/// # use veil_transport::rotation::parse_duration_spec;
/// # use std::time::Duration;
/// assert_eq!(parse_duration_spec("30s").unwrap(), Duration::from_secs(30));
/// assert_eq!(parse_duration_spec("5m").unwrap(), Duration::from_secs(300));
/// assert_eq!(parse_duration_spec("3h").unwrap(), Duration::from_secs(10_800));
/// assert_eq!(parse_duration_spec("7d").unwrap(), Duration::from_secs(604_800));
/// assert!(parse_duration_spec("3").is_err());
/// assert!(parse_duration_spec("3x").is_err());
/// ```
/// Parse а rate-limit spec в the `"N/period"` form used by
/// `[listen.on_demand].rate_limit`.  Returns `(burst, window)`.
///
/// Period unit follows the [`parse_duration_spec`] convention:
/// `s` / `m` / `h` / `d`.  Examples: `"3/h"` → `(3, 1h)`;
/// `"1/m"` → `(1, 1m)`; `"10/30s"` → `(10, 30s)`.  When the period
/// number is omitted (i.e. just а unit letter), implies 1 of that
/// unit — `"3/h"` is shorthand для `"3/1h"`.
///
/// # Examples
/// ```
/// # use veil_transport::rotation::parse_rate_spec;
/// # use std::time::Duration;
/// assert_eq!(parse_rate_spec("3/h").unwrap(), (3, Duration::from_secs(3600)));
/// assert_eq!(parse_rate_spec("1/m").unwrap(), (1, Duration::from_secs(60)));
/// assert_eq!(parse_rate_spec("10/30s").unwrap(), (10, Duration::from_secs(30)));
/// assert!(parse_rate_spec("3").is_err());
/// assert!(parse_rate_spec("3/").is_err());
/// assert!(parse_rate_spec("/h").is_err());
/// ```
pub fn parse_rate_spec(s: &str) -> Result<(u32, Duration)> {
    let trimmed = s.trim();
    let Some((burst_str, period_str)) = trimmed.split_once('/') else {
        return Err(TransportError::Unsupported(format!(
            "rate spec `{s}`: missing `/` separator (expected `N/period`)",
        )));
    };
    if burst_str.is_empty() || period_str.is_empty() {
        return Err(TransportError::Unsupported(format!(
            "rate spec `{s}`: both sides of `/` must be non-empty",
        )));
    }
    let burst: u32 = burst_str.parse().map_err(|_| {
        TransportError::Unsupported(format!(
            "rate spec `{s}`: burst part `{burst_str}` не parses as u32",
        ))
    })?;
    // Allow bare unit ("h" instead of "1h").
    let period_full = if period_str.len() == 1 {
        format!("1{period_str}")
    } else {
        period_str.to_owned()
    };
    let window = parse_duration_spec(&period_full)?;
    Ok((burst, window))
}

pub fn parse_duration_spec(s: &str) -> Result<Duration> {
    let trimmed = s.trim_end();
    if trimmed.is_empty() {
        return Err(TransportError::Unsupported(
            "duration spec is empty".to_owned(),
        ));
    }
    let last = trimmed.as_bytes()[trimmed.len() - 1];
    let unit_secs: u64 = match last {
        b's' => 1,
        b'm' => 60,
        b'h' => 3600,
        b'd' => 86_400,
        _ => {
            return Err(TransportError::Unsupported(format!(
                "duration spec `{s}`: missing unit suffix (expected s/m/h/d)",
            )));
        }
    };
    let num_part = &trimmed[..trimmed.len() - 1];
    let n: u64 = num_part.parse().map_err(|_| {
        TransportError::Unsupported(format!(
            "duration spec `{s}`: numeric part `{num_part}` не parses as u64",
        ))
    })?;
    Ok(Duration::from_secs(n.saturating_mul(unit_secs)))
}

// ── RotationSpec ────────────────────────────────────────────────────

/// Fully-parsed view of а listener's ephemeral-rotation config.
/// Construction validates ranges и duration parsing so the loop never
/// encounters garbage at runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationSpec {
    /// Bind host (e.g. `"0.0.0.0"`, `"::"`, or а specific local IP).
    pub host: String,
    /// Inclusive port range. `start > end` rejected at construction.
    pub port_range: RangeInclusive<u16>,
    /// Bind retry count for [`super::ephemeral::bind_random_port`].
    pub bind_retries: u32,
    /// Interval между successive rotations. Zero rejected at construction.
    pub rotation_interval: Duration,
    /// Grace period после а successful rotation before the old listener
    /// is dropped. Zero is valid (drop immediately) но typically operators
    /// set 30m–1h к let in-flight handshakes complete.
    pub grace_period: Duration,
}

impl RotationSpec {
    /// Construct + validate.  Designed for `From<EphemeralConfig>`
    /// glue layer в `veilcore` — это crate doesn't have the config
    /// type itself к avoid а dep cycle.
    pub fn new(
        host: impl Into<String>,
        port_range: RangeInclusive<u16>,
        bind_retries: u32,
        rotation_interval: Duration,
        grace_period: Duration,
    ) -> Result<Self> {
        if port_range.start() > port_range.end() {
            return Err(TransportError::Unsupported(format!(
                "port range invalid: {}..={}",
                port_range.start(),
                port_range.end(),
            )));
        }
        if rotation_interval.is_zero() {
            return Err(TransportError::Unsupported(
                "rotation_interval must be > 0 (would spin tight)".to_owned(),
            ));
        }
        Ok(Self {
            host: host.into(),
            port_range,
            bind_retries,
            rotation_interval,
            grace_period,
        })
    }
}

// ── rotation loop primitive ─────────────────────────────────────────

/// Outcome reported by the rotation loop on every iteration.  Wrapped
/// в а channel send (test fixtures observe them via the `events_tx` arg)
/// и mirrored к structured logs in production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationEvent {
    /// Successfully bound а new port; broadcast was issued; the old
    /// listener will be dropped после the grace period.
    Rotated { new_port: u16 },
    /// Bind failed at this tick (port range exhausted, all attempts
    /// `EADDRINUSE`, etc.). The OLD listener stays in place и the loop
    /// retries at the next interval; до then existing peers keep
    /// connecting к the unchanged URI.
    BindFailed { reason: String },
    /// Loop has been cancelled через the watch channel.
    Shutdown,
}

/// Trait для the bind closure injected into [`run_rotation_loop`].
/// Production builds use [`super::ephemeral::bind_random_port`]; tests
/// inject а mock что returns scripted results.  The function-trait shape
/// (rather than just а `Fn`) is used because the closure is async и
/// needs `&` instead of `move`-once semantics.
pub trait BindFn: Send + Sync + 'static {
    fn bind(&self, host: String, port_range: RangeInclusive<u16>, bind_retries: u32) -> BindFuture;
}

/// Boxed-future return type для [`Binder::bind`].  Aliased к suppress
/// clippy::type_complexity на the trait method signature и give consumers
/// а cleaner name к refer to.
pub type BindFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(TcpListener, u16)>> + Send + 'static>,
>;

/// Default production bind: dispatches к [`super::ephemeral::bind_random_port`].
pub struct DefaultBinder;

impl BindFn for DefaultBinder {
    fn bind(
        &self,
        host: String,
        port_range: RangeInclusive<u16>,
        bind_retries: u32,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(TcpListener, u16)>> + Send + 'static>,
    > {
        Box::pin(async move {
            super::ephemeral::bind_random_port(&host, port_range, bind_retries).await
        })
    }
}

/// Trait для the broadcast closure called после а successful rotation
/// с the freshly-bound port.  In production это constructs а signed
/// `TransportMigrationNotify` payload + pushes it через the session-tx
/// registry's `send_to_all` path.  Tests pass а closure что records
/// invocations so the assertion can check (port, count).
pub trait BroadcastFn: Send + Sync + 'static {
    fn broadcast(
        &self,
        new_port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;
}

/// Drive the rotation lifecycle for one ephemeral listener.
///
/// Lifecycle per tick:
///
/// 1. Sleep `spec.rotation_interval` (interruptible via `shutdown_rx`).
/// 2. Call `binder.bind(...)`. On error → emit `BindFailed`, skip к
///    step 1 (the old listener stays live).
/// 3. Call `broadcaster.broadcast(new_port)`. The broadcaster is
///    responsible for signing + transmitting the migration notify.
/// 4. Sleep `spec.grace_period` (interruptible).
/// 5. Drop the old listener implicitly — the caller owns the swap.
///    `new_port` is reported through `events_tx` so the caller can pick
///    it up + replace the listener в whatever wrapper it owns.
///
/// The loop exits cleanly when `shutdown_rx` flips to `true`.
///
/// **Why the caller owns the listener swap, не the rotator:** binding +
/// broadcasting are stateless side-effects; rebinding the runtime's
/// task spawner к accept against the NEW listener requires lifecycle
/// access (tx registry, handshake spawn, etc.) что lives в veilcore.
/// Returning the new port + binder gives the caller everything it
/// needs without dragging cross-crate types here.
pub async fn run_rotation_loop<B, C>(
    spec: RotationSpec,
    binder: B,
    broadcaster: C,
    events_tx: tokio::sync::mpsc::Sender<RotationEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    B: BindFn,
    C: BroadcastFn,
{
    loop {
        // Step 1: sleep к next rotation tick (or be cancelled).
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                // changed() returns Err когда the sender is dropped;
                // either way we treat it as а shutdown signal so а
                // rotator outliving its driver doesn't leak.
                if changed.is_err() || *shutdown_rx.borrow() {
                    let _ = events_tx.send(RotationEvent::Shutdown).await;
                    return;
                }
            }
            _ = tokio::time::sleep(spec.rotation_interval) => {}
        }

        // Step 2: try к bind.
        let bind_result = binder
            .bind(
                spec.host.clone(),
                spec.port_range.clone(),
                spec.bind_retries,
            )
            .await;
        let new_port = match bind_result {
            Ok((listener, port)) => {
                // Caller owns the listener post-rotation — drop our
                // reference так it goes из scope after broadcast/
                // grace.  Actually we drop it immediately: the
                // production caller's tx-registry-driven broadcast
                // includes the listener bind upstream (lifecycle.rs
                // pulls а fresh listener through here only once и
                // hands it to its own accept loop). Keeping the
                // listener inside this loop would orphan а bound
                // socket каждую iteration.
                drop(listener);
                port
            }
            Err(e) => {
                let _ = events_tx
                    .send(RotationEvent::BindFailed {
                        reason: format!("{e}"),
                    })
                    .await;
                continue;
            }
        };

        // Step 3: broadcast the new port.  Caller-supplied closure
        // does the actual sign+send; we don't observe its outcome
        // since broadcasts are best-effort (peer may have just
        // closed the session anyway).
        broadcaster.broadcast(new_port).await;

        // Step 4: grace sleep — let in-flight handshakes finish
        // against the old listener.  Zero grace = drop immediately;
        // valid but typically operators set 30m+.
        if !spec.grace_period.is_zero() {
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        // Report the rotation as completed even на
                        // mid-grace shutdown so the caller knows about
                        // the new port (it'll bind+accept on the next
                        // startup against whichever listener it owns).
                        let _ = events_tx
                            .send(RotationEvent::Rotated { new_port })
                            .await;
                        let _ = events_tx.send(RotationEvent::Shutdown).await;
                        return;
                    }
                }
                _ = tokio::time::sleep(spec.grace_period) => {}
            }
        }

        // Step 5: report.  Caller picks up the new port via events_tx
        // и swaps its accept-loop against а listener it owns separately.
        let _ = events_tx.send(RotationEvent::Rotated { new_port }).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::mpsc;

    // ── parse_duration_spec ──────────────────────────────────────

    #[test]
    fn parse_basic_units() {
        assert_eq!(parse_duration_spec("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration_spec("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(
            parse_duration_spec("3h").unwrap(),
            Duration::from_secs(10_800)
        );
        assert_eq!(
            parse_duration_spec("7d").unwrap(),
            Duration::from_secs(604_800)
        );
    }

    #[test]
    fn parse_zero_is_allowed() {
        // Zero seconds is а valid duration here — the rotation-loop
        // constructor separately rejects а zero interval, но that's
        // RotationSpec policy not the parser's.
        assert_eq!(parse_duration_spec("0s").unwrap(), Duration::ZERO);
    }

    #[test]
    fn parse_missing_suffix_rejected() {
        let err = parse_duration_spec("300").unwrap_err();
        assert!(format!("{err}").contains("missing unit suffix"));
    }

    #[test]
    fn parse_bad_suffix_rejected() {
        let err = parse_duration_spec("3y").unwrap_err();
        assert!(format!("{err}").contains("missing unit suffix"));
    }

    #[test]
    fn parse_non_numeric_rejected() {
        let err = parse_duration_spec("abch").unwrap_err();
        assert!(format!("{err}").contains("numeric part"));
    }

    #[test]
    fn parse_negative_rejected() {
        // "-30s" — `u64::from_str` rejects the minus sign cleanly.
        assert!(parse_duration_spec("-30s").is_err());
    }

    #[test]
    fn parse_overflow_saturates() {
        // 18446744073709551615 seconds × 86400 wraps к а small number
        // в normal mul; `saturating_mul` keeps the result safe.
        let huge = format!("{}d", u64::MAX);
        let dur = parse_duration_spec(&huge).unwrap();
        // We don't check the exact value — just that it didn't panic
        // и returned _some_ duration.
        assert!(dur >= Duration::from_secs(1));
    }

    #[test]
    fn parse_trims_trailing_whitespace() {
        assert_eq!(
            parse_duration_spec("30s\n").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_duration_spec("30s ").unwrap(),
            Duration::from_secs(30)
        );
    }

    // ── parse_rate_spec ─────────────────────────────────────────

    #[test]
    fn parse_rate_basic() {
        assert_eq!(
            parse_rate_spec("3/h").unwrap(),
            (3, Duration::from_secs(3600))
        );
        assert_eq!(
            parse_rate_spec("1/m").unwrap(),
            (1, Duration::from_secs(60))
        );
        assert_eq!(
            parse_rate_spec("10/30s").unwrap(),
            (10, Duration::from_secs(30))
        );
        assert_eq!(
            parse_rate_spec("5/d").unwrap(),
            (5, Duration::from_secs(86_400))
        );
    }

    #[test]
    fn parse_rate_missing_separator_rejected() {
        assert!(parse_rate_spec("3h").is_err());
        assert!(parse_rate_spec("3").is_err());
    }

    #[test]
    fn parse_rate_empty_side_rejected() {
        assert!(parse_rate_spec("3/").is_err());
        assert!(parse_rate_spec("/h").is_err());
    }

    #[test]
    fn parse_rate_bad_burst_rejected() {
        assert!(parse_rate_spec("abc/h").is_err());
        assert!(parse_rate_spec("-3/h").is_err());
    }

    #[test]
    fn parse_rate_bad_unit_rejected() {
        assert!(parse_rate_spec("3/y").is_err());
        assert!(parse_rate_spec("3/abc").is_err());
    }

    // ── RotationSpec ──────────────────────────────────────────────

    #[test]
    #[allow(clippy::reversed_empty_ranges)] // intentional — verifies negative-path validation rejects inverted range
    fn rotation_spec_rejects_inverted_range() {
        let err = RotationSpec::new(
            "0.0.0.0",
            60000..=10000,
            8,
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("port range invalid"));
    }

    #[test]
    fn rotation_spec_rejects_zero_interval() {
        let err = RotationSpec::new(
            "0.0.0.0",
            10000..=60000,
            8,
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("rotation_interval must be > 0"));
    }

    #[test]
    fn rotation_spec_accepts_single_port_range() {
        let spec = RotationSpec::new(
            "0.0.0.0",
            3306..=3306,
            64,
            Duration::from_secs(3600),
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(*spec.port_range.start(), 3306);
        assert_eq!(*spec.port_range.end(), 3306);
    }

    // ── run_rotation_loop ────────────────────────────────────────

    /// Mock binder что returns scripted results.
    struct MockBinder {
        results: Arc<std::sync::Mutex<Vec<Result<u16>>>>,
        bind_calls: Arc<AtomicU32>,
    }

    impl BindFn for MockBinder {
        fn bind(
            &self,
            _host: String,
            _port_range: RangeInclusive<u16>,
            _bind_retries: u32,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(TcpListener, u16)>> + Send + 'static>,
        > {
            self.bind_calls.fetch_add(1, Ordering::SeqCst);
            let next = self.results.lock().unwrap().remove(0);
            Box::pin(async move {
                match next {
                    Ok(port) => {
                        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
                        Ok((listener, port))
                    }
                    Err(e) => Err(e),
                }
            })
        }
    }

    /// Mock broadcaster что records the ports it was called with.
    struct MockBroadcaster {
        calls: Arc<std::sync::Mutex<Vec<u16>>>,
    }

    impl BroadcastFn for MockBroadcaster {
        fn broadcast(
            &self,
            new_port: u16,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
            let calls = Arc::clone(&self.calls);
            Box::pin(async move {
                calls.lock().unwrap().push(new_port);
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn loop_emits_rotated_on_successful_bind() {
        let spec = RotationSpec::new(
            "127.0.0.1",
            10000..=60000,
            8,
            Duration::from_secs(60),
            Duration::ZERO, // skip grace to speed test
        )
        .unwrap();
        let binder = MockBinder {
            results: Arc::new(std::sync::Mutex::new(vec![Ok(42424), Ok(42425)])),
            bind_calls: Arc::new(AtomicU32::new(0)),
        };
        let broadcast_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let broadcaster = MockBroadcaster {
            calls: Arc::clone(&broadcast_calls),
        };
        let bind_calls = Arc::clone(&binder.bind_calls);

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            run_rotation_loop(spec, binder, broadcaster, events_tx, shutdown_rx).await;
        });

        // Advance к first rotation.
        tokio::time::advance(Duration::from_secs(60)).await;
        let ev = events_rx.recv().await.unwrap();
        assert_eq!(ev, RotationEvent::Rotated { new_port: 42424 });

        // Advance к second rotation.
        tokio::time::advance(Duration::from_secs(60)).await;
        let ev = events_rx.recv().await.unwrap();
        assert_eq!(ev, RotationEvent::Rotated { new_port: 42425 });

        assert_eq!(bind_calls.load(Ordering::SeqCst), 2);
        assert_eq!(&*broadcast_calls.lock().unwrap(), &vec![42424, 42425]);

        // Cleanup.
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    #[tokio::test(start_paused = true)]
    async fn loop_emits_bind_failed_on_collision() {
        let spec = RotationSpec::new(
            "127.0.0.1",
            10000..=60000,
            8,
            Duration::from_secs(60),
            Duration::ZERO,
        )
        .unwrap();
        let binder = MockBinder {
            results: Arc::new(std::sync::Mutex::new(vec![Err(TransportError::Io(
                std::io::Error::new(std::io::ErrorKind::AddrInUse, "test"),
            ))])),
            bind_calls: Arc::new(AtomicU32::new(0)),
        };
        let broadcast_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let broadcaster = MockBroadcaster {
            calls: Arc::clone(&broadcast_calls),
        };

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            run_rotation_loop(spec, binder, broadcaster, events_tx, shutdown_rx).await;
        });

        tokio::time::advance(Duration::from_secs(60)).await;
        let ev = events_rx.recv().await.unwrap();
        match ev {
            RotationEvent::BindFailed { reason } => {
                assert!(reason.to_lowercase().contains("in use") || reason.contains("test"));
            }
            other => panic!("expected BindFailed, got {other:?}"),
        }
        // Broadcast must NOT fire on bind failure — the OLD URI is still
        // the authoritative one.
        assert!(broadcast_calls.lock().unwrap().is_empty());

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    #[tokio::test(start_paused = true)]
    async fn loop_emits_shutdown_when_signalled() {
        let spec = RotationSpec::new(
            "127.0.0.1",
            10000..=60000,
            8,
            Duration::from_secs(60),
            Duration::ZERO,
        )
        .unwrap();
        let binder = MockBinder {
            results: Arc::new(std::sync::Mutex::new(vec![])),
            bind_calls: Arc::new(AtomicU32::new(0)),
        };
        let broadcaster = MockBroadcaster {
            calls: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let bind_calls = Arc::clone(&binder.bind_calls);

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            run_rotation_loop(spec, binder, broadcaster, events_tx, shutdown_rx).await;
        });

        // Signal shutdown before any tick fires — loop must exit cleanly.
        let _ = shutdown_tx.send(true);
        let ev = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("shutdown event timed out")
            .unwrap();
        assert_eq!(ev, RotationEvent::Shutdown);
        assert_eq!(bind_calls.load(Ordering::SeqCst), 0);

        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    #[tokio::test(start_paused = true)]
    async fn loop_grace_period_delays_rotated_event() {
        let spec = RotationSpec::new(
            "127.0.0.1",
            10000..=60000,
            8,
            Duration::from_secs(60),
            Duration::from_secs(30), // grace
        )
        .unwrap();
        let binder = MockBinder {
            results: Arc::new(std::sync::Mutex::new(vec![Ok(50000)])),
            bind_calls: Arc::new(AtomicU32::new(0)),
        };
        let broadcaster = MockBroadcaster {
            calls: Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            run_rotation_loop(spec, binder, broadcaster, events_tx, shutdown_rx).await;
        });

        // Advance к rotation tick (60s) AND wait through the bind +
        // broadcast.  Event should still be pending due к grace.
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::time::sleep(Duration::from_secs(1)).await; // let task run
        assert!(
            events_rx.try_recv().is_err(),
            "Rotated should not fire до grace period elapses"
        );

        // Advance through grace (30s).
        tokio::time::advance(Duration::from_secs(31)).await;
        let ev = events_rx.recv().await.unwrap();
        assert_eq!(ev, RotationEvent::Rotated { new_port: 50000 });

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }
}
