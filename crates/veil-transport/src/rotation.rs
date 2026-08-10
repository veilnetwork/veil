//! Ephemeral-port rotation primitives — Phase 5f.
//!
//! Builds on top of [`super::ephemeral::bind_random_port`] (Phase 5a)
//! and pairs with the wire-frame from `veil-proto::session::
//! TransportMigrationNotify` (Phase 5b) + the dispatcher arm in
//! `veilcore::node::session::runner::handle_transport_migration_
//! notify_arm` (Phase 5e).
//!
//! ## Two layers
//!
//! [`RotationSpec`]: parsed snapshot of the operator's per-listener
//! `[listen.ephemeral]` config (range, interval, grace period).
//! Construction is fallible — invalid duration strings, inverted port
//! ranges, and zero rotation intervals are caught up-front so the loop
//! never spins on garbage.
//!
//! [`run_rotation_loop`]: a generic async task primitive that drives
//! the rotation lifecycle. Caller injects the bind closure (typically
//! [`super::ephemeral::bind_random_port`]) and the broadcast closure
//! (sign + send `TransportMigrationNotify` to active sessions); the loop
//! handles the timing + grace-period choreography.
//!
//! The split — primitives in `veil-transport`, runtime integration in
//! `veilcore` — keeps signing key and session-registry concerns out
//! of this crate (which avoids a cyclic dep on veil-proto + crypto
//! material that veil-transport must not know about).

use std::ops::RangeInclusive;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;

use super::error::{Result, TransportError};

// ── duration parsing ────────────────────────────────────────────────

/// Parse a compact duration spec accepted in the `[listen.ephemeral]`
/// section: `"30s"`, `"5m"`, `"3h"`, `"7d"`.  Trailing whitespace is
/// trimmed; leading whitespace and signs are NOT.
///
/// Numeric part must be a decimal integer ≥ 0 fitting in `u64`; suffix
/// must be exactly one of `s / m / h / d`.  Returns a `Duration` saturated
/// at `Duration::MAX` if a wildly large value would overflow seconds.
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
/// Parse a rate-limit spec in the `"N/period"` form used by
/// `[listen.on_demand].rate_limit`.  Returns `(burst, window)`.
///
/// Period unit follows the [`parse_duration_spec`] convention:
/// `s` / `m` / `h` / `d`.  Examples: `"3/h"` → `(3, 1h)`;
/// `"1/m"` → `(1, 1m)`; `"10/30s"` → `(10, 30s)`.  When the period
/// number is omitted (i.e. just a unit letter), implies 1 of that
/// unit — `"3/h"` is shorthand for `"3/1h"`.
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
            "rate spec `{s}`: burst part `{burst_str}` not parses as u32",
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
            "duration spec `{s}`: numeric part `{num_part}` not parses as u64",
        ))
    })?;
    Ok(Duration::from_secs(n.saturating_mul(unit_secs)))
}

// ── RotationSpec ────────────────────────────────────────────────────

/// Fully-parsed view of a listener's ephemeral-rotation config.
/// Construction validates ranges and duration parsing so the loop never
/// encounters garbage at runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationSpec {
    /// Bind host (e.g. `"0.0.0.0"`, `"::"`, or a specific local IP).
    pub host: String,
    /// Inclusive port range. `start > end` rejected at construction.
    pub port_range: RangeInclusive<u16>,
    /// Bind retry count for [`super::ephemeral::bind_random_port`].
    pub bind_retries: u32,
    /// Interval between successive rotations. Zero rejected at construction.
    pub rotation_interval: Duration,
    /// Grace period after a successful rotation before the old listener
    /// is dropped. Zero is valid (drop immediately) but typically operators
    /// set 30m–1h to let in-flight handshakes complete.
    pub grace_period: Duration,
}

impl RotationSpec {
    /// Construct + validate.  Designed for `From<EphemeralConfig>`
    /// glue layer in `veilcore` — this crate doesn't have the config
    /// type itself to avoid a dep cycle.
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
/// in a channel send (test fixtures observe them via the `events_tx` arg)
/// and mirrored to structured logs in production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationEvent {
    /// The caller is accepting on `new_port` and the broadcast has been
    /// issued. Reported after both, so a peer that acts on this event
    /// acts on a port that is already serving.
    Rotated { new_port: u16 },
    /// The caller was handed a free port and did not come up on it, so
    /// nothing was broadcast: the old listener keeps serving the URI
    /// peers already hold, and the loop retries at the next interval.
    AdoptFailed { reason: String },
    /// The grace period after a `Rotated` has elapsed. The caller may
    /// now close the listener that rotation replaced; until this event
    /// BOTH are expected to be accepting, which is the whole point of
    /// the grace period — a peer whose cached URI still names the old
    /// port must be able to connect while its cache expires.
    RetireOld,
    /// Bind failed at this tick (port range exhausted, all attempts
    /// `EADDRINUSE`, etc.). The OLD listener stays in place and the loop
    /// retries at the next interval; until then existing peers keep
    /// connecting to the unchanged URI.
    BindFailed { reason: String },
    /// Loop has been cancelled through the watch channel.
    Shutdown,
}

/// Trait for the bind closure injected into [`run_rotation_loop`].
/// Production builds use [`super::ephemeral::bind_random_port`]; tests
/// inject a mock that returns scripted results.  The function-trait shape
/// (rather than just a `Fn`) is used because the closure is async and
/// needs `&` instead of `move`-once semantics.
pub trait BindFn: Send + Sync + 'static {
    fn bind(&self, host: String, port_range: RangeInclusive<u16>, bind_retries: u32) -> BindFuture;
}

/// Boxed-future return type for [`Binder::bind`].  Aliased to suppress
/// clippy::type_complexity on the trait method signature and give consumers
/// a cleaner name to refer to.
pub type BindFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(TcpListener, u16)>> + Send + 'static>,
>;

/// Default production bind: dispatches to [`super::ephemeral::bind_random_port`].
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

/// Trait for the broadcast closure called after a successful rotation
/// with the freshly-bound port.  In production this constructs a signed
/// `TransportMigrationNotify` payload + pushes it through the session-tx
/// registry's `send_to_all` path.  Tests pass a closure that records
/// invocations so the assertion can check (port, count).
pub trait AdoptFn: Send + Sync + 'static {
    /// Bind `new_port` and start accepting on it, keeping whatever
    /// listener is already in service. Returns whether that succeeded:
    /// `false` means nothing may be advertised for this port.
    fn adopt(
        &self,
        new_port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'static>>;
}

/// Trait for the broadcast closure called after a successful rotation
/// with the freshly-bound port.  In production this constructs a signed
/// `TransportMigrationNotify` payload + pushes it through the session-tx
/// registry's `send_to_all` path.  Tests pass a closure that records
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
/// 2. Call `binder.bind(...)` to find a free port. On error → emit
///    `BindFailed`, skip to step 1 (the old listener stays live).
/// 3. Call `adopter.adopt(new_port)`: the caller binds it for real and
///    starts accepting, KEEPING the listener already in service. On
///    `false` → emit `AdoptFailed`, skip to step 1. Nothing has been
///    advertised, so peers are still holding a URI that works.
/// 4. Call `broadcaster.broadcast(new_port)` and emit `Rotated`.
/// 5. Sleep `spec.grace_period` (interruptible), then emit `RetireOld`
///    so the caller closes the listener rotation replaced.
///
/// The loop exits cleanly when `shutdown_rx` flips to `true`.
///
/// **Why the adopt comes before the broadcast.** It used to come after
/// the grace period, and the probe listener from step 2 was dropped the
/// moment it was bound — so the port in the migration notify was closed
/// for the whole grace period, 30 minutes by default. Peers cached an
/// endpoint that refused connections; anything else on the host could
/// take the freed port in the meantime, and then the caller's real bind
/// failed and the port stayed dead. A port is advertised now only once
/// something is accepting on it.
///
/// **Why both listeners run through the grace period.** The broadcast is
/// best-effort and peers cache the old URI for several rotation
/// intervals, so retiring the old listener at swap time would break
/// exactly the peers that missed the notify — the case the grace period
/// exists for. Step 5 is what actually closes it.
///
/// **Why the caller owns the listeners, not the rotator:** binding +
/// broadcasting are stateless side-effects; rebinding the runtime's
/// task spawner to accept against the NEW listener requires lifecycle
/// access (tx registry, handshake spawn, etc.) that lives in veilcore.
pub async fn run_rotation_loop<B, A, C>(
    spec: RotationSpec,
    binder: B,
    adopter: A,
    broadcaster: C,
    events_tx: tokio::sync::mpsc::Sender<RotationEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    B: BindFn,
    A: AdoptFn,
    C: BroadcastFn,
{
    loop {
        // Step 1: sleep to next rotation tick (or be cancelled).
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                // changed() returns Err when the sender is dropped;
                // either way we treat it as a shutdown signal so a
                // rotator outliving its driver doesn't leak.
                if changed.is_err() || *shutdown_rx.borrow() {
                    let _ = events_tx.send(RotationEvent::Shutdown).await;
                    return;
                }
            }
            _ = tokio::time::sleep(spec.rotation_interval) => {}
        }

        // Step 2: try to bind.
        let bind_result = binder
            .bind(
                spec.host.clone(),
                spec.port_range.clone(),
                spec.bind_retries,
            )
            .await;
        let new_port = match bind_result {
            Ok((listener, port)) => {
                // The bind was a PROBE: it proves the port is free and
                // is dropped straight away, because the caller has to
                // bind the port itself to accept on it. That leaves a
                // window in which anything on the host could take the
                // port, which is why `adopt` below is the thing that
                // decides whether this rotation happened — and why
                // nothing is advertised before it answers.
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

        // Step 3: hand the port over BEFORE anything is advertised. The
        // caller binds it for real and starts accepting on it alongside
        // the listener already in service; `false` means it did not, and
        // then this tick simply did not happen. Peers keep the URI they
        // hold, which still works, and the next interval tries again.
        if !adopter.adopt(new_port).await {
            let _ = events_tx
                .send(RotationEvent::AdoptFailed {
                    reason: format!("caller did not come up on port {new_port}"),
                })
                .await;
            continue;
        }

        // Step 4: broadcast, now that the port answers.  Caller-supplied
        // closure does the actual sign+send; we don't observe its outcome
        // since broadcasts are best-effort (peer may have just closed the
        // session anyway).
        broadcaster.broadcast(new_port).await;
        let _ = events_tx.send(RotationEvent::Rotated { new_port }).await;

        // Step 5: grace sleep — both listeners are accepting throughout,
        // so a peer connecting on either the cached port or the new one
        // gets through. Zero grace = retire the old one immediately;
        // valid but typically operators set 30m+.
        if !spec.grace_period.is_zero() {
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        // No RetireOld on the way out: the caller is
                        // dropping both listeners with the runtime, and
                        // asking it to close the old one first would only
                        // shorten the window in which peers can still land.
                        let _ = events_tx.send(RotationEvent::Shutdown).await;
                        return;
                    }
                }
                _ = tokio::time::sleep(spec.grace_period) => {}
            }
        }

        // Step 6: the cached-URI window is over; the old listener can go.
        let _ = events_tx.send(RotationEvent::RetireOld).await;
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
        // Zero seconds is a valid duration here — the rotation-loop
        // constructor separately rejects a zero interval, but that's
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
        // 18446744073709551615 seconds × 86400 wraps to a small number
        // in normal mul; `saturating_mul` keeps the result safe.
        let huge = format!("{}d", u64::MAX);
        let dur = parse_duration_spec(&huge).unwrap();
        // We don't check the exact value — just that it didn't panic
        // and returned _some_ duration.
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

    /// Mock binder that returns scripted results.
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

    /// Mock adopter. Records what it was handed, answers per script, and
    /// appends to a log the broadcaster shares — so the ORDER of the two
    /// is observable, which is the whole property of the reorder.
    struct MockAdopter {
        fail_ports: Vec<u16>,
        order: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl AdoptFn for MockAdopter {
        fn adopt(
            &self,
            new_port: u16,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'static>> {
            let order = Arc::clone(&self.order);
            let ok = !self.fail_ports.contains(&new_port);
            Box::pin(async move {
                order.lock().unwrap().push(format!("adopt:{new_port}"));
                ok
            })
        }
    }

    /// An adopter that always comes up, for the tests that are about
    /// something else.
    fn adopter_ok() -> MockAdopter {
        MockAdopter {
            fail_ports: Vec::new(),
            order: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Mock broadcaster that records the ports it was called with.
    struct MockBroadcaster {
        calls: Arc<std::sync::Mutex<Vec<u16>>>,
        order: Option<Arc<std::sync::Mutex<Vec<String>>>>,
    }

    impl BroadcastFn for MockBroadcaster {
        fn broadcast(
            &self,
            new_port: u16,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
            let calls = Arc::clone(&self.calls);
            let order = self.order.clone();
            Box::pin(async move {
                calls.lock().unwrap().push(new_port);
                if let Some(o) = order {
                    o.lock().unwrap().push(format!("broadcast:{new_port}"));
                }
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
            order: None,
        };
        let adopter = adopter_ok();
        let bind_calls = Arc::clone(&binder.bind_calls);

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            run_rotation_loop(spec, binder, adopter, broadcaster, events_tx, shutdown_rx).await;
        });

        // Advance to first rotation. Zero grace, so the old listener is
        // retired in the same breath — but still AFTER the rotation is
        // reported, because "retire the old one" only means anything
        // once something else is serving.
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(
            events_rx.recv().await.unwrap(),
            RotationEvent::Rotated { new_port: 42424 }
        );
        assert_eq!(events_rx.recv().await.unwrap(), RotationEvent::RetireOld);

        // Advance to second rotation.
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(
            events_rx.recv().await.unwrap(),
            RotationEvent::Rotated { new_port: 42425 }
        );
        assert_eq!(events_rx.recv().await.unwrap(), RotationEvent::RetireOld);

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
            order: None,
        };
        let adopter = adopter_ok();

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            run_rotation_loop(spec, binder, adopter, broadcaster, events_tx, shutdown_rx).await;
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
            order: None,
        };
        let adopter = adopter_ok();
        let bind_calls = Arc::clone(&binder.bind_calls);

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            run_rotation_loop(spec, binder, adopter, broadcaster, events_tx, shutdown_rx).await;
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

    /// The grace period must delay the RETIREMENT of the old listener,
    /// and must not delay the new port going live.
    ///
    /// It used to do the opposite, and that was the defect: the probe
    /// listener was dropped at bind time, the port went into the migration
    /// notify immediately, and the caller was only told to bind it once the
    /// grace period was over — 30 minutes by default. For that whole window
    /// the advertised endpoint refused connections, and anything else on the
    /// host was free to take the port, after which the caller's bind failed
    /// and it never came up at all.
    ///
    /// Asserted on the CLOCK rather than on "no event yet": the previous
    /// version of this test advanced time, slept, and called `try_recv`,
    /// which is empty whenever the loop task has not been polled yet. It
    /// passed against the reordered loop it was supposed to forbid — it was
    /// measuring scheduling latency, not the grace period.
    #[tokio::test(start_paused = true)]
    async fn grace_delays_retiring_the_old_listener_not_the_new_port() {
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
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let broadcaster = MockBroadcaster {
            calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            order: Some(Arc::clone(&order)),
        };
        let adopter = MockAdopter {
            fail_ports: Vec::new(),
            order: Arc::clone(&order),
        };

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let started = tokio::time::Instant::now();
        let handle = tokio::spawn(async move {
            run_rotation_loop(spec, binder, adopter, broadcaster, events_tx, shutdown_rx).await;
        });

        // Time auto-advances while this awaits, so the arrival time is the
        // assertion: the rotation is reported at the tick, not a grace later.
        assert_eq!(
            events_rx.recv().await.unwrap(),
            RotationEvent::Rotated { new_port: 50000 }
        );
        let at_rotated = started.elapsed();
        assert!(
            at_rotated < Duration::from_secs(90),
            "the new port was only reported after the grace period ({at_rotated:?}) — \
             it is advertised by then, so it was advertised closed"
        );

        // And the old listener stays until the grace is actually over.
        assert_eq!(events_rx.recv().await.unwrap(), RotationEvent::RetireOld);
        let at_retire = started.elapsed();
        assert!(
            at_retire >= at_rotated + Duration::from_secs(30),
            "the old listener was retired {:?} after the swap, short of the \
             30s grace — peers still holding the old URI lose their route",
            at_retire - at_rotated
        );

        // The port answers before anyone is told about it.
        assert_eq!(
            &*order.lock().unwrap(),
            &vec!["adopt:50000".to_string(), "broadcast:50000".to_string()],
            "the migration notify must not go out ahead of the bind"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    /// A caller that cannot come up on the port must not have it advertised.
    ///
    /// The probe bind proves the port was free a moment ago, not that the
    /// caller holds it: between the probe's `drop` and the caller's own bind
    /// anything on the host can take it. Broadcasting on the strength of the
    /// probe is what turned that race into a dead advertised endpoint.
    #[tokio::test(start_paused = true)]
    async fn a_port_the_caller_could_not_take_is_never_broadcast() {
        let spec = RotationSpec::new(
            "127.0.0.1",
            10000..=60000,
            8,
            Duration::from_secs(60),
            Duration::ZERO,
        )
        .unwrap();
        let binder = MockBinder {
            results: Arc::new(std::sync::Mutex::new(vec![Ok(50000), Ok(50001)])),
            bind_calls: Arc::new(AtomicU32::new(0)),
        };
        let broadcast_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let broadcaster = MockBroadcaster {
            calls: Arc::clone(&broadcast_calls),
            order: None,
        };
        let adopter = MockAdopter {
            fail_ports: vec![50000],
            order: Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            run_rotation_loop(spec, binder, adopter, broadcaster, events_tx, shutdown_rx).await;
        });

        match events_rx.recv().await.unwrap() {
            RotationEvent::AdoptFailed { reason } => {
                assert!(
                    reason.contains("50000"),
                    "reason should name the port: {reason}"
                );
            }
            other => panic!("expected AdoptFailed for a port the caller lost, got {other:?}"),
        }
        // The tick is a no-op, so the next one rotates normally.
        assert_eq!(
            events_rx.recv().await.unwrap(),
            RotationEvent::Rotated { new_port: 50001 }
        );
        assert_eq!(
            &*broadcast_calls.lock().unwrap(),
            &vec![50001],
            "a port nothing was accepting on was put into a migration notify"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }
}
