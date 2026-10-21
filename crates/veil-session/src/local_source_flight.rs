//! One node-local flight pool for trusted outgoing source transports.
//! The ordinary per-connection CC still applies. No role is sent to a peer.
//! Primary flight is charged before competing work; the primary itself keeps
//! its normal controller, without an additional pause behind secondary debt.
//! This is a local congestion-flight policy, not a path capacity estimate.
use super::local_source_activity::{IDLE_GRACE, PRESSURE_GRACE};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
    task::Waker,
    time::{Duration, Instant},
};
use veil_transport::{LocalSendBudget, QuicDatagramHandle};
use veil_util::lock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Primary,
    Control,
    Secondary,
}

#[derive(Debug)]
struct Row {
    binding: Weak<Binding>,
    role: Role,
    // Factories bind before the handshake; this becomes true only when a
    // trusted local producer selects the connection for actual source work.
    source_coupled: bool,
    flight: u64,
    mtu: u16,
    used: Instant,
    observed: Instant,
    closed_until: Option<Instant>,
    waker: Option<Waker>,
    blocked_window: Option<(Instant, u64, u64)>,
    queue_drained: bool,
}
#[derive(Clone, Copy, Debug, Default)]
struct DeliveryDiagnostics {
    calls: u64,
    stale: u64,
    inactive: u64,
    unhealthy: u64,
    pressured: u64,
    held: u64,
    hold_observations: u64,
    no_demand: u64,
    funded_bytes: u64,
    credit_wait: u64,
    rtt_wait: u64,
    grows: u64,
    blocked: u64,
    drained: u64,
    transport_pressure_applied: u64,
    transport_pressure_deferred: u64,
}
#[derive(Debug, Default)]
struct State {
    rows: HashMap<u64, Row>,
    active_until: Option<Instant>,
    healthy_until: Option<Instant>,
    pressure_until: Option<Instant>,
    growth_hold_until: Option<Instant>,
    // Retain, never enlarge, an already-permitted allowance through the
    // validated health sample's TTL, independently of the growth hold's end.
    // Retained health cannot fund growth without new positive feedback.
    held_secondary_trial: Option<(Instant, u64)>,
    window: u64,
    // Reserve included in the last funded/reduced window. Retiring control
    // headroom must not turn it into another competing data packet.
    window_reserve: u64,
    delivered_credit: u64,
    last_growth: Option<Instant>,
    last_reduction: Option<Instant>,
    preparing: bool,
    turn_waiters: HashMap<u64, Waker>,
    last_trace: Option<Instant>,
    last_secondary_trace: Option<Instant>,
    delivery_diagnostics: DeliveryDiagnostics,
}
#[derive(Debug, Default)]
pub(crate) struct SourceFlightPool(Mutex<State>);

impl State {
    fn pressure(&mut self, now: Instant) {
        self.pressure_until = Some(
            self.pressure_until
                .map_or(now + PRESSURE_GRACE, |at| at.max(now + PRESSURE_GRACE)),
        );
        self.healthy_until = None;
        self.held_secondary_trial = None;
        self.delivered_credit = 0;
        if self
            .last_reduction
            .is_none_or(|at| now.saturating_duration_since(at) >= PRESSURE_GRACE)
        {
            self.window = (self.limit(now) / 2).max(self.floor(now));
            self.window_reserve = self.reserve(now);
            self.last_reduction = Some(now);
        }
    }

    fn demanded(&self, now: Instant, window: u64) -> bool {
        let reserve = self.reserve(now);
        self.rows.values().any(|r| {
            r.role == Role::Secondary
                && r.source_coupled
                && r.closed_until.is_none()
                && r.blocked_window.is_some_and(|(at, used, reserved)| {
                    used == window
                        && reserved == reserve
                        && at <= now
                        && now.saturating_duration_since(at) < IDLE_GRACE
                })
        })
    }
    fn active(&self, now: Instant) -> bool {
        self.active_until.is_some_and(|until| now < until)
    }
    fn prune(&mut self, now: Instant) {
        self.rows
            .retain(|_, r| r.closed_until.is_none_or(|until| now < until));
    }
    fn total(&self) -> u64 {
        self.rows
            .values()
            .map(|r| r.flight)
            .fold(0, u64::saturating_add)
    }
    fn reserve(&self, now: Instant) -> u64 {
        self.rows
            .values()
            .filter(|r| {
                r.closed_until.is_none()
                    && r.role != Role::Secondary
                    && now.saturating_duration_since(r.used) < IDLE_GRACE
            })
            .map(|r| u64::from(r.mtu))
            .fold(0, u64::saturating_add)
    }
    fn floor(&self, now: Instant) -> u64 {
        self.reserve(now)
            .saturating_add(2 * u64::from(self.rows.values().map(|r| r.mtu).max().unwrap_or(1200)))
    }
    fn limit(&self, now: Instant) -> u64 {
        self.window
            .saturating_sub(self.window_reserve.saturating_sub(self.reserve(now)))
            .max(self.floor(now))
    }
    // A node-wide control ledger is not a measurement of a short media path.
    // DHT/keepalive connections on other RTTs can keep more control bytes in
    // flight than the paid source window, indefinitely preventing even a
    // secondary probe. Fresh healthy primary feedback permits the shared
    // usable source window: the initial two-MTU trial plus growth already
    // paid for by real demand and delivery. Keeping this exception fixed at
    // two MTUs would make that earned growth unusable behind control debt.
    // Retired control reserve cannot become paid source capacity (limit()
    // removes it). Coupled secondary debt still debits the allowance, including
    // abandoned source work. Primary flight remains charged in the ordinary
    // ledger, but healthy primary BDP must not erase this finite source window.
    // Prewarmed secondary handshakes have not carried a local producer yet;
    // they stay in the ordinary ledger, rather than starving a real probe.
    // Control debt remains in the ordinary ledger; it cannot consume this
    // allowance, whether its connection is live or has just closed.
    // A growth hold may retain the previously permitted limit until its
    // original deadline, without increasing it or banking a paid window.
    fn secondary_trial_limit(&self, now: Instant) -> Option<u64> {
        if self.pressure_until.is_some_and(|until| now < until) {
            return None;
        }
        if self.growth_hold_until.is_some_and(|until| now < until) {
            return self
                .held_secondary_trial
                .filter(|(until, _)| now < *until)
                .map(|(_, limit)| limit);
        }
        if self.healthy_until.is_some_and(|until| now < until) {
            let mtu = u64::from(self.rows.values().map(|r| r.mtu).max().unwrap_or(1200));
            return Some(
                self.limit(now)
                    .saturating_sub(self.reserve(now))
                    .max(2 * mtu),
            );
        }
        // An event can expire between frontend polls while its most recent
        // known-health sample remains fresh. Withdrawing admission here would
        // discard part of a frame until the next positive report arrives.
        self.held_secondary_trial
            .filter(|(until, _)| now < *until)
            .map(|(_, limit)| limit)
    }

    fn healthy_secondary_probe(&self, now: Instant) -> Option<u64> {
        let limit = self.secondary_trial_limit(now)?;
        let charged = self
            .rows
            .values()
            .filter(|r| r.role == Role::Secondary && r.source_coupled)
            .map(|r| r.flight)
            .fold(0, u64::saturating_add);
        Some(limit.saturating_sub(charged))
    }

    fn wakers(&self) -> Vec<Waker> {
        self.rows.values().filter_map(|r| r.waker.clone()).collect()
    }
}
fn wake(wakers: Vec<Waker>) {
    for waker in wakers {
        waker.wake();
    }
}

impl SourceFlightPool {
    #[cfg(test)]
    pub(crate) fn transport_members(&self) -> usize {
        lock!(self.0).rows.len()
    }

    pub(crate) fn note_primary(&self, now: Instant) {
        let wakers = {
            let mut s = lock!(self.0);
            if !s.active(now) {
                s.window = 0;
                s.delivered_credit = 0;
                s.healthy_until = None;
                s.growth_hold_until = None;
                s.held_secondary_trial = None;
                for row in s.rows.values_mut() {
                    row.blocked_window = None;
                }
            }
            s.active_until = Some(
                s.active_until
                    .map_or(now + IDLE_GRACE, |t| t.max(now + IDLE_GRACE)),
            );
            s.wakers()
        };
        wake(wakers);
    }
    pub(crate) fn feedback(&self, pressured: bool, now: Instant) {
        let wakers = {
            let mut s = lock!(self.0);
            if pressured {
                s.pressure(now);
            } else {
                s.healthy_until = Some(now + IDLE_GRACE);
            }
            s.wakers()
        };
        wake(wakers);
    }

    /// A first-hop warning cannot contradict fresh trusted consumer health:
    /// redundant primary paths may deliver it despite this connection's loss.
    /// The path's own CC still applies. No warning creates or renews health,
    /// grants flight, clears an existing pressure lease or funds source growth.
    /// Unknown/expired health retains the conservative node-wide fallback.
    pub(crate) fn transport_pressure(&self, now: Instant) -> bool {
        let wakers = {
            let mut s = lock!(self.0);
            if s.active(now)
                && (s.healthy_until.is_some_and(|until| now < until)
                    || s.held_secondary_trial.is_some_and(|(until, _)| now < until))
            {
                s.delivery_diagnostics.transport_pressure_deferred = s
                    .delivery_diagnostics
                    .transport_pressure_deferred
                    .saturating_add(1);
                return false;
            }
            s.delivery_diagnostics.transport_pressure_applied = s
                .delivery_diagnostics
                .transport_pressure_applied
                .saturating_add(1);
            s.pressure(now);
            s.wakers()
        };
        wake(wakers);
        true
    }
    /// Preserve paid flight and any already-permitted shared trial, but earn
    /// no growth from held feedback and never create a new trial under a hold.
    /// Growth uses the original event deadline. Admission retention uses the
    /// current-health sample's original TTL, never IPC receipt or replay time.
    pub(crate) fn hold_growth(&self, sampled_at: Instant, until: Instant, received_at: Instant) {
        if sampled_at > received_at || until <= received_at {
            return;
        }
        let Some(health_until) = sampled_at
            .checked_add(IDLE_GRACE)
            .filter(|until| received_at < *until)
        else {
            return;
        };
        let mut s = lock!(self.0);
        // A hold means known current health with no permission to grow.
        // Removing the existing trial here can stop all video behind unrelated
        // control debt, even though the achieved window was meant to survive.
        // Freeze its total allowance before retiring positive growth credit.
        // Replayed deadlines cannot extend it; a new MTU cannot enlarge it.
        s.held_secondary_trial = s.secondary_trial_limit(received_at).map(|limit| {
            let deadline = s
                .held_secondary_trial
                .filter(|(old, _)| received_at < *old)
                .map_or(health_until, |(old, _)| old.max(health_until));
            (deadline, limit)
        });
        s.growth_hold_until = Some(s.growth_hold_until.map_or(until, |old| old.max(until)));
        s.healthy_until = None;
        s.delivered_credit = 0;
        s.delivery_diagnostics.hold_observations =
            s.delivery_diagnostics.hold_observations.saturating_add(1);
    }
    pub(crate) fn bind(
        self: &Arc<Self>,
        handle: &QuicDatagramHandle,
        role: Role,
        now: Instant,
    ) -> bool {
        let id = handle.local_trace_id();
        let Some(binding) = self.binding(id, role, now) else {
            return false;
        };
        let installed = handle.set_local_send_budget(binding.clone());
        if !installed {
            binding.closed();
        }
        if installed && crate::rt_trace::rt_trace_enabled() {
            let snapshot = {
                let mut state = lock!(self.0);
                if state
                    .last_trace
                    .is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(1))
                {
                    state.last_trace = Some(now);
                    Some((
                        state.rows.len(),
                        state.total(),
                        state.limit(now),
                        state.reserve(now),
                        state.healthy_until.is_some_and(|t| now < t),
                        state.pressure_until.is_some_and(|t| now < t),
                        state.delivered_credit,
                        state.delivery_diagnostics,
                        state.window,
                        state.window_reserve,
                        state
                            .rows
                            .values()
                            .filter(|r| r.role == Role::Primary)
                            .map(|r| r.flight)
                            .sum::<u64>(),
                        state
                            .rows
                            .values()
                            .filter(|r| r.role == Role::Control)
                            .map(|r| r.flight)
                            .sum::<u64>(),
                        state
                            .rows
                            .values()
                            .filter(|r| r.role == Role::Secondary)
                            .map(|r| r.flight)
                            .sum::<u64>(),
                    ))
                } else {
                    None
                }
            };
            if let Some((
                members,
                flight,
                window,
                reserve,
                healthy,
                pressured,
                credit,
                d,
                stored_window,
                stored_reserve,
                primary_flight,
                control_flight,
                secondary_flight,
            )) = snapshot
            {
                log::info!(target: "veil::source_flight",
                    "connection_trace_id={id} members={members} in_flight_bytes={flight} primary_flight_bytes={primary_flight} control_flight_bytes={control_flight} secondary_flight_bytes={secondary_flight} window_bytes={window} primary_control_reserve_bytes={reserve} stored_window_bytes={stored_window} stored_reserve_bytes={stored_reserve} scope=endpoint hold_observations={} ack_held={} healthy={healthy} pressured={pressured} credit_bytes={credit} ack_calls={} ack_stale={} ack_inactive={} ack_unhealthy={} ack_pressured={} ack_no_demand={} ack_funded_bytes={} ack_credit_wait={} ack_rtt_wait={} window_grows={} blocked_calls={} drained_witnesses={} transport_pressure_applied={} transport_pressure_deferred={}",
                    d.hold_observations, d.held, d.calls, d.stale, d.inactive, d.unhealthy, d.pressured, d.no_demand,
                    d.funded_bytes, d.credit_wait, d.rtt_wait, d.grows, d.blocked, d.drained,
                    d.transport_pressure_applied, d.transport_pressure_deferred);
            }
        }
        installed
    }
    pub(crate) fn factory(self: &Arc<Self>, role: Role) -> veil_transport::LocalSendBudgetFactory {
        let pool = self.clone();
        Arc::new(move |id| -> Arc<dyn LocalSendBudget> {
            pool.binding_for_source(id, role, Instant::now(), false)
                .expect("fresh local connection ordinal")
        })
    }

    fn binding(self: &Arc<Self>, id: u64, role: Role, now: Instant) -> Option<Arc<Binding>> {
        self.binding_for_source(id, role, now, true)
    }

    fn binding_for_source(
        self: &Arc<Self>,
        id: u64,
        role: Role,
        now: Instant,
        source_coupled: bool,
    ) -> Option<Arc<Binding>> {
        let mut s = lock!(self.0);
        s.prune(now);
        if let Some(row) = s.rows.get_mut(&id) {
            if row.role != role || row.closed_until.is_some() {
                return None;
            }
            row.used = row.used.max(now);
            row.source_coupled |= source_coupled;
            return row.binding.upgrade();
        }
        let binding = Arc::new(Binding {
            pool: self.clone(),
            id,
        });
        s.rows.insert(
            id,
            Row {
                binding: Arc::downgrade(&binding),
                role,
                source_coupled,
                flight: 0,
                mtu: 1200,
                used: now,
                observed: now,
                closed_until: None,
                waker: None,
                blocked_window: None,
                queue_drained: false,
            },
        );
        Some(binding)
    }
}

#[derive(Debug)]
struct Binding {
    pool: Arc<SourceFlightPool>,
    id: u64,
}
struct Turn(Arc<SourceFlightPool>);
impl Drop for Turn {
    fn drop(&mut self) {
        let wakers = {
            let mut s = lock!(self.0.0);
            s.preparing = false;
            s.turn_waiters.drain().map(|(_, w)| w).collect()
        };
        wake(wakers);
    }
}
impl LocalSendBudget for Binding {
    fn acquire_transmit(&self, now: Instant) -> Option<Box<dyn Send>> {
        let mut s = lock!(self.pool.0);
        s.prune(now);
        if let Some(row) = s.rows.get_mut(&self.id) {
            row.observed = row.observed.max(now);
        }
        if s.preparing {
            if let Some(waker) = s.rows.get(&self.id).and_then(|r| r.waker.clone()) {
                s.turn_waiters.insert(self.id, waker);
            }
            return None;
        }
        s.preparing = true;
        Some(Box::new(Turn(self.pool.clone())))
    }
    fn window(&self, now: Instant, path_flight: u64, mtu: u16) -> u64 {
        let mut s = lock!(self.pool.0);
        s.prune(now);
        if !s.active(now) {
            return u64::MAX;
        }
        let Some(row) = s.rows.get_mut(&self.id) else {
            return 1;
        };
        row.mtu = mtu;
        row.observed = row.observed.max(now);
        // An unselected secondary still needs its bounded control handshake;
        // it neither earns nor spends the shared live-source trial.
        let secondary = row.role == Role::Secondary;
        let source_coupled = row.source_coupled;
        let role = if secondary && !source_coupled {
            Role::Control
        } else {
            row.role
        };
        let flight = row.flight;
        // The pool regulates competing work. The primary keeps its ordinary
        // QUIC controller: older secondary debt (or a former route's primary
        // flight) must not impose an additional pause on fresh audio. Its REAL
        // bytes still debit the shared ledger before any secondary can send.
        if role == Role::Primary {
            return u64::MAX;
        }
        let limit = s.limit(now);
        let mut available = limit.saturating_sub(s.total());
        if role == Role::Secondary {
            available = available.saturating_sub(s.reserve(now));
            if let Some(probe) = s.healthy_secondary_probe(now) {
                available = available.max(probe);
            }
        } else if role == Role::Control {
            let primary_reserve = s
                .rows
                .values()
                .filter(|r| {
                    r.role == Role::Primary
                        && r.closed_until.is_none()
                        && now.saturating_duration_since(r.used) < IDLE_GRACE
                })
                .map(|r| u64::from(r.mtu))
                .sum();
            available = available
                .saturating_sub(primary_reserve)
                .max(u64::from(mtu).saturating_sub(flight));
        }
        let window = path_flight.saturating_add(available).saturating_add(1);
        let trace = if secondary
            && available < u64::from(mtu)
            && crate::rt_trace::rt_trace_enabled()
            && s.last_secondary_trace
                .is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(1))
        {
            s.last_secondary_trace = Some(now);
            Some(format!(
                "connection_trace_id={} effective_role={role:?} source_coupled={source_coupled} path_flight_bytes={path_flight} ledger_flight_bytes={flight} available_bytes={available} window_bytes={window} ordinary_limit_bytes={limit} total_flight_bytes={} reserve_bytes={} probe_bytes={} healthy={} pressured={} held={} scope=endpoint",
                self.id,
                s.total(),
                s.reserve(now),
                s.healthy_secondary_probe(now).unwrap_or(0),
                s.healthy_until.is_some_and(|t| now < t),
                s.pressure_until.is_some_and(|t| now < t),
                s.growth_hold_until.is_some_and(|t| now < t)
            ))
        } else {
            None
        };
        drop(s);
        if let Some(trace) = trace {
            log::info!(target: "veil::source_flight", "secondary_blocked {trace}");
        }
        window
    }
    fn update_flight(&self, bytes: u64) {
        let wakers = {
            let mut s = lock!(self.pool.0);
            let Some(row) = s.rows.get_mut(&self.id) else {
                return;
            };
            let reduced = bytes < row.flight;
            row.flight = bytes;
            if bytes == 0 && row.queue_drained {
                // ACK delivery is accounted before releasing this flight.
                // With no queued or outstanding work, its demand is finished.
                let cleared = row.blocked_window.take().is_some();
                if cleared {
                    s.delivery_diagnostics.drained =
                        s.delivery_diagnostics.drained.saturating_add(1);
                }
            }
            if reduced { s.wakers() } else { Vec::new() }
        };
        wake(wakers);
    }
    fn blocked(&self, now: Instant) {
        let mut s = lock!(self.pool.0);
        let window = s.limit(now);
        if !s.demanded(now, window) {
            s.delivered_credit = 0;
        }
        if s.rows
            .get(&self.id)
            .is_some_and(|r| r.role == Role::Secondary && r.source_coupled)
        {
            let reserve = s.reserve(now);
            s.delivery_diagnostics.blocked = s.delivery_diagnostics.blocked.saturating_add(1);
            let row = s.rows.get_mut(&self.id).unwrap();
            row.queue_drained = false;
            row.blocked_window = Some((now, window, reserve));
        }
    }
    fn app_limited(&self, now: Instant) {
        let mut s = lock!(self.pool.0);
        if let Some(row) = s.rows.get_mut(&self.id) {
            row.queue_drained = true;
            // Draining the producer queue does not finish a blocked send:
            // its real unacknowledged bytes still have to pay for the window.
            if row.flight == 0 {
                let cleared = row.blocked_window.take().is_some();
                if cleared {
                    s.delivery_diagnostics.drained =
                        s.delivery_diagnostics.drained.saturating_add(1);
                }
            }
        }
        if !s.demanded(now, s.limit(now)) {
            s.delivered_credit = 0;
        }
    }
    fn delivered(&self, now: Instant, sent: Instant, bytes: u64, rtt: Duration) {
        let wakers = {
            let mut s = lock!(self.pool.0);
            s.delivery_diagnostics.calls = s.delivery_diagnostics.calls.saturating_add(1);
            if sent > now || now.saturating_duration_since(sent) >= IDLE_GRACE || rtt.is_zero() {
                s.delivery_diagnostics.stale = s.delivery_diagnostics.stale.saturating_add(1);
                return;
            }
            if !s.active(now) {
                s.delivery_diagnostics.inactive = s.delivery_diagnostics.inactive.saturating_add(1);
                return;
            }
            if s.growth_hold_until.is_some_and(|until| now < until) {
                s.delivery_diagnostics.held = s.delivery_diagnostics.held.saturating_add(1);
                return;
            }
            if !s.healthy_until.is_some_and(|t| now < t) {
                s.delivery_diagnostics.unhealthy =
                    s.delivery_diagnostics.unhealthy.saturating_add(1);
                return;
            }
            if s.pressure_until.is_some_and(|t| now < t) {
                s.delivery_diagnostics.pressured =
                    s.delivery_diagnostics.pressured.saturating_add(1);
                return;
            }
            let limit = s.limit(now);
            if !s.demanded(now, limit) {
                s.delivery_diagnostics.no_demand =
                    s.delivery_diagnostics.no_demand.saturating_add(1);
                s.delivered_credit = 0;
                return;
            }
            s.delivered_credit = s.delivered_credit.saturating_add(bytes);
            s.delivery_diagnostics.funded_bytes =
                s.delivery_diagnostics.funded_bytes.saturating_add(bytes);
            // A full usable secondary flight, excluding the unsent primary
            // reserve. Requiring delivery of the reserve would prevent a
            // backlogged secondary from ever probing a larger window.
            let usable = limit.saturating_sub(s.reserve(now)).max(1);
            if s.delivered_credit < usable {
                s.delivery_diagnostics.credit_wait =
                    s.delivery_diagnostics.credit_wait.saturating_add(1);
                return;
            }
            if s.last_growth
                .is_some_and(|at| now <= at || now.saturating_duration_since(at) < rtt)
            {
                s.delivery_diagnostics.rtt_wait = s.delivery_diagnostics.rtt_wait.saturating_add(1);
                return;
            }
            // One packet per delivered usable window, at most once per RTT.
            // A new limit needs a NEW blocked-send witness before growing again;
            // neither old demand nor compressed ACKs can spend unfilled windows.
            let mtu = u64::from(s.rows.get(&self.id).map_or(1200, |r| r.mtu));
            s.window = limit.saturating_add(mtu).min(u64::from(u32::MAX));
            s.window_reserve = s.reserve(now);
            s.delivery_diagnostics.grows = s.delivery_diagnostics.grows.saturating_add(1);
            s.delivered_credit = 0;
            s.last_growth = Some(now);
            s.wakers()
        };
        wake(wakers);
    }
    fn route_changed(&self) {
        let wakers = {
            let mut s = lock!(self.pool.0);
            s.window = 0;
            s.delivered_credit = 0;
            s.healthy_until = None;
            s.growth_hold_until = None;
            s.held_secondary_trial = None;
            s.last_growth = None;
            for row in s.rows.values_mut() {
                row.blocked_window = None;
            }
            s.wakers()
        };
        wake(wakers);
    }
    fn next_wakeup(&self, now: Instant) -> Option<Instant> {
        let s = lock!(self.pool.0);
        s.active_until
            .into_iter()
            .chain(s.rows.values().filter_map(|r| r.closed_until))
            .filter(|at| *at > now)
            .min()
    }
    fn register_waker(&self, waker: &Waker) {
        if let Some(row) = lock!(self.pool.0).rows.get_mut(&self.id)
            && row.waker.as_ref().is_none_or(|old| !old.will_wake(waker))
        {
            row.waker = Some(waker.clone());
        }
    }
    fn closed(&self) {
        let wakers = {
            let mut s = lock!(self.pool.0);
            if let Some(row) = s.rows.get_mut(&self.id) {
                // Keep abandoned bytes as debt through the activity lease;
                // reconnect cannot erase queued wire work or earn a new window.
                row.closed_until = Some(row.observed + IDLE_GRACE);
                row.waker = None;
                row.blocked_window = None;
            }
            s.wakers()
        };
        wake(wakers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counter(AtomicUsize);
    impl std::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn path_warnings_preserve_paid_flight_only_until_consumer_health_expires() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let control = pool.binding(1, Role::Control, now).unwrap();
        let primary = pool.binding(2, Role::Primary, now).unwrap();
        let video = pool.binding(3, Role::Secondary, now).unwrap();
        control.update_flight(100_000);
        pool.note_primary(now);
        // Unknown health must still protect the primary.
        assert!(pool.transport_pressure(now));
        assert_eq!(video.window(now, 0, 1200), 1);
        let fresh = now + PRESSURE_GRACE;
        pool.note_primary(fresh);
        pool.feedback(false, fresh);
        video.blocked(fresh);
        primary.delivered(fresh, fresh, 2400, Duration::from_millis(100));
        assert_eq!(video.window(fresh, 0, 1200), 3601);
        for offset in [100, 1000, 2999] {
            let at = fresh + Duration::from_millis(offset);
            pool.note_primary(at);
            assert!(!pool.transport_pressure(at));
            assert_eq!(video.window(at, 0, 1200), 3601);
        }
        // Transport warnings must not restamp or manufacture consumer health.
        let expired = fresh + IDLE_GRACE;
        pool.note_primary(expired);
        assert!(pool.transport_pressure(expired));
        assert_eq!(video.window(expired, 0, 1200), 1);
        // A later positive sample cannot cancel the existing pressure lease.
        pool.feedback(false, expired);
        assert!(!pool.transport_pressure(expired));
        assert_eq!(video.window(expired, 0, 1200), 1);
    }

    #[test]
    fn held_health_survives_path_warning_but_negative_feedback_and_route_reset_win() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let control = pool.binding(1, Role::Control, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        control.update_flight(100_000);
        pool.note_primary(now);
        pool.feedback(false, now);
        pool.hold_growth(now, now + Duration::from_secs(1), now);
        let warning = now + Duration::from_millis(1500);
        assert!(!pool.transport_pressure(warning));
        assert_eq!(video.window(warning, 0, 1200), 2401);
        pool.feedback(true, warning);
        assert!(pool.transport_pressure(warning));
        assert_eq!(video.window(warning, 0, 1200), 1);
        let recovered = warning + PRESSURE_GRACE;
        pool.note_primary(recovered);
        pool.feedback(false, recovered);
        assert!(!pool.transport_pressure(recovered));
        assert_eq!(video.window(recovered, 0, 1200), 2401);
        video.route_changed();
        assert!(pool.transport_pressure(recovered));
        assert_eq!(video.window(recovered, 0, 1200), 1);
    }

    #[test]
    fn growth_hold_keeps_paid_flight_and_cannot_bank_delivery_or_renew_on_replay() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(false, now);
        video.blocked(now);
        primary.delivered(now, now, 2400, Duration::from_millis(100));
        assert_eq!(video.window(now, 0, 1200), 3601);
        let until = now + Duration::from_secs(3);
        for milliseconds in [1000, 2000, 2999] {
            let at = now + Duration::from_millis(milliseconds);
            pool.note_primary(at);
            let _ = pool.binding(1, Role::Primary, at).unwrap();
            pool.hold_growth(at, until, at);
            video.blocked(at);
            primary.delivered(at, at, 100_000, Duration::from_millis(100));
            assert_eq!(video.window(at, 0, 1200), 3601);
        }
        pool.note_primary(until);
        let _ = pool.binding(1, Role::Primary, until).unwrap();
        pool.hold_growth(until, until, until); // An expired replay cannot renew it.
        primary.delivered(until, until, 100_000, Duration::from_millis(100));
        assert_eq!(
            video.window(until, 0, 1200),
            3601,
            "a hold is not a positive quality observation after expiration"
        );
        pool.feedback(false, until);
        primary.delivered(until, until, 1200, Duration::from_millis(100));
        assert_eq!(
            video.window(until, 0, 1200),
            3601,
            "ACKs received during the hold cannot fund later growth"
        );
        primary.delivered(until, until, 2400, Duration::from_millis(100));
        assert_eq!(video.window(until, 0, 1200), 4801);
        pool.feedback(true, until);
        pool.hold_growth(until, until + Duration::from_secs(1), until);
        assert!(
            video.window(until, 0, 1200) < 3601,
            "hold cannot undo genuine primary protection"
        );
    }

    #[test]
    fn healthy_growth_hold_preserves_shared_trial_through_background_debt() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let control = pool.binding(2, Role::Control, now).unwrap();
        let video = pool.binding(3, Role::Secondary, now).unwrap();
        let screen = pool.binding(4, Role::Secondary, now).unwrap();
        control.update_flight(100_000);
        pool.note_primary(now);
        pool.feedback(false, now);
        assert_eq!(video.window(now, 0, 1200), 2401);
        let at = now + Duration::from_secs(1);
        let until = now + Duration::from_secs(3);
        pool.hold_growth(at, until, at);
        assert_eq!(
            video.window(at, 0, 1200),
            2401,
            "holding growth cannot withdraw the already-permitted healthy trial"
        );
        video.update_flight(1200);
        assert_eq!(screen.window(at, 0, 1200), 1201, "one shared allowance");
        video.blocked(at);
        let paid = lock!(pool.0).window;
        primary.delivered(at, now, 100_000, Duration::from_millis(100));
        assert_eq!(lock!(pool.0).window, paid, "held ACKs earn no growth");
        pool.hold_growth(at, until, at + Duration::from_secs(1));
        assert_eq!(
            screen.window(at + Duration::from_secs(1), 0, 1500),
            1201,
            "replay or a larger MTU cannot inflate the inherited allowance"
        );
        video.update_flight(0);
        pool.note_primary(until);
        pool.hold_growth(until, until, until);
        assert_eq!(
            video.window(until, 0, 1200),
            1,
            "expired hold is not fresh positive health"
        );
        pool.feedback(false, until);
        assert_eq!(video.window(until, 0, 1200), 3001);
        pool.hold_growth(until, until + Duration::from_secs(1), until);
        pool.feedback(true, until);
        assert_eq!(
            video.window(until, 0, 1200),
            1,
            "actual pressure cancels the trial"
        );
    }

    #[test]
    fn held_trial_cannot_start_from_unknown_health_or_survive_a_route_change() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let control = pool.binding(1, Role::Control, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        control.update_flight(100_000);
        pool.note_primary(now);
        let until = now + Duration::from_secs(1);
        pool.hold_growth(now, until, now);
        assert_eq!(video.window(now, 0, 1200), 1);
        pool.hold_growth(until, until, until);
        assert_eq!(video.window(until, 0, 1200), 1);
        pool.feedback(false, until);
        assert_eq!(video.window(until, 0, 1200), 2401);
        pool.hold_growth(until, until + Duration::from_secs(1), until);
        assert_eq!(video.window(until, 0, 1200), 2401);
        video.route_changed();
        assert_eq!(video.window(until, 0, 1200), 1);
    }

    #[test]
    fn a_drained_queue_still_funds_its_outstanding_blocked_flight() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(false, now);
        video.blocked(now);
        video.update_flight(1200);
        video.app_limited(now); // Queue empty, but this packet is not ACKed.
        let ack = now + Duration::from_millis(120);
        primary.delivered(ack, now, 1200, Duration::from_millis(120));
        // QUIC reports real delivery before releasing this packet's flight.
        video.delivered(ack, now, 1200, Duration::from_millis(120));
        assert_eq!(
            video.window(ack, 1200, 1200),
            3601,
            "an empty producer queue must not erase demand for unacknowledged work"
        );
        video.update_flight(0);
        let later = ack + Duration::from_millis(120);
        primary.delivered(later, now, 20_000, Duration::from_millis(120));
        assert_eq!(
            video.window(later, 0, 1200),
            3601,
            "once the queued work and its flight drain, new ACKs cannot buy another window"
        );
    }

    #[test]
    fn a_finished_partial_flight_cannot_fund_a_later_blocked_send() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(false, now);
        video.blocked(now);
        video.update_flight(1200);
        video.app_limited(now);
        let ack = now + Duration::from_millis(120);
        primary.delivered(ack, now, 600, Duration::from_millis(120));
        video.delivered(ack, now, 1200, Duration::from_millis(120));
        video.update_flight(0); // 1800 paid bytes did not fill the usable 2400.
        let later = ack + Duration::from_millis(120);
        video.blocked(later);
        primary.delivered(later, later, 600, Duration::from_millis(120));
        assert_eq!(
            video.window(later, 0, 1200),
            2401,
            "a new send must not reuse an already finished flight's partial credit"
        );
    }

    #[test]
    fn changing_primary_reserve_cannot_reprice_old_credit() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(false, now);
        for step in 0..2 {
            let at = now + Duration::from_millis(step * 120);
            video.blocked(at);
            primary.delivered(at, at, 6000, Duration::from_millis(120));
        }
        let later = now + Duration::from_millis(240);
        video.blocked(later);
        primary.delivered(later, later, 3000, Duration::from_millis(120));
        let _control = pool.binding(3, Role::Control, later).unwrap();
        primary.delivered(later, later, 1000, Duration::from_millis(120));
        assert_eq!(
            video.window(later, 0, 1200),
            3601,
            "a larger primary reserve must invalidate the old waiting/credit scope"
        );
    }

    #[test]
    fn a_new_window_requires_a_new_blocked_send_not_old_waiting_history() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(false, now);
        video.blocked(now);
        primary.delivered(now, now, 3600, Duration::from_millis(120));
        assert_eq!(video.window(now, 0, 1200), 3601);
        let later = now + Duration::from_millis(120);
        primary.delivered(later, now, 4800, Duration::from_millis(120));
        assert_eq!(
            video.window(later, 0, 1200),
            3601,
            "old waiting history cannot spend an unfilled new window"
        );
    }

    #[test]
    fn drained_secondary_cannot_bank_primary_acks_for_a_later_burst() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(false, now);
        video.blocked(now);
        primary.delivered(now, now, 1200, Duration::from_millis(120));
        video.app_limited(now);
        primary.delivered(now, now, 20_000, Duration::from_millis(120));
        assert_eq!(video.window(now, 0, 1200), 2401);
        video.blocked(now);
        primary.delivered(now, now, 1200, Duration::from_millis(120));
        assert_eq!(
            video.window(now, 0, 1200),
            2401,
            "new work cannot reuse the drained work's ACK credit"
        );
        primary.delivered(now, now, 1200, Duration::from_millis(120));
        assert_eq!(video.window(now, 0, 1200), 3601);
    }

    #[test]
    fn control_and_other_nodes_cannot_spend_the_primary_reserve() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let control = pool.binding(2, Role::Control, now).unwrap();
        let video = pool.binding(3, Role::Secondary, now).unwrap();
        let other = Arc::new(SourceFlightPool::default());
        let unrelated = other.binding(1, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        video.update_flight(2400);
        control.update_flight(1200);
        assert_eq!(video.window(now, 2400, 1200), 2401);
        assert_eq!(control.window(now, 1200, 1200), 1201);
        assert_eq!(primary.window(now, 0, 1200), u64::MAX);
        assert_eq!(unrelated.window(now, 0, 1200), u64::MAX);
    }

    #[test]
    fn stale_progress_and_reordered_pressure_cannot_fund_growth() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(false, now);
        video.blocked(now);
        primary.delivered(now, now - IDLE_GRACE, 100_000, Duration::from_millis(120));
        primary.delivered(now, now, 100_000, Duration::ZERO);
        assert_eq!(video.window(now, 0, 1200), 2401);
        pool.feedback(true, now);
        pool.feedback(true, now - Duration::from_secs(1));
        assert_eq!(lock!(pool.0).pressure_until, Some(now + PRESSURE_GRACE));
    }

    #[test]
    fn independent_secondary_children_share_flight_and_leave_a_primary_packet() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        let screen = pool.binding(3, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        assert_eq!(video.window(now, 0, 1200), 2401);
        video.update_flight(2400);
        assert_eq!(screen.window(now, 0, 1200), 1);
        assert_eq!(primary.window(now, 0, 1200), u64::MAX);
        primary.update_flight(1200);
        assert_eq!(video.window(now, 2400, 1200), 2401);
        video.update_flight(1200);
        primary.update_flight(0);
        assert_eq!(screen.window(now, 0, 1200), 1201);
    }

    #[test]
    fn serialization_and_flight_progress_wake_other_connections_without_polling() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let a = pool.binding(1, Role::Primary, now).unwrap();
        let b = pool.binding(2, Role::Secondary, now).unwrap();
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        b.register_waker(&Waker::from(counter.clone()));
        let turn = a.acquire_transmit(now).unwrap();
        assert!(b.acquire_transmit(now).is_none());
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
        drop(turn);
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        drop(b.acquire_transmit(now).unwrap());
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            1,
            "no busy-loop wake on an uncontended turn"
        );
        a.update_flight(1200);
        a.update_flight(0);
        assert_eq!(counter.0.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn only_fresh_feedback_and_real_demand_allow_bounded_growth() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(false, now);
        for _ in 0..10 {
            let _ = video.window(now, 0, 1200); // stats reads are not demand
            primary.delivered(now, now, 100_000, Duration::from_millis(120));
        }
        assert_eq!(video.window(now, 0, 1200), 2401);
        video.blocked(now);
        primary.delivered(now, now, 100_000, Duration::from_millis(120));
        assert_eq!(video.window(now, 0, 1200), 3601);
        primary.delivered(now, now, 100_000, Duration::from_millis(120));
        assert_eq!(
            video.window(now, 0, 1200),
            3601,
            "ACK compression cannot grant repeated windows"
        );
        primary.route_changed();
        primary.delivered(now, now, 100_000, Duration::from_millis(120));
        assert_eq!(
            video.window(now, 0, 1200),
            2401,
            "old route cannot keep delivery credit"
        );
        assert_eq!(video.window(now + IDLE_GRACE, 0, 1200), u64::MAX);
    }

    #[test]
    fn reconnect_retains_abandoned_flight_without_blocking_the_primary() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let old = pool.binding(2, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        old.update_flight(2400);
        old.closed();
        let new = pool.binding(3, Role::Secondary, now).unwrap();
        assert_eq!(new.window(now, 0, 1200), 1);
        assert!(pool.binding(2, Role::Primary, now).is_none());
        assert_eq!(primary.window(now, 0, 1200), u64::MAX);
        primary.update_flight(4800);
        primary.route_changed();
        assert_eq!(
            primary.window(now, 4800, 1200),
            u64::MAX,
            "old primary/secondary debt cannot add a pause beyond the normal QUIC controller"
        );
        assert_eq!(
            new.window(now, 0, 1200),
            1,
            "actual primary flight must still debit competing sources"
        );
        let later = now + IDLE_GRACE;
        pool.note_primary(later);
        primary.update_flight(0);
        assert!(new.window(later, 0, 1200) > 1);
        assert!(!lock!(pool.0).rows.contains_key(&2));
    }
    #[test]
    fn expired_control_reserve_does_not_become_unfunded_secondary_flight() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let _control = pool.binding(2, Role::Control, now).unwrap();
        let video = pool.binding(3, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(true, now);
        let before = now + IDLE_GRACE - Duration::from_millis(1);
        pool.note_primary(before);
        let _ = pool.binding(1, Role::Primary, before).unwrap();
        pool.feedback(true, before);
        let after = now + IDLE_GRACE + Duration::from_millis(1);
        pool.note_primary(after);
        let _ = pool.binding(1, Role::Primary, after).unwrap();
        assert_eq!(
            video.window(after, 0, 1200),
            2401,
            "an expired control reserve is not an ACK-funded extra packet"
        );
        assert_eq!(primary.window(after, 0, 1200), u64::MAX);
    }

    #[test]
    fn expired_control_reserve_preserves_only_the_paid_secondary_growth() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let _control = pool.binding(2, Role::Control, now).unwrap();
        let video = pool.binding(3, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(false, now);
        video.blocked(now);
        primary.delivered(now, now, 2400, Duration::from_millis(100));
        assert_eq!(video.window(now, 0, 1200), 3601);
        let before = now + IDLE_GRACE - Duration::from_millis(1);
        pool.note_primary(before);
        let _ = pool.binding(1, Role::Primary, before).unwrap();
        let after = now + IDLE_GRACE + Duration::from_millis(1);
        pool.note_primary(after);
        let _ = pool.binding(1, Role::Primary, after).unwrap();
        assert_eq!(
            video.window(after, 0, 1200),
            3601,
            "retain the real paid packet without spending retired control headroom"
        );
    }

    #[test]
    fn closed_control_reserve_does_not_refund_its_outstanding_wire_debt() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let control = pool.binding(2, Role::Control, now).unwrap();
        let video = pool.binding(3, Role::Secondary, now).unwrap();
        pool.note_primary(now);
        pool.feedback(true, now);
        control.update_flight(1200);
        control.closed();
        assert_eq!(
            video.window(now, 0, 1200),
            1201,
            "closed control bytes still debit the correctly scoped window"
        );
        assert_eq!(primary.window(now, 0, 1200), u64::MAX);
    }
    #[test]
    fn expired_hold_preserves_its_fresh_health_without_authorizing_growth() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let _primary = pool.binding(1, Role::Primary, now).unwrap();
        let control = pool.binding(2, Role::Control, now).unwrap();
        let video = pool.binding(3, Role::Secondary, now).unwrap();
        control.update_flight(100_000);
        pool.note_primary(now);
        pool.feedback(false, now);
        let until = now + Duration::from_secs(3);
        let sampled = now + Duration::from_millis(2750);
        pool.note_primary(sampled);
        pool.hold_growth(sampled, until, sampled);
        let after_hold = until + Duration::from_millis(100);
        assert_eq!(
            video.window(after_hold, 0, 1200),
            2401,
            "a fresh known-health report must not become a one-byte window between polls"
        );
        video.blocked(after_hold);
        video.delivered(after_hold, after_hold, 100_000, Duration::from_millis(100));
        assert_eq!(lock!(pool.0).window, 0, "held health is not growth credit");
        pool.hold_growth(sampled, until, after_hold); // Expired replay cannot extend health.
        let expires = sampled + IDLE_GRACE;
        pool.note_primary(expires - Duration::from_millis(1));
        assert_eq!(
            video.window(expires, 0, 1200),
            1,
            "sampling TTL remains binding"
        );
    }

    #[test]
    fn delayed_or_replayed_hold_cannot_rebase_health_at_receipt() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let _primary = pool.binding(1, Role::Primary, now).unwrap();
        let control = pool.binding(2, Role::Control, now).unwrap();
        let video = pool.binding(3, Role::Secondary, now).unwrap();
        control.update_flight(100_000);
        pool.note_primary(now);
        pool.feedback(false, now);
        let sampled = now + Duration::from_millis(500);
        let received = now + Duration::from_millis(2500);
        let until = now + Duration::from_secs(3);
        pool.note_primary(received);
        pool.hold_growth(sampled, until, received);
        pool.hold_growth(sampled, until, received + Duration::from_millis(300));
        pool.hold_growth(received + Duration::from_millis(1), until, received);
        let after_hold = until + Duration::from_millis(100);
        assert_eq!(video.window(after_hold, 0, 1200), 2401);
        pool.hold_growth(until - Duration::from_millis(1), until, after_hold);
        let stale = sampled + IDLE_GRACE;
        assert_eq!(
            video.window(stale, 0, 1200),
            1,
            "delay, replay, future samples and expired events cannot extend the original health TTL"
        );
    }

    #[test]
    fn healthy_paid_growth_is_usable_behind_unrelated_control_flight() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let _primary = pool.binding(1, Role::Primary, now).unwrap();
        let control = pool.binding(2, Role::Control, now).unwrap();
        let video = pool.binding(3, Role::Secondary, now).unwrap();
        let screen = pool.binding(4, Role::Secondary, now).unwrap();
        control.update_flight(100_000);
        pool.note_primary(now);
        pool.feedback(false, now);
        assert_eq!(video.window(now, 0, 1200), 2401);
        video.blocked(now);
        video.delivered(now, now, 2400, Duration::from_millis(100));
        assert_eq!(
            video.window(now, 0, 1200),
            3601,
            "ACK-funded growth must not remain an unusable two-packet trial"
        );
        video.update_flight(2400);
        assert_eq!(screen.window(now, 0, 1200), 1201, "one shared paid limit");
        video.closed();
        assert_eq!(
            screen.window(now, 0, 1200),
            1201,
            "closed source debt remains"
        );
        pool.feedback(true, now);
        assert_eq!(
            screen.window(now, 0, 1200),
            1,
            "actual pressure overrides growth"
        );
    }

    #[test]
    fn paid_source_allowance_cannot_bank_control_ack_or_grow_during_hold() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let _primary = pool.binding(1, Role::Primary, now).unwrap();
        let control = pool.binding(2, Role::Control, now).unwrap();
        let video = pool.binding(3, Role::Secondary, now).unwrap();
        control.update_flight(100_000);
        pool.note_primary(now);
        pool.feedback(false, now);
        control.delivered(now, now, 100_000, Duration::from_millis(100));
        assert_eq!(video.window(now, 0, 1200), 2401, "no demand, no growth");
        video.blocked(now);
        video.delivered(now, now, 2400, Duration::from_millis(100));
        assert_eq!(video.window(now, 0, 1200), 3601);
        let held = now + Duration::from_secs(1);
        let until = now + Duration::from_secs(2);
        pool.hold_growth(held, until, held);
        assert_eq!(video.window(held, 0, 1200), 3601);
        video.blocked(held);
        video.delivered(held, held, 100_000, Duration::from_millis(100));
        assert_eq!(
            video.window(held, 0, 1500),
            3601,
            "hold cannot earn growth or reprice its MTU"
        );
        pool.hold_growth(held, until, held + Duration::from_millis(1));
        assert_eq!(
            video.window(held, 0, 1500),
            3601,
            "replay cannot enlarge the cap"
        );
        assert_eq!(
            video.window(until, 0, 1500),
            3601,
            "fresh frozen allowance survives between polls"
        );
        video.delivered(until, until, 100_000, Duration::from_millis(100));
        assert_eq!(
            video.window(until, 0, 1500),
            3601,
            "retention is not positive growth feedback"
        );
        pool.feedback(false, until);
        assert_eq!(video.window(until, 0, 1500), 3601);
        video.route_changed();
        assert_eq!(
            video.window(until, 0, 1500),
            1,
            "new route earns its own window"
        );
    }

    #[test]
    fn healthy_probe_survives_live_background_control_flight_but_not_pressure() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        let screen = pool.binding(3, Role::Secondary, now).unwrap();
        let controls: Vec<_> = (4..18)
            .map(|id| {
                let row = pool.binding(id, Role::Control, now).unwrap();
                row.update_flight(2400);
                row
            })
            .collect();
        pool.note_primary(now);
        primary.update_flight(200);
        assert_eq!(
            video.window(now, 0, 1200),
            1,
            "unknown primary cannot earn a probe"
        );
        pool.feedback(false, now);
        assert_eq!(video.window(now, 0, 1200), 2401);
        video.update_flight(1200);
        assert_eq!(
            screen.window(now, 0, 1200),
            1201,
            "the trial is shared, not per connection"
        );
        video.update_flight(2400);
        assert_eq!(screen.window(now, 0, 1200), 1);
        assert_eq!(primary.window(now, 200, 1200), u64::MAX);
        video.update_flight(0);
        primary.update_flight(120000);
        assert_eq!(
            video.window(now, 0, 1200),
            2401,
            "healthy audio BDP cannot erase or enlarge the fixed video trial"
        );
        let paid = lock!(pool.0).window;
        assert_eq!(paid, 0, "temporary trial did not manufacture paid growth");
        pool.feedback(true, now);
        assert_eq!(
            video.window(now, 0, 1200),
            1,
            "measured pressure stops the exception"
        );
        pool.feedback(false, now);
        assert_eq!(
            video.window(now, 0, 1200),
            1,
            "healthy feedback cannot erase a pressure lease"
        );
        drop(controls);
    }

    #[test]
    fn healthy_probe_charges_abandoned_secondary_and_cannot_outlive_its_feedback() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        let retired_video = pool.binding(3, Role::Secondary, now).unwrap();
        let background = pool.binding(4, Role::Control, now).unwrap();
        let retired_control = pool.binding(5, Role::Control, now).unwrap();
        background.update_flight(24000);
        retired_control.update_flight(24000);
        retired_control.closed();
        retired_video.update_flight(1200);
        retired_video.closed();
        primary.update_flight(200);
        pool.note_primary(now);
        pool.feedback(false, now);
        assert_eq!(video.window(now, 0, 1200), 1201);
        pool.hold_growth(now, now + Duration::from_millis(500), now);
        assert_eq!(
            video.window(now, 0, 1200),
            1201,
            "a hold retains the trial while still charging abandoned secondary debt"
        );
        let later = now + IDLE_GRACE;
        pool.note_primary(later);
        assert_eq!(
            video.window(later, 0, 1200),
            1,
            "expiry is not a new healthy observation"
        );
    }
    #[test]
    fn prewarmed_secondary_handshakes_cannot_consume_the_live_source_trial() {
        let now = Instant::now();
        let pool = Arc::new(SourceFlightPool::default());
        let primary = pool.binding(1, Role::Primary, now).unwrap();
        let video = pool.binding(2, Role::Secondary, now).unwrap();
        let prewarm = pool.factory(Role::Secondary)(3);
        prewarm.update_flight(24000);
        primary.update_flight(200);
        pool.note_primary(now);
        pool.feedback(false, now);
        assert_eq!(video.window(now, 0, 1200), 2401);
        assert_eq!(
            prewarm.window(now, 24000, 1200),
            24001,
            "a handshake cannot spend the shared source trial"
        );
        prewarm.blocked(now);
        {
            let state = lock!(pool.0);
            assert!(!state.demanded(now, state.limit(now)));
        }
        let source = pool.binding(3, Role::Secondary, now).unwrap();
        assert_eq!(
            video.window(now, 0, 1200),
            1,
            "selecting a real source charges its existing flight immediately"
        );
        source.closed();
        assert_eq!(
            video.window(now, 0, 1200),
            1,
            "closing/reconnecting cannot erase actual source debt"
        );
        assert_eq!(
            lock!(pool.0).window,
            0,
            "handshakes did not manufacture paid video growth"
        );
    }
}
