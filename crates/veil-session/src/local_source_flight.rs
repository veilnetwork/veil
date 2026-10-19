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
    flight: u64,
    mtu: u16,
    used: Instant,
    observed: Instant,
    closed_until: Option<Instant>,
    waker: Option<Waker>,
    blocked_window: Option<(Instant, u64, u64)>,
}
#[derive(Debug, Default)]
struct State {
    rows: HashMap<u64, Row>,
    active_until: Option<Instant>,
    healthy_until: Option<Instant>,
    pressure_until: Option<Instant>,
    window: u64,
    delivered_credit: u64,
    last_growth: Option<Instant>,
    last_reduction: Option<Instant>,
    preparing: bool,
    turn_waiters: HashMap<u64, Waker>,
    last_trace: Option<Instant>,
}
#[derive(Debug, Default)]
pub(crate) struct SourceFlightPool(Mutex<State>);

impl State {
    fn demanded(&self, now: Instant, window: u64) -> bool {
        let reserve = self.reserve(now);
        self.rows.values().any(|r| {
            r.role == Role::Secondary
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
                s.pressure_until = Some(
                    s.pressure_until
                        .map_or(now + PRESSURE_GRACE, |at| at.max(now + PRESSURE_GRACE)),
                );
                s.healthy_until = None;
                s.delivered_credit = 0;
                if s.last_reduction
                    .is_none_or(|at| now.saturating_duration_since(at) >= PRESSURE_GRACE)
                {
                    s.window = (s.window / 2).max(s.floor(now));
                    s.last_reduction = Some(now);
                }
            } else {
                s.healthy_until = Some(now + IDLE_GRACE);
            }
            s.wakers()
        };
        wake(wakers);
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
                        state.window.max(state.floor(now)),
                        state.reserve(now),
                    ))
                } else {
                    None
                }
            };
            if let Some((members, flight, window, reserve)) = snapshot {
                log::info!(target: "veil::source_flight",
                    "connection_trace_id={id} members={members} in_flight_bytes={flight} window_bytes={window} primary_control_reserve_bytes={reserve} scope=endpoint");
            }
        }
        installed
    }
    pub(crate) fn factory(self: &Arc<Self>, role: Role) -> veil_transport::LocalSendBudgetFactory {
        let pool = self.clone();
        Arc::new(move |id| -> Arc<dyn LocalSendBudget> {
            pool.binding(id, role, Instant::now())
                .expect("fresh local connection ordinal")
        })
    }

    fn binding(self: &Arc<Self>, id: u64, role: Role, now: Instant) -> Option<Arc<Binding>> {
        let mut s = lock!(self.0);
        s.prune(now);
        if let Some(row) = s.rows.get_mut(&id) {
            if row.role != role || row.closed_until.is_some() {
                return None;
            }
            row.used = row.used.max(now);
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
                flight: 0,
                mtu: 1200,
                used: now,
                observed: now,
                closed_until: None,
                waker: None,
                blocked_window: None,
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
        let (role, flight) = (row.role, row.flight);
        // The pool regulates competing work. The primary keeps its ordinary
        // QUIC controller: older secondary debt (or a former route's primary
        // flight) must not impose an additional pause on fresh audio. Its REAL
        // bytes still debit the shared ledger before any secondary can send.
        if role == Role::Primary {
            return u64::MAX;
        }
        let limit = s.window.max(s.floor(now));
        let mut available = limit.saturating_sub(s.total());
        if role == Role::Secondary {
            available = available.saturating_sub(s.reserve(now));
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
        path_flight.saturating_add(available).saturating_add(1)
    }
    fn update_flight(&self, bytes: u64) {
        let wakers = {
            let mut s = lock!(self.pool.0);
            let Some(row) = s.rows.get_mut(&self.id) else {
                return;
            };
            let reduced = bytes < row.flight;
            row.flight = bytes;
            if reduced { s.wakers() } else { Vec::new() }
        };
        wake(wakers);
    }
    fn blocked(&self, now: Instant) {
        let mut s = lock!(self.pool.0);
        let window = s.window.max(s.floor(now));
        if !s.demanded(now, window) {
            s.delivered_credit = 0;
        }
        if s.rows
            .get(&self.id)
            .is_some_and(|r| r.role == Role::Secondary)
        {
            let reserve = s.reserve(now);
            s.rows.get_mut(&self.id).unwrap().blocked_window = Some((now, window, reserve));
        }
    }
    fn app_limited(&self, now: Instant) {
        let mut s = lock!(self.pool.0);
        if let Some(row) = s.rows.get_mut(&self.id) {
            row.blocked_window = None;
        }
        if !s.demanded(now, s.window.max(s.floor(now))) {
            s.delivered_credit = 0;
        }
    }
    fn delivered(&self, now: Instant, sent: Instant, bytes: u64, rtt: Duration) {
        let wakers = {
            let mut s = lock!(self.pool.0);
            if sent > now
                || now.saturating_duration_since(sent) >= IDLE_GRACE
                || rtt.is_zero()
                || !s.active(now)
                || !s.healthy_until.is_some_and(|t| now < t)
                || s.pressure_until.is_some_and(|t| now < t)
            {
                return;
            }
            let floor = s.floor(now);
            let limit = s.window.max(floor);
            if !s.demanded(now, limit) {
                s.delivered_credit = 0;
                return;
            }
            s.delivered_credit = s.delivered_credit.saturating_add(bytes);
            // A full usable secondary flight, excluding the unsent primary
            // reserve. Requiring delivery of the reserve would prevent a
            // backlogged secondary from ever probing a larger window.
            let usable = limit.saturating_sub(s.reserve(now)).max(1);
            if s.delivered_credit < usable
                || s.last_growth
                    .is_some_and(|at| now <= at || now.saturating_duration_since(at) < rtt)
            {
                return;
            }
            // One packet per delivered usable window, at most once per RTT.
            // A new limit needs a NEW blocked-send witness before growing again;
            // neither old demand nor compressed ACKs can spend unfilled windows.
            let mtu = u64::from(s.rows.get(&self.id).map_or(1200, |r| r.mtu));
            s.window = limit.saturating_add(mtu).min(u64::from(u32::MAX));
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
        if let Some(row) = lock!(self.pool.0).rows.get_mut(&self.id) {
            if row.waker.as_ref().is_none_or(|old| !old.will_wake(waker)) {
                row.waker = Some(waker.clone());
            }
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
}
