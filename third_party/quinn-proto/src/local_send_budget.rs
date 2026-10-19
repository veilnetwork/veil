//! Optional process-local coupling of independently congestion-controlled connections.
//! Nothing in this interface is negotiated or carried on the wire.

use crate::{Duration, Instant};
use std::{fmt::Debug, sync::Arc, task::Waker};

/// An additional local flight limit. Ordinary congestion control remains in force.
/// Implementations must never call into another connection while handling a hook.
pub trait LocalSendBudget: Debug + Send + Sync {
    /// Serialize packet preparation across participating connections. Dropping
    /// the returned guard releases the turn. A refused turn must arrange a wake.
    fn acquire_transmit(&self, now: Instant) -> Option<Box<dyn Send>>;
    /// Maximum current-path congestion window, including this path's existing flight.
    /// Inspection must not manufacture producer demand or delivery credit.
    fn window(&self, now: Instant, path_flight: u64, mtu: u16) -> u64;
    /// Actual retained congestion-counted bytes across all routes of this connection.
    fn update_flight(&self, bytes: u64);
    /// A real pending send was blocked by the local flight limit.
    fn blocked(&self, now: Instant);
    /// The sender has no queued work after a real transmit poll. Old waiting
    /// history must not fund growth after application demand has ended.
    fn app_limited(&self, _now: Instant) {}
    /// An actual, current, validated-route Data packet was explicitly acknowledged.
    fn delivered(&self, now: Instant, sent: Instant, bytes: u64, rtt: Duration);
    /// A route change invalidates delivery-model credit, but not outstanding flight.
    fn route_changed(&self);
    /// Timer needed to retire local leases/debt without polling.
    fn next_wakeup(&self, now: Instant) -> Option<Instant>;
    /// Register the driver's wakeup without acquiring any connection lock.
    fn register_waker(&self, waker: &Waker);
    /// Retire this participant. Outstanding wire work must not mint new credit.
    fn closed(&self);
}

#[derive(Debug)]
pub(crate) struct Attachment(pub Arc<dyn LocalSendBudget>);
impl Drop for Attachment {
    fn drop(&mut self) {
        self.0.closed();
    }
}
