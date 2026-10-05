//! Node-local producer activity shared across this node's session runners.
//! No remote priority, payload role or wire metadata enters this state.
use std::sync::Mutex;
use std::time::{Duration, Instant};
use veil_util::lock;

#[derive(Debug, Default)]
pub(crate) struct LocalSourceActivity(Mutex<Option<Instant>>);

impl LocalSourceActivity {
    pub(crate) fn note(&self, now: Instant) {
        *lock!(self.0) = Some(now);
    }

    pub(crate) fn active(&self, now: Instant) -> bool {
        lock!(self.0).is_some_and(|at| now.saturating_duration_since(at) < Duration::from_secs(3))
    }
}
