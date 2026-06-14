//! Listener supervisor types and helpers.
//!
//! The actual listener task loop lives in `runtime.rs` because it needs to
//! spawn inbound session tasks with access to `SessionRuntimeContext`.
//! This module owns the shared state types so `runtime.rs` does not define
//! them inline.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::oneshot;

use veil_transport::TransportConnection;

use crate::types::{ListenId, ListenerHandle};

/// Per-listener queues of debug-session accept waiters.
pub type AcceptWaiters =
    BTreeMap<ListenId, VecDeque<oneshot::Sender<(ListenerHandle, Box<dyn TransportConnection>)>>>;

/// Pop the next waiter for `listen_id`, removing the queue when empty.
pub fn pop_accept_waiter(
    waiters: &Arc<Mutex<AcceptWaiters>>,
    listen_id: ListenId,
) -> Option<oneshot::Sender<(ListenerHandle, Box<dyn TransportConnection>)>> {
    let mut guard = lock_waiters(waiters);
    let queue = guard.get_mut(&listen_id)?;
    let waiter = queue.pop_front()?;
    if queue.is_empty() {
        guard.remove(&listen_id);
    }
    Some(waiter)
}

pub fn lock_waiters(waiters: &Arc<Mutex<AcceptWaiters>>) -> MutexGuard<'_, AcceptWaiters> {
    waiters.lock().unwrap_or_else(|p| p.into_inner())
}
