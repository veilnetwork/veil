//! How many sends to ONE destination may be in progress at once.
//!
//! An app's sends leave the IPC read loop and run concurrently, bounded by a
//! per-connection pool (`MAX_SPAWNED_HANDLERS_PER_CONNECTION`). A send to a
//! destination nobody can reach is slow — a route discovery that times out, a
//! certificate walk that finds nothing, a relay attempt — and it held its pool
//! slot the whole time. Measured on a stand after a restart: sends to one
//! absent device took 6–15 s each, the app re-drove its backlog to it, and in
//! the first two minutes other sends waited for a slot more than 600 times; a
//! message to a live device sat behind them for 48–102 s.
//!
//! So each destination gets its own small gate, entered BEFORE the shared
//! pool. A slow destination queues behind itself and holds at most
//! [`MAX_SENDS_PER_DESTINATION`] pool slots; everyone else keeps moving.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Sends to one destination in progress at once. Small next to the pool, so
/// several stuck destinations together still leave room for a live one.
pub(crate) const MAX_SENDS_PER_DESTINATION: usize = 4;

// What the cap is FOR: four stuck destinations together must still leave the
// connection's pool room for a live one. Checked where it cannot be skipped.
const _: () = assert!(
    MAX_SENDS_PER_DESTINATION * 4 <= crate::server::MAX_SPAWNED_HANDLERS_PER_CONNECTION,
    "four stuck destinations would fill the connection's send pool"
);

/// The gates of one IPC connection, created with it.
#[derive(Default)]
pub(crate) struct DestinationGates {
    gates: Mutex<HashMap<[u8; 32], Arc<Semaphore>>>,
}

/// A turn at one destination's gate. Dropping it hands the turn on, and the
/// last one out removes the gate, so the map holds only destinations with a
/// send in progress.
pub(crate) struct DestinationTurn {
    _permit: OwnedSemaphorePermit,
    gate: Arc<Semaphore>,
    owner: Arc<DestinationGates>,
    dst: [u8; 32],
}

impl DestinationGates {
    /// Wait for a turn at `dst`'s gate.
    pub(crate) async fn enter(self: &Arc<Self>, dst: [u8; 32]) -> DestinationTurn {
        let gate = {
            let mut gates = self.gates.lock().unwrap_or_else(|p| p.into_inner());
            Arc::clone(
                gates
                    .entry(dst)
                    .or_insert_with(|| Arc::new(Semaphore::new(MAX_SENDS_PER_DESTINATION))),
            )
        };
        let permit = Arc::clone(&gate)
            .acquire_owned()
            .await
            .expect("a destination gate is never closed");
        DestinationTurn {
            _permit: permit,
            gate,
            owner: Arc::clone(self),
            dst,
        }
    }

    #[cfg(test)]
    fn open_gates(&self) -> usize {
        self.gates.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl Drop for DestinationTurn {
    fn drop(&mut self) {
        let mut gates = self.owner.gates.lock().unwrap_or_else(|p| p.into_inner());
        // The permit is still held here (fields drop after this body), so the
        // last turn out sees every other permit free. Three owners then: the
        // map, this turn, and the owned permit, which keeps its own reference
        // to the semaphore. A caller still waiting in `enter` holds a fourth.
        if Arc::strong_count(&self.gate) == 3
            && self.gate.available_permits() + 1 == MAX_SENDS_PER_DESTINATION
        {
            gates.remove(&self.dst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const SLOW: [u8; 32] = [0x41; 32];
    const LIVE: [u8; 32] = [0x13; 32];

    /// A destination that cannot be served takes its own turns, never the
    /// ones a live destination needs.
    #[tokio::test]
    async fn a_stuck_destination_waits_behind_itself_not_in_front_of_others() {
        let gates = Arc::new(DestinationGates::default());
        let mut held = Vec::new();
        for _ in 0..MAX_SENDS_PER_DESTINATION {
            held.push(gates.enter(SLOW).await);
        }
        let over = tokio::time::timeout(Duration::from_millis(50), gates.enter(SLOW)).await;
        assert!(
            over.is_err(),
            "one more send to the stuck destination waits"
        );

        let live = tokio::time::timeout(Duration::from_millis(50), gates.enter(LIVE)).await;
        assert!(live.is_ok(), "a send to another destination does not");
        drop(live);

        held.pop();
        let next = tokio::time::timeout(Duration::from_millis(50), gates.enter(SLOW)).await;
        assert!(next.is_ok(), "a turn handed back lets the next send in");
        drop(next);
        drop(held);
        assert_eq!(
            gates.open_gates(),
            0,
            "a destination with nothing in progress leaves no gate behind"
        );
    }

    /// The gate is entered BEFORE the connection's pool slot, and on the send
    /// path itself. Held in the source because the send runs only inside a
    /// live IPC connection: entered after the slot, a stuck destination would
    /// still hold the pool while it waits.
    #[test]
    fn the_send_path_takes_its_destination_turn_before_a_pool_slot() {
        let src = include_str!("server.rs");
        let spawn = src
            .find("handlers::send::SendReply::Offloop(reply_tx)")
            .expect("the off-loop send spawn moved; this guard is stale");
        let body = &src[..spawn];
        let turn = body
            .rfind("gates.enter(send.dst_node_id).await")
            .expect("the send path no longer takes a destination turn");
        let slot = body
            .rfind("sem.acquire_owned().await")
            .expect("the send path no longer takes a pool slot");
        assert!(turn < slot, "the destination turn must come first");
    }
}
