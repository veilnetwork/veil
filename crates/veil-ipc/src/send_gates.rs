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

use std::sync::{Arc, Mutex};
use std::{collections::HashMap, future::Future};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::IpcSendAdmissionLimit;

/// Sends to one destination in progress at once. Small next to the pool, so
/// several stuck destinations together still leave room for a live one.
pub(crate) const MAX_SENDS_PER_DESTINATION: usize = 4;

/// Keep at least half of the process-wide retained-body budget available to
/// other IPC connections. A 16 MiB frame (including a decoded batch copy) fits.
pub(crate) const CONNECTION_SEND_BYTES: usize = 32 * 1024 * 1024;

// What the cap is FOR: four stuck destinations together must still leave the
// connection's pool room for a live one. Checked where it cannot be skipped.
const _: () = assert!(
    MAX_SENDS_PER_DESTINATION * 4 <= crate::server::MAX_SPAWNED_HANDLERS_PER_CONNECTION,
    "four stuck destinations would fill the connection's send pool"
);

/// Admission happens before spawning, and both guards live until the body
/// and any per-destination wait are gone. Busy senders receive SERVER_BUSY and
/// retry from their existing host outbox; the IPC loop stays responsive.
pub(crate) fn admit_queued_send(
    jobs: &Arc<Semaphore>,
    bytes: &Arc<Semaphore>,
    connection_bytes: &Arc<Semaphore>,
    retained: usize,
) -> Result<
    (
        OwnedSemaphorePermit,
        OwnedSemaphorePermit,
        OwnedSemaphorePermit,
    ),
    IpcSendAdmissionLimit,
> {
    let count = Arc::clone(jobs)
        .try_acquire_owned()
        .map_err(|_| IpcSendAdmissionLimit::QueuedJobs)?;
    let cost =
        u32::try_from(retained.max(1)).map_err(|_| IpcSendAdmissionLimit::ConnectionBytes)?;
    let local = Arc::clone(connection_bytes)
        .try_acquire_many_owned(cost)
        .map_err(|_| IpcSendAdmissionLimit::ConnectionBytes)?;
    let memory = Arc::clone(bytes)
        .try_acquire_many_owned(cost)
        .map_err(|_| IpcSendAdmissionLimit::GlobalBytes)?;
    Ok((count, local, memory))
}

/// The gates of one IPC connection, created with it.
#[derive(Default)]
pub(crate) struct DestinationGates {
    gates: Mutex<HashMap<[u8; 32], DestinationGate>>,
}

struct DestinationGate {
    semaphore: Arc<Semaphore>,
    users: usize,
}

/// A turn at one destination's gate. Dropping it hands the turn on, and the
/// last one out removes the gate, so the map holds only destinations with a
/// send in progress.
pub(crate) struct DestinationTurn {
    permit: Option<OwnedSemaphorePermit>,
    owner: Arc<DestinationGates>,
    dst: [u8; 32],
}

impl DestinationGates {
    /// Wait for a turn at `dst`'s gate.
    pub(crate) async fn enter(self: &Arc<Self>, dst: [u8; 32]) -> DestinationTurn {
        let semaphore = {
            let mut gates = self.gates.lock().unwrap_or_else(|p| p.into_inner());
            let gate = gates.entry(dst).or_insert_with(|| DestinationGate {
                semaphore: Arc::new(Semaphore::new(MAX_SENDS_PER_DESTINATION)),
                users: 0,
            });
            gate.users += 1;
            Arc::clone(&gate.semaphore)
        };
        let mut turn = DestinationTurn {
            permit: None,
            owner: Arc::clone(self),
            dst,
        };
        let permit = semaphore
            .acquire_owned()
            .await
            .expect("a destination gate is never closed");
        turn.permit = Some(permit);
        turn
    }

    #[cfg(test)]
    fn open_gates(&self) -> usize {
        self.gates.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl Drop for DestinationTurn {
    fn drop(&mut self) {
        let mut gates = self.owner.gates.lock().unwrap_or_else(|p| p.into_inner());
        // Registered users include pending acquisitions, which can be cancelled
        // by a source deadline without ever obtaining a permit.
        drop(self.permit.take());
        let gate = gates.get_mut(&self.dst).expect("registered destination");
        gate.users -= 1;
        if gate.users == 0 {
            gates.remove(&self.dst);
        }
    }
}

/// Run the normal send pipeline under an optional budget set at IPC receipt.
/// The deadline covers both waits and first-hop admission. A timed-out job
/// releases its turns, permits and retained-body charge when the task exits.
pub(crate) async fn run_send_job(
    gates: &Arc<DestinationGates>,
    slots: Arc<Semaphore>,
    destination: Option<[u8; 32]>,
    deadline: Option<tokio::time::Instant>,
    send: impl Future<Output = ()>,
) {
    let job = async {
        let started = std::time::Instant::now();
        let _turn = match destination {
            Some(dst) => Some(gates.enter(dst).await),
            None => None,
        };
        let turn_ms = started.elapsed().as_millis();
        if turn_ms >= 200 {
            log::warn!(
                "ipc.send_turn_wait at={} ms={turn_ms}",
                veil_util::unix_secs_now_u64()
            );
        }
        let started = std::time::Instant::now();
        let _slot = slots.acquire_owned().await;
        let waited_ms = started.elapsed().as_millis();
        if waited_ms >= 1_000 {
            log::warn!(
                "ipc.send_permit_wait at={} ms={waited_ms}",
                veil_util::unix_secs_now_u64()
            );
        }
        if deadline.is_none_or(|deadline| tokio::time::Instant::now() < deadline) {
            send.await;
        }
    };
    if let Some(deadline) = deadline {
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => (),
            _ = job => (),
        }
    } else {
        job.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn queued_send_admission_bounds_both_waiters_and_bytes_and_releases_on_drop() {
        let jobs = Arc::new(Semaphore::new(2));
        let bytes = Arc::new(Semaphore::new(100));
        let local = Arc::new(Semaphore::new(100));
        let one = admit_queued_send(&jobs, &bytes, &local, 60).unwrap();
        assert_eq!(
            admit_queued_send(&jobs, &bytes, &local, 41).unwrap_err(),
            IpcSendAdmissionLimit::ConnectionBytes
        );
        assert_eq!(jobs.available_permits(), 1); // failed byte admission rolls back
        let two = admit_queued_send(&jobs, &bytes, &local, 1).unwrap();
        assert_eq!(
            admit_queued_send(&jobs, &bytes, &local, 1).unwrap_err(),
            IpcSendAdmissionLimit::QueuedJobs
        );
        drop((one, two));
        assert_eq!(jobs.available_permits(), 2);
        assert_eq!(bytes.available_permits(), 100);
        assert_eq!(local.available_permits(), 100);
        assert_eq!(
            admit_queued_send(&jobs, &bytes, &local, usize::MAX).unwrap_err(),
            IpcSendAdmissionLimit::ConnectionBytes
        );
    }

    #[test]
    fn one_connection_cannot_take_the_entire_shared_send_budget() {
        let jobs_a = Arc::new(Semaphore::new(128));
        let jobs_b = Arc::new(Semaphore::new(128));
        let shared = Arc::new(Semaphore::new(64 * 1024 * 1024));
        let bytes_a = Arc::new(Semaphore::new(CONNECTION_SEND_BYTES));
        let bytes_b = Arc::new(Semaphore::new(CONNECTION_SEND_BYTES));
        let frame = 16 * 1024 * 1024;
        let a1 = admit_queued_send(&jobs_a, &shared, &bytes_a, frame).unwrap();
        let a2 = admit_queued_send(&jobs_a, &shared, &bytes_a, frame).unwrap();
        assert_eq!(
            admit_queued_send(&jobs_a, &shared, &bytes_a, frame).unwrap_err(),
            IpcSendAdmissionLimit::ConnectionBytes
        );
        assert_eq!(jobs_a.available_permits(), 126);
        let b = admit_queued_send(&jobs_b, &shared, &bytes_b, 512).unwrap();
        drop((a1, a2, b));
        assert_eq!(shared.available_permits(), 64 * 1024 * 1024);
        assert_eq!(bytes_a.available_permits(), CONNECTION_SEND_BYTES);
        assert_eq!(bytes_b.available_permits(), CONNECTION_SEND_BYTES);

        // A failure at the global budget must also release the local charge.
        let held = shared
            .clone()
            .try_acquire_many_owned(64 * 1024 * 1024)
            .unwrap();
        assert_eq!(
            admit_queued_send(&jobs_a, &shared, &bytes_a, frame).unwrap_err(),
            IpcSendAdmissionLimit::GlobalBytes
        );
        assert_eq!(bytes_a.available_permits(), CONNECTION_SEND_BYTES);
        assert_eq!(jobs_a.available_permits(), 128);
        drop(held);
    }

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

    #[tokio::test(start_paused = true)]
    async fn expired_call_sends_release_active_and_queued_turns() {
        let gates = Arc::new(DestinationGates::default());
        let slots = Arc::new(Semaphore::new(MAX_SENDS_PER_DESTINATION));
        let entered = std::cell::Cell::new(0);
        let deadline =
            tokio::time::Instant::now() + veil_proto::ipc::LOCAL_BOUNDED_RELIABLE_MAX_AGE;
        let mut old = Vec::new();
        for _ in 0..=MAX_SENDS_PER_DESTINATION {
            old.push(Box::pin(run_send_job(
                &gates,
                Arc::clone(&slots),
                Some(SLOW),
                Some(deadline),
                async {
                    entered.set(entered.get() + 1);
                    std::future::pending::<()>().await;
                },
            )));
        }
        for send in &mut old {
            assert!(futures::poll!(send.as_mut()).is_pending());
        }
        assert_eq!(entered.get(), MAX_SENDS_PER_DESTINATION);
        assert_eq!(slots.available_permits(), 0);
        tokio::time::advance(veil_proto::ipc::LOCAL_BOUNDED_RELIABLE_MAX_AGE).await;
        // Let active sends leave before dropping the already-expired waiter.
        // The waiter must not inherit a newly free turn at the deadline.
        for send in &mut old {
            assert!(futures::poll!(send.as_mut()).is_ready());
        }
        assert_eq!(entered.get(), MAX_SENDS_PER_DESTINATION);
        assert_eq!(gates.open_gates(), 0);
        assert_eq!(slots.available_permits(), MAX_SENDS_PER_DESTINATION);

        run_send_job(&gates, slots, Some(SLOW), None, async {
            entered.set(entered.get() + 1);
        })
        .await;
        assert_eq!(entered.get(), MAX_SENDS_PER_DESTINATION + 1);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_send_expires_while_waiting_for_a_pool_slot() {
        let gates = Arc::new(DestinationGates::default());
        let slots = Arc::new(Semaphore::new(0));
        let deadline =
            tokio::time::Instant::now() + veil_proto::ipc::LOCAL_BOUNDED_RELIABLE_MAX_AGE;
        let send = run_send_job(&gates, slots, Some(SLOW), Some(deadline), async {
            panic!("expired send reached the handler");
        });
        tokio::pin!(send);
        assert!(futures::poll!(send.as_mut()).is_pending());
        assert_eq!(gates.open_gates(), 1);
        tokio::time::advance(veil_proto::ipc::LOCAL_BOUNDED_RELIABLE_MAX_AGE).await;
        assert!(futures::poll!(send.as_mut()).is_ready());
        assert_eq!(gates.open_gates(), 0);
    }

    /// The gate is entered BEFORE the connection's pool slot, and on the send
    /// path itself. Held in the source because the send runs only inside a
    /// live IPC connection: entered after the slot, a stuck destination would
    /// still hold the pool while it waits.
    #[test]
    fn the_send_path_takes_its_destination_turn_before_a_pool_slot() {
        let server = include_str!("server.rs");
        assert!(server.contains("send_gates::run_send_job(&gates, sem, destination, deadline"));
        let path = include_str!("send_gates.rs");
        let job = path.find("pub(crate) async fn run_send_job(").unwrap();
        let body = &path[job..path.find("#[cfg(test)]\nmod tests").unwrap()];
        let turn = body
            .find("gates.enter(dst).await")
            .expect("the send path no longer takes a destination turn");
        let slot = body
            .find("slots.acquire_owned().await")
            .expect("the send path no longer takes a pool slot");
        assert!(turn < slot, "the destination turn must come first");
    }
}
