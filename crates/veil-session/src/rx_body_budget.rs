//! Node-wide budget for inbound frame bodies held in memory at once.
//!
//! ## What the per-frame cap does not bound
//!
//! `decode_header` rejects `body_len > MAX_FRAME_BODY` (16 MiB), and a
//! body that stops arriving is cut off by the runner's 30-second
//! slow-loris deadline. Both are **per frame, per session**. Neither
//! says anything about how many sessions may be doing this at once.
//!
//! Every authenticated session is an independent reader: it announces a
//! length, allocates a buffer that big, and waits up to the deadline for
//! the bytes. A node holding a thousand authenticated sessions —
//! ordinary for a relay — therefore admits a thousand simultaneous
//! allocations of up to 16 MiB, held for up to 30 seconds each, with
//! nothing anywhere summing them. The peers need not be malicious;
//! a synchronised burst of large legitimate transfers has the same
//! shape. What makes it cheap for an attacker is that the *body* need
//! never arrive: the header alone reserves the memory.
//!
//! ## The budget
//!
//! A session must reserve `body_len` bytes here before it allocates,
//! and holds the reservation until the body has been consumed. Demand
//! above the budget queues rather than allocating, so total in-flight
//! body memory is bounded by the budget regardless of session count.
//!
//! Queuing is safe from deadlock because every holder is already bounded
//! by the runner's body deadline, so the budget always drains. The floor
//! below guarantees a single largest-possible frame can always be
//! admitted — without it, a `MAX_FRAME_BODY` frame under a smaller
//! budget would wait forever for permits that cannot exist.
//!
//! ## Deliberately not an abuse signal
//!
//! Waiting for the budget means *this node* is saturated, not that the
//! peer misbehaved. A caller that gives up waiting must not feed its
//! violation tracker: the peer would be banned for our congestion, and
//! under load that turns a memory-pressure event into a mesh-wide
//! disconnect storm. Shed the session if you must, but do not blame it.

use std::sync::OnceLock;

use tokio::sync::{Semaphore, SemaphorePermit};
use veil_proto::codec::MAX_FRAME_BODY;

/// Default ceiling on inbound body bytes in flight node-wide (64 MiB).
///
/// Four largest-possible frames, or a few thousand ordinary ones. Sized
/// to be unreachable by honest traffic on a busy relay while keeping the
/// worst case a fraction of what one adversarial peer-set could pin
/// before — a thousand sessions could reserve ~16 GiB.
pub const DEFAULT_RX_BODY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Env override, in bytes. Clamped up to [`MAX_FRAME_BODY`] so the
/// budget can never be set below a single admissible frame.
pub const RX_BODY_BUDGET_ENV: &str = "VEIL_RX_BODY_BUDGET";

/// Apply the single-frame floor to a requested budget.
///
/// A value below `MAX_FRAME_BODY` is raised rather than rejected: the
/// operator asked for less memory, and the smallest amount that still
/// works is one frame's worth. Silently accepting it would wedge every
/// large transfer instead.
///
/// Split from [`configured_budget`] so the rule is testable without
/// touching the process environment — a global that parallel tests in
/// one binary cannot share without racing each other.
fn clamp_to_one_frame(requested: usize) -> usize {
    requested.max(MAX_FRAME_BODY as usize)
}

/// Resolve the configured budget from the environment.
fn configured_budget() -> usize {
    let requested = std::env::var(RX_BODY_BUDGET_ENV)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_RX_BODY_BUDGET_BYTES);
    clamp_to_one_frame(requested)
}

/// The process-wide budget. First call wins; race-safe via `OnceLock`.
///
/// Global for the same reason [`veil_bufpool::global`] is: the resource
/// being shared is host memory, which is a property of the process, not
/// of any one session or runtime handle.
pub fn global() -> &'static Semaphore {
    static GLOBAL: OnceLock<Semaphore> = OnceLock::new();
    GLOBAL.get_or_init(|| Semaphore::new(configured_budget()))
}

/// Reserve `body_len` bytes, waiting if the budget is currently spent.
///
/// The returned permit must be held for as long as the body occupies
/// memory; dropping it returns the bytes to the budget.
///
/// `body_len` is assumed to have passed `decode_header`, so it is at
/// most `MAX_FRAME_BODY` and always fits the `u32` the semaphore takes.
pub async fn reserve(body_len: usize) -> SemaphorePermit<'static> {
    let want = body_len.min(MAX_FRAME_BODY as usize) as u32;
    global()
        .acquire_many(want)
        .await
        // The budget is a process-lifetime static that nothing closes;
        // `acquire_many` can only fail on a closed semaphore.
        .expect("rx body budget semaphore is never closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor exists so a largest-possible frame is always admissible.
    /// Without it a small configured budget would park every 16 MiB
    /// transfer forever on permits that cannot exist.
    #[test]
    fn a_budget_below_one_frame_is_raised_to_one_frame() {
        assert_eq!(clamp_to_one_frame(1024), MAX_FRAME_BODY as usize);
        assert_eq!(clamp_to_one_frame(0), MAX_FRAME_BODY as usize);
        assert_eq!(
            clamp_to_one_frame(MAX_FRAME_BODY as usize - 1),
            MAX_FRAME_BODY as usize,
            "one byte short is still short"
        );
    }

    /// A budget at or above the floor is left exactly as asked — the
    /// clamp must not quietly inflate an operator's deliberate setting.
    #[test]
    fn a_budget_at_or_above_one_frame_is_left_alone() {
        assert_eq!(
            clamp_to_one_frame(MAX_FRAME_BODY as usize),
            MAX_FRAME_BODY as usize
        );
        assert_eq!(
            clamp_to_one_frame(DEFAULT_RX_BODY_BUDGET_BYTES),
            DEFAULT_RX_BODY_BUDGET_BYTES
        );
    }

    /// The shipped default must not be silently rewritten by its own
    /// floor — if it ever drops below one frame that is a mistake, not
    /// something to paper over.
    #[test]
    fn the_default_clears_the_floor_on_its_own() {
        assert!(DEFAULT_RX_BODY_BUDGET_BYTES >= MAX_FRAME_BODY as usize);
    }

    /// The point of the whole module: concurrent readers cannot exceed
    /// the budget between them, however many there are.
    #[tokio::test]
    async fn reservations_beyond_the_budget_wait_for_a_release() {
        let sem = Semaphore::new(MAX_FRAME_BODY as usize);
        let first = sem.acquire_many(MAX_FRAME_BODY).await.unwrap();
        // The budget is now fully spent — a second reader of any size
        // must not be admitted.
        assert!(sem.try_acquire_many(1).is_err());
        drop(first);
        assert!(
            sem.try_acquire_many(MAX_FRAME_BODY).is_ok(),
            "releasing must return the full reservation"
        );
    }

    /// A body larger than the budget can still be admitted, because the
    /// budget floor guarantees room for one whole frame.
    #[tokio::test]
    async fn a_largest_possible_body_is_admissible() {
        let sem = Semaphore::new(configured_budget());
        assert!(sem.try_acquire_many(MAX_FRAME_BODY).is_ok());
    }
}
