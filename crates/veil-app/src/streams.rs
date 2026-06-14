//! App-plane stream lifecycle table.
//!
//! `AppStreamTable` tracks the state of open application streams. A stream
//! is identified by the pair `(peer_id, stream_id)` where `stream_id` comes
//! from the `FrameHeader.stream_id` field of the `APP_OPEN` frame.
//!
//! # Lifecycle
//!
//! ```text
//! APP_OPEN ──► Open ──► (APP_DATA, APP_SEND, …)
//! ↓
//! APP_CLOSE ──► Closed (entry removed)
//! ```
//!
//! Duplicate `APP_OPEN` for an already-open stream returns `OpenResult::AlreadyOpen`.
//! When either the global or per-peer stream cap is reached, `OpenResult::CapacityReached`
//! is returned and the caller should respond with `AppReceipt{REJECTED}`.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};
use veil_util::lock;

// ── CloseNotify ───────────────────────────────────────────────────────────────

/// A one-shot close notification that fires when the owning `AppStreamState`
/// is dropped without an explicit [`AppStreamTable::close`] call.
///
/// Wrapping in `Arc<Mutex<Option<_>>>` lets `AppStreamState` derive `Clone`
/// while ensuring the callback fires at most once (the first `Drop` to
/// succeed in `take` owns it). Callers that hold a clone from
/// [`AppStreamTable::get`] (which returns an `AppStreamSnapshot`, not the
/// state itself) will never observe the callback.
type CloseNotifyFn = Box<dyn FnOnce() + Send>;
type CloseNotify = Arc<Mutex<Option<CloseNotifyFn>>>;

use veil_proto::budget::{
    MAX_STREAM_RECV_WINDOW, MAX_STREAM_SEND_WINDOW, MAX_STREAMS_PER_PEER, MAX_TOTAL_STREAMS,
};

/// Default initial receive window: 256 KiB.
pub const APP_STREAM_INITIAL_WINDOW: u32 = 256 * 1024;

// ── AppStreamState ────────────────────────────────────────────────────────────

/// State of an open application stream.
///
/// Two flow-control windows are tracked:
///
/// * `send_window` — credits remaining to send to the remote peer. Decremented
///   when the local node forwards APP_DATA to the peer; incremented when the
///   peer sends APP_WINDOW_UPDATE. Capped at `MAX_STREAM_SEND_WINDOW`.
///
/// * `recv_window` — credits the remote peer has been granted to send to us.
///   Decremented when we receive APP_DATA from the peer; incremented when we
///   issue our own APP_WINDOW_UPDATE (buffer freed by the local app).
///
/// # Implicit-close notification
///
/// An optional close-notify callback can be registered via
/// [`AppStreamTable::set_close_notify`]. The callback fires once when the
/// stream is removed from the table without an explicit
/// [`AppStreamTable::close`] call (e.g. on session drop or table teardown).
/// On explicit close the callback is disarmed before the state is dropped.
pub struct AppStreamState {
    pub app_id: [u8; 32],
    pub endpoint_id: u32,
    pub opened_at: Instant,
    /// Send credits: bytes this node may still forward to the remote peer.
    /// Never exceeds `MAX_STREAM_SEND_WINDOW`.
    pub(crate) send_window: u32,
    /// Receive credits: bytes the remote peer may still send to this node.
    pub(crate) recv_window: u32,
    /// One-shot implicit-close callback. Armed by `set_close_notify`;
    /// disarmed by `close`. Wrapped in `Arc<Mutex<Option>>` so the struct
    /// is `Send` without requiring `Clone` on `FnOnce`.
    close_notify: CloseNotify,
}

impl std::fmt::Debug for AppStreamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStreamState")
            .field("app_id", &self.app_id)
            .field("endpoint_id", &self.endpoint_id)
            .field("send_window", &self.send_window)
            .field("recv_window", &self.recv_window)
            .finish()
    }
}

impl Drop for AppStreamState {
    fn drop(&mut self) {
        if let Some(cb) = lock!(self.close_notify).take() {
            cb();
        }
    }
}

/// A snapshot of an `AppStreamState` returned by [`AppStreamTable::get`].
///
/// This is a plain value type (no Drop side-effects) used for inspecting
/// stream metadata without holding the table lock or triggering close logic.
#[derive(Debug, Clone)]
pub struct AppStreamSnapshot {
    pub app_id: [u8; 32],
    pub endpoint_id: u32,
    pub opened_at: Instant,
    pub send_window: u32,
    pub recv_window: u32,
}

// ── AppStreamTableInner ───────────────────────────────────────────────────────

#[derive(Debug)]
struct AppStreamTableInner {
    streams: HashMap<StreamKey, AppStreamState>,
    /// Per-peer open-stream count for enforcing `MAX_STREAMS_PER_PEER`.
    per_peer: HashMap<[u8; 32], usize>,
}

// ── AppStreamTable ────────────────────────────────────────────────────────────

/// Tracks open application streams per `(peer_id, stream_id)`.
///
/// Clone-cheap: inner state is behind `Arc<Mutex<_>>`.
///
/// # Capacity
///
/// At most `MAX_TOTAL_STREAMS` streams may be open simultaneously across all
/// peers. Additionally, a single peer may not open more than
/// `MAX_STREAMS_PER_PEER` streams. `open` / `open_with_window` return
/// `OpenResult::CapacityReached` when either limit is exceeded.
#[derive(Clone, Debug)]
pub struct AppStreamTable {
    inner: Arc<Mutex<AppStreamTableInner>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StreamKey {
    peer_id: [u8; 32],
    stream_id: u32,
}

/// Result of attempting to open a stream.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenResult {
    /// Stream was successfully opened.
    Opened,
    /// A stream with the same `(peer_id, stream_id)` is already open.
    AlreadyOpen,
    /// The global stream limit (`MAX_TOTAL_STREAMS`) or the per-peer limit
    /// (`MAX_STREAMS_PER_PEER`) has been reached. The caller should reject
    /// the `APP_OPEN` with `AppReceipt{REJECTED}`.
    CapacityReached,
}

impl Default for AppStreamTable {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(AppStreamTableInner {
                streams: HashMap::new(),
                per_peer: HashMap::new(),
            })),
        }
    }
}

impl AppStreamTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new stream with default initial windows.
    ///
    /// Returns `AlreadyOpen` if a stream with the same key already exists, or
    /// `CapacityReached` if either the global or per-peer limit is exhausted.
    pub fn open(
        &self,
        peer_id: [u8; 32],
        stream_id: u32,
        app_id: [u8; 32],
        endpoint_id: u32,
    ) -> OpenResult {
        self.open_with_window(
            peer_id,
            stream_id,
            app_id,
            endpoint_id,
            APP_STREAM_INITIAL_WINDOW,
            APP_STREAM_INITIAL_WINDOW,
        )
    }

    /// Open a new stream with explicit initial windows.
    pub fn open_with_window(
        &self,
        peer_id: [u8; 32],
        stream_id: u32,
        app_id: [u8; 32],
        endpoint_id: u32,
        initial_send_window: u32,
        initial_recv_window: u32,
    ) -> OpenResult {
        let key = StreamKey { peer_id, stream_id };
        let mut inner = lock!(self.inner);
        if inner.streams.contains_key(&key) {
            return OpenResult::AlreadyOpen;
        }
        // Global capacity check.
        if inner.streams.len() >= MAX_TOTAL_STREAMS {
            return OpenResult::CapacityReached;
        }
        // Per-peer capacity check.
        let peer_count = inner.per_peer.get(&peer_id).copied().unwrap_or(0);
        if peer_count >= MAX_STREAMS_PER_PEER {
            return OpenResult::CapacityReached;
        }
        inner.streams.insert(
            key,
            AppStreamState {
                app_id,
                endpoint_id,
                opened_at: Instant::now(),
                send_window: initial_send_window.min(MAX_STREAM_SEND_WINDOW),
                recv_window: initial_recv_window.min(MAX_STREAM_RECV_WINDOW),
                close_notify: Arc::new(Mutex::new(None)),
            },
        );
        *inner.per_peer.entry(peer_id).or_insert(0) += 1;
        OpenResult::Opened
    }

    /// Record that we received `byte_count` bytes of APP_DATA from the peer.
    ///
    /// Decrements `recv_window`. Returns `false` if the peer has exceeded the
    /// receive window (flow-control violation); the caller should treat this as
    /// a protocol error.
    pub fn record_data_received(
        &self,
        peer_id: &[u8; 32],
        stream_id: u32,
        byte_count: u32,
    ) -> bool {
        let key = StreamKey {
            peer_id: *peer_id,
            stream_id,
        };
        let mut inner = lock!(self.inner);
        if let Some(state) = inner.streams.get_mut(&key) {
            if state.recv_window < byte_count {
                return false; // window exhausted — violation
            }
            state.recv_window -= byte_count;
            true
        } else {
            false // unknown stream
        }
    }

    /// Record that we sent `byte_count` bytes of APP_DATA to the peer.
    ///
    /// Decrements `send_window`. Returns `false` if the send window has been
    /// exhausted (caller must not forward the frame).
    pub fn record_data_sent(&self, peer_id: &[u8; 32], stream_id: u32, byte_count: u32) -> bool {
        let key = StreamKey {
            peer_id: *peer_id,
            stream_id,
        };
        let mut inner = lock!(self.inner);
        if let Some(state) = inner.streams.get_mut(&key) {
            if state.send_window < byte_count {
                return false; // window exhausted
            }
            state.send_window -= byte_count;
            true
        } else {
            false
        }
    }

    /// Apply an APP_WINDOW_UPDATE from the peer: increases `send_window`.
    ///
    /// The window is clamped to `MAX_STREAM_SEND_WINDOW` so a malicious peer
    /// cannot inflate it to `u32::MAX` and bypass flow control.
    pub fn apply_window_update(&self, peer_id: &[u8; 32], stream_id: u32, increment: u32) {
        let key = StreamKey {
            peer_id: *peer_id,
            stream_id,
        };
        let mut inner = lock!(self.inner);
        if let Some(state) = inner.streams.get_mut(&key) {
            let before = state.send_window;
            state.send_window = before.saturating_add(increment).min(MAX_STREAM_SEND_WINDOW);
            // Log when the window is already at the ceiling so flow-control issues
            // are visible in debug traces (increment absorbed without effect).
            if state.send_window == MAX_STREAM_SEND_WINDOW && before == MAX_STREAM_SEND_WINDOW {
                log::debug!(
                    "stream ({stream_id}): APP_WINDOW_UPDATE increment={increment} ignored — send_window already at MAX ({MAX_STREAM_SEND_WINDOW})",
                );
            }
        }
    }

    /// Replenish `recv_window` by `increment` (called after local app consumes data).
    ///
    /// Returns the new `recv_window` value so the caller can decide whether to
    /// emit an APP_WINDOW_UPDATE to the peer.
    pub fn replenish_recv_window(
        &self,
        peer_id: &[u8; 32],
        stream_id: u32,
        increment: u32,
    ) -> Option<u32> {
        let key = StreamKey {
            peer_id: *peer_id,
            stream_id,
        };
        let mut inner = lock!(self.inner);
        inner.streams.get_mut(&key).map(|state| {
            state.recv_window = state
                .recv_window
                .saturating_add(increment)
                .min(MAX_STREAM_RECV_WINDOW);
            state.recv_window
        })
    }

    /// Close a stream explicitly. Returns `true` if the stream was found and removed.
    ///
    /// Disarms any registered close-notify callback so it does not fire on
    /// `Drop` — only implicitly closed streams (removed without calling this
    /// method) trigger the notification.
    pub fn close(&self, peer_id: &[u8; 32], stream_id: u32) -> bool {
        let key = StreamKey {
            peer_id: *peer_id,
            stream_id,
        };
        let mut inner = lock!(self.inner);
        if let Some(state) = inner.streams.remove(&key) {
            // Disarm close-notify before drop so it is not treated as implicit.
            lock!(state.close_notify).take();
            // Decrement per-peer counter; remove entry when it reaches zero.
            if let std::collections::hash_map::Entry::Occupied(mut e) =
                inner.per_peer.entry(*peer_id)
            {
                if *e.get() <= 1 {
                    e.remove();
                } else {
                    *e.get_mut() -= 1;
                }
            }
            true
        } else {
            false
        }
    }

    /// Register a callback that fires when the stream is implicitly closed
    /// (dropped from the table without an explicit [`close`] call).
    ///
    /// Replaces any previously registered callback. Returns `false` if the
    /// stream is not currently open.
    ///
    /// [`close`]: Self::close
    pub fn set_close_notify(
        &self,
        peer_id: &[u8; 32],
        stream_id: u32,
        notify: impl FnOnce() + Send + 'static,
    ) -> bool {
        let key = StreamKey {
            peer_id: *peer_id,
            stream_id,
        };
        let inner = lock!(self.inner);
        if let Some(state) = inner.streams.get(&key) {
            *lock!(state.close_notify) = Some(Box::new(notify));
            true
        } else {
            false
        }
    }

    /// Check whether a stream is currently open.
    pub fn is_open(&self, peer_id: &[u8; 32], stream_id: u32) -> bool {
        let key = StreamKey {
            peer_id: *peer_id,
            stream_id,
        };
        lock!(self.inner).streams.contains_key(&key)
    }

    /// Return a snapshot of the state for an open stream, if any.
    ///
    /// Returns an [`AppStreamSnapshot`] — a plain value type with no Drop
    /// side-effects — rather than the internal `AppStreamState` directly.
    pub fn get(&self, peer_id: &[u8; 32], stream_id: u32) -> Option<AppStreamSnapshot> {
        let key = StreamKey {
            peer_id: *peer_id,
            stream_id,
        };
        lock!(self.inner)
            .streams
            .get(&key)
            .map(|s| AppStreamSnapshot {
                app_id: s.app_id,
                endpoint_id: s.endpoint_id,
                opened_at: s.opened_at,
                send_window: s.send_window,
                recv_window: s.recv_window,
            })
    }

    /// Number of currently open streams.
    pub fn len(&self) -> usize {
        lock!(self.inner).streams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: [u8; 32] = [0x01u8; 32];
    const APP: [u8; 32] = [0xABu8; 32];

    #[test]
    fn open_new_stream_returns_opened() {
        let t = AppStreamTable::new();
        let r = t.open(PEER, 1, APP, 7);
        assert_eq!(r, OpenResult::Opened);
        assert!(t.is_open(&PEER, 1));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn duplicate_open_returns_already_open() {
        let t = AppStreamTable::new();
        t.open(PEER, 1, APP, 7);
        let r = t.open(PEER, 1, APP, 7);
        assert_eq!(r, OpenResult::AlreadyOpen);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn close_existing_stream_removes_entry() {
        let t = AppStreamTable::new();
        t.open(PEER, 1, APP, 7);
        let removed = t.close(&PEER, 1);
        assert!(removed);
        assert!(!t.is_open(&PEER, 1));
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn close_nonexistent_returns_false() {
        let t = AppStreamTable::new();
        assert!(!t.close(&PEER, 99));
    }

    #[test]
    fn different_stream_ids_are_independent() {
        let t = AppStreamTable::new();
        t.open(PEER, 1, APP, 1);
        t.open(PEER, 2, APP, 2);
        assert_eq!(t.len(), 2);
        t.close(&PEER, 1);
        assert_eq!(t.len(), 1);
        assert!(t.is_open(&PEER, 2));
    }

    // ── 28.5: window exhausted → WINDOW_UPDATE → resumes ─────────────────

    #[test]
    fn window_exhausted_then_updated_resumes() {
        let t = AppStreamTable::new();
        // Open with tiny 10-byte recv window.
        t.open_with_window(PEER, 5, APP, 1, APP_STREAM_INITIAL_WINDOW, 10);

        // Consume all 10 bytes.
        assert!(t.record_data_received(&PEER, 5, 10));

        // One more byte exceeds window → violation.
        assert!(!t.record_data_received(&PEER, 5, 1));

        // Replenish recv window (local app consumed data).
        let new_window = t.replenish_recv_window(&PEER, 5, 20).unwrap();
        assert_eq!(new_window, 20);

        // Now 20 bytes is fine.
        assert!(t.record_data_received(&PEER, 5, 20));
    }

    // ── 28.5 send side: exhausted → apply_window_update → resumes ────────

    #[test]
    fn send_window_exhausted_then_updated_resumes() {
        let t = AppStreamTable::new();
        // Open with tiny 10-byte send window (peer's recv window).
        t.open_with_window(PEER, 6, APP, 1, 10, APP_STREAM_INITIAL_WINDOW);

        // Send 10 bytes — OK.
        assert!(t.record_data_sent(&PEER, 6, 10));

        // Send 1 more — window exhausted.
        assert!(!t.record_data_sent(&PEER, 6, 1));

        // Peer sends APP_WINDOW_UPDATE(increment=100).
        t.apply_window_update(&PEER, 6, 100);

        // Now 100 bytes can be sent.
        assert!(t.record_data_sent(&PEER, 6, 100));
        assert!(!t.record_data_sent(&PEER, 6, 1));
    }

    // ── 28.6: initial 1 MiB window; 2 MiB bulk — second MiB waits ────────

    #[test]
    fn bulk_send_second_mb_blocked_until_window_update() {
        let t = AppStreamTable::new();
        let one_mb: u32 = 1024 * 1024;
        // Open with 1 MiB send window.
        t.open_with_window(PEER, 7, APP, 1, one_mb, one_mb);

        // First 1 MiB goes through.
        assert!(t.record_data_sent(&PEER, 7, one_mb));

        // Second 1 MiB is blocked.
        assert!(!t.record_data_sent(&PEER, 7, one_mb));

        // Peer sends WINDOW_UPDATE for 1 MiB.
        t.apply_window_update(&PEER, 7, one_mb);

        // Now the second MiB proceeds.
        assert!(t.record_data_sent(&PEER, 7, one_mb));
    }

    // ── 96.1: per-peer stream limit ───────────────────────────────────────

    #[test]
    fn per_peer_stream_limit_enforced() {
        let t = AppStreamTable::new();
        // Fill up the per-peer bucket.
        for i in 0..MAX_STREAMS_PER_PEER {
            let result = t.open(PEER, i as u32, APP, 0);
            assert_eq!(result, OpenResult::Opened, "stream {i} should open");
        }
        // Next open for the same peer must be rejected.
        let result = t.open(PEER, MAX_STREAMS_PER_PEER as u32, APP, 0);
        assert_eq!(result, OpenResult::CapacityReached);
        // A *different* peer can still open streams.
        let other_peer = [0x02u8; 32];
        assert_eq!(t.open(other_peer, 0, APP, 0), OpenResult::Opened);
    }

    #[test]
    fn per_peer_counter_decremented_on_close() {
        let t = AppStreamTable::new();
        // Fill bucket, then close one, then re-open.
        for i in 0..MAX_STREAMS_PER_PEER {
            t.open(PEER, i as u32, APP, 0);
        }
        // Over limit.
        assert_eq!(
            t.open(PEER, MAX_STREAMS_PER_PEER as u32, APP, 0),
            OpenResult::CapacityReached
        );
        // Close one.
        t.close(&PEER, 0);
        // Now there's room for one more.
        assert_eq!(
            t.open(PEER, MAX_STREAMS_PER_PEER as u32, APP, 0),
            OpenResult::Opened
        );
    }

    // ── 96.2: send_window cap ─────────────────────────────────────────────

    #[test]
    fn window_update_capped_at_max_send_window() {
        let t = AppStreamTable::new();
        t.open_with_window(PEER, 10, APP, 1, 0, APP_STREAM_INITIAL_WINDOW);
        // Inflate with u32::MAX — must be clamped.
        t.apply_window_update(&PEER, 10, u32::MAX);
        // Verify: sending MAX_STREAM_SEND_WINDOW bytes succeeds.
        assert!(t.record_data_sent(&PEER, 10, MAX_STREAM_SEND_WINDOW));
        // Verify: one more byte fails (window was exactly MAX_STREAM_SEND_WINDOW).
        assert!(!t.record_data_sent(&PEER, 10, 1));
    }

    // ── implicit-close notification on Drop ───────────────────────────

    /// Dropping a stream from the table WITHOUT calling `close` fires the
    /// registered close-notify callback exactly once.
    #[test]
    fn implicit_close_notify_fires_on_drop() {
        let t = AppStreamTable::new();
        t.open(PEER, 42, APP, 1);

        let fired = Arc::new(Mutex::new(false));
        let fired_clone = Arc::clone(&fired);
        let ok = t.set_close_notify(&PEER, 42, move || {
            *fired_clone.lock().unwrap() = true;
        });
        assert!(ok, "set_close_notify should return true for an open stream");

        // Drop the entire table — all streams are removed without explicit close.
        drop(t);

        assert!(
            *fired.lock().unwrap(),
            "implicit-close callback must fire on table drop"
        );
    }

    /// An explicit `close` disarms the notify callback — it must NOT fire.
    #[test]
    fn explicit_close_disarms_notify() {
        let t = AppStreamTable::new();
        t.open(PEER, 43, APP, 1);

        let fired = Arc::new(Mutex::new(false));
        let fired_clone = Arc::clone(&fired);
        t.set_close_notify(&PEER, 43, move || {
            *fired_clone.lock().unwrap() = true;
        });

        // Explicit close: must disarm the notify.
        t.close(&PEER, 43);
        drop(t);

        assert!(
            !*fired.lock().unwrap(),
            "explicit close must disarm the implicit-close callback"
        );
    }

    // ── 204.window already at MAX — no deadlock ───────────────────────────

    /// When `send_window` is already at `MAX_STREAM_SEND_WINDOW`, a subsequent
    /// `apply_window_update` is silently absorbed. The caller can detect this
    /// by observing `send_window == MAX_STREAM_SEND_WINDOW` — meaning it can
    /// send up to that many bytes regardless. No deadlock: the sender is not
    /// blocked waiting for additional credits it will never receive.
    #[test]
    fn window_at_max_absorbed_without_deadlock() {
        let t = AppStreamTable::new();
        // Open with send_window already at MAX.
        t.open_with_window(PEER, 20, APP, 1, MAX_STREAM_SEND_WINDOW, 0);

        // Window is already at MAX; another increment is absorbed.
        t.apply_window_update(&PEER, 20, 1);

        // The sender still has MAX credits available — no deadlock.
        let state = t.get(&PEER, 20).unwrap();
        assert_eq!(
            state.send_window, MAX_STREAM_SEND_WINDOW,
            "send_window should remain at MAX, not deadlock at 0",
        );
    }
}

// ── property-based tests (103.5) ─────────────────────────────────────────────

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    const APP: [u8; 32] = [0xABu8; 32];

    proptest! {
        /// `apply_window_update` with any increment never lets send_window
        /// exceed MAX_STREAM_SEND_WINDOW.
        #[test]
        fn window_update_never_exceeds_max(
            increment in 0u32..=u32::MAX,
            initial_window in 0u32..=MAX_STREAM_SEND_WINDOW,
        ) {
            let peer = [0x11u8; 32];
            let t = AppStreamTable::new();
            t.open_with_window(peer, 1, APP, 7, 0, initial_window);
            t.apply_window_update(&peer, 1, increment);
            let state = t.get(&peer, 1).expect("stream must still be open");
            prop_assert!(
                state.send_window <= MAX_STREAM_SEND_WINDOW,
                "send_window={} exceeds MAX_STREAM_SEND_WINDOW={}",
                state.send_window, MAX_STREAM_SEND_WINDOW
            );
        }

        /// Per-peer stream count never exceeds MAX_STREAMS_PER_PEER regardless
        /// of how many opens are attempted for the same peer.
        #[test]
        fn per_peer_limit_enforced(
            stream_ids in proptest::collection::vec(1u32..=1000, 1..=MAX_STREAMS_PER_PEER * 2),
        ) {
            let peer = [0x22u8; 32];
            let t = AppStreamTable::new();
            for sid in &stream_ids {
                let _ = t.open(peer, *sid, APP, 7);
            }
            // Count DISTINCT stream IDs that are open (dedup the input first).
            let distinct_ids: std::collections::HashSet<u32> = stream_ids.iter().copied().collect();
            let open_count = distinct_ids.iter()
                .filter(|sid| t.is_open(&peer, **sid))
                .count();
            prop_assert!(
                open_count <= MAX_STREAMS_PER_PEER,
                "open streams for peer: {open_count} > MAX_STREAMS_PER_PEER={MAX_STREAMS_PER_PEER}"
            );
        }

        /// close followed by open for the same stream_id increments then
        /// decrements the per-peer count correctly — never goes negative and
        /// cap is maintained.
        #[test]
        fn open_close_open_maintains_counter(
            stream_id in 1u32..=500,
            repeat in 1usize..=20,
        ) {
            let peer = [0x33u8; 32];
            let t = AppStreamTable::new();
            for _ in 0..repeat {
                let _ = t.open(peer, stream_id, APP, 7);
                t.close(&peer, stream_id);
            }
            // After all closes, the stream should be closed.
            prop_assert!(!t.is_open(&peer, stream_id), "stream must be closed after close()");
        }

        /// Total stream count never exceeds MAX_TOTAL_STREAMS.
        #[test]
        fn total_limit_enforced(
            peers in proptest::collection::vec(proptest::array::uniform32(0u8..), 1..=10),
        ) {
            let t = AppStreamTable::new();
            // Try to open many streams across multiple peers.
            for (pi, peer) in peers.iter().enumerate() {
                for sid in 1u32..=((MAX_STREAMS_PER_PEER / peers.len().max(1) + 1) as u32) {
                    let mut p = *peer;
                    p[0] = pi as u8;
                    let _ = t.open(p, sid, APP, 7);
                }
            }
            prop_assert!(
                t.len() <= MAX_TOTAL_STREAMS,
                "total streams {} > MAX_TOTAL_STREAMS={MAX_TOTAL_STREAMS}",
                t.len()
            );
        }
    }
}
