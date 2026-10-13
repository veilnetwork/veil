//! OVL1 session state machine crate — Phase 2 of veilcore extraction.
//!
//! Hosts the post-handshake frame loop ([`runner::SessionRunner`]) and
//! per-session typed state modules previously living in
//! `veilcore/src/node/session/`.
//!
//! ## Test-fixture strategy
//!
//! Integration tests (`runner_tests.rs` + `chaos_sim.rs`) stay in
//! veilcore because they construct a real `FrameDispatcher`
//! (veilcore-private).  This crate hosts only production code;
//! callers reach it through the trait abstractions
//! ([`dispatcher_sink::DispatcherSink`], [`handshake::LocalHandshakeIdentity`]).
//!
//! See [`docs/en/PLAN_VEILCORE_EXTRACTION.md`] for the full plan.

pub mod backpressure_signal;
pub mod battery_adjusted_keepalive;
pub mod cover_traffic;
mod datagram_activity;
mod datagram_flows;
pub mod dispatcher_sink;
pub mod frame_diag;
pub mod frame_outbox;
mod local_datagram_status;
mod local_source_activity;
pub mod local_lossy_trace;
pub use local_datagram_status::DatagramTransportLease;
pub use local_datagram_status::LocalDatagramChannelState;
pub mod fsm;
pub mod glue;
pub mod handoff;
pub mod handshake;
pub mod hot_standby;
pub mod keepalive_emit;
pub mod manager;
pub mod mlkem_rekey_context;
pub mod once_trigger;
pub mod outbound_batch_coalescer;
pub mod outbox;
pub mod parallel_binding;
pub mod pending_response_table;
pub mod priority_queue;
pub mod realtime_datagram;
pub mod rekey_context;
pub mod rekey_rx_grace_buffer;
pub mod reliable_frames;
pub mod rendezvous;
mod resume_capabilities;
pub mod rotation_deadline;
pub mod rt_trace;
pub mod runner;
pub mod rx_body_budget;
pub mod session_alias_guard;
pub mod ticket;
pub mod timers;
pub mod tx_registry;
pub mod warm_probe;
pub mod write_error_tracker;

// `SessionFsm` is a REFERENCE / validation handshake state machine: it is
// exercised by this crate's own tests and by veilcore's cross-crate
// integration tests (which drive a real two-node handshake against it), but it
// is NOT the production driver. The live path is the straight-line
// `handshake::perform_ovl1_handshake`, which enforces phase ordering via the
// transcript hash; wiring the FSM into it as a second barrier is a documented
// deferral (see `handshake.rs`). Kept public so downstream test/sim code can
// reuse the model.
pub use frame_outbox::{FrameOutbox, FrameSender};
pub use fsm::{SessionFsm, SessionHandshakeData, SessionPhase};
pub use manager::{RemoteRole, SessionEntry, SessionId, SessionRegistry};
pub use outbox::SessionOutbox;
pub use priority_queue::{
    DEFAULT_WEIGHTS, LOCAL_NETWORK_CONTROL_LANE, LOCAL_SIGNALING_LANE, PriorityQueue,
};
pub use tx_registry::{PriorityFrame, SendToError, SessionTxRegistry};
