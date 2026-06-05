//! OVL1 session state machine crate — Phase 2 of veilcore extraction.
//!
//! Hosts the post-handshake frame loop ([`runner::SessionRunner`]) и
//! per-session typed state modules previously living в
//! `veilcore/src/node/session/`.
//!
//! ## Test-fixture strategy
//!
//! Integration tests (`runner_tests.rs` + `chaos_sim.rs`) stay в
//! veilcore because they construct а real `FrameDispatcher`
//! (veilcore-private).  This crate hosts only production code;
//! callers reach it through the trait abstractions
//! ([`dispatcher_sink::DispatcherSink`], [`handshake::LocalHandshakeIdentity`]).
//!
//! See [`docs/en/PLAN_VEILCORE_EXTRACTION.md`] для the full plan.

pub mod backpressure_signal;
pub mod battery_adjusted_keepalive;
pub mod cover_traffic;
pub mod dispatcher_sink;
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
pub mod pending_response_table;
pub mod priority_queue;
pub mod rekey_context;
pub mod rekey_rx_grace_buffer;
pub mod rendezvous;
pub mod rotation_deadline;
pub mod runner;
pub mod session_alias_guard;
pub mod ticket;
pub mod timers;
pub mod tx_registry;
pub mod warm_probe;
pub mod write_error_tracker;

pub use fsm::{SessionFsm, SessionHandshakeData, SessionPhase};
pub use manager::{RemoteRole, SessionEntry, SessionId, SessionRegistry};
pub use outbox::SessionOutbox;
pub use priority_queue::{DEFAULT_WEIGHTS, PriorityQueue};
pub use tx_registry::{PriorityFrame, SessionTxRegistry};
