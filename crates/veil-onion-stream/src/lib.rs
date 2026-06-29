//! # veil-onion-stream — a reliable byte-stream over a lossy anonymous cell channel
//!
//! veil's onion circuits move FIXED-SIZE cells (≤ 382 B payload each) that are
//! ORDERED + anti-replayed but **NOT reliable**: a relay whose outbound TX queue
//! is full silently DROPS the cell (`veil-session` `tx_registry`, `try_send`).
//! The IPC stream FSM, by contrast, does only window flow-control and delegates
//! reliability to its transport (TCP). Put those together and a stream pushed
//! over a circuit corrupts the instant one cell is lost. So an anonymous,
//! reliable byte-stream needs its OWN end-to-end reliability + congestion
//! control — which is what this crate is.
//!
//! This is a **sans-IO** core (à la quinn/quiche): a deterministic state machine
//! ([`StreamEngine`]) that is driven entirely by
//! - [`StreamEngine::write`] — app bytes to send,
//! - [`StreamEngine::on_cell`] — an inbound cell decoded off the circuit,
//! - [`StreamEngine::on_timeout`] — a monotonic-clock tick (millis, injected),
//! - [`StreamEngine::poll_transmit`] — drains cells to PUT on the circuit,
//! - [`StreamEngine::read`] — delivered, in-order app bytes.
//!
//! No sockets, no tokio, no wall clock — every effect is a value in or out. That
//! makes loss / reorder / duplication / congestion testable byte-for-byte and
//! deterministic (see the `sim` test harness). An async driver that pumps this
//! over a real circuit + tokio timers is a thin layer above (Phase 1.5 / 2).
//!
//! ## Wire (inside one ≤382 B circuit cell) — see [`wire`]
//! Every frame is `[ver u8][type u8][stream_id u32][…]`. Types: `SYN`, `SYN_ACK`,
//! `DATA`, `ACK`, `FIN`, `RST`. Multi-byte fields big-endian. A full-duplex
//! stream carries a `DATA`/`FIN` byte-sequence in EACH direction with its own
//! ISN + window; `ACK` (cumulative + up to [`wire::MAX_SACKS`] selective ranges)
//! and a piggy-backed receive window flow the other way.
//!
//! ## Reliability + congestion control (TCP NewReno-shaped, well-trodden)
//! - **Byte sequence numbers** (`u32`, TCP-style **modular** comparison via
//!   [`seq`] helpers) → supports streams > 4 GiB by wraparound.
//! - **ARQ**: the sender retains unacked segments; the receiver returns a
//!   cumulative ACK + SACK ranges; retransmit on **RTO** (Jacobson/Karels RTT
//!   estimate) or **3 duplicate ACKs** (fast retransmit / fast recovery).
//! - **Congestion control (AIMD)**: slow-start (`cwnd += MSS` per good ACK until
//!   `ssthresh`), congestion-avoidance (`cwnd += MSS²/cwnd` per ACK), and on loss
//!   `ssthresh = cwnd/2`, `cwnd = ssthresh` (fast recovery) or `1·MSS` (RTO). This
//!   is the fix for the original "blast 6:1 → 80 % tx_queue drop": the sender now
//!   clocks itself to the bottleneck relay's drain rate instead of overrunning it.
//! - **Flow control**: the receiver advertises a window (`rwnd`); the sender never
//!   has more than `min(cwnd, rwnd)` bytes in flight.
//!
//! ## Resumability (why `FIN` ≠ `RST`)
//! A clean end is `FIN` → [`Event::PeerFinished`] → the reader sees EOF. An
//! aborted circuit / dead peer / local error is `RST` (or an idle-timeout the
//! driver maps to one) → [`Event::Reset`]. The application distinguishes "done"
//! from "interrupted": on the latter it reopens a stream and its own handshake
//! asks the sender for only the byte ranges it is still missing (the file layer
//! already hash-verifies + persists pieces). The transport stays a dumb reliable
//! pipe; *which* bytes to resume is the app's call.

#![forbid(unsafe_code)]

pub mod driver;
pub mod engine;
pub mod mux;
pub mod seq;
pub mod wire;

pub use driver::{CellDuplex, End, OnionStream};
pub use engine::{Config, Event, StreamEngine};
pub use mux::{CellSender, Peer, StreamMux};
pub use wire::{Frame, MAX_CELL, MSS, SackRange};
