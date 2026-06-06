//! Per-message IPC handlers.
//!
//! `handle_ipc_client` in server.rs dispatches each decoded frame to one of
//! these handlers.  Splitting them out of server.rs keeps that file focused
//! on connection lifecycle (accept, handshake, dispatch loop) while each
//! handler owns its own decode → validate → respond pipeline.

pub(crate) mod anycast;
pub(crate) mod bind;
pub(crate) mod mailbox;
pub(crate) mod mobile;
pub(crate) mod outbox;
pub(crate) mod queries;
pub(crate) mod send;
pub(crate) mod stream;
