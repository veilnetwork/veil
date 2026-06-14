//! Integration tests for the session-runner state machine.
//!
//! Extracted from veilcore in audit batch 2026-05-21 Phase D14:
//! `runner_tests.rs` was 5568 LoC coupled to veilcore-private path
//! `crate::node::dispatcher::make_test_dispatcher` plus `use super::*;`
//! wildcards into the veilcore session module shim.  Moving it here
//! pins the tests to the published surface of veil-session,
//! veil-dispatcher, veil-proto, veil-transport, veil-cfg
//! and veil-node-runtime — same coupling profile as any downstream
//! integration test would have.
//!
//! The library itself is empty; the suite lives entirely under `tests/`.
