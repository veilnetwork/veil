//! veilcore — thin re-export shim + integration-test crate.
//!
//! After the 5-phase extraction campaign (2026-05-21, see
//! [`docs/en/PLAN_VEILCORE_EXTRACTION.md`]):
//!
//! * Configuration types (Phase 1) → `veil-cfg`
//! * Session state machine (Phase 2) → `veil-session`
//! * Frame dispatcher (Phase 3) → `veil-dispatcher`
//! * Node runtime + admin (Phase 4) → `veil-node-runtime`
//! * CLI binary + cmd helpers (Phase 5) → `veil-cli`
//!
//! veilcore retains:
//! * Re-export shims keeping `crate::node::X` callable paths working
//!   for crates that haven't been swept to direct sibling-crate imports.
//! * Integration test scaffolding (`#[cfg(test)] mod sim`,
//!   `node::session::{chaos_sim, runner_tests, integration_tests}`)
//!   that spans multiple sibling crates and needs the unified `crate::`
//!   namespace to compose them.
//!
//! Lock macros (`lock!`, `rlock!`, `wlock!`) live in veil-util;
//! the duplicated veilcore defs were removed in Phase 6.

pub use veil_cfg as cfg;
pub use veil_cfg::identity_ops;
pub use veil_cfg::identity_policy;
// Phase 5 (veilcore extraction): `cmd` extracted to `veil-cli` crate
// (along with the `veil-cli` binary).  Reachable as `veil_cli::cmd` from
// the binary side; no in-tree consumer of veilcore needs it directly.
pub mod crypto;
pub mod node;
pub mod proto;
pub mod transport;
pub mod util;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
pub mod sim;
