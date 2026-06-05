//! Veil CLI crate — Phase 5 of veilcore extraction.
//!
//! Hosts the `veil-cli` binary + supporting `cmd/` modules
//! (handlers, output formatters, identity tooling, etc.).

pub mod cmd;

#[cfg(test)]
pub mod test_support;
