//! Re-export shim for the extracted [`veil_routing::control_plane`] module.
//!
//! Phase 3 prep (veilcore extraction): `ControlPlaneService` moved к
//! `veil-routing::control_plane` так dispatcher can move к а sibling
//! crate without veilcore-private deps.  Existing call sites use
//! `crate::node::control::ControlPlaneService` — preserved via re-export.

pub use veil_routing::control_plane::*;
