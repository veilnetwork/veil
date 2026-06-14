//! Re-export shim for the extracted [`veil-observability`](veil_observability) crate.
//!
//! the crate split moved NodeLogger / NodeMetrics / MetricsSnapshot
//! out to a standalone Tier-3 crate. The cfg-aware `from_config(&Config)`
//! factories were lifted to `crate::cfg::observability_glue`.

pub use veil_observability::*;
