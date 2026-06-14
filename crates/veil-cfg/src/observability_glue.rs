//! Bridge [`Config`] [`veil_observability`] constructors.
//!
//! `NodeLogger::from_config` and `NodeMetrics::from_config` previously lived
//! in `node::observability` but pulled in the cfg layer, breaking the desired
//! Tier-2 layering. Both factories are preserved verbatim here on the cfg
//! side; observability exposes the primitive constructors
//! ([`NodeLogger::from_parts`] and [`NodeMetrics::new`]) that this glue
//! calls.

use std::path::PathBuf;

use veil_observability::{NodeLogger, NodeMetrics};
use veil_types::MetricsConfig;

use super::Config;
use veil_error::{ConfigError, Result};

/// Construct a [`NodeLogger`] honoring the `[global]` log section of `Config`.
pub fn logger_from_config(config: &Config) -> Result<NodeLogger> {
    let log_file: Option<PathBuf> = config.global.log_file.as_ref().map(PathBuf::from);
    NodeLogger::from_parts(
        config.global.logs,
        log_file.as_deref(),
        config.global.log_level,
        config.global.log_format,
    )
    .map_err(|e| ConfigError::ValidationFailed(format!("logger init failed: {e}")))
}

/// If a `[metrics]` section is present, construct [`NodeMetrics`]
/// counters and clone the config back so the runtime can spin up the
/// scrape endpoint.
pub fn metrics_from_config(config: &Config) -> Option<(NodeMetrics, MetricsConfig)> {
    config
        .metrics
        .as_ref()
        .cloned()
        .map(|cfg| (NodeMetrics::new(), cfg))
}
