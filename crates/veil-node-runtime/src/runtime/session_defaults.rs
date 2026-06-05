//! H10 stage-B (4/N) decomposition: session-defaults bundle
//! extracted into а dedicated [`Arc<SessionDefaults>`].
//!
//! ## Why а dedicated struct
//!
//! Pre-stage-B, sixteen pure-value config knobs (Duration / u32 /
//! u64 / usize / [u32; 4]) were duplicated across three propagation
//! structs:
//!
//! - `NodeServices` carried 15 (всё кроме `gateway_lease_ttl`).
//! - `SessionRuntimeContext` carried 11 (subset used at session-
//!   admit time).
//! - `NodeRuntime` carried all 16.
//!
//! Each struct definition listed the fields в slightly different
//! orders; each `access()` / listener-spawn / inbound-context site
//! copied them individually (15 lines of `field: self.field,` per
//! boundary).  Bundle-then-Arc collapses к one field в each struct.
//!
//! ## Why Arc-shared
//!
//! These fields are read-only after construction (configuration
//! semantics — reload rebuilds the entire `NodeRuntime`, не mutates
//! the bundle). `Arc<SessionDefaults>` matches the established
//! `Arc<MailboxState>` / `Arc<MobileState>` / `Arc<RoutingState>` /
//! `Arc<ResumptionState>` / `Arc<HandoffRuntime>` pattern: cheap
//! Arc-clone at boundary, zero locking, snapshot semantics free.
//!
//! Plain `Clone` would also work (the struct is ~100 bytes of
//! Copy values), но then every `inbound_context.clone()` would
//! duplicate а 100-byte payload вместо incrementing one atomic
//! counter.
//!
//! ## Migration surface
//!
//! Every callsite reading `self.keepalive_interval` /
//! `self.idle_timeout` / etc. now reads `self.defaults.<field>`.
//! Boundary clones collapse от 15-16 `field: self.field,` lines
//! to one `defaults: Arc::clone(&self.defaults),`.
//!
//! `SessionRunner` keeps its own copies of these knobs as
//! sibling fields (they are unbundled at session-spawn time для
//! ergonomic intra-runner reads) — `SessionDefaults` does not
//! propagate inside the runner.

use std::sync::Arc;
use std::time::Duration;

/// Session-defaults bundle owned by [`crate::node::NodeRuntime`]
/// и cloned (Arc) into `NodeServices` / `SessionRuntimeContext`
/// at boundary builds. All fields are pure value types (Duration /
/// u32 / u64 / usize / [u32; 4]) — no Mutex, no Arc inside.
pub struct SessionDefaults {
    /// keepalive send interval (0 = disabled).
    pub keepalive_interval: Duration,
    /// session idle timeout.
    pub idle_timeout: Duration,
    /// max in-flight RPC response slots per session.
    pub max_pending_responses: usize,
    /// TTL for in-flight RPC response slots.
    pub pending_response_ttl: Duration,
    /// per-session frame body size limit (bytes).
    pub max_frame_body: u32,
    /// Bytes-threshold for triggering а session rekey.
    pub rekey_bytes_threshold: u64,
    /// Time-threshold (seconds) for triggering а session rekey.
    pub rekey_time_threshold_secs: u64,
    /// WRR weights для the 4 traffic classes `[RT, IN, BK, BG]`.
    pub qos_weights: [u32; 4],
    /// max concurrent OVL1 sessions.
    pub max_concurrent: usize,
    /// max inbound sessions per source IP.
    pub max_per_ip: usize,
    /// max inbound sessions per /24 subnet.
    pub max_per_subnet: usize,
    // audit cleanup: field `gateway_lease_ttl` removed.
    // It was redundant — `GatewayService::new_with_lease_ttl(...)` is
    // already constructed at startup with `config.gateway.attachment_lease_ttl_secs`
    // (see `runtime/mod.rs:898` и `runtime/lifecycle.rs:409`), and the
    // eviction task does not consult `SessionDefaults` for TTL. Keeping
    // а duplicate field with `#[allow(dead_code)]` masked the fact that
    // it never wired into anything.
    /// interval at which а leaf node sends `SessionMsg::Keepalive`
    /// to its gateway.
    pub gateway_keepalive_interval: Duration,
    /// minimum outbound reconnect back-off.
    pub reconnect_backoff_min: Duration,
    /// maximum outbound reconnect back-off.
    pub reconnect_backoff_max: Duration,
    /// after this many consecutive reconnect failures the
    /// per-attempt log is downgraded from WARN к DEBUG. 0 disables
    /// the quiet mode.
    pub reconnect_quiet_after_failures: u32,
}

impl SessionDefaults {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keepalive_interval: Duration,
        idle_timeout: Duration,
        max_pending_responses: usize,
        pending_response_ttl: Duration,
        max_frame_body: u32,
        rekey_bytes_threshold: u64,
        rekey_time_threshold_secs: u64,
        qos_weights: [u32; 4],
        max_concurrent: usize,
        max_per_ip: usize,
        max_per_subnet: usize,
        gateway_keepalive_interval: Duration,
        reconnect_backoff_min: Duration,
        reconnect_backoff_max: Duration,
        reconnect_quiet_after_failures: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            keepalive_interval,
            idle_timeout,
            max_pending_responses,
            pending_response_ttl,
            max_frame_body,
            rekey_bytes_threshold,
            rekey_time_threshold_secs,
            qos_weights,
            max_concurrent,
            max_per_ip,
            max_per_subnet,
            gateway_keepalive_interval,
            reconnect_backoff_min,
            reconnect_backoff_max,
            reconnect_quiet_after_failures,
        })
    }
}
