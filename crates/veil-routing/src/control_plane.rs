//! Control-plane service — handles ROUTE_PROBE / ROUTE_REPLY.
//!
//! `ControlPlaneService` manages RTT measurements used by
//! `NeighborScorer` и `RouteCache`.  Sits behind а `FrameDispatcher`-
//! field в production; isolated here as а dispatcher-agnostic service.
//!
//! Phase 3 prep (veilcore extraction): moved here от
//! `veilcore::node::control` so dispatcher can move к а sibling crate.
//! Lives в veil-routing because it uses veil-routing's `RttTable`
//! и `PeerReportedRtt` types.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use veil_proto::control::{RouteProbePayload, RouteReplyPayload};
use veil_util::lock;

use crate::probe::{PeerReportedRtt, RttTable};

/// Shared control-plane state.  Clone-cheap: inner state behind `Arc<Mutex>`.
#[derive(Clone, Debug)]
pub struct ControlPlaneService {
    rtt_table: Arc<Mutex<RttTable>>,
}

impl ControlPlaneService {
    /// Construct с а private `RttTable`.
    ///
    /// Used в tests + initial dispatcher-construction; production code uses
    /// [`Self::with_rtt_table`] so the table is shared across subsystems.
    pub fn new(rtt_max_age: Duration) -> Self {
        Self {
            rtt_table: Arc::new(Mutex::new(RttTable::new(rtt_max_age))),
        }
    }

    /// Create а service що shares the provided `rtt_table`.  Use this when
    /// multiple subsystems (DHT, routing, scoring) need к read RTT data що
    /// is updated by the control plane.
    pub fn with_rtt_table(rtt_table: Arc<Mutex<RttTable>>) -> Self {
        Self { rtt_table }
    }

    /// Shared reference к the RTT table — allows other services к observe
    /// RTT measurements.
    pub fn rtt_table(&self) -> Arc<Mutex<RttTable>> {
        Arc::clone(&self.rtt_table)
    }

    /// Build а `RouteReplyPayload` що echoes the probe back к the sender.
    ///
    /// `rtt_ms` is set к `0` here (the *receiver* doesn't know the one-way
    /// latency yet — the *sender* computes it on receipt).
    pub fn handle_probe(&self, payload: &RouteProbePayload) -> RouteReplyPayload {
        RouteReplyPayload {
            probe_id: payload.probe_id,
            timestamp_ms: payload.timestamp_ms,
            rtt_ms: 0,
            congestion: 0,
        }
    }

    /// Record the RTT от an incoming `RouteReplyPayload` into `RttTable`.
    pub fn handle_reply(&self, peer_id: &[u8; 32], payload: &RouteReplyPayload) {
        let rtt = PeerReportedRtt::from_raw_ms(payload.rtt_ms);
        lock!(self.rtt_table).record(*peer_id, rtt, payload.congestion);
    }

    /// Read the latest smoothed RTT (ms) для а peer.  Originally test-
    /// only; promoted к public для cross-crate test access после the
    /// Phase 3 move.
    pub fn rtt_ms(&self, peer_id: &[u8; 32]) -> Option<u32> {
        lock!(self.rtt_table).get(peer_id).map(|p| p.rtt_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> ControlPlaneService {
        ControlPlaneService::new(Duration::from_secs(60))
    }

    #[test]
    fn probe_echo_carries_probe_id_and_timestamp() {
        let svc = svc();
        let probe = RouteProbePayload {
            probe_id: 0xABCD,
            timestamp_ms: 999_000,
        };
        let reply = svc.handle_probe(&probe);
        assert_eq!(reply.probe_id, probe.probe_id);
        assert_eq!(reply.timestamp_ms, probe.timestamp_ms);
    }

    #[test]
    fn reply_stores_rtt_in_table() {
        let svc = svc();
        let peer = [0x01u8; 32];
        let reply = RouteReplyPayload {
            probe_id: 1,
            timestamp_ms: 0,
            rtt_ms: 42,
            congestion: 0,
        };
        svc.handle_reply(&peer, &reply);
        assert_eq!(svc.rtt_ms(&peer), Some(42));
    }

    #[test]
    fn unknown_peer_returns_none() {
        let svc = svc();
        assert_eq!(svc.rtt_ms(&[0x99u8; 32]), None);
    }
}
