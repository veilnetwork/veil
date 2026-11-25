use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Clone, Copy)]
pub(crate) enum DropReason {
    EgressInvalidIp,
    EgressNoRoute,
    EgressAdmission,
    EgressOversize,
    EgressQueuedRoute,
    EgressIpcFrame,
    IngressUnauthenticatedFrame,
    IngressAppCertFrame,
    IngressOversize,
    IngressExpired,
    IngressUnauthorized,
    IngressBadSource,
    IngressTunWrite,
}

const REASONS: [(DropReason, &str); 13] = [
    (DropReason::EgressInvalidIp, "egress_invalid_ip"),
    (DropReason::EgressNoRoute, "egress_no_active_route"),
    (DropReason::EgressAdmission, "egress_admission_unavailable"),
    (DropReason::EgressOversize, "egress_oversize"),
    (
        DropReason::EgressQueuedRoute,
        "egress_queued_route_unavailable",
    ),
    (DropReason::EgressIpcFrame, "egress_ipc_submit_error_frames"),
    (
        DropReason::IngressUnauthenticatedFrame,
        "ingress_unauthenticated_frames",
    ),
    (
        DropReason::IngressAppCertFrame,
        "ingress_app_cert_denied_frames",
    ),
    (DropReason::IngressOversize, "ingress_oversize"),
    (DropReason::IngressExpired, "ingress_expired_admission"),
    (DropReason::IngressUnauthorized, "ingress_unauthorized"),
    (
        DropReason::IngressBadSource,
        "ingress_invalid_or_mismatched_source",
    ),
    (DropReason::IngressTunWrite, "ingress_tun_write_error"),
];

#[derive(Default)]
pub(crate) struct PacketDrops {
    counts: [AtomicU64; REASONS.len()],
}

impl PacketDrops {
    pub(crate) fn record(&self, reason: DropReason, count: u64) {
        self.counts[reason as usize].fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) async fn report_every(&self, period: Duration) {
        loop {
            tokio::time::sleep(period).await;
            for (reason, label) in REASONS {
                let count = self.counts[reason as usize].swap(0, Ordering::Relaxed);
                if count > 0 {
                    tracing::info!(reason = label, count, "ogate packet drops");
                }
            }
        }
    }
}

pub(crate) fn record_one(counters: Option<&PacketDrops>, reason: DropReason) {
    if let Some(counters) = counters {
        counters.record(reason, 1);
    }
}
