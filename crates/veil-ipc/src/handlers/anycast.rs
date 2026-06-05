//! Anycast и transport-hint handlers.
//!
//! Anycast: service-tag → candidate node-ids resolution.  Apps advertise
//! themselves as serving а tag (`AnycastAdvertise`), withdraw later
//! (`AnycastWithdraw`), и other apps look up по tag (`AnycastResolve`).
//! When no `AnycastService` is wired the resolve returns an empty list и
//! advertise / withdraw silently no-op (feature off gracefully).
//!
//! Transport-hint query: returns the daemon's per-scheme connect-success
//! rates so apps can prefer а transport that's currently working better.
//! When no `TransportHintRegistry` is wired the result is empty.

use std::sync::Arc;

use veil_anycast::AnycastService;
use veil_proto::{
    FrameFamily, LocalAppMsg,
    anycast::{
        AnycastAdvertisePayload, AnycastReportFailurePayload, AnycastResolvePayload,
        AnycastResultPayload, AnycastWithdrawPayload,
    },
    transport_hints::{TransportHintEntry, TransportHintResultPayload},
};
use veil_transport::hint_registry::TransportHintRegistry;

use crate::frame_io::write_frame_wh;
use crate::transport::IpcWriteHalf;

pub(crate) async fn handle_anycast_resolve(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    anycast_service: Option<&Arc<AnycastService>>,
) -> std::io::Result<()> {
    let Ok(req) = AnycastResolvePayload::decode(body) else {
        return Ok(());
    };
    let result = if let Some(svc) = anycast_service {
        svc.resolve(req.service_tag, req.max_results)
    } else {
        AnycastResultPayload {
            service_tag: req.service_tag,
            node_ids: vec![],
        }
    };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::AnycastResult as u16,
        &result.encode(),
    )
    .await
}

pub(crate) fn handle_anycast_advertise(body: &[u8], anycast_service: Option<&Arc<AnycastService>>) {
    if let (Ok(req), Some(svc)) = (AnycastAdvertisePayload::decode(body), anycast_service) {
        svc.advertise(req.service_tag, req.score, req.ttl_secs);
    }
}

pub(crate) fn handle_anycast_withdraw(body: &[u8], anycast_service: Option<&Arc<AnycastService>>) {
    if let (Ok(req), Some(svc)) = (AnycastWithdrawPayload::decode(body), anycast_service) {
        svc.withdraw(req.service_tag);
    }
}

/// Feed an app-reported candidate failure into the local reputation ledger
/// (audit cycle-7 M6). Fire-and-forget — no reply. When no `AnycastService`
/// is wired this silently no-ops (feature off gracefully).
pub(crate) fn handle_anycast_report_failure(
    body: &[u8],
    anycast_service: Option<&Arc<AnycastService>>,
) {
    if let (Ok(req), Some(svc)) = (AnycastReportFailurePayload::decode(body), anycast_service) {
        svc.reputation()
            .record_failure(req.node_id, req.service_tag);
    }
}

pub(crate) async fn handle_transport_hint_query(
    wh: &mut IpcWriteHalf,
    hint_registry: Option<&Arc<TransportHintRegistry>>,
) -> std::io::Result<()> {
    let entries = hint_registry
        .map(|r| {
            r.ranked_snapshot()
                .into_iter()
                .map(|(scheme, c)| TransportHintEntry {
                    scheme,
                    success_pct: c.success_pct(),
                    sample_count: c.total().min(u16::MAX as u32) as u16,
                })
                .collect()
        })
        .unwrap_or_default();
    let payload = TransportHintResultPayload { entries };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::TransportHintResult as u16,
        &payload.encode(),
    )
    .await
}
