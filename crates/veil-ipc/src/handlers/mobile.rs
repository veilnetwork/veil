//! Mobile lifecycle и push-envelope handlers.
//!
//! Apps report background-mode tier transitions, network-state changes,
//! и register sealed push envelopes (FCM/APNs tokens) here.  All three
//! handlers degrade gracefully when no sink is wired (desktop builds, or
//! test fixtures with no mobile-runtime integration).

use std::sync::Arc;

use veil_proto::{
    FrameFamily, LocalAppMsg, NetworkChangedPayload, SetMobileBackgroundModePayload,
    SetPushEnvelopePayload, SetPushEnvelopeStatus, SetWakeHmacEnvelopePayload,
    SetWakeHmacEnvelopeStatus,
};

use crate::frame_io::write_frame_wh;
use crate::transport::IpcWriteHalf;
use crate::{MobileEventSink, PushEnvelopeSink};

pub(crate) fn handle_set_mobile_background_mode(
    body: &[u8],
    mobile_event_sink: Option<&Arc<dyn MobileEventSink>>,
) {
    // Drop silently на malformed input — apps shouldn't get к wedge the
    // daemon with bad payloads.
    if let (Ok(req), Some(sink)) = (
        SetMobileBackgroundModePayload::decode(body),
        mobile_event_sink,
    ) {
        sink.set_mobile_background_mode(req.mode);
    }
}

pub(crate) fn handle_network_changed(
    body: &[u8],
    mobile_event_sink: Option<&Arc<dyn MobileEventSink>>,
) {
    if let (Ok(req), Some(sink)) = (NetworkChangedPayload::decode(body), mobile_event_sink) {
        sink.network_changed(req);
    }
}

pub(crate) async fn handle_set_push_envelope(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    push_envelope_sink: Option<&Arc<dyn PushEnvelopeSink>>,
) -> std::io::Result<()> {
    // App registers а sealed FCM/APNs envelope on а rendezvous-publisher
    // entry.  Reply carries OK / NoMatchingRendezvous / EnvelopeTooLarge.
    // Drop malformed silently (no response).
    let Ok(req) = SetPushEnvelopePayload::decode(body) else {
        return Ok(());
    };
    let status = if req.envelope.len() > veil_proto::MAX_PUSH_ENVELOPE_BYTES {
        SetPushEnvelopeStatus::EnvelopeTooLarge
    } else if let Some(sink) = push_envelope_sink {
        if sink.set_rendezvous_push_envelope(req.rendezvous_node_id, req.auth_cookie, req.envelope)
        {
            SetPushEnvelopeStatus::Ok
        } else {
            SetPushEnvelopeStatus::NoMatchingRendezvous
        }
    } else {
        // No sink wired (e.g. desktop deployment without rendezvous
        // publishers).  Tell the app cleanly so it doesn't retry.
        SetPushEnvelopeStatus::NoMatchingRendezvous
    };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::SetPushEnvelopeOk as u16,
        &[status as u8],
    )
    .await
}

/// Epic 489.10 slice 4.3.4 — analog of `handle_set_push_envelope` for
/// the wake-HMAC envelope.  Same response shape (1-byte status).
pub(crate) async fn handle_set_wake_hmac_envelope(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    push_envelope_sink: Option<&Arc<dyn PushEnvelopeSink>>,
) -> std::io::Result<()> {
    let Ok(req) = SetWakeHmacEnvelopePayload::decode(body) else {
        return Ok(());
    };
    let status = if req.envelope.len() > veil_proto::MAX_WAKE_HMAC_ENVELOPE_BYTES {
        SetWakeHmacEnvelopeStatus::EnvelopeTooLarge
    } else if let Some(sink) = push_envelope_sink {
        if sink.set_rendezvous_wake_hmac_envelope(
            req.rendezvous_node_id,
            req.auth_cookie,
            req.envelope,
        ) {
            SetWakeHmacEnvelopeStatus::Ok
        } else {
            SetWakeHmacEnvelopeStatus::NoMatchingRendezvous
        }
    } else {
        SetWakeHmacEnvelopeStatus::NoMatchingRendezvous
    };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::SetWakeHmacEnvelopeOk as u16,
        &[status as u8],
    )
    .await
}
