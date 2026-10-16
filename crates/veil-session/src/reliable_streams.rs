//! Whole App streams and negotiated self-contained Delivery/direct App records.
//! No stream striping, midstream fallback or remote scheduling class.
use super::*;
use std::collections::HashMap;
use veil_proto::app::{AppClosePayload, AppOpenPayload, AppReceiptPayload, AppWindowUpdatePayload};
use veil_proto::header::HEADER_SIZE;

const MAX_PINS: usize = 1024;

fn delivery_record(h: &FrameHeader) -> bool {
    use veil_proto::family::DeliveryMsg;
    h.family == FrameFamily::Delivery as u8
        && matches!(
            DeliveryMsg::try_from(h.msg_type),
            Ok(DeliveryMsg::Forward
                | DeliveryMsg::DeliveryStatus
                | DeliveryMsg::Transit
                | DeliveryMsg::RecursiveRelay
                | DeliveryMsg::RelayPath)
        )
}

// These messages own no App stream sequence space. The application/ratchet/
// chunk reassembler still validates their bytes through the canonical peer.
fn direct_app_record(h: &FrameHeader, body: &[u8]) -> bool {
    if h.family != FrameFamily::App as u8 || h.stream_id != 0 || h.body_len as usize != body.len() {
        return false;
    }
    match AppMsg::try_from(h.msg_type) {
        Ok(AppMsg::AppSendUnopenable) => body.is_empty(),
        Ok(AppMsg::AppSend | AppMsg::AppSendSealed | AppMsg::AppSendChunk) => {
            // Match AppSendPayload's framing without copying its data or
            // interpreting an application's bytes to choose a transport.
            body.len() >= 72
                && u32::from_be_bytes(body[68..72].try_into().unwrap()) as usize <= body.len() - 72
        }
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Route {
    Canonical,
    Child([u8; 32]),
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Scope {
    app: [u8; 32],
    endpoint: u32,
}
struct Pin {
    scope: Scope,
    route: Route,
    active: bool,
    closing: bool,
}

pub(super) struct ReliableStreams {
    enabled: bool,
    delivery: bool,
    direct_app: bool,
    pins: HashMap<u32, Pin>,
    sink: Arc<dyn crate::dispatcher_sink::DispatcherSink>,
    peer: NodeIdBytes,
}

fn scope(frame: &[u8]) -> Option<(FrameHeader, Scope)> {
    let h = decode_header(frame).ok()?;
    if h.body_len as usize + HEADER_SIZE != frame.len() {
        return None;
    }
    let identity = scope_parts(&h, &frame[HEADER_SIZE..])?;
    Some((h, identity))
}

fn scope_parts(h: &FrameHeader, b: &[u8]) -> Option<Scope> {
    if h.family != FrameFamily::App as u8 {
        return None;
    }
    let valid = match AppMsg::try_from(h.msg_type).ok()? {
        AppMsg::AppOpen => b.len() >= AppOpenPayload::WIRE_SIZE,
        AppMsg::AppClose => b.len() >= AppClosePayload::WIRE_SIZE,
        AppMsg::AppReceipt => b.len() >= AppReceiptPayload::WIRE_SIZE,
        AppMsg::AppData => {
            b.len() >= 48 && u32::from_be_bytes(b[44..48].try_into().ok()?) as usize <= b.len() - 48
        }
        _ => false,
    };
    if !valid {
        return None;
    }
    Some(Scope {
        app: b[..32].try_into().ok()?,
        endpoint: u32::from_be_bytes(b[32..36].try_into().ok()?),
    })
}

fn window_stream(h: &FrameHeader, b: &[u8]) -> Option<u32> {
    if h.family != FrameFamily::App as u8 || h.msg_type != AppMsg::AppWindowUpdate as u16 {
        return None;
    }
    let payload = AppWindowUpdatePayload::decode(b).ok()?;
    if h.stream_id != 0 && h.stream_id != payload.stream_id {
        return None;
    }
    Some(payload.stream_id)
}

impl ReliableStreams {
    pub(super) fn new(
        enabled: bool,
        sink: Arc<dyn crate::dispatcher_sink::DispatcherSink>,
        peer: NodeIdBytes,
    ) -> Self {
        Self {
            enabled,
            delivery: false,
            direct_app: false,
            pins: HashMap::new(),
            sink,
            peer,
        }
    }

    pub(super) fn with_delivery(mut self, negotiated: bool) -> Self {
        self.delivery = self.enabled && negotiated;
        self
    }

    pub(super) fn with_direct_app(mut self, negotiated: bool) -> Self {
        self.direct_app = self.enabled && negotiated;
        self
    }

    pub(super) fn route_with_local_class(
        &self,
        frame: &[u8],
        ready: Option<[u8; 32]>,
        local_priority: u8,
    ) -> Route {
        // Only the originating local outbox classification can retain network
        // control on the parent. No incoming priority or media role is trusted.
        if local_priority != crate::LOCAL_NETWORK_CONTROL_LANE
            && let Ok(h) = decode_header(frame)
            && ((self.delivery && delivery_record(&h))
                || (self.direct_app && direct_app_record(&h, &frame[HEADER_SIZE..])))
            // Older peers may send Delivery bodies larger than this child's
            // fixed record limit. Keep their existing parent carrier rather
            // than retiring a healthy child and dropping the envelope.
            && crate::reliable_frames::valid_plain(frame)
            // Expiring loss-tolerant forwards retain their existing datagram
            // or canonical fallback lifecycle; never queue them as reliable data.
            && decode_realtime_lane_frame(frame).is_none()
        {
            return ready.map_or(Route::Canonical, Route::Child);
        }
        self.route(frame, ready)
    }
    pub(super) fn route(&self, frame: &[u8], ready: Option<[u8; 32]>) -> Route {
        if !self.enabled {
            return Route::Canonical;
        }
        if let Ok(h) = decode_header(frame)
            && h.family == FrameFamily::App as u8
            && h.msg_type == AppMsg::AppWindowUpdate as u16
        {
            return window_stream(&h, &frame[HEADER_SIZE..]).map_or(Route::Failed, |stream| {
                self.pins
                    .get(&stream)
                    .map_or(Route::Canonical, |pin| pin.route)
            });
        }
        let Some((h, identity)) = scope(frame) else {
            return Route::Canonical;
        };
        if let Some(pin) = self.pins.get(&h.stream_id) {
            return if pin.scope == identity {
                pin.route
            } else {
                Route::Failed
            };
        }
        if h.msg_type == AppMsg::AppOpen as u16 && self.pins.len() < MAX_PINS {
            ready.map_or(Route::Canonical, Route::Child)
        } else {
            Route::Canonical
        }
    }
    pub(super) fn admitted(&mut self, frame: &[u8], route: Route) {
        if !self.enabled {
            return;
        }
        let Some((h, identity)) = scope(frame) else {
            return;
        };
        if h.msg_type == AppMsg::AppOpen as u16 && self.pins.len() < MAX_PINS {
            self.pins.entry(h.stream_id).or_insert(Pin {
                scope: identity,
                route,
                active: true,
                closing: false,
            });
        }
        if h.msg_type == AppMsg::AppClose as u16
            && let Some(pin) = self.pins.get_mut(&h.stream_id)
        {
            pin.closing = true;
        }
    }
    pub(super) fn incoming(&mut self, frame: &[u8], route: Route) -> Result<(), &'static str> {
        let h = decode_header(frame).map_err(|_| "bad reliable frame header")?;
        if h.body_len as usize + HEADER_SIZE != frame.len() {
            return Err("bad reliable frame length");
        }
        self.incoming_parts(&h, &frame[HEADER_SIZE..], route)
    }
    pub(super) fn incoming_parts(
        &mut self,
        h: &FrameHeader,
        body: &[u8],
        route: Route,
    ) -> Result<(), &'static str> {
        if !self.enabled && route == Route::Canonical {
            return Ok(());
        }
        // These records carry their own message/chunk identities; they do not
        // own App stream pins. The dispatcher still validates the full payload,
        // signatures, replay state and peer budgets using the canonical peer.
        if (self.delivery && delivery_record(h)) || (self.direct_app && direct_app_record(h, body))
        {
            return Ok(());
        }
        if h.family == FrameFamily::App as u8 && h.msg_type == AppMsg::AppWindowUpdate as u16 {
            let Some(stream) = window_stream(h, body) else {
                return Err("bad App window stream identity");
            };
            return match self.pins.get(&stream) {
                Some(pin) if pin.route == route => Ok(()),
                None if route == Route::Canonical => Ok(()),
                _ => Err("App window carrier mismatch"),
            };
        }
        let Some(identity) = scope_parts(h, body) else {
            return if route == Route::Canonical {
                Ok(())
            } else {
                Err("ineligible reliable child frame")
            };
        };
        if let Some(pin) = self.pins.get(&h.stream_id) {
            if pin.scope != identity || pin.route != route {
                return Err("App stream carrier or scope mismatch");
            }
        } else if h.msg_type == AppMsg::AppOpen as u16 {
            if self.pins.len() >= MAX_PINS {
                return if route == Route::Canonical {
                    Ok(())
                } else {
                    Err("reliable stream ownership capacity reached")
                };
            }
            self.pins.insert(
                h.stream_id,
                Pin {
                    scope: identity,
                    route,
                    active: true,
                    closing: false,
                },
            );
        } else if route != Route::Canonical {
            return Err("reliable child frame without AppOpen");
        }
        if h.msg_type == AppMsg::AppReceipt as u16
            && let Some(pin) = self.pins.get_mut(&h.stream_id)
            && pin.closing
            && AppReceiptPayload::decode(body)
                .is_ok_and(|p| p.status == veil_proto::app::receipt_status::ACCEPTED)
        {
            pin.active = false;
        }
        Ok(())
    }
    pub(super) fn dispatched(&mut self, h: &FrameHeader) {
        if h.msg_type == AppMsg::AppClose as u16
            && let Some(pin) = self.pins.get_mut(&h.stream_id)
        {
            pin.active = false;
        }
    }
    pub(super) fn fail_child(&mut self, child: [u8; 32]) {
        for (stream, pin) in &mut self.pins {
            if pin.route == Route::Child(child) {
                // Always retire waiters, even when an earlier valid close
                // already notified the endpoint. Only the notification is once.
                self.sink.abort_app_stream(
                    self.peer,
                    *stream,
                    pin.scope.app,
                    pin.scope.endpoint,
                    pin.active,
                );
                pin.active = false;
                pin.route = Route::Failed;
            }
        }
    }
    pub(super) fn reconcile(&mut self, ready: Option<[u8; 32]>) {
        let retired: Vec<_> = self
            .pins
            .values()
            .filter_map(|pin| match pin.route {
                Route::Child(child) if Some(child) != ready => Some(child),
                _ => None,
            })
            .collect();
        for child in retired {
            self.fail_child(child);
        }
    }
}

impl Drop for ReliableStreams {
    fn drop(&mut self) {
        self.reconcile(None);
    }
}

#[cfg(test)]
#[path = "reliable_streams_tests.rs"]
mod tests;

/// Responses stay plaintext and FIFO until the child's writer has credit.
/// RX keeps draining while a response waits, so simultaneous duplex writes
/// cannot stop both readers behind a full TX actor. The bounds limit a peer
/// flooding more outstanding Open/Data requests than this endpoint can serve.
pub(super) struct Replies {
    queue: std::collections::VecDeque<([u8; 32], Vec<u8>)>,
    bytes: usize,
}
impl Replies {
    pub(super) fn new() -> Self {
        Self {
            queue: Default::default(),
            bytes: 0,
        }
    }
    pub(super) fn push(&mut self, child: [u8; 32], frame: Vec<u8>) -> Result<(), &'static str> {
        if self.queue.len() >= 512 || frame.len() > 65536usize.saturating_sub(self.bytes) {
            return Err("reliable response capacity exceeded");
        }
        self.bytes += frame.len();
        self.queue.push_back((child, frame));
        Ok(())
    }
    pub(super) fn front(&self) -> Option<([u8; 32], &[u8])> {
        self.queue
            .front()
            .map(|(id, frame)| (*id, frame.as_slice()))
    }
    pub(super) fn try_flush(
        &mut self,
        handle: &crate::reliable_frames::ReliableFrameHandle,
        allow: impl FnOnce(usize) -> bool,
    ) -> Result<Option<(Vec<u8>, usize)>, crate::reliable_frames::FrameReservationError> {
        use crate::reliable_frames::{FrameAdmissionError, FrameReservationError};
        let Some((_, frame)) = self.front() else {
            return Ok(None);
        };
        let reservation = handle.try_reserve(frame)?;
        let bytes = frame.len() + veil_crypto::session_cipher::AEAD_OVERHEAD + 2;
        if !allow(bytes) {
            return Err(FrameReservationError::Full);
        }
        let envelope = crate::frame_outbox::FrameEnvelope::from((
            veil_proto::priority::INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(frame.to_vec()),
        ));
        reservation.commit(envelope).map_err(|error| match error {
            FrameAdmissionError::Full(_) => FrameReservationError::Full,
            FrameAdmissionError::Closed(_) => FrameReservationError::Closed,
            FrameAdmissionError::Invalid(_) => FrameReservationError::Invalid,
        })?;
        Ok(Some((self.pop().expect("committed reply"), bytes)))
    }
    pub(super) fn pop(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front().map(|(_, frame)| {
            self.bytes -= frame.len();
            frame
        })
    }
    pub(super) fn reconcile(&mut self, ready: Option<[u8; 32]>) {
        self.queue.retain(|(id, _)| Some(*id) == ready);
        self.bytes = self.queue.iter().map(|(_, f)| f.len()).sum();
    }
}
