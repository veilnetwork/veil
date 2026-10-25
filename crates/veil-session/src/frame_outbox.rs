//! Independent local session ingress queues. A full ordinary outbox must not
//! prevent a local latency-sensitive producer from reaching the scheduler.
//! These lanes are process-local; they add no field to an OVL1 wire frame.
//! Relayed user data always uses the ordinary lane, regardless of wire hints.

use std::{
    task::{Context, Poll},
    time::Instant,
};

use tokio::sync::mpsc;

use crate::PriorityFrame;

pub const RESERVED_QUEUE_DEPTH: usize = 64;
/// Keep only a small lookahead of already sealed local DATA. At the pressure
/// rate, 64 packet-sized frames can wait about 14 seconds here, on top of the
/// producer's admission wait. That exhausted ordinary Forward's 30-second
/// lifetime before a relay could forward the last fragments. Backpressure
/// belongs before publishing, not in a large buffer of aging wire envelopes.
/// This does not change the independent primary or ordinary transit budgets.
pub const RELIABLE_SOURCE_QUEUE_DEPTH: usize = 4;

/// Queue admission and synchronous frame construction have different failures.
#[derive(Debug, PartialEq, Eq)]
pub enum BuildSendError<E> {
    Queue(crate::SendToError),
    Build(E),
    LengthMismatch,
}
// One packet-sized frame uses one credit. Compatibility frames use several,
// and an oversized frame owns the whole lookahead rather than sitting behind
// three other huge envelopes. Capping its cost permits eventual admission.
const RELIABLE_SOURCE_CREDIT_BYTES: usize = 1536;
fn reliable_source_cost(bytes: usize) -> u32 {
    bytes
        .div_ceil(RELIABLE_SOURCE_CREDIT_BYTES)
        .clamp(1, RELIABLE_SOURCE_QUEUE_DEPTH) as u32
}
const MAX_RESERVED_BURST: usize = 8;
const MAX_CONTROL_BURST: usize = 4;
pub(crate) const NETWORK_CONTROL_QUEUE_DEPTH: usize = 64;

/// Local transport metadata follows a frame through the ordinary queue. It
/// never changes the wire header, priority, FIFO position or queue budget.
#[derive(Debug)]
pub struct FrameEnvelope {
    pub(crate) local_work: Option<veil_types::local_lossy_work::LocalLossyCell>,
    pub frame: PriorityFrame,
    pub carrier: Option<veil_anonymity::circuit_carrier::Carrier>,
    /// Process-local admission time. Loss tolerance is classified by the
    /// runner, but residence in this upstream queue must count toward its age.
    /// Never serialized, and never derived from a peer's clock or wire hint.
    pub(crate) queued_at: Instant,
    /// Trusted local producer deadline; never serialized or accepted from peers.
    pub(crate) expires_at: Option<Instant>,
    /// Endpoint-only reliable admission. Held through the scheduler, never
    /// serialized or inferred from a remote frame's priority or contents.
    pub(crate) reliable_credit: Option<tokio::sync::OwnedSemaphorePermit>,
    pub(crate) signaling_pending: Option<crate::local_source_activity::PendingSignaling>,
}

impl From<PriorityFrame> for FrameEnvelope {
    fn from(frame: PriorityFrame) -> Self {
        Self {
            frame,
            carrier: None,
            queued_at: Instant::now(),
            expires_at: None,
            reliable_credit: None,
            signaling_pending: None,
            local_work: None,
        }
    }
}

#[derive(Debug)]
enum EnvelopeReceiver {
    Live(mpsc::Receiver<FrameEnvelope>),
    Legacy(mpsc::Receiver<PriorityFrame>),
}

impl EnvelopeReceiver {
    fn len(&self) -> usize {
        match self {
            Self::Live(rx) => rx.len(),
            Self::Legacy(rx) => rx.len(),
        }
    }
    fn is_closed(&self) -> bool {
        match self {
            Self::Live(rx) => rx.is_closed(),
            Self::Legacy(rx) => rx.is_closed(),
        }
    }
    fn close(&mut self) {
        match self {
            Self::Live(rx) => rx.close(),
            Self::Legacy(rx) => rx.close(),
        }
    }
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<FrameEnvelope>> {
        match self {
            Self::Live(rx) => rx.poll_recv(cx),
            Self::Legacy(rx) => rx.poll_recv(cx).map(|frame| frame.map(FrameEnvelope::from)),
        }
    }
    fn try_recv(&mut self) -> Result<FrameEnvelope, mpsc::error::TryRecvError> {
        match self {
            Self::Live(rx) => rx.try_recv(),
            Self::Legacy(rx) => rx.try_recv().map(FrameEnvelope::from),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FrameSender {
    source_activity: std::sync::Arc<crate::local_source_activity::LocalSourceActivity>,
    ordinary: mpsc::Sender<FrameEnvelope>,
    network_control: mpsc::Sender<FrameEnvelope>,
    control_credits: std::sync::Arc<tokio::sync::Semaphore>,
    status: std::sync::Arc<crate::local_datagram_status::LocalDatagramStatus>,
    reserved: mpsc::Sender<FrameEnvelope>,
    reliable_credits: std::sync::Arc<tokio::sync::Semaphore>,
}

impl FrameSender {
    /// Reserve the same ordinary queue and byte credits as recoverable
    /// `try_send`, before calling a builder that may allocate a crypto nonce.
    /// Dropping either reservation on a build failure restores admission;
    /// accepted frames keep their credit through the scheduler as usual.
    pub fn try_send_recoverable_with<E>(
        &self,
        expected_len: usize,
        build: impl FnOnce() -> Result<veil_bufpool::PooledShared, E>,
    ) -> Result<(), BuildSendError<E>> {
        use crate::SendToError;
        if self.ordinary.is_closed() {
            return Err(BuildSendError::Queue(SendToError::Closed));
        }
        let credit = self
            .reliable_credits
            .clone()
            .try_acquire_many_owned(reliable_source_cost(expected_len))
            .map_err(|_| BuildSendError::Queue(SendToError::Full))?;
        let permit = self.ordinary.try_reserve().map_err(|error| {
            BuildSendError::Queue(match error {
                mpsc::error::TrySendError::Full(()) => SendToError::Full,
                mpsc::error::TrySendError::Closed(()) => SendToError::Closed,
            })
        })?;
        let frame = build().map_err(BuildSendError::Build)?;
        if frame.len() != expected_len {
            return Err(BuildSendError::LengthMismatch);
        }
        if self.ordinary.is_closed() {
            return Err(BuildSendError::Queue(SendToError::Closed));
        }
        let mut envelope =
            FrameEnvelope::from((veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE, frame));
        envelope.reliable_credit = Some(credit);
        permit.send(envelope);
        Ok(())
    }

    /// Generic transport readiness only; does not alter relay scheduling.
    pub fn has_datagram_transport(&self) -> bool {
        self.status.has_datagram_transport()
    }

    pub fn has_neutral_forward_datagram_transport(&self) -> bool {
        self.status.has_neutral_forward_datagram_transport()
    }

    pub fn request_local_datagram_channel(
        &self,
        local_lane: u8,
    ) -> crate::LocalDatagramChannelState {
        self.status.request(local_lane)
    }

    pub fn local_datagram_channel_state(&self, local_lane: u8) -> crate::LocalDatagramChannelState {
        self.status.state(local_lane)
    }

    pub fn local_packet_framing(&self, local_lane: u8) -> Option<crate::LocalPacketFraming> {
        self.status.framing(local_lane)
    }

    pub fn refresh_local_datagram_channel(
        &self,
        local_lane: u8,
    ) -> crate::LocalDatagramChannelState {
        self.status.request_fresh(local_lane)
    }

    fn lane(&self, frame: &PriorityFrame) -> &mpsc::Sender<FrameEnvelope> {
        if frame.0 == veil_proto::priority::REALTIME {
            &self.reserved
        } else {
            &self.ordinary
        }
    }

    pub(crate) fn try_send_local_work(
        &self,
        frame: PriorityFrame,
        cell: veil_types::local_lossy_work::LocalLossyCell,
    ) -> bool {
        if !matches!(
            frame.0,
            veil_proto::priority::BULK | veil_proto::priority::BACKGROUND
        ) {
            return false;
        }
        let mut envelope = FrameEnvelope::from(frame);
        envelope.expires_at = cell.expires_at();
        if envelope
            .expires_at
            .is_some_and(|until| Instant::now() >= until)
        {
            cell.reject();
            return false;
        }
        envelope.local_work = Some(cell);
        self.ordinary.try_send(envelope).is_ok()
    }

    pub fn try_send_before(&self, frame: PriorityFrame, expires_at: Instant) -> bool {
        if Instant::now() >= expires_at {
            return false;
        }
        let lane = self.lane(&frame);
        let mut envelope = FrameEnvelope::from(frame);
        envelope.expires_at = Some(expires_at);
        if envelope.frame.0 == crate::LOCAL_SIGNALING_LANE {
            envelope.signaling_pending = Some(
                self.source_activity
                    .pending_signal_before(envelope.queued_at, expires_at),
            );
        }
        lane.try_send(envelope).is_ok()
    }

    pub fn try_send(
        &self,
        frame: PriorityFrame,
    ) -> Result<(), mpsc::error::TrySendError<PriorityFrame>> {
        let control = frame.0 == crate::LOCAL_NETWORK_CONTROL_LANE;
        let lane = if control {
            &self.network_control
        } else {
            self.lane(&frame)
        };
        let recoverable = frame.0 == veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE;
        let credit = if control || recoverable {
            if lane.is_closed() {
                return Err(mpsc::error::TrySendError::Closed(frame));
            }
            let (credits, cost) = if recoverable {
                (
                    self.reliable_credits.clone(),
                    reliable_source_cost(frame.1.len()),
                )
            } else {
                (self.control_credits.clone(), 1)
            };
            match credits.try_acquire_many_owned(cost) {
                Ok(credit) => Some(credit),
                Err(_) => return Err(mpsc::error::TrySendError::Full(frame)),
            }
        } else {
            None
        };
        let mut envelope = FrameEnvelope::from(frame);
        if envelope.frame.0 == crate::LOCAL_SIGNALING_LANE {
            envelope.signaling_pending =
                Some(self.source_activity.pending_signal(envelope.queued_at));
        }
        envelope.reliable_credit = credit;
        lane.try_send(envelope).map_err(|error| match error {
            mpsc::error::TrySendError::Full(envelope) => {
                crate::local_lossy_trace::cell("ingress_full", envelope.frame.0, &envelope.frame.1);
                mpsc::error::TrySendError::Full(envelope.frame)
            }
            mpsc::error::TrySendError::Closed(envelope) => {
                mpsc::error::TrySendError::Closed(envelope.frame)
            }
        })
    }

    pub async fn send(
        &self,
        frame: PriorityFrame,
    ) -> Result<(), mpsc::error::SendError<PriorityFrame>> {
        // This is the attempt before an awaited ingress admission, not receipt.
        // Ordinary forwarding never selects this private local producer lane.
        if frame.0 == crate::LOCAL_SIGNALING_LANE {
            crate::frame_diag::note_chunk_frame("source_ingress_attempt", &frame.1);
        }
        let control = frame.0 == crate::LOCAL_NETWORK_CONTROL_LANE;
        let lane = if control {
            &self.network_control
        } else {
            self.lane(&frame)
        };
        let recoverable = frame.0 == veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE;
        let credit = if control || recoverable {
            let (credits, cost) = if recoverable {
                (
                    self.reliable_credits.clone(),
                    reliable_source_cost(frame.1.len()),
                )
            } else {
                (self.control_credits.clone(), 1)
            };
            tokio::select! {
                biased;
                _ = lane.closed() => return Err(mpsc::error::SendError(frame)),
                permit = credits.acquire_many_owned(cost) => match permit {
                    Ok(credit) => Some(credit),
                    Err(_) => return Err(mpsc::error::SendError(frame)),
                },
            }
        } else {
            None
        };
        let mut envelope = FrameEnvelope::from(frame);
        if envelope.frame.0 == crate::LOCAL_SIGNALING_LANE {
            envelope.signaling_pending =
                Some(self.source_activity.pending_signal(envelope.queued_at));
        }
        envelope.reliable_credit = credit;
        lane.send(envelope)
            .await
            .map_err(|error| mpsc::error::SendError(error.0.frame))
    }

    /// A bounded reliable source keeps its admission credit while waiting in
    /// ingress AND the scheduler, so draining ingress cannot erase pressure.
    pub(crate) async fn send_reliable(&self, bytes: veil_bufpool::PooledShared) -> bool {
        let cost = reliable_source_cost(bytes.len());
        let Ok(credit) = self.reliable_credits.clone().acquire_many_owned(cost).await else {
            return false;
        };
        crate::frame_diag::note_chunk_frame("source_enqueue", &bytes);
        self.ordinary
            .send(FrameEnvelope {
                frame: (veil_proto::priority::BACKGROUND, bytes),
                carrier: None,
                queued_at: Instant::now(),
                expires_at: None,
                reliable_credit: Some(credit),
                signaling_pending: None,
                local_work: None,
            })
            .await
            .is_ok()
    }

    /// A return carrier always uses the ordinary neutral FIFO; callers cannot
    /// promote a routed cell by tagging its wire header or source queue.
    pub(crate) fn try_send_on_carrier(
        &self,
        bytes: veil_bufpool::PooledShared,
        carrier: veil_anonymity::circuit_carrier::Carrier,
    ) -> Result<(), mpsc::error::TrySendError<FrameEnvelope>> {
        self.ordinary.try_send(FrameEnvelope {
            frame: (veil_proto::priority::INTERACTIVE, bytes),
            carrier: Some(carrier),
            queued_at: Instant::now(),
            expires_at: None,
            reliable_credit: None,
            signaling_pending: None,
            local_work: None,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.ordinary.is_closed() && self.reserved.is_closed() && self.network_control.is_closed()
    }

    pub fn capacity(&self) -> usize {
        self.ordinary.capacity() + self.reserved.capacity() + self.network_control.capacity()
    }

    pub fn max_capacity(&self) -> usize {
        self.ordinary.max_capacity()
            + self.reserved.max_capacity()
            + self.network_control.max_capacity()
    }

    pub fn queued(&self) -> usize {
        self.max_capacity().saturating_sub(self.capacity())
    }
}

#[derive(Debug)]
pub struct FrameOutbox {
    source_activity: std::sync::Arc<crate::local_source_activity::LocalSourceActivity>,
    ordinary: EnvelopeReceiver,
    network_control: Option<EnvelopeReceiver>,
    control_burst: usize,
    status: Option<std::sync::Arc<crate::local_datagram_status::LocalDatagramStatus>>,
    reserved: Option<EnvelopeReceiver>,
    reserved_burst: usize,
}

/// Keep the existing ordinary budget; add a small independent reserve.
pub fn frame_channel(capacity: usize) -> (FrameSender, FrameOutbox) {
    frame_channel_with_source_activity(capacity, std::sync::Arc::default())
}

pub(crate) fn frame_channel_with_source_activity(
    capacity: usize,
    source_activity: std::sync::Arc<crate::local_source_activity::LocalSourceActivity>,
) -> (FrameSender, FrameOutbox) {
    let status = std::sync::Arc::default();
    let (ordinary_tx, ordinary) = mpsc::channel(capacity);
    let (control_tx, control) = mpsc::channel(capacity.min(NETWORK_CONTROL_QUEUE_DEPTH));
    let (reserved_tx, reserved) = mpsc::channel(capacity.min(RESERVED_QUEUE_DEPTH));
    (
        FrameSender {
            source_activity: std::sync::Arc::clone(&source_activity),
            ordinary: ordinary_tx,
            network_control: control_tx,
            control_credits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                NETWORK_CONTROL_QUEUE_DEPTH,
            )),
            status: std::sync::Arc::clone(&status),
            reserved: reserved_tx,
            reliable_credits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                RELIABLE_SOURCE_QUEUE_DEPTH,
            )),
        },
        FrameOutbox {
            source_activity,
            ordinary: EnvelopeReceiver::Live(ordinary),
            network_control: Some(EnvelopeReceiver::Live(control)),
            control_burst: 0,
            status: Some(status),
            reserved: Some(EnvelopeReceiver::Live(reserved)),
            reserved_burst: 0,
        },
    )
}

/// Synthetic callers may still supply one FIFO, without reserving a lane.
impl From<mpsc::Receiver<PriorityFrame>> for FrameOutbox {
    fn from(ordinary: mpsc::Receiver<PriorityFrame>) -> Self {
        Self {
            source_activity: std::sync::Arc::default(),
            ordinary: EnvelopeReceiver::Legacy(ordinary),
            network_control: None,
            control_burst: 0,
            status: None,
            reserved: None,
            reserved_burst: 0,
        }
    }
}

impl FrameOutbox {
    pub(crate) fn source_activity(&self) -> &crate::local_source_activity::LocalSourceActivity {
        &self.source_activity
    }

    pub(crate) fn shared_source_activity(
        &self,
    ) -> std::sync::Arc<crate::local_source_activity::LocalSourceActivity> {
        std::sync::Arc::clone(&self.source_activity)
    }

    /// The runner owns this lease only while its datagram sender is usable.
    pub fn activate_datagram_transport(&self) -> Option<crate::DatagramTransportLease> {
        self.activate_datagram_transport_with_neutral_forwards(false)
    }

    pub(crate) fn activate_datagram_transport_with_neutral_forwards(
        &self,
        negotiated: bool,
    ) -> Option<crate::DatagramTransportLease> {
        self.status
            .as_ref()
            .map(|status| status.activate_transport(negotiated))
    }

    pub(crate) fn local_datagram_status(
        &self,
    ) -> Option<std::sync::Arc<crate::local_datagram_status::LocalDatagramStatus>> {
        self.status.clone()
    }

    pub async fn recv(&mut self) -> Option<PriorityFrame> {
        self.recv_envelope().await.map(|envelope| envelope.frame)
    }

    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<PriorityFrame>> {
        self.poll_recv_envelope(cx)
            .map(|frame| frame.map(|envelope| envelope.frame))
    }

    pub(crate) async fn recv_envelope(&mut self) -> Option<FrameEnvelope> {
        std::future::poll_fn(|cx| self.poll_recv_envelope(cx)).await
    }

    fn receive_order(&self) -> [usize; 3] {
        let lower = if self.control_burst >= MAX_CONTROL_BURST {
            [2, 1]
        } else {
            [1, 2]
        };
        if self.reserved_burst >= MAX_RESERVED_BURST {
            [lower[0], lower[1], 0]
        } else {
            [0, lower[0], lower[1]]
        }
    }

    fn received_from(&mut self, lane: usize) {
        if lane == 0 {
            self.reserved_burst = self.reserved_burst.saturating_add(1);
        } else {
            self.reserved_burst = 0;
            self.control_burst = if lane == 1 {
                self.control_burst.saturating_add(1)
            } else {
                0
            };
        }
    }

    pub(crate) fn poll_recv_envelope(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<FrameEnvelope>> {
        let mut pending = false;
        for lane in self.receive_order() {
            let receiver = match lane {
                0 => self.reserved.as_mut(),
                1 => self.network_control.as_mut(),
                _ => Some(&mut self.ordinary),
            };
            let Some(receiver) = receiver else { continue };
            match receiver.poll_recv(cx) {
                Poll::Ready(Some(frame)) => {
                    self.received_from(lane);
                    return Poll::Ready(Some(frame));
                }
                Poll::Pending => pending = true,
                Poll::Ready(None) => {}
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }

    pub fn try_recv(&mut self) -> Result<PriorityFrame, mpsc::error::TryRecvError> {
        self.try_recv_envelope().map(|envelope| envelope.frame)
    }

    pub(crate) fn try_recv_envelope(&mut self) -> Result<FrameEnvelope, mpsc::error::TryRecvError> {
        let mut empty = false;
        for lane in self.receive_order() {
            let receiver = match lane {
                0 => self.reserved.as_mut(),
                1 => self.network_control.as_mut(),
                _ => Some(&mut self.ordinary),
            };
            let Some(receiver) = receiver else { continue };
            match receiver.try_recv() {
                Ok(frame) => {
                    self.received_from(lane);
                    return Ok(frame);
                }
                Err(mpsc::error::TryRecvError::Empty) => empty = true,
                Err(mpsc::error::TryRecvError::Disconnected) => {}
            }
        }
        Err(if empty {
            mpsc::error::TryRecvError::Empty
        } else {
            mpsc::error::TryRecvError::Disconnected
        })
    }

    pub fn len(&self) -> usize {
        self.ordinary.len()
            + self.reserved.as_ref().map_or(0, EnvelopeReceiver::len)
            + self
                .network_control
                .as_ref()
                .map_or(0, EnvelopeReceiver::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_closed(&self) -> bool {
        self.ordinary.is_closed()
            && self
                .network_control
                .as_ref()
                .is_none_or(EnvelopeReceiver::is_closed)
            && self
                .reserved
                .as_ref()
                .is_none_or(EnvelopeReceiver::is_closed)
    }

    pub fn close(&mut self) {
        self.ordinary.close();
        if let Some(control) = &mut self.network_control {
            control.close();
        }
        if let Some(reserved) = &mut self.reserved {
            reserved.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::priority::{INTERACTIVE, REALTIME};

    #[tokio::test]
    async fn interactive_control_does_not_spend_a_recoverable_cell_credit() {
        let (tx, mut rx) = frame_channel(8);
        let mut header = veil_proto::FrameHeader::new(
            veil_proto::family::FrameFamily::RelayChain as u8,
            veil_proto::family::RelayChainMsg::Hop as u16,
        );
        header.set_priority(INTERACTIVE);
        header.body_len = 16_384;
        let mut cell = veil_proto::codec::encode_header(&header).to_vec();
        cell.resize(cell.len() + 16_384, 0x53);
        let frame = veil_bufpool::pooled_shared_from_vec(cell);
        tx.try_send((veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE, frame.clone()))
            .unwrap();
        let held = rx.recv_envelope().await.unwrap();
        assert_eq!(tx.reliable_credits.available_permits(), 0);
        assert!(
            tx.try_send((veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE, frame.clone()))
                .is_err()
        );
        tx.try_send((INTERACTIVE, frame.clone())).unwrap();
        let control = rx.recv_envelope().await.unwrap();
        assert_eq!(
            control.frame.1, held.frame.1,
            "source choice must not change any wire byte"
        );
        assert!(control.reliable_credit.is_none());
        assert_eq!(
            tx.reliable_credits.available_permits(),
            0,
            "control cannot consume DATA credit"
        );
        drop(held);
        assert_eq!(
            tx.reliable_credits.available_permits(),
            RELIABLE_SOURCE_QUEUE_DEPTH
        );
    }

    #[tokio::test]
    async fn recoverable_builder_reserves_credit_through_scheduler_restore() {
        let (tx, mut rx) = frame_channel(8);
        let calls = std::cell::Cell::new(0);
        let build = || {
            calls.set(calls.get() + 1);
            Ok::<_, &'static str>(veil_bufpool::pooled_shared_from_vec(vec![42; 2048]))
        };
        tx.try_send_recoverable_with(2048, build).unwrap();
        tx.try_send_recoverable_with(2048, build).unwrap();
        let mut pq = crate::PriorityQueue::with_default_weights();
        pq.push_envelope(rx.recv_envelope().await.unwrap(), true);
        assert!(matches!(
            tx.try_send_recoverable_with(2048, build),
            Err(BuildSendError::Queue(crate::SendToError::Full))
        ));
        let frame = pq.pop_datagram_envelope_if(|_| true).unwrap();
        assert!(frame.reliable_credit.is_some());
        pq.restore_lossy_envelope(frame);
        assert!(matches!(
            tx.try_send_recoverable_with(2048, build),
            Err(BuildSendError::Queue(crate::SendToError::Full))
        ));
        assert_eq!(calls.get(), 2, "rejected builder consumed a nonce/work");
        drop(pq);
        tx.try_send_recoverable_with(2048, build).unwrap();
        assert_eq!(calls.get(), 3);
        assert_eq!(
            rx.recv().await.unwrap().0,
            veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE
        );
    }

    #[test]
    fn recoverable_builder_does_not_run_on_full_or_closed_ingress() {
        let (tx, mut rx) = frame_channel(1);
        tx.try_send((INTERACTIVE, veil_bufpool::pooled_shared_from_vec(vec![1])))
            .unwrap();
        let calls = std::cell::Cell::new(0);
        let build = || {
            calls.set(calls.get() + 1);
            Ok::<_, &'static str>(veil_bufpool::pooled_shared_from_vec(vec![42; 2048]))
        };
        assert!(matches!(
            tx.try_send_recoverable_with(2048, build),
            Err(BuildSendError::Queue(crate::SendToError::Full))
        ));
        assert_eq!(
            tx.reliable_credits.available_permits(),
            RELIABLE_SOURCE_QUEUE_DEPTH
        );
        rx.close();
        assert!(matches!(
            tx.try_send_recoverable_with(2048, build),
            Err(BuildSendError::Queue(crate::SendToError::Closed))
        ));
        assert_eq!(calls.get(), 0);
    }

    #[tokio::test]
    async fn recoverable_builder_failure_releases_reserved_slot_and_credit() {
        let (tx, mut rx) = frame_channel(1);
        assert!(matches!(
            tx.try_send_recoverable_with(2048, || Err::<veil_bufpool::PooledShared, _>(
                "build failed"
            )),
            Err(BuildSendError::Build("build failed"))
        ));
        assert_eq!(tx.ordinary.capacity(), 1);
        assert_eq!(
            tx.reliable_credits.available_permits(),
            RELIABLE_SOURCE_QUEUE_DEPTH
        );
        assert!(matches!(
            tx.try_send_recoverable_with(2048, || Ok::<_, &'static str>(
                veil_bufpool::pooled_shared_from_vec(vec![1; 2047])
            )),
            Err(BuildSendError::LengthMismatch)
        ));
        assert_eq!(tx.ordinary.capacity(), 1);
        assert_eq!(
            tx.reliable_credits.available_permits(),
            RELIABLE_SOURCE_QUEUE_DEPTH
        );
        tx.try_send_recoverable_with(2048, || {
            Ok::<_, &'static str>(veil_bufpool::pooled_shared_from_vec(vec![1; 2048]))
        })
        .unwrap();
        assert_eq!(rx.recv().await.unwrap().1.len(), 2048);
    }

    #[tokio::test]
    async fn recoverable_data_credit_survives_scheduler_and_datagram_restore() {
        let lane = veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE;
        let (tx, mut rx) = frame_channel(64);
        let packet = || (lane, veil_bufpool::pooled_shared_from_vec(vec![42; 2048]));
        tx.try_send(packet()).unwrap();
        tx.try_send(packet()).unwrap();
        assert!(matches!(
            tx.try_send(packet()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        let admitted = rx.recv_envelope().await.unwrap();
        let original_time = admitted.queued_at;
        let mut pq = crate::priority_queue::PriorityQueue::with_default_weights();
        pq.push_envelope(admitted, true);
        // Moving a frame out of ingress does not manufacture source capacity.
        assert!(matches!(
            tx.try_send(packet()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        let queued = pq.pop_datagram_envelope_if(|_| true).unwrap();
        assert!(queued.reliable_credit.is_some());
        pq.restore_lossy_envelope(queued);
        assert!(matches!(
            tx.try_send(packet()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        let queued = pq.pop_datagram_envelope_if(|_| true).unwrap();
        assert_eq!(queued.queued_at, original_time);
        assert!(queued.reliable_credit.is_some());
        drop(queued);
        tx.try_send(packet()).unwrap();
        // Primary media owns its independent ingress budget.
        tx.try_send((
            veil_proto::priority::REALTIME,
            veil_bufpool::pooled_shared_from_vec(vec![1]),
        ))
        .unwrap();
        assert_eq!(pq.drops_total(), 0);
    }

    #[tokio::test]
    async fn recoverable_credit_wait_is_released_by_admission_and_wakes_on_shutdown() {
        let lane = veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE;
        let (tx, mut rx) = frame_channel(64);
        let packet = || (lane, veil_bufpool::pooled_shared_from_vec(vec![42; 2048]));
        tx.try_send(packet()).unwrap();
        tx.try_send(packet()).unwrap();
        let mut pq = crate::priority_queue::PriorityQueue::with_default_weights();
        pq.push_envelope(rx.recv_envelope().await.unwrap(), true);
        let sender = tx.clone();
        let waiting = sender.send(packet());
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        drop(pq.pop_datagram_envelope_if(|_| true));
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut waiting)
            .await
            .unwrap()
            .unwrap();
        let sender = tx.clone();
        let waiting = sender.send(packet());
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        drop(rx);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn signaling_ownership_survives_ingress_scheduler_and_restore() {
        let activity =
            std::sync::Arc::new(crate::local_source_activity::LocalSourceActivity::default());
        let (sender, mut outbox) = frame_channel_with_source_activity(4, activity.clone());
        let now = Instant::now();
        activity.note(now);
        sender
            .try_send((
                crate::LOCAL_SIGNALING_LANE,
                veil_bufpool::pooled_shared_from_vec(b"control".to_vec()),
            ))
            .unwrap();
        let mut pq = crate::PriorityQueue::with_default_weights();
        pq.push_envelope(outbox.recv_envelope().await.unwrap(), true);
        assert_eq!(activity.admit_signaling(1024, now), Ok(()));
        let ready = now + std::time::Duration::from_millis(50);
        let selected = pq.pop_local_datagram_envelope_if(|_| true).unwrap();
        assert!(activity.admit_reliable_secondary(1024, ready).is_err());
        pq.restore_lossy_envelope(selected);
        assert!(activity.admit_reliable_secondary(1024, ready).is_err());
        drop(pq);
        assert_eq!(activity.admit_reliable_secondary(1024, ready), Ok(()));
    }

    #[tokio::test]
    async fn failed_and_canceled_signaling_admission_releases_data() {
        let activity =
            std::sync::Arc::new(crate::local_source_activity::LocalSourceActivity::default());
        let (sender, _outbox) = frame_channel_with_source_activity(1, activity.clone());
        let frame = |p| (p, veil_bufpool::pooled_shared_from_vec(b"frame".to_vec()));
        let now = Instant::now();
        activity.note(now);
        sender.try_send(frame(INTERACTIVE)).unwrap();
        assert!(sender.try_send(frame(crate::LOCAL_SIGNALING_LANE)).is_err());
        assert_eq!(activity.admit_reliable_secondary(1, now), Ok(()));
        let ready = now + std::time::Duration::from_millis(1);
        let mut pending = Box::pin(sender.send(frame(crate::LOCAL_SIGNALING_LANE)));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), &mut pending)
                .await
                .is_err()
        );
        assert!(activity.admit_reliable_secondary(1, ready).is_err());
        drop(pending);
        assert_eq!(activity.admit_reliable_secondary(1, ready), Ok(()));
    }

    #[tokio::test]
    async fn shedding_or_expiring_signaling_releases_data() {
        let activity =
            std::sync::Arc::new(crate::local_source_activity::LocalSourceActivity::default());
        let (sender, mut outbox) = frame_channel_with_source_activity(4, activity.clone());
        let now = Instant::now();
        activity.note(now);
        let frame = |p| (p, veil_bufpool::pooled_shared_from_vec(b"frame".to_vec()));
        sender
            .send(frame(crate::LOCAL_SIGNALING_LANE))
            .await
            .unwrap();
        let mut pq = crate::PriorityQueue::with_capacity(crate::DEFAULT_WEIGHTS, 1);
        pq.push_envelope(outbox.recv_envelope().await.unwrap(), true);
        assert!(activity.admit_reliable_secondary(1, now).is_err());
        pq.push(REALTIME, frame(REALTIME).1);
        assert_eq!(activity.admit_reliable_secondary(1, now), Ok(()));
        sender
            .send(frame(crate::LOCAL_SIGNALING_LANE))
            .await
            .unwrap();
        let mut expired = outbox.recv_envelope().await.unwrap();
        expired.queued_at = now - std::time::Duration::from_secs(6);
        pq.push_envelope(expired, true);
        assert_eq!(
            activity.admit_reliable_secondary(1, now + std::time::Duration::from_millis(1)),
            Ok(())
        );
    }

    #[tokio::test]
    async fn own_control_has_reserved_ingress_and_keeps_credit_through_scheduler() {
        use crate::{LOCAL_NETWORK_CONTROL_LANE as CONTROL, PriorityQueue};
        let (tx, mut rx) = frame_channel(1);
        tx.try_send(frame(INTERACTIVE, 200)).unwrap();
        let mut pq = PriorityQueue::with_capacity([8, 4, 2, 1], 1);
        for byte in 0..NETWORK_CONTROL_QUEUE_DEPTH as u8 {
            tx.try_send(frame(CONTROL, byte)).unwrap();
            if byte == 0 {
                tx.try_send(frame(REALTIME, 250)).unwrap();
                assert_eq!(rx.recv().await.unwrap().1[0], 250);
            }
            // Account for the bounded ordinary interleave.
            let mut envelope = rx.recv_envelope().await.unwrap();
            if envelope.frame.0 == INTERACTIVE {
                assert_eq!(envelope.frame.1[0], 200);
                envelope = rx.recv_envelope().await.unwrap();
            }
            assert_eq!(envelope.frame.0, CONTROL);
            pq.push_envelope(envelope, false);
        }
        assert!(matches!(
            tx.try_send(frame(CONTROL, 64)),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        for byte in 100..200 {
            pq.push(INTERACTIVE, frame(INTERACTIVE, byte).1);
        }
        assert_eq!(pq.len(), NETWORK_CONTROL_QUEUE_DEPTH + 1);
        assert_eq!(&*pq.pop().unwrap(), &[199]);
        let head = pq.pop_envelope_if(|_, _| true).unwrap();
        assert_eq!(head.frame.1[0], 0);
        assert!(matches!(
            tx.try_send(frame(CONTROL, 64)),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        drop(head);
        tx.try_send(frame(CONTROL, 64)).unwrap();
        pq.push_envelope(rx.recv_envelope().await.unwrap(), false);
        for byte in 1..NETWORK_CONTROL_QUEUE_DEPTH as u8 {
            assert_eq!(&*pq.pop().unwrap(), &[byte]);
        }
        assert_eq!(&*pq.pop().unwrap(), &[64]);
    }

    #[tokio::test]
    async fn closing_control_wakes_waiter_even_with_all_credits_held_by_scheduler() {
        use crate::{LOCAL_NETWORK_CONTROL_LANE as CONTROL, PriorityQueue};
        let (tx, mut rx) = frame_channel(1);
        let mut pq = PriorityQueue::with_default_weights();
        for byte in 0..NETWORK_CONTROL_QUEUE_DEPTH as u8 {
            tx.send(frame(CONTROL, byte)).await.unwrap();
            pq.push_envelope(rx.recv_envelope().await.unwrap(), false);
        }
        let waiting = tokio::spawn(async move { tx.send(frame(CONTROL, 64)).await });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        rx.close();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(pq.len(), NETWORK_CONTROL_QUEUE_DEPTH);
    }

    #[tokio::test]
    async fn neutral_transit_is_not_starved_by_continuous_control_and_primary() {
        use crate::LOCAL_NETWORK_CONTROL_LANE as CONTROL;
        let (tx, mut rx) = frame_channel(64);
        tx.try_send(frame(INTERACTIVE, 99)).unwrap();
        for _ in 0..64 {
            tx.try_send(frame(REALTIME, 1)).unwrap();
            tx.try_send(frame(CONTROL, 2)).unwrap();
        }
        for control in 0..=MAX_CONTROL_BURST {
            for n in 0..MAX_RESERVED_BURST {
                let got = if n % 2 == 0 {
                    rx.recv().await.unwrap()
                } else {
                    rx.try_recv().unwrap()
                };
                assert_eq!(got.0, REALTIME);
            }
            let got = rx.recv().await.unwrap();
            if control == MAX_CONTROL_BURST {
                assert_eq!(got.1[0], 99);
            } else {
                assert_eq!(got.0, CONTROL);
            }
        }
    }

    #[tokio::test]
    async fn reliable_credit_survives_ingress_drain_and_scheduler_overflow() {
        use crate::priority_queue::PriorityQueue;
        use std::future::Future;
        let (tx, mut rx) = frame_channel(1);
        let mut pq = PriorityQueue::with_capacity([8, 4, 2, 1], 1);
        for byte in 0..RELIABLE_SOURCE_QUEUE_DEPTH as u8 {
            assert!(tx.send_reliable(frame(3, byte).1).await);
            pq.push_envelope(rx.recv_envelope().await.unwrap(), false);
        }
        let mut waiting = Box::pin(tx.send_reliable(frame(3, 64).1));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // Ordinary overflow retains its own bounded budget and cannot evict
        // an already admitted byte-stream frame, regardless of priority.
        for byte in 100..200 {
            pq.push(INTERACTIVE, frame(INTERACTIVE, byte).1);
        }
        assert_eq!(pq.len(), RELIABLE_SOURCE_QUEUE_DEPTH + 1);
        assert_eq!(pq.drops_total(), 99);
        // A stalled reliable source still cannot exhaust primary ingress.
        tx.try_send(frame(REALTIME, 250)).unwrap();
        assert_eq!(rx.recv().await.unwrap().0, REALTIME);
        assert_eq!(&*pq.pop().unwrap(), &[199]);
        let first = pq.pop_envelope_if(|_, _| true).unwrap();
        assert_eq!(&*first.frame.1, &[0]);
        std::future::poll_fn(|cx| {
            assert!(
                waiting.as_mut().poll(cx).is_pending(),
                "pop lost its credit before consumption"
            );
            Poll::Ready(())
        })
        .await;
        drop(first);
        assert!(waiting.await);
        pq.push_envelope(rx.recv_envelope().await.unwrap(), false);
        for byte in 1..RELIABLE_SOURCE_QUEUE_DEPTH as u8 {
            assert_eq!(&*pq.pop().unwrap(), &[byte]);
        }
        assert_eq!(&*pq.pop().unwrap(), &[64]);
        assert!(pq.is_empty());
    }

    #[tokio::test]
    async fn an_oversized_source_frame_owns_lookahead_without_blocking_primary() {
        use std::future::Future;
        let (tx, mut rx) = frame_channel(8);
        let big = veil_bufpool::pooled_shared_from_vec(vec![7; 60 * 1024]);
        assert!(tx.send_reliable(big).await);
        let held = rx.recv_envelope().await.unwrap();
        let mut waiting = Box::pin(tx.send_reliable(frame(3, 9).1));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        tx.try_send(frame(REALTIME, 250)).unwrap();
        assert_eq!(rx.recv().await.unwrap().0, REALTIME);
        // Draining ingress does not erase the large frame's debt/credit.
        drop(held);
        assert!(waiting.await);
        assert_eq!(&*rx.recv().await.unwrap().1, &[9]);
    }

    #[tokio::test]
    async fn closing_a_stalled_reliable_source_releases_waiters() {
        use crate::priority_queue::PriorityQueue;
        let (tx, mut rx) = frame_channel(1);
        let mut pq = PriorityQueue::with_default_weights();
        for byte in 0..RELIABLE_SOURCE_QUEUE_DEPTH as u8 {
            assert!(tx.send_reliable(frame(3, byte).1).await);
            pq.push_envelope(rx.recv_envelope().await.unwrap(), false);
        }
        let waiting = tokio::spawn(async move { tx.send_reliable(frame(3, 64).1).await });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(rx);
        drop(pq);
        assert!(
            !tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn waiting_for_ingress_capacity_counts_toward_lossy_age() {
        use crate::priority_queue::{LOCAL_PRIMARY_MAX_AGE, PriorityQueue};
        use std::{future::Future, time::Duration};
        let (tx, mut rx) = frame_channel(1);
        tx.try_send(frame(REALTIME, 1)).unwrap();
        let mut waiting = Box::pin(tx.send(frame(REALTIME, 2)));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::sleep(LOCAL_PRIMARY_MAX_AGE + Duration::from_millis(60)).await;
        rx.recv_envelope().await.unwrap();
        waiting.await.unwrap();
        let mut pq = PriorityQueue::with_default_weights();
        pq.push_envelope(rx.recv_envelope().await.unwrap(), true);
        assert!(pq.pop().is_none(), "blocked send renewed old media age");
        assert_eq!(pq.drops_total(), 1);
        tx.try_send(frame(REALTIME, 3)).unwrap();
        pq.push_envelope(rx.recv_envelope().await.unwrap(), true);
        assert_eq!(&*pq.pop().unwrap(), &[3]);
    }

    fn frame(priority: u8, byte: u8) -> PriorityFrame {
        (priority, veil_bufpool::pooled_shared_from_vec(vec![byte]))
    }

    struct NoDirectSend;
    impl veil_anonymity::circuit_carrier::DatagramCarrier for NoDirectSend {
        fn try_send(
            &self,
            _: &[u8; 32],
            _: &[u8],
            _: &mut dyn FnMut(usize) -> bool,
        ) -> veil_anonymity::circuit_carrier::CarrierSend {
            panic!("queue admission must never transmit directly")
        }
    }

    #[tokio::test]
    async fn carrier_uses_ordinary_capacity_and_cannot_overtake_reliable_data() {
        let carrier: std::sync::Arc<dyn veil_anonymity::circuit_carrier::DatagramCarrier> =
            std::sync::Arc::new(NoDirectSend);
        let weak = std::sync::Arc::downgrade(&carrier);
        let (tx, mut rx) = frame_channel(1);
        tx.try_send(frame(INTERACTIVE, 1)).unwrap();
        assert!(matches!(
            tx.try_send_on_carrier(frame(REALTIME, 2).1, weak.clone()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        // The reserved capacity still exists; a carrier cannot spend it.
        assert_eq!(tx.capacity(), 2);
        let mut pq = crate::priority_queue::PriorityQueue::with_default_weights();
        pq.push_envelope(rx.recv_envelope().await.unwrap(), false);
        tx.try_send_on_carrier(frame(REALTIME, 2).1, weak.clone())
            .unwrap();
        let routed = rx.recv_envelope().await.unwrap();
        assert_eq!(routed.frame.0, INTERACTIVE);
        assert!(std::sync::Weak::ptr_eq(
            routed.carrier.as_ref().unwrap(),
            &weak
        ));
        pq.push_envelope(routed, true);
        assert!(pq.pop_datagram_envelope_if(|bytes| bytes == [2]).is_none());
        assert_eq!(&*pq.pop().unwrap(), &[1]);
        let routed = pq.pop_datagram_envelope_if(|bytes| bytes == [2]).unwrap();
        let admitted = routed.queued_at;
        pq.restore_lossy_envelope(routed);
        let routed = pq.pop_datagram_envelope_if(|bytes| bytes == [2]).unwrap();
        assert_eq!(routed.queued_at, admitted);
        assert_eq!(routed.frame.0, INTERACTIVE);
        assert_eq!(&*routed.frame.1, &[2]);
        assert!(std::sync::Weak::ptr_eq(
            routed.carrier.as_ref().unwrap(),
            &weak
        ));
        drop(carrier);
        assert!(
            routed.carrier.unwrap().upgrade().is_none(),
            "queued routes must not retain transports"
        );
    }

    #[tokio::test]
    async fn full_ordinary_lane_does_not_block_reserved_ingress() {
        let (tx, mut rx) = frame_channel(2);
        tx.try_send(frame(INTERACTIVE, 1)).unwrap();
        tx.try_send(frame(INTERACTIVE, 2)).unwrap();
        assert!(matches!(
            tx.try_send(frame(INTERACTIVE, 3)),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        tx.try_send(frame(REALTIME, 4)).unwrap();
        assert_eq!(rx.recv().await.unwrap().1[0], 4);
        assert_eq!(rx.recv().await.unwrap().1[0], 1);
        assert_eq!(rx.recv().await.unwrap().1[0], 2);
    }

    #[tokio::test]
    async fn ordinary_lane_is_not_starved_by_a_continuous_reserved_producer() {
        let (tx, mut rx) = frame_channel(16);
        tx.try_send(frame(INTERACTIVE, 99)).unwrap();
        for _ in 0..16 {
            tx.try_send(frame(REALTIME, 1)).unwrap();
        }
        for _ in 0..MAX_RESERVED_BURST / 2 {
            assert_eq!(rx.recv().await.unwrap().1[0], 1);
        }
        for _ in 0..MAX_RESERVED_BURST / 2 {
            assert_eq!(rx.try_recv().unwrap().1[0], 1);
        }
        assert_eq!(rx.try_recv().unwrap().1[0], 99);
    }

    #[tokio::test]
    async fn closing_drains_both_lanes_and_wakes_a_waiting_receiver() {
        let (tx, mut rx) = frame_channel(2);
        tx.try_send(frame(INTERACTIVE, 1)).unwrap();
        tx.try_send(frame(REALTIME, 2)).unwrap();
        drop(tx);
        assert!(rx.recv().await.is_some());
        assert!(rx.recv().await.is_some());
        assert!(rx.recv().await.is_none());
        let (tx, mut rx) = frame_channel(2);
        let waiter = tokio::spawn(async move { rx.recv().await });
        tokio::task::yield_now().await;
        drop(tx);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), waiter)
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
    }
}
