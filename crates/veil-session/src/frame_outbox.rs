//! Independent local session ingress queues. A full ordinary outbox must not
//! prevent a local latency-sensitive producer from reaching the scheduler.
//! These lanes are process-local; they add no field to an OVL1 wire frame.
//! Relayed user data always uses the ordinary lane, regardless of wire hints.

use std::task::{Context, Poll};

use tokio::sync::mpsc;

use crate::PriorityFrame;

pub const RESERVED_QUEUE_DEPTH: usize = 64;
const MAX_RESERVED_BURST: usize = 8;

/// Local transport metadata follows a frame through the ordinary queue. It
/// never changes the wire header, priority, FIFO position or queue budget.
#[derive(Debug)]
pub struct FrameEnvelope {
    pub frame: PriorityFrame,
    pub carrier: Option<veil_anonymity::circuit_carrier::Carrier>,
}

impl From<PriorityFrame> for FrameEnvelope {
    fn from(frame: PriorityFrame) -> Self {
        Self {
            frame,
            carrier: None,
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
    ordinary: mpsc::Sender<FrameEnvelope>,
    reserved: mpsc::Sender<FrameEnvelope>,
}

impl FrameSender {
    fn lane(&self, frame: &PriorityFrame) -> &mpsc::Sender<FrameEnvelope> {
        if frame.0 == veil_proto::priority::REALTIME {
            &self.reserved
        } else {
            &self.ordinary
        }
    }

    pub fn try_send(
        &self,
        frame: PriorityFrame,
    ) -> Result<(), mpsc::error::TrySendError<PriorityFrame>> {
        self.lane(&frame)
            .try_send(frame.into())
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(envelope) => {
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
        self.lane(&frame)
            .send(frame.into())
            .await
            .map_err(|error| mpsc::error::SendError(error.0.frame))
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
        })
    }

    pub fn is_closed(&self) -> bool {
        self.ordinary.is_closed() && self.reserved.is_closed()
    }

    pub fn capacity(&self) -> usize {
        self.ordinary.capacity() + self.reserved.capacity()
    }

    pub fn max_capacity(&self) -> usize {
        self.ordinary.max_capacity() + self.reserved.max_capacity()
    }

    pub fn queued(&self) -> usize {
        self.max_capacity().saturating_sub(self.capacity())
    }
}

#[derive(Debug)]
pub struct FrameOutbox {
    ordinary: EnvelopeReceiver,
    reserved: Option<EnvelopeReceiver>,
    reserved_burst: usize,
}

/// Keep the existing ordinary budget; add a small independent reserve.
pub fn frame_channel(capacity: usize) -> (FrameSender, FrameOutbox) {
    let (ordinary_tx, ordinary) = mpsc::channel(capacity);
    let (reserved_tx, reserved) = mpsc::channel(capacity.min(RESERVED_QUEUE_DEPTH));
    (
        FrameSender {
            ordinary: ordinary_tx,
            reserved: reserved_tx,
        },
        FrameOutbox {
            ordinary: EnvelopeReceiver::Live(ordinary),
            reserved: Some(EnvelopeReceiver::Live(reserved)),
            reserved_burst: 0,
        },
    )
}

/// Synthetic callers may still supply one FIFO, without reserving a lane.
impl From<mpsc::Receiver<PriorityFrame>> for FrameOutbox {
    fn from(ordinary: mpsc::Receiver<PriorityFrame>) -> Self {
        Self {
            ordinary: EnvelopeReceiver::Legacy(ordinary),
            reserved: None,
            reserved_burst: 0,
        }
    }
}

impl FrameOutbox {
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

    pub(crate) fn poll_recv_envelope(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<FrameEnvelope>> {
        let Some(reserved) = self.reserved.as_mut() else {
            return self.ordinary.poll_recv(cx);
        };
        let ordinary_first = self.reserved_burst >= MAX_RESERVED_BURST;
        let (first, second) = if ordinary_first {
            (&mut self.ordinary, reserved)
        } else {
            (reserved, &mut self.ordinary)
        };
        let first_result = first.poll_recv(cx);
        if let Poll::Ready(Some(frame)) = first_result {
            self.reserved_burst = if ordinary_first {
                0
            } else {
                self.reserved_burst + 1
            };
            return Poll::Ready(Some(frame));
        }
        let second_result = second.poll_recv(cx);
        if let Poll::Ready(Some(frame)) = second_result {
            self.reserved_burst = if ordinary_first {
                self.reserved_burst.saturating_add(1)
            } else {
                0
            };
            return Poll::Ready(Some(frame));
        }
        if matches!(first_result, Poll::Ready(None)) && matches!(second_result, Poll::Ready(None)) {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    pub fn try_recv(&mut self) -> Result<PriorityFrame, mpsc::error::TryRecvError> {
        self.try_recv_envelope().map(|envelope| envelope.frame)
    }

    pub(crate) fn try_recv_envelope(&mut self) -> Result<FrameEnvelope, mpsc::error::TryRecvError> {
        let Some(reserved) = self.reserved.as_mut() else {
            return self.ordinary.try_recv();
        };
        let ordinary_first = self.reserved_burst >= MAX_RESERVED_BURST;
        let (first, second) = if ordinary_first {
            (&mut self.ordinary, reserved)
        } else {
            (reserved, &mut self.ordinary)
        };
        let first_result = first.try_recv();
        if let Ok(frame) = first_result {
            self.reserved_burst = if ordinary_first {
                0
            } else {
                self.reserved_burst + 1
            };
            return Ok(frame);
        }
        let second_result = second.try_recv();
        if let Ok(frame) = second_result {
            self.reserved_burst = if ordinary_first {
                self.reserved_burst.saturating_add(1)
            } else {
                0
            };
            return Ok(frame);
        }
        if matches!(first_result, Err(mpsc::error::TryRecvError::Disconnected))
            && matches!(second_result, Err(mpsc::error::TryRecvError::Disconnected))
        {
            Err(mpsc::error::TryRecvError::Disconnected)
        } else {
            Err(mpsc::error::TryRecvError::Empty)
        }
    }

    pub fn len(&self) -> usize {
        self.ordinary.len() + self.reserved.as_ref().map_or(0, EnvelopeReceiver::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_closed(&self) -> bool {
        self.ordinary.is_closed()
            && self
                .reserved
                .as_ref()
                .is_none_or(EnvelopeReceiver::is_closed)
    }

    pub fn close(&mut self) {
        self.ordinary.close();
        if let Some(reserved) = &mut self.reserved {
            reserved.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::priority::{INTERACTIVE, REALTIME};

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
        assert_eq!(tx.capacity(), 1);
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
