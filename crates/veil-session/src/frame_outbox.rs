//! Independent local session ingress queues. A full ordinary outbox must not
//! prevent a local latency-sensitive producer from reaching the scheduler.
//! These lanes are process-local; they add no field to an OVL1 wire frame.
//! Relayed user data always uses the ordinary lane, regardless of wire hints.

use std::task::{Context, Poll};

use tokio::sync::mpsc;

use crate::PriorityFrame;

pub const RESERVED_QUEUE_DEPTH: usize = 64;
const MAX_RESERVED_BURST: usize = 8;

#[derive(Clone, Debug)]
pub struct FrameSender {
    ordinary: mpsc::Sender<PriorityFrame>,
    reserved: mpsc::Sender<PriorityFrame>,
}

impl FrameSender {
    fn lane(&self, frame: &PriorityFrame) -> &mpsc::Sender<PriorityFrame> {
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
        self.lane(&frame).try_send(frame)
    }

    pub async fn send(
        &self,
        frame: PriorityFrame,
    ) -> Result<(), mpsc::error::SendError<PriorityFrame>> {
        self.lane(&frame).send(frame).await
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
    ordinary: mpsc::Receiver<PriorityFrame>,
    reserved: Option<mpsc::Receiver<PriorityFrame>>,
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
            ordinary,
            reserved: Some(reserved),
            reserved_burst: 0,
        },
    )
}

/// Synthetic callers may still supply one FIFO, without reserving a lane.
impl From<mpsc::Receiver<PriorityFrame>> for FrameOutbox {
    fn from(ordinary: mpsc::Receiver<PriorityFrame>) -> Self {
        Self {
            ordinary,
            reserved: None,
            reserved_burst: 0,
        }
    }
}

impl FrameOutbox {
    pub async fn recv(&mut self) -> Option<PriorityFrame> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<PriorityFrame>> {
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
        self.ordinary.len() + self.reserved.as_ref().map_or(0, mpsc::Receiver::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_closed(&self) -> bool {
        self.ordinary.is_closed() && self.reserved.as_ref().is_none_or(mpsc::Receiver::is_closed)
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
