//! Userspace deadline for an outstanding TCP flight on a loss-tolerant child.
//! The kernel option remains a backstop when progress cannot be observed.

use super::ORDERED_ACK_TIMEOUT;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Waker};
use std::time::Duration;
use tokio::time::{Instant, Sleep};

const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Default)]
pub(super) struct OrderedAckWatch {
    timer: Option<Pin<Box<Sleep>>>,
    idle_reader: Option<Waker>,
    outstanding: Option<(u64, Instant)>,
    unavailable: bool,
}

impl OrderedAckWatch {
    pub(super) fn note_write(&mut self) {
        if self.unavailable || self.timer.is_some() {
            return;
        }
        self.timer = Some(Box::pin(tokio::time::sleep(SAMPLE_INTERVAL)));
        // The split reader may already be waiting for incoming bytes. It
        // owns the timer so progress is checked even after a successful flush
        // and with no further writes.
        if let Some(reader) = self.idle_reader.take() {
            reader.wake();
        }
    }

    fn register_idle_reader(&mut self, cx: &Context<'_>) {
        if self
            .idle_reader
            .as_ref()
            .is_none_or(|w| !w.will_wake(cx.waker()))
        {
            self.idle_reader = Some(cx.waker().clone());
        }
    }

    /// True only after observing the same ACK watermark across a full
    /// deadline with packets still in flight. Idle sockets need no polling.
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        sample: impl FnOnce() -> Option<(u32, u64)>,
    ) -> bool {
        if self.unavailable {
            return false;
        }
        let Some(timer) = self.timer.as_mut() else {
            self.register_idle_reader(cx);
            return false;
        };
        if timer.as_mut().poll(cx).is_pending() {
            return false;
        }
        match sample() {
            Some((unacked, acked)) if unacked != 0 => {
                let now = Instant::now();
                let (_, since) = self
                    .outstanding
                    .filter(|(last, _)| *last == acked)
                    .unwrap_or((acked, now));
                self.outstanding = Some((acked, since));
                if now.duration_since(since) >= ORDERED_ACK_TIMEOUT {
                    return true;
                }
                timer.as_mut().reset(now + SAMPLE_INTERVAL);
                let _ = timer.as_mut().poll(cx);
            }
            idle_or_unavailable => {
                self.timer = None;
                self.outstanding = None;
                self.unavailable = idle_or_unavailable.is_none();
                if !self.unavailable {
                    self.register_idle_reader(cx);
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use std::task::Poll;

    #[tokio::test(start_paused = true)]
    async fn partial_ack_progress_renews_the_outstanding_deadline() {
        let mut watch = OrderedAckWatch::default();
        watch.note_write();
        let started = Instant::now();
        poll_fn(|cx| {
            let stalled = watch.poll(cx, || {
                // Keep packets outstanding while a partial ACK advances the
                // watermark one sample before the first deadline.
                Some((2, u64::from(started.elapsed() >= ORDERED_ACK_TIMEOUT)))
            });
            if stalled {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        assert_eq!(started.elapsed(), 2 * ORDERED_ACK_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_or_unavailable_observations_do_not_close_a_child() {
        for sample in [None, Some((0, 23))] {
            let mut watch = OrderedAckWatch::default();
            watch.note_write();
            tokio::time::advance(SAMPLE_INTERVAL).await;
            poll_fn(|cx| {
                assert!(!watch.poll(cx, || sample));
                assert!(watch.timer.is_none());
                Poll::Ready(())
            })
            .await;
            watch.note_write();
            assert_eq!(watch.timer.is_some(), sample.is_some());
        }
    }
}
