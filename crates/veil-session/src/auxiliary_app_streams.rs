//! Pinned App streams on already authenticated generic record channels.
//! Each channel keeps its own bounded response FIFO. A blocked peer cannot
//! block another channel's replies or acquire trusted local source credit.
use super::reliable_streams::Replies;
use crate::reliable_frames::ReliableFrameHandle;
use std::collections::HashMap;

const MAX_CHANNELS: usize = 2 * veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION;

struct Channel {
    handle: ReliableFrameHandle,
    replies: Replies,
}

#[derive(Default)]
pub(super) struct AuxiliaryAppStreams {
    channels: HashMap<[u8; 32], Channel>,
}

impl AuxiliaryAppStreams {
    pub(super) fn attach(&mut self, handle: ReliableFrameHandle) -> Result<[u8; 32], &'static str> {
        if handle.failed() {
            return Err("retired auxiliary App channel");
        }
        self.attach_received(handle)
    }

    pub(super) fn attach_received(
        &mut self,
        handle: ReliableFrameHandle,
    ) -> Result<[u8; 32], &'static str> {
        let id = handle.id();
        if !handle.parent_active() {
            return Err("retired auxiliary App channel");
        }
        if !self.channels.contains_key(&id) && self.channels.len() >= MAX_CHANNELS {
            return Err("auxiliary App channel capacity exceeded");
        }
        self.channels.entry(id).or_insert_with(|| Channel {
            handle,
            replies: Replies::new(),
        });
        Ok(id)
    }

    pub(super) fn handle(&self, id: [u8; 32]) -> Option<ReliableFrameHandle> {
        self.channels
            .get(&id)
            .filter(|c| c.handle.parent_active())
            .map(|c| c.handle.clone())
    }

    pub(super) fn close(&mut self, id: [u8; 32]) {
        if let Some(channel) = self.channels.remove(&id) {
            channel.handle.close();
        }
    }

    pub(super) fn retired(&mut self) -> Vec<[u8; 32]> {
        let ids: Vec<_> = self
            .channels
            .iter()
            .filter(|(_, c)| !c.handle.parent_active())
            .map(|(id, _)| *id)
            .collect();
        for id in &ids {
            self.channels.remove(id);
        }
        ids
    }

    pub(super) fn replies(&mut self, id: [u8; 32]) -> Option<&mut Replies> {
        self.channels
            .get_mut(&id)
            .map(|channel| &mut channel.replies)
    }

    /// Returns completed local admissions, not peer ACKs. Bound per-channel
    /// work per scheduler pass and leave full writers pending without a nonce.
    pub(super) fn flush(
        &mut self,
        mut allow: impl FnMut(usize) -> bool,
    ) -> (Vec<(Vec<u8>, usize)>, bool) {
        use crate::reliable_frames::FrameReservationError;
        let mut sent = Vec::new();
        let mut pending = false;
        for channel in self.channels.values_mut() {
            for _ in 0..8 {
                match channel.replies.try_flush(&channel.handle, &mut allow) {
                    Ok(Some(frame)) => sent.push(frame),
                    Ok(None) => break,
                    Err(FrameReservationError::Full) => {
                        pending = true;
                        break;
                    }
                    // TX failure does not discard already completed RX. The
                    // reader's FIFO End marker retires pins after its tail.
                    Err(_) => {
                        channel.replies.reconcile(None);
                        break;
                    }
                }
            }
            pending |= channel.replies.front().is_some();
        }
        (sent, pending)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        auxiliary_records,
        reliable_streams::{ReliableStreams, Route},
    };
    use super::*;
    use crate::{parallel_binding::ParallelParent, reliable_frames::ReliableFrameChannel};
    use veil_proto::{
        AppMsg, FrameFamily,
        app::{AppClosePayload, AppDataPayload, AppOpenPayload, AppReceiptPayload},
        codec::encode_frame,
        header::FrameHeader,
    };

    fn frame(msg: AppMsg) -> Vec<u8> {
        let body = match msg {
            AppMsg::AppOpen => AppOpenPayload {
                app_id: [5; 32],
                endpoint_id: 17,
                flags: 0,
            }
            .encode()
            .to_vec(),
            AppMsg::AppData => AppDataPayload {
                app_id: [5; 32],
                endpoint_id: 17,
                seq: 0,
                data: vec![8; 1024],
            }
            .encode(),
            AppMsg::AppClose => AppClosePayload {
                app_id: [5; 32],
                endpoint_id: 17,
                reason: 0,
            }
            .encode()
            .to_vec(),
            AppMsg::AppReceipt => AppReceiptPayload {
                app_id: [5; 32],
                endpoint_id: 17,
                seq: 0,
                status: 0,
            }
            .encode()
            .to_vec(),
            _ => unreachable!(),
        };
        let mut h = FrameHeader::new(FrameFamily::App as u8, msg as u16);
        h.stream_id = 51;
        h.body_len = body.len() as u32;
        encode_frame(&h, &body)
    }

    #[tokio::test]
    async fn auxiliary_app_streams_drain_completed_rx_before_fifo_retirement() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let pa = ParallelParent::new([1; 32], [2; 32], [3; 32]);
            let pb = ParallelParent::new([1; 32], [3; 32], [2; 32]);
            let (hello, pending) = pa.begin_reliable([4; 32]).unwrap();
            let (ack, keys) = pb.accept_reliable(&hello, [4; 32]).unwrap();
            let (left, right) = tokio::io::duplex(16384);
            let a = ReliableFrameChannel::new(
                pending
                    .finish(&ack)
                    .unwrap()
                    .into_reliable(Box::new(left))
                    .unwrap(),
            );
            let b = std::sync::Arc::new(ReliableFrameChannel::new(
                keys.into_reliable(Box::new(right)).unwrap(),
            ));
            let (send, mut recv) = tokio::sync::mpsc::channel(1);
            let reader = auxiliary_records::spawn(b.clone(), pb.handle(), send);
            let expected = [
                frame(AppMsg::AppOpen),
                frame(AppMsg::AppData),
                frame(AppMsg::AppClose),
            ];
            for plain in &expected {
                a.handle()
                    .try_send(
                        (
                            veil_proto::priority::INTERACTIVE,
                            veil_bufpool::pooled_shared_from_vec(plain.clone()),
                        )
                            .into(),
                    )
                    .ok()
                    .unwrap()
                    .wait()
                    .await
                    .unwrap();
            }
            while b.handle().record_progress().received_records != 3 {
                tokio::task::yield_now().await;
            }
            // The TX actor can fail after the scheduler reserves a slot but
            // before it commits. That failure must preserve the same RX tail.
            let reserved = b.handle().try_reserve(&frame(AppMsg::AppReceipt)).unwrap();
            drop(a);
            b.handle().retire_tx();
            assert!(matches!(
                reserved.commit(
                    (
                        veil_proto::priority::INTERACTIVE,
                        veil_bufpool::pooled_shared_from_vec(frame(AppMsg::AppReceipt))
                    )
                        .into()
                ),
                Err(crate::reliable_frames::FrameAdmissionError::Closed(_))
            ));
            drop(b); // RX tail still belongs to the reader, not a live TX actor.
            let ctx = crate::runner::ordered_receiver_tests::pool_fixture_context();
            let mut streams = ReliableStreams::new(true, ctx.dispatcher, ctx.peer_id);
            let mut channels = AuxiliaryAppStreams::default();
            let mut count = 0;
            loop {
                let event = recv.recv().await.unwrap();
                let id = event.handle.id();
                if event.ended {
                    assert_eq!(count, expected.len());
                    channels.close(id);
                    streams.fail_child(id);
                    assert_eq!(
                        streams.route(&frame(AppMsg::AppData), Some([99; 32])),
                        Route::Failed
                    );
                    break;
                }
                assert_eq!(&*event.frame, expected[count].as_slice());
                channels.attach_received(event.handle).unwrap();
                streams.incoming(&event.frame, Route::Child(id)).unwrap();
                channels
                    .replies(id)
                    .unwrap()
                    .push(id, frame(AppMsg::AppReceipt))
                    .unwrap();
                let (sent, pending) = channels.flush(|_| true);
                assert!(
                    sent.is_empty() && !pending,
                    "failed TX cannot stop RX drain"
                );
                assert!(channels.retired().is_empty());
                streams.reconcile_with(|id| channels.handle(id).is_some());
                count += 1;
            }
            reader.await.unwrap();
            assert!(recv.recv().await.is_none());
        })
        .await
        .unwrap();
    }
}
