//! Stateless records carried by an already authenticated generic QUIC child.
//! Local origin chooses an outgoing source; incoming traffic has no such privilege.
use super::*;
use crate::parallel_binding::ParallelParentHandle;
use crate::reliable_frames::ReliableFrameHandle;

/// A complete authenticated record, retaining the parent authorization witness.
pub struct Received {
    /// Local FIFO retirement marker, after every completed authenticated frame.
    /// Never serialized on the wire.
    pub(crate) ended: bool,
    pub(crate) frame: veil_bufpool::PooledShared,
    pub(crate) parent: ParallelParentHandle,
    pub(crate) handle: ReliableFrameHandle,
    pub(crate) received_at: tokio::time::Instant,
}

pub(crate) fn eligible(frame: &[u8]) -> bool {
    eligible_direction(frame, false)
}

/// An own keepalive probes the canonical TX leg. Sending it on a healthy
/// auxiliary child would clear that probe while the parent remains blocked.
/// Receive eligibility and replies, including KeepaliveAck, stay unchanged.
pub(crate) fn outgoing_eligible(frame: &[u8]) -> bool {
    eligible_direction(frame, true)
}

fn eligible_direction(frame: &[u8], outgoing: bool) -> bool {
    if !crate::reliable_frames::valid_plain(frame) || decode_realtime_lane_frame(frame).is_some() {
        return false;
    }
    let Ok(header) = decode_header(frame) else {
        return false;
    };
    if header.family == FrameFamily::Session as u8 {
        return false;
    }
    if outgoing
        && header.family == FrameFamily::Control as u8
        && header.msg_type == ControlMsg::Keepalive as u16
    {
        return false;
    }
    if header.family == FrameFamily::App as u8 {
        return super::reliable_streams::direct_app_record(
            &header,
            &frame[veil_proto::header::HEADER_SIZE..],
        );
    }
    // Stream-bearing protocols keep their pinned carrier and rekey machinery.
    header.stream_id == 0
        && FrameFamily::try_from(header.family)
            .is_ok_and(|family| !matches!(family, FrameFamily::LocalApp))
}

/// Preserve the canonical response policy. Peer-triggered application,
/// discovery and delivery replies carry no trusted own-source credit/class.
/// Only existing session/control responses use the bounded local control lane.
pub(super) fn response(frame: Vec<u8>) -> crate::frame_outbox::FrameEnvelope {
    let control = decode_header(&frame).is_ok_and(|header| {
        header.family == FrameFamily::Session as u8 || header.family == FrameFamily::Control as u8
    });
    let priority = if control {
        crate::LOCAL_NETWORK_CONTROL_LANE
    } else {
        veil_proto::priority::INTERACTIVE
    };
    (priority, veil_bufpool::pooled_shared_from_vec(frame)).into()
}

pub(in crate::runner) fn spawn(
    owner: Arc<crate::reliable_frames::ReliableFrameChannel>,
    parent: ParallelParentHandle,
    outgoing: mpsc::Sender<Received>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let handle = owner.handle();
        loop {
            let frame = tokio::select! {
                biased;
                _ = parent.retired() => break,
                frame = handle.recv() => match frame { Ok(frame) => frame, Err(_) => break },
            };
            let event = Received {
                ended: false,
                frame,
                parent: parent.clone(),
                handle: handle.clone(),
                received_at: tokio::time::Instant::now(),
            };
            if !tokio::select! {
                biased;
                _ = parent.retired() => false,
                result = outgoing.send(event) => result.is_ok(),
            } {
                break;
            }
        }
        if parent.is_active() {
            let event = Received {
                ended: true,
                frame: veil_bufpool::pooled_shared_from_vec(Vec::new()),
                parent: parent.clone(),
                handle: handle.clone(),
                received_at: tokio::time::Instant::now(),
            };
            tokio::select! {
                biased;
                _ = parent.retired() => {},
                _ = outgoing.send(event) => {},
            }
        }
        handle.close();
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parallel_binding::ParallelParent, reliable_frames::ReliableFrameChannel};
    use tokio::time::{Duration, timeout};

    #[test]
    fn own_keepalive_probe_stays_canonical_without_rejecting_received_control() {
        let probe = crate::keepalive_emit::build_keepalive_frame();
        assert!(eligible(&probe), "receive compatibility must not change");
        assert!(
            !outgoing_eligible(&probe),
            "TX probe must observe its parent"
        );
        let mut ack = probe.clone();
        let mut header = decode_header(&ack).unwrap();
        header.msg_type = ControlMsg::KeepaliveAck as u16;
        ack[..veil_proto::header::HEADER_SIZE]
            .copy_from_slice(&veil_proto::codec::encode_header(&header));
        assert!(outgoing_eligible(&ack));
    }
    #[test]
    fn peer_triggered_data_replies_keep_neutral_local_admission() {
        use crate::priority_queue::{HeadAdmission, PriorityQueue};
        for (family, msg, priority) in [
            (
                FrameFamily::Discovery,
                DiscoveryMsg::FindValueResponse as u16,
                veil_proto::priority::INTERACTIVE,
            ),
            (
                FrameFamily::Delivery,
                veil_proto::DeliveryMsg::DeliveryStatus as u16,
                veil_proto::priority::INTERACTIVE,
            ),
            (
                FrameFamily::App,
                AppMsg::AppSendUnopenable as u16,
                veil_proto::priority::INTERACTIVE,
            ),
            (
                FrameFamily::Control,
                ControlMsg::KeepaliveAck as u16,
                crate::LOCAL_NETWORK_CONTROL_LANE,
            ),
        ] {
            let header = FrameHeader::new(family as u8, msg); // default wire flags even claim REALTIME
            let reply = response(veil_proto::codec::encode_header(&header).to_vec());
            assert_eq!(reply.frame.0, priority);
            assert!(reply.reliable_credit.is_none());
            let mut queue = PriorityQueue::with_default_weights();
            queue.push_envelope(reply, false);
            assert!(
                queue
                    .pop_admitted_envelope(|actual, _, own, _| {
                        assert_eq!(actual, priority);
                        assert!(!own, "a response to a peer is not an own file source");
                        HeadAdmission::Allow
                    })
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn auxiliary_reader_drains_completed_records_after_transport_eof() {
        timeout(Duration::from_secs(3), async {
            let pa = ParallelParent::new([1; 32], [2; 32], [3; 32]);
            let pb = ParallelParent::new([1; 32], [3; 32], [2; 32]);
            let (hello, pending) = pa.begin_reliable([4; 32]).unwrap();
            let (ack, bkeys) = pb.accept_reliable(&hello, [4; 32]).unwrap();
            let (left, right) = tokio::io::duplex(16384);
            let a = ReliableFrameChannel::new(
                pending
                    .finish(&ack)
                    .unwrap()
                    .into_reliable(Box::new(left))
                    .unwrap(),
            );
            let b = Arc::new(ReliableFrameChannel::new(
                bkeys.into_reliable(Box::new(right)).unwrap(),
            ));
            let weak = Arc::downgrade(&b);
            let (send, mut recv) = mpsc::channel(1);
            let task = spawn(b.clone(), pb.handle(), send);
            for n in 0..4u8 {
                let mut h = FrameHeader::new(
                    FrameFamily::Discovery as u8,
                    DiscoveryMsg::FindValueResponse as u16,
                );
                h.body_len = 1;
                let plain =
                    veil_bufpool::pooled_shared_from_vec(veil_proto::codec::encode_frame(&h, &[n]));
                a.handle()
                    .try_send((crate::LOCAL_NETWORK_CONTROL_LANE, plain).into())
                    .ok()
                    .unwrap()
                    .wait()
                    .await
                    .unwrap();
            }
            while b.handle().record_progress().received_records != 4 {
                tokio::task::yield_now().await;
            }
            drop(a); // EOF, while the single-event forwarding queue is full.
            b.handle().retire_tx();
            drop(b); // The draining task must own the codec through its tail.
            for n in 0..4u8 {
                let event = recv.recv().await.unwrap();
                assert!(event.parent.is_active());
                assert_eq!(&event.frame[veil_proto::header::HEADER_SIZE..], &[n]);
            }
            let ended = recv.recv().await.unwrap();
            assert!(ended.ended && ended.frame.is_empty() && ended.parent.is_active());
            task.await.unwrap();
            assert!(weak.upgrade().is_none());
            assert!(recv.recv().await.is_none());
        })
        .await
        .unwrap();
    }
}
