//! Rewinding a resegmented flight must retain only unacknowledged bytes.
use veil_onion_stream::{Config, Frame, StreamEngine};

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;
use veil_onion_stream::{CellDuplex, End, OnionStream};

#[test]
fn late_partial_ack_then_another_rewind_does_not_repeat_application_credit() {
    for rack in [false, true] {
        for iss in [100, u32::MAX - 12] {
            let config = Config {
                mss: 16,
                init_cwnd: 64,
                recv_window: 4096,
                init_rto_ms: 50,
                min_rto_ms: 10,
                max_rto_ms: 1000,
                max_retransmits: 10,
                rto_rewind_no_sack: true,
                ack_every: 1,
                rack,
                ..Config::default()
            };
            let mut sender = StreamEngine::connect(7, config, 0, iss);
            let mut peer = StreamEngine::accept(7, config, 0, 500);
            let mut frame = Vec::new();
            assert!(sender.poll_transmit(0, &mut frame));
            peer.on_cell(&frame, 0);
            assert!(peer.poll_transmit(0, &mut frame));
            sender.on_cell(&frame, 0);
            while sender.poll_transmit(0, &mut frame) {
                peer.on_cell(&frame, 0);
            }

            let first = 65_536u64.to_be_bytes();
            let second = 131_072u64.to_be_bytes();
            sender.write(&first);
            assert!(sender.poll_transmit(1, &mut frame));
            assert!(
                matches!(Frame::decode(&frame), Some(Frame::Data { payload, .. }) if payload == first)
            );
            peer.on_cell(&frame, 1);
            assert!(peer.poll_transmit(1, &mut frame));
            let late_ack = frame.clone();
            assert!(matches!(Frame::decode(&late_ack), Some(Frame::Ack { .. })));

            // The original eight-byte segment arrived, but its ACK is delayed.
            // A rewind coalesces it with a new eight-byte application credit.
            sender.write(&second);
            sender.on_timeout(51);
            assert!(sender.poll_transmit(51, &mut frame));
            assert!(
                matches!(Frame::decode(&frame), Some(Frame::Data { payload, .. }) if payload == [first, second].concat())
            );
            // This new, larger retransmission is lost. The old ACK covers only
            // its first half; the next RTO must not requeue that half again.
            sender.on_cell(&late_ack, 52);
            sender.on_timeout(152);
            assert!(sender.poll_transmit(152, &mut frame));
            peer.on_cell(&frame, 152);
            let mut actual = [0; 32];
            let received = peer.read(&mut actual);
            assert_eq!(
                &actual[..received],
                [first, second].concat(),
                "acked prefix repeated, rack={rack}, wrapping={}",
                iss != 100
            );
        }
    }
}

#[derive(Default)]
struct Received {
    bytes: Mutex<Vec<u8>>,
    first: Notify,
    complete: Notify,
    closed: Notify,
}

struct DelayedAckPeer {
    engine: StreamEngine,
    base: Instant,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    received: Arc<Received>,
    data_sends: usize,
    delayed: Option<Vec<u8>>,
}

impl CellDuplex for DelayedAckPeer {
    async fn send_cell(&mut self, bytes: &[u8]) -> io::Result<()> {
        let data = matches!(Frame::decode(bytes), Some(Frame::Data { .. }));
        if data {
            self.data_sends += 1;
            if self.data_sends == 2 || self.data_sends == 4 {
                return Ok(()); // lose the second original and the new tail
            }
            if self.data_sends == 3 {
                assert!(
                    matches!(Frame::decode(bytes), Some(Frame::Data { payload, .. }) if payload.len() == 16),
                    "fixture did not coalesce the rewind"
                );
                // The larger resegmented retry is lost after real local
                // acceptance. Its first half's old ACK arrives instead.
                self.tx.send(self.delayed.take().unwrap()).unwrap();
                return Ok(());
            }
        }
        let now = self.base.elapsed().as_millis() as u64;
        self.engine.on_cell(bytes, now);
        let mut buf = [0; 64];
        let n = self.engine.read(&mut buf);
        if n > 0 {
            let mut received = self.received.bytes.lock().unwrap();
            received.extend_from_slice(&buf[..n]);
            if received.len() >= 24 {
                self.received.complete.notify_one();
            }
        }
        if self.engine.is_eof() {
            self.engine.finish();
        }
        let mut reply = Vec::new();
        while self.engine.poll_transmit(now, &mut reply) {
            if data
                && self.data_sends == 1
                && matches!(Frame::decode(&reply), Some(Frame::Ack { .. }))
            {
                self.delayed = Some(reply.clone());
                self.received.first.notify_one();
            } else {
                self.tx.send(reply.clone()).unwrap();
            }
        }
        Ok(())
    }

    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }

    async fn on_stream_closed(&mut self, _: u32, _: End) {
        self.received.closed.notify_one();
    }
}

#[tokio::test(start_paused = true)]
async fn real_driver_preserves_credit_bytes_across_partial_ack_rewinds() {
    for rack in [false, true] {
        let config = Config {
            mss: 16,
            init_cwnd: 16, // third credit waits for an ACK or RTO
            recv_window: 4096,
            init_rto_ms: 50,
            min_rto_ms: 10,
            max_rto_ms: 1000,
            max_retransmits: 10,
            rto_rewind_no_sack: true,
            ack_every: 1,
            rack,
            ..Config::default()
        };
        let received = Arc::new(Received::default());
        let (tx, rx) = mpsc::unbounded_channel();
        let peer = DelayedAckPeer {
            engine: StreamEngine::accept(7, config, 0, 500),
            base: Instant::now(),
            tx,
            rx,
            received: received.clone(),
            data_sends: 0,
            delayed: None,
        };
        let stream = OnionStream::connect(peer, config, 7, 100);
        let first = 65_536u64.to_be_bytes();
        let second = 131_072u64.to_be_bytes();
        let third = 196_608u64.to_be_bytes();
        stream.write_all(&first).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), received.first.notified())
            .await
            .unwrap();
        stream.write_all(&[second, third].concat()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), received.complete.notified())
            .await
            .unwrap();
        stream.finish().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), received.closed.notified())
            .await
            .unwrap();
        assert_eq!(
            *received.bytes.lock().unwrap(),
            [first, second, third].concat(),
            "real handoff driver duplicated credit, rack={rack}"
        );
    }
}
