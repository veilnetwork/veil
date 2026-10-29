//! A full but responsive peer must survive beyond the normal loss retry budget.
use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use veil_onion_stream::{CellDuplex, Config, End, Frame, OnionStream, wire::SackVec};

struct Peer {
    replies: mpsc::UnboundedSender<Vec<u8>>,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    next: u32,
    ready_at: tokio::time::Instant,
    received: Arc<Mutex<Vec<u8>>>,
    refused: Arc<AtomicUsize>,
    loss_events: Arc<AtomicUsize>,
    closed: Arc<Notify>,
}
impl CellDuplex for Peer {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        let frame = Frame::decode(cell).unwrap();
        let sid = frame.stream_id();
        let mut finish = false;
        match frame {
            Frame::Syn { isn, .. } => {
                self.next = isn.wrapping_add(1);
                self.replies
                    .send(
                        Frame::SynAck {
                            stream_id: sid,
                            isn: 500,
                            ack: self.next,
                            win: 0,
                        }
                        .encode(),
                    )
                    .unwrap();
                return Ok(());
            }
            Frame::Data { seq, payload, .. } => {
                if tokio::time::Instant::now() < self.ready_at {
                    assert!(self.received.lock().unwrap().is_empty());
                    assert_eq!(payload.len(), 1, "zero-window peer got normal DATA");
                    self.refused.fetch_add(1, Ordering::Relaxed);
                    // Refuse the byte: keep cumulative ACK at the old value.
                } else if seq == self.next {
                    self.received.lock().unwrap().extend_from_slice(payload);
                    self.next = self.next.wrapping_add(payload.len() as u32);
                }
            }
            Frame::Fin { seq, .. } if seq == self.next => {
                self.next = self.next.wrapping_add(1);
                finish = true;
            }
            _ => return Ok(()),
        }
        let win = if tokio::time::Instant::now() < self.ready_at {
            0
        } else {
            4096
        };
        self.replies
            .send(
                Frame::Ack {
                    stream_id: sid,
                    ack: self.next,
                    win,
                    sacks: SackVec::new(),
                }
                .encode(),
            )
            .unwrap();
        if finish {
            self.replies
                .send(
                    Frame::Fin {
                        stream_id: sid,
                        seq: 500,
                    }
                    .encode(),
                )
                .unwrap();
        }
        Ok(())
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.incoming.recv().await)
    }
    async fn on_data_rto(&mut self, _: u32, _: u32, _: u32) {
        self.loss_events.fetch_add(1, Ordering::Relaxed);
    }
    async fn on_stream_closed(&mut self, _: u32, _: End) {
        eprintln!(
            "persist_driver_closed refused={} received={} losses={}",
            self.refused.load(Ordering::Relaxed),
            self.received.lock().unwrap().len(),
            self.loss_events.load(Ordering::Relaxed)
        );
        self.closed.notify_one();
    }
}

#[tokio::test(start_paused = true)]
async fn responsive_full_peer_survives_then_receives_exact_bytes_and_clean_eof() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (tx, rx) = mpsc::unbounded_channel();
        let received = Arc::new(Mutex::new(Vec::new()));
        let refused = Arc::new(AtomicUsize::new(0));
        let loss = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(Notify::new());
        let stream = OnionStream::connect(
            Peer {
                replies: tx,
                incoming: rx,
                next: 0,
                ready_at: tokio::time::Instant::now() + Duration::from_millis(2000),
                received: received.clone(),
                refused: refused.clone(),
                loss_events: loss.clone(),
                closed: closed.clone(),
            },
            Config {
                mss: 16,
                init_rto_ms: 50,
                min_rto_ms: 50,
                max_rto_ms: 400,
                max_retransmits: 2,
                rack: true,
                rto_rewind_no_sack: true,
                ..Config::default()
            },
            7,
            100,
        );
        let payload: Vec<u8> = (0..256).map(|i| i as u8).collect();
        stream.write_all(&payload).await.unwrap();
        stream.finish().await.unwrap();
        let mut stream = stream;
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        closed.notified().await;
        assert_eq!(*received.lock().unwrap(), payload);
        assert!(
            refused.load(Ordering::Relaxed) > 2,
            "test never exceeded retry budget"
        );
        assert_eq!(
            loss.load(Ordering::Relaxed),
            0,
            "flow control became a route loss event"
        );
    })
    .await
    .expect("persist driver watchdog expired");
}
