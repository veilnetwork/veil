//! EOF becomes visible only after the driver's read-buffer handoff. Keep the
//! app writer alive while the peer sends its final credit and FIN together.
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::{
    sync::{Notify, mpsc},
    time::{Duration, Instant},
};
use veil_onion_stream::{CellDuplex, Config, End, Frame, OnionStream};

const SID: u32 = 29;
const CREDIT: &[u8] = b"12345678";
const CREDIT_SEQ: u32 = 500;
const FINAL_ACK: u32 = CREDIT_SEQ + CREDIT.len() as u32 + 1;

#[derive(Default)]
struct Observed {
    payload: Mutex<Vec<u8>>,
    fin: AtomicBool,
    final_acks: AtomicUsize,
    linger: AtomicUsize,
    end: Mutex<Option<End>>,
    closed: Notify,
}

struct Peer {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    observed: Arc<Observed>,
    sent_tail: bool,
    drop_first_ack: bool,
    retry_at: Option<Instant>,
}

impl Peer {
    fn emit(&self, frame: Frame<'_>) {
        self.tx.send(frame.encode()).unwrap();
    }

    fn final_fin(&self) -> Frame<'static> {
        Frame::Fin {
            stream_id: SID,
            seq: FINAL_ACK - 1,
        }
    }
}

impl CellDuplex for Peer {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        match Frame::decode(cell).unwrap() {
            Frame::Syn { isn, .. } => self.emit(Frame::SynAck {
                stream_id: SID,
                isn: CREDIT_SEQ,
                ack: isn.wrapping_add(1),
                win: 4096,
            }),
            Frame::Data { seq, payload, .. } => {
                let received = {
                    let mut bytes = self.observed.payload.lock().unwrap();
                    bytes.extend_from_slice(payload);
                    bytes.len()
                };
                self.emit(Frame::Ack {
                    stream_id: SID,
                    ack: seq.wrapping_add(payload.len() as u32),
                    win: 4096,
                    sacks: Default::default(),
                });
                if received == 73 && !self.sent_tail {
                    self.sent_tail = true;
                    self.emit(Frame::Data {
                        stream_id: SID,
                        seq: CREDIT_SEQ,
                        win: 4096,
                        payload: CREDIT,
                    });
                    self.emit(self.final_fin());
                }
            }
            Frame::Fin { seq, .. } => {
                self.observed.fin.store(true, Ordering::Relaxed);
                self.emit(Frame::Ack {
                    stream_id: SID,
                    ack: seq.wrapping_add(1),
                    win: 4096,
                    sacks: Default::default(),
                });
            }
            Frame::Ack { ack: FINAL_ACK, .. } => {
                if self.drop_first_ack {
                    self.drop_first_ack = false;
                    self.retry_at = Some(Instant::now() + Duration::from_millis(50));
                } else {
                    self.observed.final_acks.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ => (),
        }
        Ok(())
    }

    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        if let Some(deadline) = self.retry_at {
            tokio::select! {
                cell = self.rx.recv() => return Ok(cell),
                _ = tokio::time::sleep_until(deadline) => (),
            }
            self.retry_at = None;
            self.emit(self.final_fin());
            return Ok(Some(
                Frame::Data {
                    stream_id: SID,
                    seq: CREDIT_SEQ,
                    win: 4096,
                    payload: CREDIT,
                }
                .encode(),
            ));
        }
        Ok(self.rx.recv().await)
    }

    async fn recv_cells(&mut self, out: &mut Vec<Vec<u8>>, max: usize) -> io::Result<usize> {
        let Some(first) = self.recv_cell().await? else {
            return Ok(0);
        };
        out.push(first);
        let mut n = 1;
        while n < max {
            let Ok(cell) = self.rx.try_recv() else { break };
            out.push(cell);
            n += 1;
        }
        Ok(n)
    }

    async fn on_stream_linger(&mut self, _: u32) {
        self.observed.linger.fetch_add(1, Ordering::Relaxed);
    }

    async fn on_stream_closed(&mut self, _: u32, end: End) {
        *self.observed.end.lock().unwrap() = Some(end);
        self.observed.closed.notify_one();
    }
}

async fn drained_eof_closes_our_half(drop_first_ack: bool) {
    let observed = Arc::new(Observed::default());
    let (tx, rx) = mpsc::unbounded_channel();
    let mut stream = OnionStream::connect(
        Peer {
            tx,
            rx,
            observed: observed.clone(),
            sent_tail: false,
            drop_first_ack,
            retry_at: None,
        },
        Config {
            mss: 64,
            init_cwnd: 256,
            recv_window: 4096,
            close_linger_ms: 120,
            ..Config::default()
        },
        SID,
        100,
    );
    let payload = vec![0x6d; 73];
    stream.write_all(&payload).await.unwrap();
    let mut credit = [0u8; CREDIT.len()];
    assert_eq!(stream.read(&mut credit).await.unwrap(), CREDIT.len());
    assert_eq!(&credit, CREDIT);
    assert_eq!(stream.read(&mut credit).await.unwrap(), 0);
    // Neither finish nor drop may manufacture the courtesy FIN under test.
    let finished = tokio::time::timeout(Duration::from_secs(1), observed.closed.notified()).await;
    let fin = observed.fin.load(Ordering::Relaxed);
    let linger = observed.linger.load(Ordering::Relaxed);
    let acks = observed.final_acks.load(Ordering::Relaxed);
    drop(stream);
    assert!(finished.is_ok(), "driver failed to settle");
    assert!(fin, "EOF handoff retired the route before our FIN was sent");
    assert_eq!(
        linger, 1,
        "the completed FIN exchange must retain its ACK route"
    );
    assert!(
        acks > 0,
        "the peer's final credit and FIN remained unacknowledged"
    );
    assert_eq!(*observed.end.lock().unwrap(), Some(End::Eof));
    assert_eq!(*observed.payload.lock().unwrap(), payload);
}

#[tokio::test(start_paused = true)]
async fn courtesy_fin_is_sent_when_eof_becomes_visible_during_the_read_handoff() {
    drained_eof_closes_our_half(false).await;
}

#[tokio::test(start_paused = true)]
async fn the_same_handoff_keeps_the_route_for_a_lost_final_credit_ack() {
    drained_eof_closes_our_half(true).await;
}
