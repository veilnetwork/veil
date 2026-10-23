//! A graceful application close still owes the peer transport ACKs. The peer
//! below sends a final eight-byte credit and FIN after our send direction ends.
use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use veil_onion_stream::{
    CellDuplex, Config, End, Frame, OnionStream, send_backpressure, wire::SackVec,
};

const SID: u32 = 17;
const CREDIT: &[u8] = b"12345678";
const FINAL_ACK: u32 = 500 + CREDIT.len() as u32 + 1;

#[derive(Default)]
struct Observed {
    ready: AtomicBool,
    blocked: Notify,
    closed: Notify,
    final_acks: AtomicU64,
    resets: AtomicU64,
    rtos: AtomicU64,
    reset_reason: Mutex<Option<u8>>,
    payload: Mutex<Vec<u8>>,
    end: Mutex<Option<End>>,
}

struct Peer {
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    observed: Arc<Observed>,
    block_final_ack: bool,
    sent_tail: bool,
}

impl Peer {
    fn emit(&self, frame: Frame<'_>) {
        let mut bytes = Vec::new();
        frame.encode_into(&mut bytes);
        self.inbound_tx.send(bytes).unwrap();
    }
}

impl CellDuplex for Peer {
    async fn send_cell(&mut self, bytes: &[u8]) -> io::Result<()> {
        match Frame::decode(bytes).unwrap() {
            Frame::Syn { isn, .. } => self.emit(Frame::SynAck {
                stream_id: SID,
                isn: 500,
                ack: isn.wrapping_add(1),
                win: 4096,
            }),
            Frame::Data { seq, payload, .. } => {
                self.observed
                    .payload
                    .lock()
                    .unwrap()
                    .extend_from_slice(payload);
                self.emit(Frame::Ack {
                    stream_id: SID,
                    ack: seq.wrapping_add(payload.len() as u32),
                    win: 4096,
                    sacks: SackVec::new(),
                });
            }
            Frame::Fin { seq, .. } if !self.sent_tail => {
                self.sent_tail = true;
                self.emit(Frame::Ack {
                    stream_id: SID,
                    ack: seq.wrapping_add(1),
                    win: 4096,
                    sacks: SackVec::new(),
                });
                self.emit(Frame::Data {
                    stream_id: SID,
                    seq: 500,
                    win: 4096,
                    payload: CREDIT,
                });
                self.emit(Frame::Fin {
                    stream_id: SID,
                    seq: FINAL_ACK - 1,
                });
            }
            Frame::Ack { ack: FINAL_ACK, .. } => {
                if self.block_final_ack && !self.observed.ready.load(Ordering::Acquire) {
                    self.observed.blocked.notify_one();
                    return Err(send_backpressure(Duration::from_millis(10)));
                }
                self.observed.final_acks.fetch_add(1, Ordering::Relaxed);
            }
            Frame::Rst { reason, .. } => {
                self.observed.resets.fetch_add(1, Ordering::Relaxed);
                *self.observed.reset_reason.lock().unwrap() = Some(reason);
            }
            _ => (),
        }
        Ok(())
    }

    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.inbound_rx.recv().await)
    }

    async fn recv_cells(&mut self, out: &mut Vec<Vec<u8>>, max: usize) -> io::Result<usize> {
        let Some(first) = self.inbound_rx.recv().await else {
            return Ok(0);
        };
        out.push(first);
        let mut count = 1;
        while count < max {
            let Ok(bytes) = self.inbound_rx.try_recv() else {
                break;
            };
            out.push(bytes);
            count += 1;
        }
        Ok(count)
    }

    async fn on_stream_closed(&mut self, _: u32, end: End) {
        *self.observed.end.lock().unwrap() = Some(end);
        self.observed.closed.notify_one();
    }

    async fn on_data_rto(&mut self, _: u32, _: u32, _: u32) {
        self.observed.rtos.fetch_add(1, Ordering::Relaxed);
    }
}

fn fixture(block_final_ack: bool) -> (OnionStream, Arc<Observed>, mpsc::UnboundedSender<Vec<u8>>) {
    fixture_with_config(block_final_ack, Config::default())
}

fn fixture_with_config(
    block_final_ack: bool,
    config: Config,
) -> (OnionStream, Arc<Observed>, mpsc::UnboundedSender<Vec<u8>>) {
    let observed = Arc::new(Observed::default());
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let peer = Peer {
        inbound_tx: inbound_tx.clone(),
        inbound_rx,
        observed: observed.clone(),
        block_final_ack,
        sent_tail: false,
    };
    let stream = OnionStream::connect(
        peer,
        Config {
            mss: 64,
            init_cwnd: 256,
            recv_window: 4096,
            ..config
        },
        SID,
        100,
    );
    (stream, observed, inbound_tx)
}

#[tokio::test(start_paused = true)]
async fn dropping_the_entire_handle_drains_late_credit_without_resetting() {
    let (stream, observed, _) = fixture(false);
    let payload = vec![0x6d; 1024];
    stream.write_all(&payload).await.unwrap();
    drop(stream);
    tokio::time::timeout(Duration::from_secs(2), observed.closed.notified())
        .await
        .unwrap();
    assert_eq!(
        *observed.payload.lock().unwrap(),
        payload,
        "queued writes lost at close"
    );
    assert_eq!(
        observed.resets.load(Ordering::Relaxed),
        0,
        "graceful whole-handle close reset late credit"
    );
    assert_eq!(observed.final_acks.load(Ordering::Relaxed), 1);
    assert_eq!(*observed.end.lock().unwrap(), Some(End::Eof));
    assert_eq!(observed.rtos.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn a_clean_close_retries_its_locally_unaccepted_final_ack() {
    let (mut stream, observed, _) = fixture(true);
    stream.finish().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), observed.blocked.notified())
        .await
        .unwrap();
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    let closed_early = observed.end.lock().unwrap().is_some();
    observed.ready.store(true, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(1), observed.closed.notified())
        .await
        .unwrap();
    let mut bytes = [0; 16];
    assert_eq!(stream.read(&mut bytes).await.unwrap(), CREDIT.len());
    assert_eq!(&bytes[..CREDIT.len()], CREDIT);
    assert_eq!(stream.read(&mut bytes).await.unwrap(), 0);
    assert!(
        !closed_early,
        "driver retired while its final ACK was only locally queued"
    );
    assert_eq!(observed.final_acks.load(Ordering::Relaxed), 1);
    assert_eq!(*observed.end.lock().unwrap(), Some(End::Eof));
    assert_eq!(observed.rtos.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn dropping_only_the_reader_preserves_explicit_abort_behavior() {
    let (stream, observed, _) = fixture(false);
    let (reader, writer) = stream.into_split();
    drop(reader);
    writer.finish().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), observed.closed.notified())
        .await
        .unwrap();
    assert_eq!(observed.resets.load(Ordering::Relaxed), 1);
    assert_eq!(
        *observed.reset_reason.lock().unwrap(),
        Some(veil_onion_stream::wire::reset_reason::APP)
    );
}

#[tokio::test(start_paused = true)]
async fn a_permanently_unavailable_final_ack_does_not_leak_a_driver() {
    let (stream, observed, _) = fixture_with_config(
        true,
        Config {
            min_rto_ms: 10,
            init_rto_ms: 50,
            max_rto_ms: 50,
            max_retransmits: 2,
            ..Config::default()
        },
    );
    // Exercise the detached graceful-close path as well as the byte-draining
    // path: there is no application handle left to cancel this driver.
    drop(stream);
    tokio::time::timeout(Duration::from_secs(1), observed.blocked.notified())
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_millis(200), observed.closed.notified())
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert_eq!(observed.final_acks.load(Ordering::Relaxed), 0);
    assert_eq!(
        observed.rtos.load(Ordering::Relaxed),
        0,
        "local close wait was reported as network loss"
    );
    assert_eq!(
        *observed.reset_reason.lock().unwrap(),
        Some(veil_onion_stream::wire::reset_reason::TIMED_OUT)
    );
}

#[tokio::test(start_paused = true)]
async fn final_ack_backpressure_still_observes_explicit_cancellation() {
    let (stream, observed, _) = fixture(true);
    stream.finish().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), observed.blocked.notified())
        .await
        .unwrap();
    stream
        .reset(veil_onion_stream::wire::reset_reason::APP)
        .await;
    tokio::time::timeout(Duration::from_millis(20), observed.closed.notified())
        .await
        .unwrap();
    assert_eq!(observed.final_acks.load(Ordering::Relaxed), 0);
    assert_eq!(
        *observed.reset_reason.lock().unwrap(),
        Some(veil_onion_stream::wire::reset_reason::APP)
    );
}
