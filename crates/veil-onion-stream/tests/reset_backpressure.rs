//! Cancellation must stay usable when ordinary writes hit the send high-water.
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Notify, mpsc};
use veil_onion_stream::{
    CellDuplex, Config, End, Frame, OnionStream, send_backpressure, wire::reset_reason,
};

const SID: u32 = 43;
const REASON: u8 = reset_reason::REFUSED;

#[derive(Default)]
struct Observed {
    blocked: Notify,
    closed: Notify,
    resets: Mutex<Vec<u8>>,
    end: Mutex<Option<End>>,
}

struct BlockedData {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    observed: Arc<Observed>,
}

impl CellDuplex for BlockedData {
    async fn send_cell(&mut self, bytes: &[u8]) -> io::Result<()> {
        match Frame::decode(bytes).unwrap() {
            Frame::Syn { isn, .. } => self
                .tx
                .try_send(
                    Frame::SynAck {
                        stream_id: SID,
                        isn: 500,
                        ack: isn.wrapping_add(1),
                        win: 65536,
                    }
                    .encode(),
                )
                .unwrap(),
            Frame::Data { .. } => {
                self.observed.blocked.notify_one();
                return Err(send_backpressure(Duration::from_secs(1)));
            }
            Frame::Rst { reason, .. } => self.observed.resets.lock().unwrap().push(reason),
            _ => (),
        }
        Ok(())
    }

    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }

    async fn on_stream_closed(&mut self, _: u32, end: End) {
        *self.observed.end.lock().unwrap() = Some(end);
        self.observed.closed.notify_one();
    }
}

async fn full_stream() -> (OnionStream, Arc<Observed>) {
    let observed = Arc::new(Observed::default());
    let (tx, rx) = mpsc::channel(4);
    let stream = OnionStream::connect(
        BlockedData {
            tx,
            rx,
            observed: observed.clone(),
        },
        Config::default(),
        SID,
        100,
    );
    // Exceeds the 4-MiB unsent high-water even after a full initial burst.
    stream.write_all(&vec![0x55; 6 << 20]).await.unwrap();
    observed.blocked.notified().await;
    (stream, observed)
}

async fn closed(observed: &Observed) {
    tokio::time::timeout(Duration::from_millis(20), observed.closed.notified())
        .await
        .expect("reset stayed behind backpressured application writes");
    assert_eq!(*observed.end.lock().unwrap(), Some(End::Reset(REASON)));
    assert_eq!(*observed.resets.lock().unwrap(), vec![REASON]);
}

#[tokio::test(start_paused = true)]
async fn reset_releases_driver_above_send_high_water() {
    let (stream, observed) = full_stream().await;
    stream.reset(REASON).await;
    closed(&observed).await;
    assert!(stream.write_all(b"after reset").await.is_err());
}

#[tokio::test(start_paused = true)]
async fn split_reset_bypasses_a_full_write_queue() {
    let (stream, observed) = full_stream().await;
    let (mut reader, writer) = stream.into_split();
    for _ in 0..8 {
        writer.write_all(b"queued").await.unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(5), writer.write_all(b"overflow"))
            .await
            .is_err(),
        "fixture must actually fill the bounded write queue"
    );
    tokio::time::timeout(Duration::from_millis(20), writer.reset(REASON))
        .await
        .expect("reset itself blocked on the full write queue");
    assert_eq!(
        reader.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    closed(&observed).await;
    assert!(writer.write_all(b"after reset").await.is_err());
}

#[tokio::test(start_paused = true)]
async fn local_reader_abort_does_not_send_a_wire_reset() {
    let (stream, observed) = full_stream().await;
    let (mut reader, writer) = stream.into_split();
    writer.abort_local(REASON);
    assert_eq!(
        reader.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    assert!(observed.resets.lock().unwrap().is_empty());
    assert!(observed.end.lock().unwrap().is_none());
    writer.reset(REASON).await;
    closed(&observed).await;
}

#[tokio::test(start_paused = true)]
async fn abort_handle_releases_a_write_holding_the_writer_mutex() {
    let (stream, observed) = full_stream().await;
    let abort = stream.abort_handle();
    let (mut reader, writer) = stream.into_split();
    for _ in 0..8 {
        writer.write_all(b"queued").await.unwrap();
    }
    // Match FFI: write_all awaits DATA capacity while holding the write lock.
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let entered = Arc::new(Notify::new());
    let worker = tokio::spawn({
        let writer = writer.clone();
        let entered = entered.clone();
        async move {
            let guard = writer.lock().await;
            entered.notify_one();
            guard.write_all(b"blocked write").await
        }
    });
    entered.notified().await;
    assert!(writer.try_lock().is_err());
    abort.reset(REASON);
    // The first cancellation reason wins and no unbounded queue accumulates.
    for _ in 0..100 {
        abort.reset(reset_reason::APP);
    }
    closed(&observed).await;
    let result = tokio::time::timeout(Duration::from_millis(20), worker)
        .await
        .expect("blocked writer survived cancellation")
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(
        reader.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    assert!(writer.try_lock().is_ok());
}
