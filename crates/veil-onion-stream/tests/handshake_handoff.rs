//! Local handshake backpressure must not be reported as a network failure.
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, mpsc};
use veil_onion_stream::{CellDuplex, Config, End, Frame, OnionStream, send_backpressure};

#[derive(Default)]
struct Observations {
    allow: AtomicBool,
    blocked: Notify,
    accepted: Notify,
    rto: Notify,
    rtos: AtomicU64,
    closed: Notify,
}
struct Carrier {
    observations: Arc<Observations>,
    inbound: mpsc::Receiver<Vec<u8>>,
}
impl CellDuplex for Carrier {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        if matches!(
            Frame::decode(cell),
            Some(Frame::Syn { .. } | Frame::SynAck { .. })
        ) {
            if !self.observations.allow.load(Ordering::Acquire) {
                self.observations.blocked.notify_one();
                return Err(send_backpressure(Duration::from_millis(10)));
            }
            // The local carrier really accepts this attempt, then its network
            // path loses it. A genuine handshake RTO must still be reported.
            self.observations.accepted.notify_one();
        }
        Ok(())
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.inbound.recv().await)
    }
    async fn on_handshake_rto(&mut self, _: u32, _: u32) {
        self.observations.rtos.fetch_add(1, Ordering::Relaxed);
        self.observations.rto.notify_one();
    }
    async fn on_stream_closed(&mut self, _: u32, _: End) {
        self.observations.closed.notify_one();
    }
}

#[tokio::test(start_paused = true)]
async fn handshake_recovery_waits_for_local_handoff_in_both_roles() {
    for responder in [false, true] {
        let obs = Arc::new(Observations::default());
        let (tx, rx) = mpsc::channel(8);
        let carrier = Carrier {
            observations: Arc::clone(&obs),
            inbound: rx,
        };
        let cfg = Config {
            handshake_rto_ms: 50,
            ..Config::default()
        };
        let stream = if responder {
            let mut syn = Vec::new();
            Frame::Syn {
                stream_id: 11,
                isn: 100,
                win: 8192,
            }
            .encode_into(&mut syn);
            tx.send(syn).await.unwrap();
            OnionStream::accept(carrier, cfg, 11, 500)
        } else {
            OnionStream::connect(carrier, cfg, 11, 100)
        };
        tokio::time::timeout(Duration::from_millis(20), obs.blocked.notified())
            .await
            .unwrap();
        tokio::time::advance(Duration::from_millis(250)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let before = obs.rtos.load(Ordering::Relaxed);
        obs.allow.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_millis(20), obs.accepted.notified())
            .await
            .unwrap();
        tokio::time::advance(Duration::from_millis(49)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let too_early = obs.rtos.load(Ordering::Relaxed);
        let genuine = tokio::time::timeout(Duration::from_millis(2), obs.rto.notified()).await;
        stream
            .reset(veil_onion_stream::wire::reset_reason::APP)
            .await;
        tokio::time::timeout(Duration::from_millis(20), obs.closed.notified())
            .await
            .unwrap();
        assert_eq!(before, 0, "unhanded handshake triggered network recovery");
        assert_eq!(too_early, 0, "network timer included time waiting locally");
        assert!(genuine.is_ok(), "real accepted handshake loss was ignored");
    }
}

#[tokio::test(start_paused = true)]
async fn a_permanently_blocked_local_handshake_keeps_the_existing_retry_budget() {
    let obs = Arc::new(Observations::default());
    let (_tx, rx) = mpsc::channel(8);
    let carrier = Carrier {
        observations: Arc::clone(&obs),
        inbound: rx,
    };
    let cfg = Config {
        handshake_rto_ms: 50,
        max_retransmits: 2,
        ..Config::default()
    };
    let stream = OnionStream::connect(carrier, cfg, 11, 100);
    tokio::time::timeout(Duration::from_millis(200), obs.closed.notified())
        .await
        .unwrap();
    assert_eq!(
        obs.rtos.load(Ordering::Relaxed),
        0,
        "local rejection became network loss"
    );
    assert_eq!(
        stream.end_reason(),
        End::Reset(veil_onion_stream::wire::reset_reason::TIMED_OUT)
    );
}
