//! Local budget installation must precede the first Initial, without changing
//! ordinary outgoing or incoming QUIC. No application classification is sent.
use super::*;
use crate::LocalSendBudget;
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::Waker,
    time::{Duration, Instant},
};

#[derive(Debug)]
struct Gate {
    open: AtomicBool,
    created: AtomicUsize,
    id: AtomicU64,
    blocked: AtomicUsize,
    peak: AtomicU64,
    closed: AtomicUsize,
    wake: Mutex<Option<Waker>>,
}
impl Gate {
    fn new(open: bool) -> Arc<Self> {
        Arc::new(Self {
            open: AtomicBool::new(open),
            created: AtomicUsize::new(0),
            id: AtomicU64::new(0),
            blocked: AtomicUsize::new(0),
            peak: AtomicU64::new(0),
            closed: AtomicUsize::new(0),
            wake: Mutex::new(None),
        })
    }
    fn factory(self: &Arc<Self>) -> crate::LocalSendBudgetFactory {
        let gate = self.clone();
        Arc::new(move |id| -> Arc<dyn LocalSendBudget> {
            gate.created.fetch_add(1, Ordering::SeqCst);
            gate.id.store(id, Ordering::SeqCst);
            gate.clone()
        })
    }
    fn release(&self) {
        self.open.store(true, Ordering::SeqCst);
        if let Some(wake) = self.wake.lock().unwrap().as_ref() {
            wake.wake_by_ref();
        }
    }
}
impl LocalSendBudget for Gate {
    fn acquire_transmit(&self, _: Instant) -> Option<Box<dyn Send>> {
        Some(Box::new(()))
    }
    fn window(&self, _: Instant, _: u64, _: u16) -> u64 {
        if self.open.load(Ordering::SeqCst) {
            u64::MAX
        } else {
            0
        }
    }
    fn update_flight(&self, bytes: u64) {
        self.peak.fetch_max(bytes, Ordering::SeqCst);
    }
    fn blocked(&self, _: Instant) {
        self.blocked.fetch_add(1, Ordering::SeqCst);
    }
    fn delivered(&self, _: Instant, _: Instant, _: u64, _: Duration) {}
    fn app_limited(&self, _: Instant) {}
    fn route_changed(&self) {}
    fn next_wakeup(&self, _: Instant) -> Option<Instant> {
        None
    }
    fn register_waker(&self, w: &Waker) {
        *self.wake.lock().unwrap() = Some(w.clone());
    }
    fn closed(&self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}
async fn until(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
fn config(ctx: &TransportContext) -> quinn::ClientConfig {
    let mut config = build_quic_client_config(ctx, vec![]).unwrap();
    let mut transport = context_transport_config(ctx);
    transport.initial_rtt(Duration::from_millis(100));
    config.transport_config(Arc::new(transport));
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_budget_factory_gates_initial_before_driver_and_stays_connection_local() {
    timeout(Duration::from_secs(8), async {
        let ctx = TransportContext::for_debug().unwrap();
        let server = build_server_endpoint(
            build_quic_server_config(&ctx, vec![]).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let gate = Gate::new(false);
        let connecting = client
            .connect_with_local_send_budget_factory(
                config(&ctx),
                server.local_addr().unwrap(),
                "localhost",
                Some(gate.factory()),
            )
            .unwrap();
        assert_eq!(
            gate.created.load(Ordering::SeqCst),
            1,
            "policy must exist before the connect call returns"
        );
        until(|| gate.blocked.load(Ordering::SeqCst) > 0).await;
        assert!(
            timeout(Duration::from_millis(15), server.accept())
                .await
                .is_err(),
            "an unbudgeted Initial escaped before the gate opened"
        );
        gate.release();
        let (outgoing, incoming) = tokio::join!(connecting, async {
            server.accept().await.unwrap().await.unwrap()
        });
        let outgoing = outgoing.unwrap();
        assert_eq!(outgoing.local_trace_id(), gate.id.load(Ordering::SeqCst));
        assert!(
            outgoing.set_local_send_budget(gate.clone()),
            "the early and later attachment must share ownership"
        );
        assert!(
            gate.peak.load(Ordering::SeqCst) > 0,
            "TLS flight must enter the shared ledger before application records"
        );
        assert_eq!(gate.created.load(Ordering::SeqCst), 1);
        assert!(
            incoming.set_local_send_budget(Gate::new(true)),
            "incoming QUIC must not inherit an initiator's policy"
        );
        let ordinary = client
            .connect_with(config(&ctx), server.local_addr().unwrap(), "localhost")
            .unwrap();
        let (ordinary, other) = tokio::join!(ordinary, async {
            server.accept().await.unwrap().await.unwrap()
        });
        let ordinary = ordinary.unwrap();
        assert!(
            ordinary.set_local_send_budget(Gate::new(true)),
            "ordinary connects must retain an empty policy slot"
        );
        assert_eq!(gate.created.load(Ordering::SeqCst), 1);
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
        drop((outgoing, incoming, ordinary, other));
        tokio::join!(client.wait_idle(), server.wait_idle());
        until(|| gate.closed.load(Ordering::SeqCst) > 0).await;
        assert_eq!(gate.closed.load(Ordering::SeqCst), 1);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_a_budgeted_pending_handshake_retires_its_owner_without_closing_the_endpoint() {
    timeout(Duration::from_secs(8), async {
        let ctx = TransportContext::for_debug().unwrap();
        let server = build_server_endpoint(
            build_quic_server_config(&ctx, vec![]).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let gate = Gate::new(false);
        let connecting = client
            .connect_with_local_send_budget_factory(
                config(&ctx),
                server.local_addr().unwrap(),
                "localhost",
                Some(gate.factory()),
            )
            .unwrap();
        until(|| gate.blocked.load(Ordering::SeqCst) > 0).await;
        assert_eq!(gate.peak.load(Ordering::SeqCst), 0);
        drop(connecting);
        until(|| gate.closed.load(Ordering::SeqCst) > 0).await;
        assert_eq!(gate.closed.load(Ordering::SeqCst), 1);
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
        tokio::join!(client.wait_idle(), server.wait_idle());
    })
    .await
    .unwrap();
}
