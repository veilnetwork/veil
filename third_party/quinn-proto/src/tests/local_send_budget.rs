use super::*;
use crate::local_send_budget::LocalSendBudget;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    task::Waker,
};

#[derive(Debug, Default)]
struct Budget {
    flight: AtomicU64,
    peak: AtomicU64,
    delivered: AtomicU64,
    routes: AtomicU64,
    closed: AtomicU64,
    idle: AtomicU64,
}
impl LocalSendBudget for Budget {
    fn acquire_transmit(&self, _: Instant) -> Option<Box<dyn Send>> {
        Some(Box::new(()))
    }
    fn window(&self, _: Instant, _: u64, _: u16) -> u64 {
        2401
    }
    fn update_flight(&self, bytes: u64) {
        self.flight.store(bytes, Ordering::SeqCst);
        self.peak.fetch_max(bytes, Ordering::SeqCst);
    }
    fn blocked(&self, _: Instant) {}
    fn app_limited(&self, _: Instant) {
        self.idle.fetch_add(1, Ordering::SeqCst);
    }
    fn delivered(&self, _: Instant, _: Instant, bytes: u64, _: Duration) {
        self.delivered.fetch_add(bytes, Ordering::SeqCst);
    }
    fn route_changed(&self) {
        self.routes.fetch_add(1, Ordering::SeqCst);
    }
    fn next_wakeup(&self, _: Instant) -> Option<Instant> {
        None
    }
    fn register_waker(&self, _: &Waker) {}
    fn closed(&self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn a_local_budget_limits_real_packets_and_survives_a_route_reset() {
    let _guard = subscribe();
    let mut config = TransportConfig::default();
    config.datagram_send_buffer_size(128 * 1024);
    let mut client_config = client_config();
    client_config.transport_config(Arc::new(config));
    let mut pair = Pair::default();
    let (client, server) = pair.connect_with(client_config);
    pair.drive();
    let budget = Arc::new(Budget::default());
    assert!(pair
        .client_conn_mut(client)
        .set_local_send_budget(budget.clone()));
    assert!(pair
        .client_conn_mut(client)
        .set_local_send_budget(budget.clone()));
    assert!(!pair
        .client_conn_mut(client)
        .set_local_send_budget(Arc::new(Budget::default())));
    let now = pair.time;
    pair.client_conn_mut(client).path_changed(now);
    assert_eq!(budget.routes.load(Ordering::SeqCst), 1);
    for n in 0..64u8 {
        pair.client_conn_mut(client)
            .datagrams()
            .send(Bytes::from(vec![n; 1024]), false)
            .unwrap();
    }
    pair.drive();
    let mut count = 0;
    while let Some(data) = pair.server_conn_mut(server).datagrams().recv() {
        assert_eq!(data.as_ref(), vec![count; 1024]);
        count += 1;
    }
    assert_eq!(count, 64);
    assert!(
        budget.peak.load(Ordering::SeqCst) <= 2400,
        "GSO preparation exceeded the shared flight limit: {}",
        budget.peak.load(Ordering::SeqCst)
    );
    assert!(budget.delivered.load(Ordering::SeqCst) >= 64 * 1024);
    assert!(
        budget.idle.load(Ordering::SeqCst) > 0,
        "drained sender must retire old budget demand"
    );
    let conn = pair.client_conn_mut(client);
    let retained: u64 = conn.retained_packet_bytes();
    assert_eq!(
        budget.flight.load(Ordering::SeqCst),
        retained,
        "account all retained paths and spaces exactly"
    );
    drop(pair);
    assert_eq!(
        budget.closed.load(Ordering::SeqCst),
        1,
        "retained inspection handles do not prolong the participant"
    );
}

#[test]
fn a_budget_installed_before_handshake_retires_crypto_flight() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client = pair.begin_connect(client_config());
    let budget = Arc::new(Budget::default());
    assert!(
        pair.client_conn_mut(client)
            .set_local_send_budget(budget.clone())
    );
    pair.drive();
    let _server = pair.server.assert_accept();
    assert!(!pair.client_conn_mut(client).is_handshaking());
    assert!(budget.peak.load(Ordering::SeqCst) > 0);
    assert_eq!(pair.client_conn_mut(client).bytes_in_flight(), 0);
    assert_eq!(
        budget.flight.load(Ordering::SeqCst),
        0,
        "retired Initial/Handshake packets cannot leave phantom source debt"
    );
}
