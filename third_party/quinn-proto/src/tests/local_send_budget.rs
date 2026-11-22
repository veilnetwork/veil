use super::*;
use crate::local_send_budget::LocalSendBudget;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    task::Waker,
};

#[derive(Debug, Default)]
struct Budget {
    limit: Option<AtomicU64>,
    mtu_probe_wake: Option<Instant>,
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
    fn window(&self, _: Instant, path_flight: u64, mtu: u16) -> u64 {
        if self.mtu_probe_wake.is_some() {
            return path_flight + u64::from(mtu) + 1;
        }
        self.limit
            .as_ref()
            .map_or(2401, |limit| limit.load(Ordering::SeqCst))
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
        self.mtu_probe_wake
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
fn blocked_local_datagram_does_not_hold_a_due_ack() {
    let mut pair = Pair::default();
    let (client, server) = pair.connect();
    pair.drive();
    let budget = Arc::new(Budget {
        limit: Some(AtomicU64::new(1)),
        ..Default::default()
    });
    assert!(pair
        .server_conn_mut(server)
        .set_local_send_budget(budget.clone()));

    let baseline = pair.client_conn_mut(client).stats().frame_rx;
    let before_flight = budget.flight.load(Ordering::SeqCst);
    let message = b"queued camera packet";
    pair.server_datagrams(server)
        .send(Bytes::from_static(message), false)
        .unwrap();

    pair.client_conn_mut(client).immediate_ack();
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();
    let received = pair.client_conn_mut(client).stats().frame_rx;
    assert_eq!(
        received.acks,
        baseline.acks + 1,
        "a due ACK must leave despite the blocked DATAGRAM"
    );
    assert_eq!(received.datagram, baseline.datagram);
    assert_eq!(budget.flight.load(Ordering::SeqCst), before_flight);

    budget.limit.as_ref().unwrap().store(2401, Ordering::SeqCst);
    pair.drive();
    assert_eq!(
        pair.client_datagrams(client).recv().as_deref(),
        Some(message.as_slice())
    );
}

#[test]
fn a_blocked_mtu_probe_cannot_postpone_an_eligible_datagram() {
    let mut transport = TransportConfig::default();
    transport.enable_segmentation_offload(false);
    let mut congestion = crate::congestion::CubicConfig::default();
    congestion.initial_window(1024 * 1024);
    transport.congestion_controller_factory(Arc::new(congestion));
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let mut pair = Pair::default();
    let (client, _server) = pair.connect_with(config);
    pair.drive();

    let now = pair.time;
    let expires = now + Duration::from_millis(100);
    let conn = pair.client_conn_mut(client);
    conn.path_changed(now);
    // After resetting the path, normal packets fit. The next MTU discovery
    // probe is larger and the shared budget asks us to retry it much later.
    assert!(conn.set_local_send_budget(Arc::new(Budget {
        mtu_probe_wake: Some(now + Duration::from_secs(2)),
        ..Default::default()
    })));
    for _ in 0..16 {
        conn.datagrams()
            .send_with_expiry_at(Bytes::from(vec![7; 1024]), false, expires, now)
            .unwrap();
    }
    let before = conn.stats().frame_tx.datagram;
    let mut buf = Vec::new();
    let mut sent = 0;
    while conn.poll_transmit(now, 1, &mut buf).is_some() {
        sent += 1;
        buf.clear();
        assert!(sent < 16, "the native pacer should spend its burst credit");
    }
    assert!(sent > 0);
    assert_eq!(conn.stats().frame_tx.datagram, before + sent);
    let paced = conn.poll_timeout().unwrap();
    assert!(paced > now);
    conn.handle_timeout(paced);
    assert_eq!(
        conn.datagrams().expired_outgoing(),
        0,
        "the MTU probe must not make ordinary paced datagrams expire"
    );
    assert!(paced < expires);
    assert!(conn.poll_transmit(paced, 1, &mut buf).is_some());
    assert_eq!(conn.stats().frame_tx.datagram, before + sent + 1);
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
