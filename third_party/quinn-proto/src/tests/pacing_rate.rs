//! Exercise the production packet builder, not just the token arithmetic.
use super::*;
use crate::congestion::{Controller, ControllerFactory, ControllerMetrics};

struct RateFactory;
#[derive(Clone)]
struct RateController;
impl ControllerFactory for RateFactory {
    fn build(self: Arc<Self>, _: Instant, _: u16) -> Box<dyn Controller> {
        Box::new(RateController)
    }
}
impl Controller for RateController {
    fn on_congestion_event(&mut self, _: Instant, _: Instant, _: bool, _: u64) {}
    fn on_mtu_update(&mut self, _: u16) {}
    fn window(&self) -> u64 {
        1024 * 1024
    }
    fn initial_window(&self) -> u64 {
        self.window()
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: Some(256_000),
        }
    }
}

#[test]
fn controller_rate_reaches_the_real_encrypted_datagram_sender() {
    let _guard = subscribe();
    let mut config = TransportConfig::default();
    config.congestion_controller_factory(Arc::new(RateFactory));
    config.datagram_send_buffer_size(128 * 1024);
    let mut client = client_config();
    client.transport_config(Arc::new(config));
    let mut pair = Pair::default();
    let (client, server) = pair.connect_with(client);
    pair.drive();
    let started = pair.time;
    for n in 0..64u8 {
        pair.client_conn_mut(client)
            .datagrams()
            .send(Bytes::from(vec![n; 1024]), false)
            .unwrap();
    }
    pair.drive();
    assert!(
        pair.time.duration_since(started) > Duration::from_secs(1),
        "a large cwnd cannot bypass a 32-KB/s controller rate"
    );
    let mut count = 0;
    while let Some(packet) = pair.server_conn_mut(server).datagrams().recv() {
        assert_eq!(packet.as_ref(), vec![count; 1024]);
        count += 1;
    }
    assert_eq!(count, 64);
}

#[test]
fn a_lone_timed_datagram_can_spend_less_than_a_full_mtu_of_pacing_credit() {
    let mut config = TransportConfig::default();
    config.congestion_controller_factory(Arc::new(RateFactory));
    config.enable_segmentation_offload(false);
    config.mtu_discovery_config(None);
    let mut client_config = client_config();
    client_config.transport_config(Arc::new(config));
    let mut pair = Pair::default();
    let (client, _) = pair.connect_with(client_config);
    pair.drive();

    let now = pair.time;
    let conn = pair.client_conn_mut(client);
    conn.path_changed(now);
    let before = conn.stats().frame_tx.datagram;
    let mut buf = Vec::new();
    for _ in 0..2 {
        conn.datagrams()
            .send(Bytes::from(vec![1; 1024]), false)
            .unwrap();
        assert!(conn.poll_transmit(now, 1, &mut buf).is_some());
        buf.clear();
    }
    assert_eq!(conn.stats().frame_tx.datagram, before + 2);

    conn.datagrams()
        .send_with_expiry_at(
            Bytes::from(vec![2; 64]),
            false,
            now + Duration::from_millis(16),
            now,
        )
        .unwrap();
    let small = conn
        .poll_transmit(now, 1, &mut buf)
        .expect("remaining credit fits the timed packet");
    assert!(small.size < usize::from(conn.current_mtu()));
    assert_eq!(conn.stats().frame_tx.datagram, before + 3);
    buf.clear();

    conn.datagrams()
        .send_with_expiry_at(
            Bytes::from(vec![3; 512]),
            false,
            now + Duration::from_millis(20),
            now,
        )
        .unwrap();
    assert!(conn.poll_transmit(now, 1, &mut buf).is_none());
    let paced = conn.poll_timeout().unwrap();
    assert!(paced > now && paced < now + Duration::from_millis(20));
    conn.handle_timeout(paced);
    assert!(conn.poll_transmit(paced, 1, &mut buf).is_some());
    assert_eq!(conn.stats().frame_tx.datagram, before + 4);
    assert_eq!(conn.datagrams().expired_outgoing(), 0);
}
