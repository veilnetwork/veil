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
