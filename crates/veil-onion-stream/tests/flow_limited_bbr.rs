//! Closed receive windows are not measurements of network bottleneck capacity.
use veil_onion_stream::{Config, Frame, StreamEngine};

fn transmit(engine: &mut StreamEngine, now: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    assert!(engine.poll_transmit(now, &mut bytes), "expected a cell");
    bytes
}

#[test]
fn peer_window_wait_does_not_seed_a_false_bandwidth_sample() {
    let cfg = Config {
        mss: 64,
        init_cwnd: 128,
        recv_window: 128,
        ack_every: 1,
        bbr: true,
        ..Config::default()
    };
    let mut a = StreamEngine::connect(7, cfg, 0, 100);
    let mut b = StreamEngine::accept(7, cfg, 0, 500);
    b.on_cell(&transmit(&mut a, 0), 0);
    a.on_cell(&transmit(&mut b, 0), 0);
    b.on_cell(&transmit(&mut a, 0), 0);
    a.write(&[3; 4096]);
    for now in [1, 1001] {
        for _ in 0..2 {
            b.on_cell(&transmit(&mut a, now), now);
        }
        let closed = transmit(&mut b, now + 1);
        assert!(matches!(
            Frame::decode(&closed),
            Some(Frame::Ack { win: 0, .. })
        ));
        a.on_cell(&closed, now + 1);
        assert!(!a.poll_transmit(now + 1, &mut Vec::new()));
        assert_eq!(b.read(&mut [0; 128]), 128);
        // Delay the real reopening ACK: a slow/stopped application, not a
        // slow network. No DATA is in flight during the zero-window interval.
        let reopened = transmit(&mut b, now + 900);
        assert!(matches!(
            Frame::decode(&reopened),
            Some(Frame::Ack { win: 128, .. })
        ));
        a.on_cell(&reopened, now + 900);
    }
    let (bandwidth, _, delivered) = a.delivery_model();
    assert_eq!(
        delivered, 256,
        "flow control must not discard receipt credit"
    );
    assert_eq!(
        bandwidth, 0,
        "peer window wait was learned as network bandwidth"
    );

    // After the receiver resumes normal consumption, fresh delivery must be
    // allowed to train the model again. Draining before ACK keeps this phase
    // genuinely window-open; the useful delivery rate is exactly 64 B / 8 ms.
    for index in 0..50 {
        let now = 2000 + 8 * index;
        b.on_cell(&transmit(&mut a, now), now);
        assert_eq!(b.read(&mut [0; 64]), 64);
        a.on_cell(&transmit(&mut b, now + 1), now + 1);
    }
    assert_eq!(
        a.delivery_model().0,
        8000,
        "fresh open-window delivery did not retrain BBR"
    );
    assert_eq!(a.delivery_model().2, 256 + 50 * 64);
}
