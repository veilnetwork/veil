//! A reordered ACK must not replace a newer cumulative ACK's flow-control window.
use veil_onion_stream::{Config, Frame, StreamEngine, wire::SackVec};

const SID: u32 = 7;

fn pair(iss: u32, rack: bool) -> (StreamEngine, StreamEngine) {
    let config = Config {
        mss: 16,
        init_cwnd: 64,
        recv_window: 32,
        ack_every: 1,
        rack,
        ..Config::default()
    };
    let mut sender = StreamEngine::connect(SID, config, 0, iss);
    let mut peer = StreamEngine::accept(SID, config, 0, 500);
    peer.on_cell(&transmit(&mut sender, 0), 0);
    sender.on_cell(&transmit(&mut peer, 0), 0);
    peer.on_cell(&transmit(&mut sender, 0), 0);
    assert!(sender.is_established() && peer.is_established());
    (sender, peer)
}

#[track_caller]
fn transmit(engine: &mut StreamEngine, now: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    assert!(
        engine.poll_transmit(now, &mut bytes),
        "fixture expected a cell"
    );
    bytes
}

fn ack_fields(bytes: &[u8]) -> (u32, u32) {
    match Frame::decode(bytes).unwrap() {
        Frame::Ack { ack, win, .. } => (ack, win),
        _ => panic!("fixture expected an ACK"),
    }
}

fn assert_data(bytes: &[u8], expected: &[u8]) {
    assert!(
        matches!(Frame::decode(bytes), Some(Frame::Data { payload, .. }) if payload == expected)
    );
}

#[test]
fn old_zero_window_ack_does_not_close_window_after_later_progress() {
    for rack in [false, true] {
        for iss in [100, u32::MAX - 20] {
            let (mut sender, mut peer) = pair(iss, rack);
            sender.write(&[1; 32]);
            peer.on_cell(&transmit(&mut sender, 1), 1);
            let second = transmit(&mut sender, 1);
            peer.on_cell(&second, 1);
            let old_closed = transmit(&mut peer, 2);
            assert_eq!(ack_fields(&old_closed), (iss.wrapping_add(33), 0));

            // The app drains the full window. A genuine duplicate DATA elicits
            // a same-cumulative window update; retain the first zero-window ACK
            // to model a delayed copy arriving over another return circuit.
            assert_eq!(peer.read(&mut [0; 32]), 32);
            peer.on_cell(&second, 3);
            let reopened = transmit(&mut peer, 3);
            assert_eq!(ack_fields(&reopened), (iss.wrapping_add(33), 32));
            sender.on_cell(&reopened, 3);
            sender.write(&[2; 16]);
            peer.on_cell(&transmit(&mut sender, 4), 4);
            assert_eq!(peer.read(&mut [0; 16]), 16);
            let current = transmit(&mut peer, 5);
            assert_eq!(ack_fields(&current), (iss.wrapping_add(49), 32));
            sender.on_cell(&current, 5);
            sender.on_cell(&old_closed, 6);

            sender.write(&[3; 16]);
            assert_data(&transmit(&mut sender, 6), &[3; 16]);
        }
    }
}

#[test]
fn old_open_window_ack_does_not_reopen_a_current_zero_window() {
    for rack in [false, true] {
        for iss in [100, u32::MAX - 20] {
            let (mut sender, mut peer) = pair(iss, rack);
            sender.write(&[1; 32]);
            peer.on_cell(&transmit(&mut sender, 1), 1);
            let old_open = transmit(&mut peer, 1);
            assert_eq!(ack_fields(&old_open), (iss.wrapping_add(17), 16));
            let second = transmit(&mut sender, 2);
            peer.on_cell(&second, 2);
            let current_closed = transmit(&mut peer, 2);
            assert_eq!(ack_fields(&current_closed), (iss.wrapping_add(33), 0));
            sender.on_cell(&current_closed, 3);
            sender.on_cell(&old_open, 4);
            sender.write(&[2; 16]);
            assert!(
                !sender.poll_transmit(4, &mut Vec::new()),
                "stale ACK reopened a full peer receive buffer"
            );

            // Equal cumulative ACKs still carry legitimate window updates.
            assert_eq!(peer.read(&mut [0; 32]), 32);
            peer.on_cell(&second, 5);
            let reopened = transmit(&mut peer, 5);
            assert_eq!(ack_fields(&reopened), (iss.wrapping_add(33), 32));
            sender.on_cell(&reopened, 5);
            assert_data(&transmit(&mut sender, 5), &[2; 16]);
        }
    }
}

#[test]
fn future_ack_cannot_close_window_before_ack_validation() {
    for iss in [100, u32::MAX - 20] {
        let (mut sender, mut peer) = pair(iss, true);
        sender.write(&[1; 16]);
        peer.on_cell(&transmit(&mut sender, 1), 1);
        assert_eq!(peer.read(&mut [0; 16]), 16);
        let current = transmit(&mut peer, 2);
        let (ack, win) = ack_fields(&current);
        assert_eq!(win, 32);
        sender.on_cell(&current, 2);
        sender.on_cell(
            &Frame::Ack {
                stream_id: SID,
                ack: ack.wrapping_add(1), // never sent
                win: 0,
                sacks: SackVec::new(),
            }
            .encode(),
            3,
        );
        sender.write(&[2; 16]);
        assert_data(&transmit(&mut sender, 3), &[2; 16]);
    }
}

#[test]
fn future_ack_cannot_reopen_a_current_zero_window() {
    for iss in [100, u32::MAX - 20] {
        let (mut sender, mut peer) = pair(iss, true);
        sender.write(&[1; 32]);
        peer.on_cell(&transmit(&mut sender, 1), 1);
        peer.on_cell(&transmit(&mut sender, 1), 1);
        let current = transmit(&mut peer, 2);
        let (ack, win) = ack_fields(&current);
        assert_eq!(win, 0);
        sender.on_cell(&current, 2);
        sender.on_cell(
            &Frame::Ack {
                stream_id: SID,
                ack: ack.wrapping_add(1), // never sent
                win: 32,
                sacks: SackVec::new(),
            }
            .encode(),
            3,
        );
        sender.write(&[2; 16]);
        assert!(!sender.poll_transmit(3, &mut Vec::new()));
    }
}

#[test]
fn equal_cumulative_ack_can_close_and_reopen_window_without_data_progress() {
    for iss in [100, u32::MAX - 20] {
        let (mut sender, _) = pair(iss, true);
        let ack = iss.wrapping_add(1);
        let update = |win| {
            Frame::Ack {
                stream_id: SID,
                ack,
                win,
                sacks: SackVec::new(),
            }
            .encode()
        };
        sender.on_cell(&update(0), 1);
        sender.write(&[2; 16]);
        assert!(!sender.poll_transmit(1, &mut Vec::new()));
        sender.on_cell(&update(32), 2);
        assert_data(&transmit(&mut sender, 2), &[2; 16]);
    }
}
