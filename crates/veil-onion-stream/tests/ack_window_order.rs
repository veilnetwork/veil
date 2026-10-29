//! ACK/DATA reordering and app reads must not corrupt or strand flow control.
use veil_onion_stream::{Config, Frame, StreamEngine, wire::SackVec};

const SID: u32 = 7;

fn pair(iss: u32, rack: bool) -> (StreamEngine, StreamEngine) {
    pair_with_reverse_iss(iss, 500, rack)
}

fn pair_with_reverse_iss(iss: u32, reverse_iss: u32, rack: bool) -> (StreamEngine, StreamEngine) {
    let config = Config {
        mss: 16,
        init_cwnd: 64,
        recv_window: 32,
        ack_every: 1,
        rack,
        ..Config::default()
    };
    let mut sender = StreamEngine::connect(SID, config, 0, iss);
    let mut peer = StreamEngine::accept(SID, config, 0, reverse_iss);
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

// DATA has its own direction's sequence, but no cumulative ACK of OUR bytes.
// Even a first-seen/in-order reverse DATA can predate a newer forward ACK.
fn delayed_data_window(closed: bool, duplicate: bool) {
    for rack in [false, true] {
        for (iss, reverse_iss) in [(100, 500), (u32::MAX - 20, u32::MAX - 7)] {
            let (mut sender, mut peer) = pair_with_reverse_iss(iss, reverse_iss, rack);
            let old_data;
            if closed {
                sender.write(&[1; 32]);
                peer.on_cell(&transmit(&mut sender, 1), 1);
                let second = transmit(&mut sender, 1);
                peer.on_cell(&second, 1);
                sender.on_cell(&transmit(&mut peer, 2), 2); // current win=0
                peer.write(&[9; 16]);
                old_data = transmit(&mut peer, 3); // reverse DATA advertises 0
                assert!(matches!(
                    Frame::decode(&old_data),
                    Some(Frame::Data { win: 0, .. })
                ));
                if duplicate {
                    sender.on_cell(&old_data, 3);
                    peer.on_cell(&transmit(&mut sender, 3), 3);
                }
                assert_eq!(peer.read(&mut [0; 32]), 32);
                // A duplicate elicits a legitimate same-cumulative update on
                // both old and new engines, independent of read notification.
                peer.on_cell(&second, 4);
                sender.on_cell(&transmit(&mut peer, 4), 4);
                sender.write(&[2; 16]);
                peer.on_cell(&transmit(&mut sender, 5), 5);
                assert_eq!(peer.read(&mut [0; 16]), 16);
                sender.on_cell(&transmit(&mut peer, 5), 5);
            } else {
                peer.write(&[9; 16]);
                old_data = transmit(&mut peer, 1); // reverse DATA advertises 32
                assert!(matches!(
                    Frame::decode(&old_data),
                    Some(Frame::Data { win: 32, .. })
                ));
                if duplicate {
                    sender.on_cell(&old_data, 1);
                    peer.on_cell(&transmit(&mut sender, 1), 1);
                }
                sender.write(&[1; 32]);
                peer.on_cell(&transmit(&mut sender, 2), 2);
                peer.on_cell(&transmit(&mut sender, 2), 2);
                let current = transmit(&mut peer, 3);
                assert_eq!(ack_fields(&current).1, 0);
                sender.on_cell(&current, 3);
            }
            sender.on_cell(&old_data, 6);
            let mut got = [0; 32];
            assert_eq!(sender.read(&mut got), 16);
            assert_eq!(&got[..16], &[9; 16]); // no duplicated payload
            sender.write(&[3; 16]);
            if closed {
                assert_data(&transmit(&mut sender, 6), &[3; 16]);
            } else {
                // A stale positive hint can solicit at most one persist byte,
                // never a full normal DATA. ACK evidence still goes back.
                let first = transmit(&mut sender, 6);
                if matches!(Frame::decode(&first), Some(Frame::Data { .. })) {
                    assert_data(&first, &[3]);
                    assert!(matches!(
                        Frame::decode(&transmit(&mut sender, 6)),
                        Some(Frame::Ack { .. })
                    ));
                } else {
                    assert!(matches!(Frame::decode(&first), Some(Frame::Ack { .. })));
                }
                assert!(
                    !sender.poll_transmit(6, &mut Vec::new()),
                    "old DATA reopened a full peer buffer"
                );
            }
        }
    }
}

#[test]
fn delayed_first_seen_data_cannot_close_a_newer_ack_window() {
    delayed_data_window(true, false);
}

#[test]
fn duplicated_data_cannot_close_a_newer_ack_window() {
    delayed_data_window(true, true);
}

#[test]
fn delayed_first_seen_data_cannot_reopen_a_newer_ack_window() {
    delayed_data_window(false, false);
}

#[test]
fn duplicated_data_cannot_reopen_a_newer_ack_window() {
    delayed_data_window(false, true);
}

#[test]
fn empty_data_cannot_change_a_window_even_without_payload_progress() {
    for closed in [false, true] {
        let (mut sender, _) = pair(100, true);
        sender.on_cell(
            &Frame::Ack {
                stream_id: SID,
                ack: 101,
                win: if closed { 0 } else { 32 },
                sacks: SackVec::new(),
            }
            .encode(),
            1,
        );
        sender.on_cell(
            &Frame::Data {
                stream_id: SID,
                seq: 500,
                win: if closed { 32 } else { 0 },
                payload: &[],
            }
            .encode(),
            2,
        );
        sender.write(&[1; 16]);
        if closed {
            assert!(!sender.poll_transmit(2, &mut Vec::new()));
        } else {
            assert_data(&transmit(&mut sender, 2), &[1; 16]);
        }
    }
}

fn fill_window(sender: &mut StreamEngine, peer: &mut StreamEngine, bytes: usize) {
    sender.write(&vec![1; bytes]);
    for _ in 0..bytes / 16 {
        peer.on_cell(&transmit(sender, 1), 1);
    }
    sender.on_cell(&transmit(peer, 2), 2);
}

#[test]
fn app_read_reopens_a_closed_window_without_waiting_for_a_persist_probe() {
    for iss in [100, u32::MAX - 20] {
        let (mut sender, mut peer) = pair(iss, true);
        fill_window(&mut sender, &mut peer, 32);
        sender.write(&[2; 16]);
        assert!(!sender.poll_transmit(3, &mut Vec::new()));
        // Small reads coalesce until one MSS (or half the receive buffer) is
        // available. Do not require incoming DATA to wake this window update.
        assert_eq!(peer.read(&mut [0; 1]), 1);
        assert!(!peer.poll_transmit(3, &mut Vec::new()));
        assert_eq!(peer.read(&mut [0; 15]), 15);
        let update = transmit(&mut peer, 3);
        assert_eq!(ack_fields(&update), (iss.wrapping_add(33), 16));
        sender.on_cell(&update, 3);
        assert_data(&transmit(&mut sender, 3), &[2; 16]);
    }
}

#[test]
fn read_updates_a_partly_open_window_and_coalesces_before_ack_emission() {
    let (mut sender, mut peer) = pair(100, true);
    fill_window(&mut sender, &mut peer, 16);
    for _ in 0..15 {
        assert_eq!(peer.read(&mut [0]), 1);
        assert!(!peer.poll_transmit(3, &mut Vec::new()));
    }
    assert_eq!(peer.read(&mut [0]), 1);
    assert_eq!(peer.read(&mut [0]), 0);
    let update = transmit(&mut peer, 3);
    assert_eq!(ack_fields(&update), (117, 32));
    assert!(!peer.poll_transmit(3, &mut Vec::new()));
}

#[test]
fn lost_read_window_update_still_recovers_with_the_existing_persist_probe() {
    let (mut sender, mut peer) = pair(100, true);
    fill_window(&mut sender, &mut peer, 32);
    sender.write(&[2; 16]);
    assert!(!sender.poll_transmit(3, &mut Vec::new()));
    assert_eq!(peer.read(&mut [0; 32]), 32);
    let update = transmit(&mut peer, 3); // deliberately lose this update
    assert_eq!(ack_fields(&update), (133, 32));
    let deadline = sender.next_timeout().unwrap();
    sender.on_timeout(deadline);
    let probe = transmit(&mut sender, deadline);
    assert_data(&probe, &[2]);
    peer.on_cell(&probe, deadline);
    sender.on_cell(&transmit(&mut peer, deadline), deadline);
    peer.on_cell(&transmit(&mut sender, deadline + 1), deadline + 1);
    assert_eq!(peer.read(&mut [0; 32]), 16);
}

#[test]
fn pure_window_updates_are_not_three_loss_reports_but_real_duplicates_still_are() {
    let (mut sender, _) = pair(100, false);
    let update = |win| {
        Frame::Ack {
            stream_id: SID,
            ack: 101,
            win,
            sacks: SackVec::new(),
        }
        .encode()
    };
    sender.write(&[1; 16]);
    let original = transmit(&mut sender, 1); // still in flight; no loss evidence
    for win in [8, 16, 32] {
        sender.on_cell(&update(win), 2);
    }
    assert!(
        !sender.poll_transmit(2, &mut Vec::new()),
        "window updates manufactured fast retransmit"
    );
    for _ in 0..3 {
        sender.on_cell(&update(32), 3); // unchanged window: real dup-ACKs
    }
    assert_eq!(transmit(&mut sender, 3), original);
}

#[test]
fn changing_window_does_not_discard_fresh_sack_loss_evidence() {
    let (mut sender, _) = pair(100, false);
    sender.on_cell(
        &Frame::Ack {
            stream_id: SID,
            ack: 101,
            win: 128,
            sacks: SackVec::new(),
        }
        .encode(),
        1,
    );
    sender.write(&[1; 64]);
    let original = transmit(&mut sender, 1);
    for _ in 0..3 {
        let _ = transmit(&mut sender, 1);
    }
    for count in 1..=3 {
        let mut sacks = SackVec::new();
        sacks.push(veil_onion_stream::wire::SackRange {
            start: 117,
            end: 117 + count * 16,
        });
        sender.on_cell(
            &Frame::Ack {
                stream_id: SID,
                ack: 101,
                win: 128 - count * 16,
                sacks,
            }
            .encode(),
            2,
        );
    }
    assert_eq!(transmit(&mut sender, 2), original);
}

#[test]
fn app_read_does_not_add_window_only_acks_when_advertised_space_is_ample() {
    let cfg = Config {
        mss: 16,
        init_cwnd: 128,
        recv_window: 128,
        ack_every: 1,
        ..Config::default()
    };
    let mut sender = StreamEngine::connect(SID, cfg, 0, 100);
    let mut peer = StreamEngine::accept(SID, cfg, 0, 500);
    peer.on_cell(&transmit(&mut sender, 0), 0);
    sender.on_cell(&transmit(&mut peer, 0), 0);
    peer.on_cell(&transmit(&mut sender, 0), 0);
    fill_window(&mut sender, &mut peer, 16); // latest advertised window = 112
    assert_eq!(peer.read(&mut [0; 16]), 16);
    assert!(!peer.poll_transmit(3, &mut Vec::new()));
}

#[test]
fn data_hint_solicits_one_probe_but_repeated_hints_cannot_bypass_closed_credit() {
    let (mut sender, _) = pair(100, true);
    let ack = |point, win| {
        Frame::Ack {
            stream_id: SID,
            ack: point,
            win,
            sacks: SackVec::new(),
        }
        .encode()
    };
    sender.on_cell(&ack(101, 0), 1);
    sender.write(&[2; 16]);
    assert!(!sender.poll_transmit(1, &mut Vec::new()));
    let hint = Frame::Data {
        stream_id: SID,
        seq: 500,
        win: 32,
        payload: &[9],
    }
    .encode();
    sender.on_cell(&hint, 2);
    assert_data(&transmit(&mut sender, 2), &[2]); // a probe, not 16 bytes of credit
    let _ = transmit(&mut sender, 2); // ACK of reverse DATA
    sender.on_cell(&ack(102, 0), 3); // real receipt of the probe, still closed
    for _ in 0..4 {
        sender.on_cell(&hint, 4);
        assert!(matches!(
            Frame::decode(&transmit(&mut sender, 4)),
            Some(Frame::Ack { .. })
        ));
        assert!(
            !sender.poll_transmit(4, &mut Vec::new()),
            "repeated hint manufactured probe credit"
        );
    }
    sender.on_cell(&ack(102, 32), 5); // only authenticated ACK grants credit
    assert_data(&transmit(&mut sender, 5), &[2; 15]);
}

#[test]
fn validated_open_ack_cancels_a_pending_hint_probe_before_data_is_segmented() {
    let (mut sender, _) = pair(100, true);
    let ack = |win| {
        Frame::Ack {
            stream_id: SID,
            ack: 101,
            win,
            sacks: SackVec::new(),
        }
        .encode()
    };
    sender.on_cell(&ack(0), 1);
    sender.write(&[2; 16]);
    sender.on_cell(
        &Frame::Data {
            stream_id: SID,
            seq: 500,
            win: 32,
            payload: &[9],
        }
        .encode(),
        2,
    );
    sender.on_cell(&ack(32), 2);
    assert_data(&transmit(&mut sender, 2), &[2; 16]);
}
