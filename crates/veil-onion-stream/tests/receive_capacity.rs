//! Bound retained payload without retracting SACK or losing the receive gap.
use veil_onion_stream::{Config, Frame, StreamEngine};

fn receiver(window: u32, start: u32) -> StreamEngine {
    let mut b = StreamEngine::accept(
        7,
        Config {
            recv_window: window,
            ack_every: 1,
            ..Config::default()
        },
        0,
        500,
    );
    b.on_cell(
        &Frame::Syn {
            stream_id: 7,
            isn: start.wrapping_sub(1),
            win: window,
        }
        .encode(),
        0,
    );
    let mut discard = Vec::new();
    assert!(b.poll_transmit(0, &mut discard)); // SYN_ACK
    b
}
fn data(b: &mut StreamEngine, seq: u32, bytes: &[u8]) {
    b.on_cell(
        &Frame::Data {
            stream_id: 7,
            seq,
            win: 4096,
            payload: bytes,
        }
        .encode(),
        1,
    );
}
fn ack(b: &mut StreamEngine) -> (u32, u32, Vec<(u32, u32)>) {
    let mut cell = Vec::new();
    assert!(b.poll_transmit(1, &mut cell));
    match Frame::decode(&cell).unwrap() {
        Frame::Ack {
            ack, win, sacks, ..
        } => (
            ack,
            win,
            sacks.as_slice().iter().map(|r| (r.start, r.end)).collect(),
        ),
        _ => panic!("expected an ACK"),
    }
}

#[test]
fn sequential_data_cannot_grow_unread_payload_past_the_window() {
    for start in [101u32, u32::MAX - 31] {
        let mut b = receiver(64, start);
        for off in (0..80).step_by(16) {
            data(&mut b, start.wrapping_add(off), &[3; 16]);
        }
        assert_eq!(b.readable_len(), 64);
        let (point, win, _) = ack(&mut b);
        assert_eq!((point, win), (start.wrapping_add(64), 0));
        let mut bytes = [0; 80];
        assert_eq!(b.read(&mut bytes), 64);
        let _ = ack(&mut b); // reopened window notification
        data(&mut b, start.wrapping_add(64), &[4; 16]); // refused tail retried
        assert_eq!(b.read(&mut bytes), 16);
        assert_eq!(&bytes[..16], &[4; 16]);
    }
}

#[test]
fn oversized_in_order_data_is_clipped_and_only_stored_prefix_is_acked() {
    let mut b = receiver(32, 101);
    data(&mut b, 101, &[1; 48]);
    assert_eq!(b.readable_len(), 32);
    assert_eq!(ack(&mut b).0, 133);
    assert_eq!(b.read(&mut [0; 32]), 32);
    data(&mut b, 101, &[1; 48]); // trim old prefix; accept the previously refused tail
    assert_eq!(b.readable_len(), 16);
    assert_eq!(ack(&mut b).0, 149);
}

#[test]
fn zero_capacity_receiver_never_acks_or_sacks_a_payload_byte() {
    let mut b = receiver(0, 101);
    data(&mut b, 101, &[3; 16]);
    data(&mut b, 102, &[3; 16]);
    assert_eq!(b.readable_len(), 0);
    assert_eq!(ack(&mut b), (101, 0, vec![]));
}

#[test]
fn overlapping_oo_bytes_do_not_consume_gap_credit_and_reassemble_without_retry() {
    for start in [101u32, u32::MAX - 31] {
        let mut b = receiver(128, start);
        let bytes: Vec<u8> = (0..128).collect();
        for off in 1..=64u32 {
            data(
                &mut b,
                start.wrapping_add(off),
                &bytes[off as usize..off as usize + 64],
            );
        }
        let (point, win, sacks) = ack(&mut b);
        assert_eq!(point, start);
        assert_eq!(win, 1, "overlapping copies consumed gap credit");
        // A partial duplicate may also produce D-SACK. The ordinary block
        // must still cover every stored byte above the one-byte head gap.
        assert!(sacks.contains(&(start.wrapping_add(1), start.wrapping_add(128))));
        data(&mut b, start, &bytes[..1]);
        assert_eq!(b.readable_len(), 128);
        assert_eq!(ack(&mut b).0, start.wrapping_add(128));
        let mut received = [0; 128];
        assert_eq!(b.read(&mut received), 128);
        assert_eq!(received.as_slice(), bytes);
    }
}

#[test]
fn sacked_bytes_survive_partial_read_new_data_and_the_remaining_gap() {
    let mut b = receiver(32, 101);
    data(&mut b, 101, &[1; 16]);
    data(&mut b, 125, &[3; 8]);
    let before = ack(&mut b);
    assert_eq!(before.0, 117);
    assert!(before.2.contains(&(125, 133)));
    assert_eq!(b.read(&mut [0; 8]), 8); // stable capacity edge moves only with reads
    data(&mut b, 133, &[4; 16]); // only 8 bytes fit at the new edge
    let during = ack(&mut b);
    assert!(
        during.2.iter().any(|&(lo, hi)| lo <= 125 && hi >= 133),
        "SACK promise was retracted"
    );
    data(&mut b, 117, &[2; 8]);
    assert_eq!(b.readable_len(), 32);
    assert_eq!(ack(&mut b).0, 141);
    let mut got = [0; 40];
    assert_eq!(b.read(&mut got), 32);
    assert_eq!(&got[..8], &[1; 8]);
    assert_eq!(&got[8..16], &[2; 8]);
    assert_eq!(&got[16..24], &[3; 8]);
    assert_eq!(&got[24..32], &[4; 8]);
    data(&mut b, 141, &[4; 8]);
    assert_eq!(b.read(&mut got), 8);
}

#[test]
fn already_sacked_content_is_not_replaced_by_overlapping_in_order_data() {
    let mut b = receiver(32, 101);
    data(&mut b, 109, &[7; 8]);
    assert!(ack(&mut b).2.contains(&(109, 117)));
    data(&mut b, 101, &[8; 24]);
    let mut got = [0; 24];
    assert_eq!(b.read(&mut got), 24);
    assert_eq!(&got[..8], &[8; 8]);
    assert_eq!(&got[8..16], &[7; 8]); // original receipt promised by SACK wins
    assert_eq!(&got[16..], &[8; 8]);
}

#[test]
fn receive_horizon_is_clamped_below_the_serial_half_range() {
    let mut b = receiver(u32::MAX, 101);
    data(&mut b, 101, &[1; 16]);
    assert_eq!(b.readable_len(), 16);
    assert_eq!(ack(&mut b).1, ((1u32 << 31) - 1) - 16);
}
