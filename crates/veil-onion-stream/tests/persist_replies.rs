//! A responsive receiver may refuse a persist byte while its buffer is full.
//! The zero-window ACK is flow control, never receipt of that byte.
use veil_onion_stream::{Config, Event, Frame, StreamEngine, wire::SackVec};

fn transmit(engine: &mut StreamEngine, now: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    assert!(engine.poll_transmit(now, &mut bytes), "expected a cell");
    bytes
}

fn fixture() -> (StreamEngine, StreamEngine) {
    fixture_with(false, false)
}

fn fixture_with(rack: bool, rewind: bool) -> (StreamEngine, StreamEngine) {
    let cfg = Config {
        mss: 16,
        recv_window: 32,
        init_cwnd: 32,
        ack_every: 1,
        init_rto_ms: 50,
        min_rto_ms: 50,
        max_rto_ms: 400,
        max_retransmits: 2,
        rack,
        rto_rewind_no_sack: rewind,
        ..Config::default()
    };
    let mut a = StreamEngine::connect(7, cfg, 0, 100);
    let mut b = StreamEngine::accept(7, cfg, 0, 500);
    b.on_cell(&transmit(&mut a, 0), 0);
    a.on_cell(&transmit(&mut b, 0), 0);
    b.on_cell(&transmit(&mut a, 0), 0);
    a.write(&[1; 32]);
    b.on_cell(&transmit(&mut a, 1), 1);
    b.on_cell(&transmit(&mut a, 1), 1);
    let closed = transmit(&mut b, 2);
    assert!(matches!(
        Frame::decode(&closed),
        Some(Frame::Ack {
            ack: 133,
            win: 0,
            ..
        })
    ));
    a.on_cell(&closed, 2);
    a.write(&[2; 16]);
    assert!(!a.poll_transmit(3, &mut Vec::new()));
    while a.poll_event().is_some() {}
    (a, b)
}

fn refusal() -> Vec<u8> {
    Frame::Ack {
        stream_id: 7,
        ack: 133,
        win: 0,
        sacks: SackVec::new(),
    }
    .encode()
}

fn first_probe(a: &mut StreamEngine) -> (u64, Vec<u8>) {
    let at = a.next_timeout().unwrap();
    a.on_timeout(at);
    let probe = transmit(a, at);
    assert!(matches!(
        Frame::decode(&probe),
        Some(Frame::Data {
            seq: 133,
            payload: [2],
            ..
        })
    ));
    (at, probe)
}

#[test]
fn responding_full_receiver_does_not_burn_loss_budget_or_ack_refused_bytes() {
    for (rack, rewind) in [(false, false), (true, false), (false, true), (true, true)] {
        let (mut a, _) = fixture_with(rack, rewind);
        let cwnd = a.cwnd();
        let (mut at, original) = first_probe(&mut a);
        for _ in 0..8 {
            // A conforming full peer rejects this byte and repeats its existing
            // ACK. In particular do not feed it to a legacy receiver which may
            // accept probes past its advertised buffer limit.
            a.on_cell(&refusal(), at + 1);
            assert_eq!(a.send_buffer_len(), 15);
            let next = a.next_timeout().unwrap();
            assert_eq!(
                next - at,
                50,
                "probe cadence changed or reply extended its timer"
            );
            a.on_timeout(next);
            assert!(!a.is_closed(), "a responding full peer was declared dead");
            assert_eq!(a.cwnd(), cwnd, "flow control cut the congestion window");
            while let Some(event) = a.poll_event() {
                assert!(
                    !matches!(event, Event::DataRto { .. } | Event::Reset(_)),
                    "false loss event: {event:?}"
                );
            }
            assert_eq!(transmit(&mut a, next), original);
            at = next;
        }
    }
}

#[test]
fn silent_full_peer_still_times_out_under_the_existing_retry_limit() {
    for (rack, rewind) in [(false, false), (true, false), (false, true), (true, true)] {
        let (mut a, _) = fixture_with(rack, rewind);
        first_probe(&mut a);
        for _ in 0..8 {
            let next = a.next_timeout().unwrap();
            a.on_timeout(next);
            if a.is_closed() {
                break;
            }
            let _ = a.poll_transmit(next, &mut Vec::new());
        }
        assert!(a.is_closed(), "silent probe peer escaped the retry limit");
    }
}

#[test]
fn duplicate_refusals_cannot_postpone_the_next_probe_or_manufacture_fast_repair() {
    let (mut a, _) = fixture();
    let (at, _) = first_probe(&mut a);
    let deadline = a.next_timeout().unwrap();
    for offset in 1..=8 {
        a.on_cell(&refusal(), at + offset);
        assert_eq!(a.next_timeout(), Some(deadline));
        assert!(
            !a.poll_transmit(at + offset, &mut Vec::new()),
            "refusal became a loss dup-ACK"
        );
    }
}

#[test]
fn reopened_window_retries_the_refused_byte_without_claiming_delivery() {
    let (mut a, mut b) = fixture();
    let (at, probe) = first_probe(&mut a);
    a.on_cell(&refusal(), at + 1);
    // Only the original 32 bytes are stored; the refused probe is not ACKed.
    assert_eq!(b.read(&mut [0; 32]), 32);
    let opened = transmit(&mut b, at + 2);
    assert!(matches!(
        Frame::decode(&opened),
        Some(Frame::Ack {
            ack: 133,
            win: 32,
            ..
        })
    ));
    a.on_cell(&opened, at + 2);
    assert_eq!(a.send_buffer_len(), 15);
    assert_eq!(a.inflight_bytes(), 1);
    assert_eq!(transmit(&mut a, at + 2), probe);
    b.on_cell(&probe, at + 3);
    a.on_cell(&transmit(&mut b, at + 3), at + 3);
    let tail = transmit(&mut a, at + 4);
    assert!(
        matches!(Frame::decode(&tail), Some(Frame::Data { seq: 134, payload, .. }) if payload == [2; 15])
    );
    b.on_cell(&tail, at + 4);
    let mut received = [0; 32];
    assert_eq!(b.read(&mut received), 16);
    assert_eq!(&received[..16], &[2; 16]);
}

#[test]
fn ordinary_one_byte_data_cannot_gain_the_probe_retry_exemption() {
    let cfg = Config {
        mss: 16,
        init_rto_ms: 50,
        min_rto_ms: 50,
        max_rto_ms: 400,
        max_retransmits: 2,
        ..Config::default()
    };
    let mut a = StreamEngine::connect(7, cfg, 0, 100);
    a.on_cell(
        &Frame::SynAck {
            stream_id: 7,
            isn: 500,
            ack: 101,
            win: 32,
        }
        .encode(),
        0,
    );
    let _ = transmit(&mut a, 0); // handshake confirmation
    a.write(&[9]);
    let _ = transmit(&mut a, 1); // normal authorized DATA, not a persist probe
    let zero = Frame::Ack {
        stream_id: 7,
        ack: 101,
        win: 0,
        sacks: SackVec::new(),
    }
    .encode();
    a.on_cell(&zero, 2);
    for _ in 0..8 {
        let next = a.next_timeout().unwrap();
        a.on_timeout(next);
        if a.is_closed() {
            return;
        }
        let _ = transmit(&mut a, next);
        a.on_cell(&zero, next + 1);
    }
    panic!("normal one-byte loss escaped its retry budget");
}

#[test]
fn a_past_refusal_cannot_keep_later_silent_attempts_alive() {
    let (mut a, _) = fixture();
    let (at, _) = first_probe(&mut a);
    a.on_cell(&refusal(), at + 1);
    let due = a.next_timeout().unwrap();
    a.on_timeout(due);
    let _ = transmit(&mut a, due); // no response to this or subsequent attempts
    for _ in 0..8 {
        let next = a.next_timeout().unwrap();
        a.on_timeout(next);
        if a.is_closed() {
            return;
        }
        let _ = transmit(&mut a, next);
    }
    panic!("an old refusal kept a now-silent peer alive indefinitely");
}
