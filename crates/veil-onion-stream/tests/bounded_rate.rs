//! Deterministic rate-limited FIFO, with fixed 2048-byte wire cells in both
//! directions. No loss, reordering, Android, DHT, crypto or public relays are
//! modeled here. Virtual time measures queueing, never host test duration.
use std::collections::VecDeque;
use veil_onion_stream::{Config, Event, Frame, StreamEngine};

struct Pipe {
    rate: u64,
    tail_us: u64,
    propagation_us: u64,
    flight: VecDeque<(u64, Vec<u8>)>,
    steady_max_queue_us: u64,
    cells: u64,
}
impl Pipe {
    fn new(rate: u64) -> Self {
        Self {
            rate,
            tail_us: 0,
            propagation_us: 25_000,
            flight: VecDeque::new(),
            steady_max_queue_us: 0,
            cells: 0,
        }
    }
    fn send(&mut self, now: u64, bytes: &[u8], steady: bool) {
        let now_us = now * 1000;
        let queued = self.tail_us.saturating_sub(now_us);
        if steady {
            self.steady_max_queue_us = self.steady_max_queue_us.max(queued);
        }
        // All frames pay the same fixed circuit-cell wire size, no role priority.
        self.tail_us = self.tail_us.max(now_us) + (2048u64 * 1_000_000).div_ceil(self.rate);
        let arrival_ms = (self.tail_us + self.propagation_us).div_ceil(1000);
        self.flight.push_back((arrival_ms, bytes.to_vec()));
        self.cells += 1;
    }
    fn deliver(&mut self, now: u64, to: &mut StreamEngine) {
        while self.flight.front().is_some_and(|(at, _)| *at <= now) {
            to.on_cell(&self.flight.pop_front().unwrap().1, now);
        }
    }
    fn next(&self) -> Option<u64> {
        self.flight.front().map(|(at, _)| *at)
    }
}

fn run(rate: u64, warm: bool) -> Outcome {
    run_bytes(rate, warm, 3 * 1024 * 1024 + 251)
}

fn run_bytes(rate: u64, warm: bool, bytes: usize) -> Outcome {
    run_path(rate, warm, bytes, false)
}

fn run_path(rate: u64, warm: bool, bytes: usize, raise_delay: bool) -> Outcome {
    let cfg = Config {
        mss: 1982,
        init_cwnd: 64 * 1982,
        recv_window: 8 << 20,
        max_pacing_batch: 256,
        ack_every: 16,
        ack_delay_ms: 5,
        init_rto_ms: 2000,
        min_rto_ms: 1000,
        max_rto_ms: 10_000,
        max_retransmits: 5,
        loss_decrease_per_mille: 750,
        rto_rewind_no_sack: true,
        bbr: true,
        rack: true,
        warm_btl_bw: if warm { rate / 2 } else { 0 },
        warm_rtt_min_ms: if warm { 200 } else { 0 },
        ..Config::default()
    };
    let mut a = StreamEngine::connect(7, cfg, 0, 100);
    let mut b = StreamEngine::accept(7, cfg, 0, 500);
    let payload: Vec<u8> = (0..bytes).map(|i| (i ^ (i >> 8)) as u8).collect();
    a.write(&payload);
    a.finish();
    let mut ab = Pipe::new(rate);
    let mut ba = Pipe::new(rate);
    let mut received = Vec::new();
    let mut scratch = [0; 65536];
    let mut frame = Vec::new();
    let mut now = 0;
    let mut rtos = 0;
    let mut short_data_cells = 0;
    let mut finished = false;
    let mut steps = 0;
    while now < 900_000 && steps < 2_000_000 {
        steps += 1;
        ab.deliver(now, &mut b);
        ba.deliver(now, &mut a);
        loop {
            let n = b.read(&mut scratch);
            if n == 0 {
                break;
            }
            received.extend_from_slice(&scratch[..n]);
        }
        if received.len() == payload.len() && !finished {
            b.finish();
            finished = true;
        }
        a.on_timeout(now);
        b.on_timeout(now);
        let steady = received.len() >= 1024 * 1024;
        if steady && raise_delay {
            ab.propagation_us = 250_000;
            ba.propagation_us = 250_000;
        }
        for _ in 0..512 {
            if !a.poll_transmit(now, &mut frame) {
                break;
            }
            if matches!(Frame::decode(&frame), Some(Frame::Data { payload, .. }) if payload.len() < cfg.mss)
            {
                short_data_cells += 1;
            }
            ab.send(now, &frame, steady);
        }
        for _ in 0..512 {
            if !b.poll_transmit(now, &mut frame) {
                break;
            }
            ba.send(now, &frame, steady);
        }
        while let Some(e) = a.poll_event() {
            if matches!(e, Event::DataRto { .. }) {
                rtos += 1;
            }
        }
        if a.is_send_complete() && b.is_send_complete() && a.is_eof() && b.is_eof() {
            break;
        }
        if a.is_closed() || b.is_closed() {
            break;
        }
        let next = [ab.next(), ba.next(), a.next_timeout(), b.next_timeout()]
            .into_iter()
            .flatten()
            .min();
        let Some(next) = next else {
            break;
        };
        now = next.max(now + 1);
    }
    assert!(received == payload, "stream lost bytes on a loss-free FIFO");
    Outcome {
        complete: a.is_send_complete() && b.is_send_complete(),
        steady_queue_bytes: ab.steady_max_queue_us * rate / 1_000_000,
        virtual_ms: now,
        rtos,
        wire_cells: ab.cells,
        short_data_cells,
        minimum_rtt_ms: a.delivery_model().1,
    }
}

struct Outcome {
    complete: bool,
    steady_queue_bytes: u64,
    virtual_ms: u64,
    rtos: u64,
    wire_cells: u64,
    short_data_cells: u64,
    minimum_rtt_ms: u32,
}

fn check_slow_fifo(warm: bool) {
    let out = run(32 * 1024, warm);
    assert!(out.complete);
    assert_eq!(out.rtos, 0);
    // The queue can absorb the configured initial 64-cell flight. Once
    // a MiB has arrived, BBR has ample delivery evidence and must not
    // sustain a still-larger queue on this unchanged, slower path.
    assert!(
        out.steady_queue_bytes <= 64 * 2048,
        "warm={warm}: steady FIFO backlog {} B exceeds the initial flight",
        out.steady_queue_bytes
    );
}

#[test]
fn cold_slow_fifo_does_not_accumulate_more_than_the_initial_flight() {
    check_slow_fifo(false);
}

#[test]
fn warm_slow_fifo_does_not_accumulate_more_than_the_initial_flight() {
    check_slow_fifo(true);
}

#[test]
fn bounded_rate_paths_complete_without_halving_the_available_goodput() {
    for rate in [32 * 1024, 128 * 1024, 1024 * 1024] {
        for warm in [false, true] {
            let out = run(rate, warm);
            assert!(out.complete);
            assert_eq!(out.rtos, 0);
            let serialization_ms = (out.wire_cells * 2048 * 1000).div_ceil(rate);
            assert!(
                out.virtual_ms <= serialization_ms * 2 + 1000,
                "rate={rate} warm={warm}: sender left the FIFO underfed"
            );
        }
    }
}

#[test]
fn bbr_window_shaping_does_not_fragment_a_backlogged_bulk_write() {
    for rate in [32 * 1024, 128 * 1024, 1024 * 1024] {
        for warm in [false, true] {
            let out = run(rate, warm);
            assert!(out.complete);
            assert!(
                out.short_data_cells <= 1,
                "rate={rate} warm={warm}: {} short DATA cells for one bulk write",
                out.short_data_cells
            );
        }
    }
}

#[test]
fn long_fifo_transfer_does_not_relearn_its_own_queue_as_propagation_delay() {
    for warm in [false, true] {
        let out = run_bytes(32 * 1024, warm, 16 * 1024 * 1024 + 251);
        assert!(out.complete);
        assert_eq!(out.rtos, 0);
        assert!(
            out.steady_queue_bytes <= 8 * 2048,
            "warm={warm}: long-transfer backlog {} B exceeds the drained-pipe bound",
            out.steady_queue_bytes
        );
    }
}

#[test]
fn a_real_propagation_delay_increase_is_learned_after_draining() {
    let out = run_path(32 * 1024, true, 3 * 1024 * 1024 + 251, true);
    assert!(out.complete);
    assert_eq!(out.rtos, 0);
    assert!(
        out.minimum_rtt_ms >= 500,
        "the new 250ms one-way path was mistaken for queueing forever"
    );
}
