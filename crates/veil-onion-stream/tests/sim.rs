//! End-to-end simulation: two [`StreamEngine`]s over a virtual, lossy,
//! reordering, duplicating cell channel with an event-driven virtual clock.
//! Deterministic (seeded PRNG) so a failure reproduces byte-for-byte.

use veil_onion_stream::engine::{Config, Event, StreamEngine};
use veil_onion_stream::wire::reset_reason;

/// Tiny deterministic PRNG (SplitMix64) — no external dep.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in [0,1).
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo)
    }
}

#[derive(Clone, Copy)]
struct Channel {
    loss: f64,       // per-cell drop probability
    dup: f64,        // per-cell duplication probability
    base_delay: u64, // one-way propagation (ms)
    jitter: u64,     // extra uniform [0,jitter] ms → reordering
}
impl Channel {
    fn perfect() -> Self {
        Channel {
            loss: 0.0,
            dup: 0.0,
            base_delay: 25,
            jitter: 0,
        }
    }
    fn lossy(loss: f64) -> Self {
        Channel {
            loss,
            dup: 0.0,
            base_delay: 25,
            jitter: 0,
        }
    }
}

/// A cell in flight toward one endpoint.
struct InFlight {
    arrive: u64,
    bytes: Vec<u8>,
}

/// One directional pipe: applies loss/dup/jitter and times delivery.
struct Pipe {
    ch: Channel,
    flight: Vec<InFlight>,
    /// Total cells the sender handed in (incl. ones later dropped) — the wire
    /// send count, for measuring retransmit overhead.
    injected: u64,
}
impl Pipe {
    fn new(ch: Channel) -> Self {
        Pipe {
            ch,
            flight: Vec::new(),
            injected: 0,
        }
    }
    fn inject(&mut self, now: u64, bytes: &[u8], rng: &mut Rng) {
        self.injected += 1;
        // Drop?
        if rng.unit() < self.ch.loss {
            return;
        }
        let deliver = |p: &mut Pipe, r: &mut Rng| {
            let arrive = now + p.ch.base_delay + r.range(0, p.ch.jitter + 1);
            p.flight.push(InFlight {
                arrive,
                bytes: bytes.to_vec(),
            });
        };
        deliver(self, rng);
        if rng.unit() < self.ch.dup {
            deliver(self, rng); // duplicate copy
        }
    }
    /// Earliest pending arrival.
    fn next_arrival(&self) -> Option<u64> {
        self.flight.iter().map(|f| f.arrive).min()
    }
    /// Remove + return all cells due by `now`, in arrival order.
    fn drain_due(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut due: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut keep: Vec<InFlight> = Vec::new();
        for f in self.flight.drain(..) {
            if f.arrive <= now {
                due.push((f.arrive, f.bytes));
            } else {
                keep.push(f);
            }
        }
        self.flight = keep;
        due.sort_by_key(|(a, _)| *a);
        due.into_iter().map(|(_, b)| b).collect()
    }
}

struct Outcome {
    received: Vec<u8>,
    max_cwnd_a: u32,
    max_inflight_a: u32,
    final_a: String,
    final_b: String,
    a_events: Vec<Event>,
    b_events: Vec<Event>,
    steps: u64,
    elapsed_ms: u64,
    payload_received_ms: Option<u64>,
    completed: bool,
    /// Cells A (the sender) put on the wire, incl. retransmits.
    tx_cells: u64,
    /// Largest number of cells A emitted at a single virtual-time instant — the
    /// burst size pacing is meant to keep small.
    max_burst_a: u64,
}

/// Drive a one-way transfer of `payload` from A→B over `ch` (both directions use
/// `ch`; the reverse carries ACKs). Returns what B received.
fn run_oneway(payload: &[u8], ch: Channel, seed: u64, cfg: Config) -> Outcome {
    let mut rng = Rng::new(seed);
    let mut a = StreamEngine::connect(1, cfg, 0, 1000);
    let mut b = StreamEngine::accept(1, cfg, 0, 7000);
    a.write(payload);
    a.finish();

    let mut a2b = Pipe::new(ch);
    let mut b2a = Pipe::new(ch);
    let mut received: Vec<u8> = Vec::new();
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    let mut max_cwnd_a = 0u32;
    let mut max_inflight_a = 0u32;

    let mut now = 0u64;
    let mut steps = 0u64;
    let cap = 20_000_000u64;
    let mut completed = false;
    let mut max_burst_a = 0u64; // most cells A put on the wire at one instant
    let mut payload_received_ms = None;

    while steps < cap {
        steps += 1;
        // 1. Drain both engines' transmits at `now`.
        let mut buf = Vec::new();
        let before = a2b.injected;
        while a.poll_transmit(now, &mut buf) {
            a2b.inject(now, &buf, &mut rng);
        }
        max_burst_a = max_burst_a.max(a2b.injected - before);
        while b.poll_transmit(now, &mut buf) {
            b2a.inject(now, &buf, &mut rng);
        }
        max_cwnd_a = max_cwnd_a.max(a.cwnd());
        max_inflight_a = max_inflight_a.max(a.inflight_bytes());

        // 2. Pump reader on B + drain events.
        let mut tmp = [0u8; 4096];
        loop {
            let n = b.read(&mut tmp);
            if n == 0 {
                break;
            }
            received.extend_from_slice(&tmp[..n]);
            if received.len() == payload.len() && payload_received_ms.is_none() {
                payload_received_ms = Some(now);
            }
        }
        while let Some(e) = a.poll_event() {
            a_events.push(e);
        }
        while let Some(e) = b.poll_event() {
            b_events.push(e);
        }

        // 3. Done?
        if received.len() == payload.len() && b.is_eof() && a.is_send_complete() {
            completed = true;
            break;
        }
        // Abort early if either side reset.
        if a.is_closed() && a_events.iter().any(|e| matches!(e, Event::Reset(_))) {
            break;
        }
        if b.is_closed() && b_events.iter().any(|e| matches!(e, Event::Reset(_))) {
            break;
        }

        // 4. Advance the virtual clock to the next event.
        let mut next: Option<u64> = None;
        let mut merge = |x: Option<u64>| {
            if let Some(v) = x {
                next = Some(next.map_or(v, |c: u64| c.min(v)));
            }
        };
        merge(a2b.next_arrival());
        merge(b2a.next_arrival());
        merge(a.next_timeout());
        merge(b.next_timeout());
        let Some(t) = next else {
            break; // nothing scheduled — stuck
        };
        now = now.max(t);

        // 5. Deliver arrivals due by `now`.
        for cell in a2b.drain_due(now) {
            b.on_cell(&cell, now);
        }
        for cell in b2a.drain_due(now) {
            a.on_cell(&cell, now);
        }
        // 6. Fire timers.
        a.on_timeout(now);
        b.on_timeout(now);
    }

    Outcome {
        received,
        max_cwnd_a,
        max_inflight_a,
        final_a: a.debug_summary(),
        final_b: b.debug_summary(),
        a_events,
        b_events,
        steps,
        elapsed_ms: now,
        payload_received_ms,
        completed,
        tx_cells: a2b.injected,
        max_burst_a,
    }
}

fn payload(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng::new(seed);
    (0..n).map(|_| (r.next_u64() & 0xff) as u8).collect()
}

#[test]
fn perfect_channel_transfers_intact() {
    let data = payload(200_000, 1);
    let out = run_oneway(&data, Channel::perfect(), 42, Config::default());
    assert!(out.completed, "did not complete in {} steps", out.steps);
    assert_eq!(out.received, data, "byte mismatch over a clean channel");
    assert!(out.b_events.contains(&Event::Connected));
    assert!(
        out.b_events.contains(&Event::PeerFinished),
        "B must see clean EOF"
    );
    // Slow start must have grown the window past the initial value.
    assert!(
        out.max_cwnd_a >= Config::default().init_cwnd * 2,
        "cwnd barely grew: {}",
        out.max_cwnd_a
    );
}

#[test]
fn ten_percent_loss_still_completes_intact() {
    let data = payload(120_000, 2);
    let out = run_oneway(&data, Channel::lossy(0.10), 7, Config::default());
    assert!(
        out.completed,
        "10% loss did not complete in {} steps",
        out.steps
    );
    assert_eq!(out.received, data, "ARQ failed to repair 10% loss");
}

#[test]
fn thirty_percent_loss_still_completes_intact() {
    let data = payload(80_000, 3);
    let out = run_oneway(&data, Channel::lossy(0.30), 11, Config::default());
    assert!(
        out.completed,
        "30% loss did not complete in {} steps",
        out.steps
    );
    assert_eq!(out.received, data, "ARQ failed to repair 30% loss");
}

#[test]
fn sack_keeps_retransmit_overhead_bounded() {
    // SACK-aware retransmit must resend roughly the LOST cells, not re-send
    // cells the receiver already SACKed. 20% loss → expect well under 2× the
    // payload on the wire (a SACK-blind retransmitter inflates far past that).
    let data = payload(120_000, 21);
    let out = run_oneway(&data, Channel::lossy(0.20), 5, Config::default());
    assert!(out.completed, "did not complete");
    assert_eq!(out.received, data);
    let payload_cells = data.len().div_ceil(veil_onion_stream::MSS) as u64;
    assert!(
        out.tx_cells < payload_cells * 2,
        "retransmit overhead too high: {} cells sent for {} payload cells",
        out.tx_cells,
        payload_cells
    );
}

#[test]
fn high_bdp_sack_does_not_storm() {
    // Mirror the onion path: SECONDS of RTT + a large window keeps THOUSANDS of
    // cells in flight at once. A naive "retransmit every un-SACKed hole below the
    // highest SACK" then re-sends most of the in-flight window on each SACK — the
    // ~10× duplicate storm seen on-device. RFC 6675 IsLost (resend only a segment
    // with >=3 higher-seq SACKed segments) must keep overhead bounded. The 25 ms
    // `sack_keeps_retransmit_overhead_bounded` channel is too low-BDP to expose
    // this; a real RTT does.
    let mss = veil_onion_stream::MSS as u32;
    let cfg = Config {
        init_rto_ms: 12_000,
        min_rto_ms: 10_000,
        max_rto_ms: 60_000,
        recv_window: 8192 * mss,
        init_cwnd: 32 * mss,
        ..Config::default()
    };
    let data = payload(400_000, 31);
    // ~1 s one-way (≈2 s RTT) — far below the 10 s RTO floor, so EVERY retransmit
    // here is SACK-driven; this isolates mark_holes from the RTO path.
    let ch = Channel {
        loss: 0.10,
        dup: 0.0,
        base_delay: 1000,
        jitter: 50,
    };
    let out = run_oneway(&data, ch, 77, cfg);
    assert!(
        out.completed,
        "high-BDP transfer did not complete in {} steps",
        out.steps
    );
    assert_eq!(out.received, data);
    let payload_cells = data.len().div_ceil(veil_onion_stream::MSS) as u64;
    assert!(
        out.tx_cells < payload_cells * 2,
        "SACK storm at high BDP: {} cells sent for {} payload cells (~{:.1}× overhead)",
        out.tx_cells,
        payload_cells,
        out.tx_cells as f64 / payload_cells as f64
    );
}

#[test]
fn pacing_spreads_sends_no_burst() {
    // On a clean high-RTT path slow-start grows cwnd large. WITHOUT pacing the
    // sender dumps a whole cwnd of new segments the instant a cumulative ACK
    // frees the window — exactly the burst that overran the onion relay queue
    // on-device (slow-start overshoot → ~3000-cell loss → 1-cell/RTT stall).
    // Pacing must cap the single-instant burst to a small constant (the initial
    // unpaced window aside) while still letting cwnd grow.
    let cfg = Config {
        recv_window: 4096 * veil_onion_stream::MSS as u32,
        ..Config::default()
    };
    let data = payload(600_000, 41);
    let ch = Channel {
        loss: 0.0,
        dup: 0.0,
        base_delay: 500,
        jitter: 0,
    }; // ~1 s RTT
    let out = run_oneway(&data, ch, 9, cfg);
    assert!(
        out.completed,
        "clean transfer did not complete in {} steps",
        out.steps
    );
    assert_eq!(out.received, data);
    // Slow-start still grew cwnd well past the initial window...
    assert!(
        out.max_cwnd_a > cfg.init_cwnd * 4,
        "cwnd did not grow under pacing: {}",
        out.max_cwnd_a
    );
    // ...yet no single instant dumped more than a small burst (init_cwnd is
    // 10·MSS; the steady state is ~1 segment per pacing tick).
    assert!(
        out.max_burst_a <= 48,
        "sender burst too large ({} cells) — pacing is not spreading sends",
        out.max_burst_a
    );
}

#[test]
fn circuit_profile_clean_path_exceeds_target_throughput() {
    // Regression guard for the original device symptom: a clean pinned-circuit
    // stream idled at ~135 KiB/s because pacing/window choices prevented it
    // from filling the path. Model the circuit wire shape (318-byte MSS after
    // the rendezvous splice envelope) and a measured-ish 150 ms RTT. On a lossless
    // path the stream core must no longer hover at the old 1.5 MiB/s target; if
    // this drops, either the old one-segment/ms floor came back or the circuit
    // window/batch profile is too small to feed the pipe.
    let circuit_mss =
        veil_onion_stream::MAX_CELL - 16 - 32 - veil_onion_stream::wire::DATA_OVERHEAD;
    let cfg = Config {
        mss: circuit_mss,
        init_rto_ms: 12_000,
        min_rto_ms: 10_000,
        max_rto_ms: 60_000,
        handshake_rto_ms: 6_000,
        recv_window: 896 * 1024,
        init_cwnd: (32 * circuit_mss) as u32,
        max_pacing_batch: 12,
        ack_every: 16,
        ack_delay_ms: 5,
        ..Config::default()
    };
    let data = payload(8 * 1024 * 1024, 51);
    let ch = Channel {
        loss: 0.0,
        dup: 0.0,
        base_delay: 75,
        jitter: 0,
    };
    let out = run_oneway(&data, ch, 5150, cfg);
    assert!(
        out.completed,
        "clean circuit-profile transfer did not complete in {} steps",
        out.steps
    );
    assert_eq!(out.received, data);
    let payload_ms = out
        .payload_received_ms
        .expect("payload completion time must be tracked");
    assert!(payload_ms > 0, "payload elapsed time must be non-zero");
    let mib_per_s = data.len() as f64 * 1000.0 / payload_ms as f64 / (1024.0 * 1024.0);
    let target_mib_per_s = 2.0;
    eprintln!(
        "clean circuit profile: {mib_per_s:.2} MiB/s over {payload_ms} ms \
         (close={} ms, max_burst={}, tx_cells={})",
        out.elapsed_ms, out.max_burst_a, out.tx_cells
    );
    assert!(
        mib_per_s >= target_mib_per_s,
        "clean circuit profile too slow: {mib_per_s:.2} MiB/s < \
         {target_mib_per_s:.2} MiB/s over {payload_ms} ms \
         (close={} ms); \
         max_cwnd={} max_inflight={} tx_cells={} max_burst={} A={} B={}",
        out.elapsed_ms,
        out.max_cwnd_a,
        out.max_inflight_a,
        out.tx_cells,
        out.max_burst_a,
        out.final_a,
        out.final_b
    );
    assert!(
        out.max_burst_a <= 48,
        "clean circuit profile burst too large: {} cells",
        out.max_burst_a
    );
}

#[test]
fn reordering_and_duplication_complete_intact() {
    let data = payload(100_000, 4);
    let ch = Channel {
        loss: 0.05,
        dup: 0.10,
        base_delay: 25,
        jitter: 80,
    };
    let out = run_oneway(&data, ch, 99, Config::default());
    assert!(
        out.completed,
        "reorder+dup did not complete in {} steps",
        out.steps
    );
    assert_eq!(out.received, data, "reassembly failed under reorder+dup");
}

#[test]
fn heavy_combined_impairment_completes() {
    let data = payload(60_000, 5);
    let ch = Channel {
        loss: 0.20,
        dup: 0.05,
        base_delay: 40,
        jitter: 120,
    };
    let out = run_oneway(&data, ch, 2024, Config::default());
    assert!(
        out.completed,
        "combined impairment did not complete in {} steps",
        out.steps
    );
    assert_eq!(out.received, data);
}

#[test]
fn small_payload_and_empty_payload() {
    for n in [0usize, 1, 5, 366, 367, 733] {
        let data = payload(n, 100 + n as u64);
        let out = run_oneway(&data, Channel::lossy(0.15), 3, Config::default());
        assert!(out.completed, "n={n} did not complete");
        assert_eq!(out.received, data, "n={n} mismatch");
    }
}

#[test]
fn dead_link_resets_with_timeout_not_eof() {
    // 100% loss: nothing ever gets through → retransmit cap → RST(TIMED_OUT).
    let data = payload(10_000, 6);
    let cfg = Config {
        max_retransmits: 6,
        ..Config::default()
    };
    let out = run_oneway(&data, Channel::lossy(1.0), 1, cfg);
    assert!(!out.completed, "a dead link must not complete");
    let saw_timeout = out
        .a_events
        .iter()
        .any(|e| matches!(e, Event::Reset(r) if *r == reset_reason::TIMED_OUT));
    assert!(
        saw_timeout,
        "expected Reset(TIMED_OUT), got {:?}",
        out.a_events
    );
    assert!(
        !out.b_events.contains(&Event::PeerFinished),
        "must NOT look like clean EOF"
    );
}

#[test]
fn smaller_window_throttles_but_completes() {
    // A tight receive window forces flow control to gate the sender.
    let data = payload(50_000, 8);
    let cfg = Config {
        recv_window: (8 * veil_onion_stream::wire::MSS) as u32,
        ..Config::default()
    };
    let out = run_oneway(&data, Channel::lossy(0.05), 5, cfg);
    assert!(out.completed, "tight-window transfer did not complete");
    assert_eq!(out.received, data);
}
