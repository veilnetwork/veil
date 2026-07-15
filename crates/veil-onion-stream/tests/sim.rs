//! End-to-end simulation: two [`StreamEngine`]s over a virtual, lossy,
//! reordering, duplicating cell channel with an event-driven virtual clock.
//! Deterministic (seeded PRNG) so a failure reproduces byte-for-byte.

use veil_onion_stream::engine::{Config, Event, StreamEngine};
use veil_onion_stream::wire::{Frame, reset_reason};

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
    /// Two-path striping model: cells alternate between these one-way delays
    /// (overrides `base_delay`), e.g. a stream round-robined across two onion
    /// routes with different latencies. Systematic reordering, zero loss.
    two_path: Option<(u64, u64)>,
}
impl Channel {
    fn perfect() -> Self {
        Channel {
            loss: 0.0,
            dup: 0.0,
            base_delay: 25,
            jitter: 0,
            two_path: None,
        }
    }
    fn lossy(loss: f64) -> Self {
        Channel {
            loss,
            dup: 0.0,
            base_delay: 25,
            jitter: 0,
            two_path: None,
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
        self.inject_with_drop(now, bytes, rng, false);
    }

    fn inject_with_drop(&mut self, now: u64, bytes: &[u8], rng: &mut Rng, force_drop: bool) {
        self.injected += 1;
        if force_drop {
            return;
        }
        // Drop?
        if rng.unit() < self.ch.loss {
            return;
        }
        let deliver = |p: &mut Pipe, r: &mut Rng| {
            let base = match p.ch.two_path {
                // Round-robin cells across the two simulated routes.
                Some((fast, slow)) => {
                    if p.injected.is_multiple_of(2) {
                        fast
                    } else {
                        slow
                    }
                }
                None => p.ch.base_delay,
            };
            let arrive = now + base + r.range(0, p.ch.jitter + 1);
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

/// Drive a one-way transfer with a deterministic A→B drop predicate. This lets
/// tests model the live single-route failure shape: an early head DATA cell is
/// lost while later tail cells and ACK/SACK traffic continue to flow.
fn run_oneway_scripted_a2b_drop<F>(
    payload: &[u8],
    ch: Channel,
    seed: u64,
    cfg: Config,
    mut drop: F,
) -> Outcome
where
    F: FnMut(u64, &[u8]) -> bool,
{
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
    let mut max_burst_a = 0u64;
    let mut payload_received_ms = None;

    while steps < cap {
        steps += 1;
        let mut buf = Vec::new();
        let before = a2b.injected;
        while a.poll_transmit(now, &mut buf) {
            let force_drop = drop(now, &buf);
            a2b.inject_with_drop(now, &buf, &mut rng, force_drop);
        }
        max_burst_a = max_burst_a.max(a2b.injected - before);
        while b.poll_transmit(now, &mut buf) {
            b2a.inject(now, &buf, &mut rng);
        }
        max_cwnd_a = max_cwnd_a.max(a.cwnd());
        max_inflight_a = max_inflight_a.max(a.inflight_bytes());

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

        if received.len() == payload.len() && b.is_eof() && a.is_send_complete() {
            completed = true;
            break;
        }
        if a.is_closed() && a_events.iter().any(|e| matches!(e, Event::Reset(_))) {
            break;
        }
        if b.is_closed() && b_events.iter().any(|e| matches!(e, Event::Reset(_))) {
            break;
        }

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
            break;
        };
        now = now.max(t);

        for cell in a2b.drain_due(now) {
            b.on_cell(&cell, now);
        }
        for cell in b2a.drain_due(now) {
            a.on_cell(&cell, now);
        }
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
    // Sized in cells, not bytes: at the 16K cell a byte-fixed payload is a
    // handful of cells and the bound drowns in small-number noise.
    let data = payload(300 * veil_onion_stream::MSS, 21);
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
    // ~1k cells in flight regardless of the cell size (byte-fixed sizing left
    // ~25 cells after the 16K flag-day — statistically meaningless).
    let data = payload(1024 * veil_onion_stream::MSS, 31);
    // ~1 s one-way (≈2 s RTT) — far below the 10 s RTO floor, so EVERY retransmit
    // here is SACK-driven; this isolates mark_holes from the RTO path.
    let ch = Channel {
        loss: 0.10,
        dup: 0.0,
        base_delay: 1000,
        jitter: 50,
        two_path: None,
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
        two_path: None,
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
        two_path: None,
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
fn circuit_profile_stubborn_head_hole_completes_without_reset() {
    // Live single-route runs can lose an early DATA cell, deliver a large tail
    // behind it, then lose the first repair too. The receiver then advertises a
    // shrinking window because its out-of-order buffer is full of tail data. This
    // scripted test gives us a cheap local reproduction target for that shape
    // without requiring a phone + three relays for every recovery experiment.
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
        rto_rewind_no_sack: true,
        ..Config::default()
    };
    let data = payload(4 * 1024 * 1024, 61);
    let ch = Channel {
        loss: 0.0,
        dup: 0.0,
        base_delay: 75,
        jitter: 0,
        two_path: None,
    };
    let mut target_seq: Option<u32> = None;
    let mut drops_left = 2usize;
    let out = run_oneway_scripted_a2b_drop(&data, ch, 6161, cfg, |_, cell| {
        let Some(Frame::Data { seq, .. }) = Frame::decode(cell) else {
            return false;
        };
        let target =
            *target_seq.get_or_insert(1000 + 1 + (512 * 1024 / circuit_mss * circuit_mss) as u32);
        if seq == target && drops_left > 0 {
            drops_left -= 1;
            return true;
        }
        false
    });
    assert!(
        out.completed,
        "stubborn head-hole transfer did not complete in {} ms / {} steps; A={} B={}",
        out.elapsed_ms, out.steps, out.final_a, out.final_b
    );
    assert_eq!(out.received, data);
    assert!(
        !out.a_events.iter().any(|e| matches!(e, Event::Reset(_))),
        "sender reset under stubborn head-hole: {:?}",
        out.a_events
    );
    eprintln!(
        "stubborn head-hole circuit profile: payload_ms={:?} close={} tx_cells={} max_inflight={}",
        out.payload_received_ms, out.elapsed_ms, out.tx_cells, out.max_inflight_a
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
        two_path: None,
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
        two_path: None,
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

// ---- RACK time-threshold loss detection --------------------------------

/// Cells striped across two routes with a 400 ms one-way latency delta:
/// systematic cross-path reordering, ZERO real loss. The SACK-count detector
/// (3 SACKed above ⇒ lost) reads this as constant loss and collapses — the
/// conclusive on-device multipath failure. RACK must adapt its reordering
/// window (no floor given here) and deliver with near-zero spurious resends.
#[test]
fn rack_two_path_reorder_adapts_without_spurious_collapse() {
    let mss = veil_onion_stream::MSS;
    let data = payload(300 * mss, 42);
    let ch = Channel {
        loss: 0.0,
        dup: 0.0,
        base_delay: 0,
        jitter: 0,
        two_path: Some((100, 500)),
    };
    let cfg = Config {
        rack: true,
        // Handshake over the slow route RTTs at exactly the 1s default —
        // keep the SYN retransmit out of the wire-cell accounting.
        handshake_rto_ms: 3_000,
        ..Config::default()
    };
    let out = run_oneway(&data, ch, 9, cfg);
    assert!(out.completed, "two-path transfer did not complete");
    assert_eq!(out.received, data, "byte corruption under reordering");
    let payload_cells = data.len().div_ceil(mss) as u64;
    // Spurious resends are allowed while the reorder window is still
    // learning (costs ~15% of the first flights; ACKs alternate routes too,
    // so the window must grow past the data delta before it converges). The
    // SACK-count detector resends a large share of EVERY flight here and
    // collapses ssthresh; anything near-payload proves adaptation.
    assert!(
        out.tx_cells < payload_cells + payload_cells / 4 + 8,
        "spurious retransmit storm under two-path reordering: {} cells for {} payload",
        out.tx_cells,
        payload_cells
    );
    assert!(
        !out.a_events
            .iter()
            .any(|e| matches!(e, Event::DataRto { .. })),
        "reordering alone must never fire the RTO: {:?}",
        out.a_events
    );
}

/// Same two-path striping with a carrier-set reorder floor covering the
/// cross-route delta (what the striping carrier will configure): NO spurious
/// retransmit at all — every wire cell is a payload cell.
#[test]
fn rack_two_path_reorder_floor_zero_spurious() {
    let mss = veil_onion_stream::MSS;
    let data = payload(300 * mss, 43);
    let ch = Channel {
        loss: 0.0,
        dup: 0.0,
        base_delay: 0,
        jitter: 0,
        two_path: Some((100, 500)),
    };
    let cfg = Config {
        rack: true,
        // The floor must cover the worst delivery-report skew: slow-route
        // DATA + slow-route ACK vs fast+fast = both one-way deltas (800 ms
        // here; this sim reorders the ACK direction too).
        rack_reo_floor_ms: 1_000,
        handshake_rto_ms: 3_000,
        ..Config::default()
    };
    let mut data_cells = 0u64;
    let out = run_oneway_scripted_a2b_drop(&data, ch, 10, cfg, |_, cell| {
        if matches!(Frame::decode(cell), Some(Frame::Data { .. })) {
            data_cells += 1;
        }
        false // count only — never drop
    });
    assert!(out.completed, "two-path transfer did not complete");
    assert_eq!(out.received, data);
    let payload_cells = data.len().div_ceil(mss) as u64;
    // Every DATA cell on the wire is a payload cell — zero spurious resends.
    assert_eq!(
        data_cells, payload_cells,
        "expected zero spurious DATA resends with a covering reorder floor"
    );
}

/// Real mid-stream loss UNDER two-path reordering must be repaired by the
/// RACK timer well before the coarse RTO: two DATA originals are dropped
/// deterministically, the RTO floor is 10 s, so completion near clean-path
/// time proves time-threshold repair worked. (Tail loss is out of scope —
/// with no later delivery RACK has no signal; that is the RTO's job.)
#[test]
fn rack_repairs_real_loss_under_reordering_before_rto() {
    let mss = veil_onion_stream::MSS;
    let data = payload(300 * mss, 44);
    let ch = Channel {
        loss: 0.0,
        dup: 0.0,
        base_delay: 0,
        jitter: 0,
        two_path: Some((100, 500)),
    };
    let cfg = Config {
        rack: true,
        rack_reo_floor_ms: 600,
        handshake_rto_ms: 3_000,
        init_rto_ms: 12_000,
        min_rto_ms: 10_000,
        max_rto_ms: 60_000,
        ..Config::default()
    };
    let mut data_seen = 0u64;
    let out = run_oneway_scripted_a2b_drop(&data, ch, 11, cfg, |_, cell| {
        let Some(Frame::Data { .. }) = Frame::decode(cell) else {
            return false;
        };
        data_seen += 1;
        // Drop two mid-stream originals (each seq passes here once more as a
        // retransmit, which must get through).
        matches!(data_seen, 40 | 41)
    });
    assert!(
        out.completed,
        "two-path transfer with drops did not complete"
    );
    assert_eq!(out.received, data, "ARQ failed under loss + reordering");
    assert!(
        out.elapsed_ms < 10_000,
        "repair leaned on the RTO instead of the RACK timer: {} ms",
        out.elapsed_ms
    );
    assert!(
        !out.a_events
            .iter()
            .any(|e| matches!(e, Event::DataRto { .. })),
        "RTO fired for a RACK-repairable mid-stream loss: {:?}",
        out.a_events
    );
}

/// RACK on a plain single lossy path: parity with the SACK-count detector —
/// still completes intact with bounded overhead (regression guard for making
/// RACK the default on the circuit path).
#[test]
fn rack_single_path_loss_parity() {
    let mss = veil_onion_stream::MSS;
    let data = payload(300 * mss, 45);
    let cfg = Config {
        rack: true,
        ..Config::default()
    };
    let out = run_oneway(&data, Channel::lossy(0.20), 5, cfg);
    assert!(out.completed, "20% loss did not complete with RACK");
    assert_eq!(out.received, data);
    let payload_cells = data.len().div_ceil(mss) as u64;
    assert!(
        out.tx_cells < payload_cells * 2,
        "RACK retransmit overhead too high: {} cells for {} payload",
        out.tx_cells,
        payload_cells
    );
}
