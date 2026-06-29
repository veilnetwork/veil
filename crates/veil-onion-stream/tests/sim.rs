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
    loss: f64,      // per-cell drop probability
    dup: f64,       // per-cell duplication probability
    base_delay: u64, // one-way propagation (ms)
    jitter: u64,    // extra uniform [0,jitter] ms → reordering
}
impl Channel {
    fn perfect() -> Self {
        Channel { loss: 0.0, dup: 0.0, base_delay: 25, jitter: 0 }
    }
    fn lossy(loss: f64) -> Self {
        Channel { loss, dup: 0.0, base_delay: 25, jitter: 0 }
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
}
impl Pipe {
    fn new(ch: Channel) -> Self {
        Pipe { ch, flight: Vec::new() }
    }
    fn inject(&mut self, now: u64, bytes: &[u8], rng: &mut Rng) {
        // Drop?
        if rng.unit() < self.ch.loss {
            return;
        }
        let deliver = |p: &mut Pipe, r: &mut Rng| {
            let arrive = now + p.ch.base_delay + r.range(0, p.ch.jitter + 1);
            p.flight.push(InFlight { arrive, bytes: bytes.to_vec() });
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
    a_events: Vec<Event>,
    b_events: Vec<Event>,
    steps: u64,
    completed: bool,
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

    let mut now = 0u64;
    let mut steps = 0u64;
    let cap = 20_000_000u64;
    let mut completed = false;

    while steps < cap {
        steps += 1;
        // 1. Drain both engines' transmits at `now`.
        let mut buf = Vec::new();
        while a.poll_transmit(now, &mut buf) {
            a2b.inject(now, &buf, &mut rng);
        }
        while b.poll_transmit(now, &mut buf) {
            b2a.inject(now, &buf, &mut rng);
        }
        max_cwnd_a = max_cwnd_a.max(a.cwnd());

        // 2. Pump reader on B + drain events.
        let mut tmp = [0u8; 4096];
        loop {
            let n = b.read(&mut tmp);
            if n == 0 {
                break;
            }
            received.extend_from_slice(&tmp[..n]);
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

    Outcome { received, max_cwnd_a, a_events, b_events, steps, completed }
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
    assert!(out.b_events.contains(&Event::PeerFinished), "B must see clean EOF");
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
    assert!(out.completed, "10% loss did not complete in {} steps", out.steps);
    assert_eq!(out.received, data, "ARQ failed to repair 10% loss");
}

#[test]
fn thirty_percent_loss_still_completes_intact() {
    let data = payload(80_000, 3);
    let out = run_oneway(&data, Channel::lossy(0.30), 11, Config::default());
    assert!(out.completed, "30% loss did not complete in {} steps", out.steps);
    assert_eq!(out.received, data, "ARQ failed to repair 30% loss");
}

#[test]
fn reordering_and_duplication_complete_intact() {
    let data = payload(100_000, 4);
    let ch = Channel { loss: 0.05, dup: 0.10, base_delay: 25, jitter: 80 };
    let out = run_oneway(&data, ch, 99, Config::default());
    assert!(out.completed, "reorder+dup did not complete in {} steps", out.steps);
    assert_eq!(out.received, data, "reassembly failed under reorder+dup");
}

#[test]
fn heavy_combined_impairment_completes() {
    let data = payload(60_000, 5);
    let ch = Channel { loss: 0.20, dup: 0.05, base_delay: 40, jitter: 120 };
    let out = run_oneway(&data, ch, 2024, Config::default());
    assert!(out.completed, "combined impairment did not complete in {} steps", out.steps);
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
    let cfg = Config { max_retransmits: 6, ..Config::default() };
    let out = run_oneway(&data, Channel::lossy(1.0), 1, cfg);
    assert!(!out.completed, "a dead link must not complete");
    let saw_timeout = out
        .a_events
        .iter()
        .any(|e| matches!(e, Event::Reset(r) if *r == reset_reason::TIMED_OUT));
    assert!(saw_timeout, "expected Reset(TIMED_OUT), got {:?}", out.a_events);
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
