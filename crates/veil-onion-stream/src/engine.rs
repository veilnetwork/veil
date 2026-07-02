//! The sans-IO reliable-stream state machine: one endpoint of a full-duplex
//! stream over a lossy cell channel. Drives ARQ + AIMD congestion control with
//! no sockets and no clock — every effect is a value in/out (see crate docs).
//!
//! Shape (TCP NewReno-flavoured): a [`TxState`] (bytes WE send: send window,
//! cwnd/ssthresh, RTO, retransmit queue, NewReno fast-recovery, FIN) plus a
//! [`RxState`] (bytes we RECEIVE: cumulative + out-of-order reassembly, SACK,
//! advertised window). Handshake is SYN → SYN_ACK; teardown is FIN (EOF) or RST
//! (interrupted → app resumes).
//!
//! Handshake sequence accounting (asymmetric, kept simple): the initiator's SYN
//! consumes one sequence number (its first data byte is `iss+1`); the SYN_ACK
//! does NOT (the responder's first data byte is its `iss`). The responder learns
//! its SYN_ACK arrived implicitly — any later frame from the initiator proves it.

use std::collections::{BTreeMap, VecDeque};

use crate::seq;
use crate::wire::{Frame, MSS, SackRange, SackVec, reset_reason};

// ---- BBR-lite estimator tuning (see `Config::bbr`) ----
/// Sliding window each delivery-rate sample is computed over.
const BBR_RATE_WINDOW_MS: u64 = 2_000;
/// Minimum spacing between delivery checkpoints.
const BBR_SAMPLE_SPACING_MS: u64 = 20;
/// Minimum span/bytes before a window qualifies as a rate sample — thinner
/// windows are treated as app-limited and leave the estimate untouched.
const BBR_MIN_SPAN_MS: u64 = 300;
const BBR_MIN_DELIVERED: u64 = 64 * 1024;
/// The bottleneck-rate estimate is the MAX of qualifying samples over this
/// window (classic BBR shape). A max filter cannot self-trap: pacing runs at
/// 5/4 of the estimate, so if the path has more capacity a faster sample
/// appears and ratchets the estimate up; if the path degrades, the stale
/// maximum simply expires. A decay-based estimator was tried first and
/// collapsed live (own pacing fed the lower samples it then decayed toward).
const BBR_BW_WINDOW_MS: u64 = 10_000;
/// Minimum spacing between stored bandwidth samples.
const BBR_BW_SAMPLE_SPACING_MS: u64 = 100;
/// BBR engages only after this many bytes were delivered on the stream, so
/// slow start first climbs to a realistic rate: an estimate seeded from the
/// first slow-start round-trips caps the window at a crawl.
const BBR_ENGAGE_DELIVERED: u64 = 1024 * 1024;
/// Expiry of the windowed-minimum RTT sample.
const BBR_MIN_RTT_WINDOW_MS: u64 = 30_000;

/// Tunables. Bytes for windows, millis for timers.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub mss: usize,
    /// Initial congestion window (bytes). ~10·MSS like modern TCP IW10.
    pub init_cwnd: u32,
    /// Initial slow-start threshold; `u32::MAX` = slow-start until first loss.
    pub init_ssthresh: u32,
    /// Our advertised receive buffer (bytes) — the reassembly/read cap.
    pub recv_window: u32,
    pub init_rto_ms: u64,
    pub min_rto_ms: u64,
    pub max_rto_ms: u64,
    /// Max CONSECUTIVE retransmits of the oldest unacked segment (or handshake
    /// frame) with no new acknowledgement before the path is declared dead →
    /// `RST(TIMED_OUT)`. Counting retransmits (not wall-clock) means exponential
    /// RTO backoff under heavy loss can never trip it spuriously.
    pub max_retransmits: u32,
    /// Handshake (SYN/SYN_ACK) retransmit interval.
    pub handshake_rto_ms: u64,
    /// Maximum number of DATA/retransmit segments released on one millisecond
    /// pacing tick. This bounds the microburst presented to the carrier while
    /// allowing rates above the old one-MSS-per-ms ceiling.
    pub max_pacing_batch: u32,
    /// On a no-SACK RTO, move the outstanding unsacked flight back into the
    /// pending queue and re-send it under normal pacing instead of leaving a
    /// large phantom `inflight` above the collapsed cwnd. This is intentionally
    /// opt-in for transports whose internal queues can drop a contiguous burst
    /// while still reporting send success (the pinned circuit path).
    pub rto_rewind_no_sack: bool,
    /// Multiplicative decrease after SACK/fast-retransmit loss, in per-mille.
    /// Classic NewReno is 500 (halve the window). Pinned onion circuits use a
    /// softer cut: their "loss" is often local relay/session queue churn or a
    /// route reset, not evidence that the full anonymous path has half the
    /// available bandwidth. Reliability is unchanged; this only controls how
    /// much sending rate we retain while SACK/RTO repairs the holes.
    pub loss_decrease_per_mille: u16,
    /// BBR-lite shaping: pace new data at 5/4 of the measured delivery rate
    /// and cap the effective send window at 2x the measured
    /// bandwidth-delay product instead of filling min(cwnd, rwnd). Without
    /// this, loss-free paths (the pinned circuit) grow cwnd unbounded and park
    /// a full receive window of cells in sender-side queues — live srtt
    /// inflated to seconds of pure queueing delay, which slows RTO/loss
    /// detection and failover. Throughput is unchanged (the drain rate is the
    /// bottleneck either way); this only bounds the standing queue. NewReno
    /// loss handling stays active underneath (the caps compose via min).
    pub bbr: bool,
    /// Number of contiguous advancing DATA segments acknowledged by one
    /// cumulative ACK. Gaps, duplicates and FIN always ACK immediately.
    pub ack_every: u8,
    /// Maximum delay before acknowledging a partial [`Self::ack_every`] group.
    pub ack_delay_ms: u64,
    /// Warm-start seed for the BBR-lite bottleneck estimate (bytes/sec), from
    /// a previous stream to the same peer. 0 = cold start. A warm stream
    /// engages BBR pacing/window shaping from the first byte (no
    /// 1 MiB engage gate, no STARTUP): the 10s max-window naturally expires
    /// the seed once real samples land, and NewReno loss handling still
    /// applies underneath, so a stale (too-high) seed self-corrects within a
    /// window while a too-low seed is out-probed at the steady 5/4 gain.
    /// Callers should seed conservatively (e.g. half the last measured rate).
    pub warm_btl_bw: u64,
    /// Warm-start seed for the windowed-minimum RTT (ms). Only used when
    /// [`Self::warm_btl_bw`] is non-zero. 0 = none (the seed then waits for
    /// the first live RTT sample before the window cap engages).
    pub warm_rtt_min_ms: u32,
    /// Optional driver-side diagnostic dump period. 0 disables it.
    pub debug_summary_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        let mss = MSS;
        Self {
            mss,
            init_cwnd: (10 * mss) as u32,
            init_ssthresh: u32::MAX,
            recv_window: (1024 * mss) as u32,
            init_rto_ms: 1000,
            min_rto_ms: 200,
            max_rto_ms: 30_000,
            max_retransmits: 12,
            handshake_rto_ms: 1000,
            max_pacing_batch: 4,
            rto_rewind_no_sack: false,
            loss_decrease_per_mille: 500,
            bbr: false,
            ack_every: 2,
            ack_delay_ms: 5,
            warm_btl_bw: 0,
            warm_rtt_min_ms: 0,
            debug_summary_ms: 0,
        }
    }
}

/// Connection-level events surfaced to the driver / app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Handshake complete — the stream may carry data both ways.
    Connected,
    /// A DATA retransmission timeout fired without new cumulative ACK progress.
    /// Useful to the carrier for route health/failover; not terminal.
    DataRto { consec_rto: u32, snd_una: u32 },
    /// The peer sent FIN: the read side has reached clean EOF.
    PeerFinished,
    /// Abnormal teardown — NOT EOF. The app should resume (`reason` from
    /// [`reset_reason`]).
    Reset(u8),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// Initiator: SYN sent, waiting for SYN_ACK.
    SynSent,
    /// Responder: created, waiting for the first SYN.
    Listen,
    Established,
    /// A RST was sent or received — terminal.
    Closed,
}

/// One sent-but-unacked segment (a FIN is a 1-seq segment with empty data).
struct Seg {
    seq: u32,
    data: Vec<u8>,
    is_fin: bool,
    sent_ms: u64,
    retransmitted: bool,
    /// The receiver SACKed this segment — it's received, never retransmit it.
    sacked: bool,
    /// Marked for retransmission (a hole below the highest SACK, or an RTO).
    needs_resend: bool,
}
impl Seg {
    /// Sequence space this segment consumes (FIN consumes 1).
    fn span(&self) -> u32 {
        if self.is_fin {
            1
        } else {
            self.data.len() as u32
        }
    }
    fn end(&self) -> u32 {
        self.seq.wrapping_add(self.span())
    }
}

struct TxState {
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    pending: VecDeque<u8>, // written, not yet segmented/sent
    segs: VecDeque<Seg>,   // sent, unacked, in seq order
    cwnd: u32,
    ssthresh: u32,
    rwnd: u32, // peer-advertised receive window
    dup_acks: u32,
    in_recovery: bool,
    recover: u32, // NewReno: snd_nxt at the moment loss was detected
    // RTT / RTO (Jacobson-Karels), millis.
    srtt: Option<u32>,
    rttvar: u32,
    rto_ms: u64,
    rto_deadline: Option<u64>,
    /// Consecutive RTO firings with no intervening new-data ack (dead detection).
    consec_rto: u32,
    /// Pacing: earliest time the next NEW-data segment may go on the wire. The
    /// sender emits one cwnd's worth of data per smoothed RTT as an even trickle
    /// instead of bursting it — a burst overruns the onion relay's bounded queue
    /// and triggers catastrophic multi-thousand-cell loss (slow-start overshoot).
    pace_next_ms: u64,
    /// New-data segments left in the current millisecond pacing tick.
    pace_budget: u32,
    /// Highest sequence number that had been sent before a no-SACK RTO rewind.
    /// ACKs up to this point are still valid even though `snd_nxt` was rewound
    /// to `snd_una` and the bytes were moved back into `pending`.
    rewind_high: Option<u32>,
    /// Whether the rewound no-SACK flight included a FIN at `rewind_high`.
    /// If a late cumulative ACK reaches that point, the old FIN was accepted and
    /// must complete the stream even though the FIN segment itself was removed
    /// from `segs` during rewind.
    rewind_fin: bool,
    fin_requested: bool,
    fin_sent: bool,
    fin_acked: bool,
    // ---- BBR-lite delivery model (maintained only when cfg.bbr) ----
    /// Total bytes acknowledged by cumulative ACK advance.
    delivered: u64,
    /// Delivery checkpoints (t_ms, delivered) spanning the rate window.
    rate_samples: VecDeque<(u64, u64)>,
    /// Qualifying rate samples (t_ms, bytes/sec); the estimate is their max
    /// over [`BBR_BW_WINDOW_MS`] (see the constants for why max, not decay).
    bw_samples: VecDeque<(u64, u64)>,
    /// Measured bottleneck delivery rate, bytes/sec (windowed max).
    btl_bw: u64,
    /// STARTUP phase: pace at 2x the estimate until it plateaus. Without it a
    /// low first sample (taken during a hiccup) needs ~10 probe windows at
    /// 5/4 gain to climb to the real capacity — live this made whole 16 MiB
    /// transfers ride the climb (bimodal 9s vs 21s runs on the same path).
    bbr_startup: bool,
    /// Estimate at the last plateau check and consecutive no-growth rounds.
    bbr_bw_at_probe: u64,
    bbr_stall_rounds: u8,
    /// Last time the STARTUP plateau was evaluated. Stored bw samples arrive
    /// as fast as every [`BBR_BW_SAMPLE_SPACING_MS`] while the estimate itself
    /// is a sliding-window AVERAGE that needs seconds to reflect a rate
    /// doubling — checking "no growth" per sample burned the 3-round budget in
    /// ~300ms and exited STARTUP far below capacity (live: plateaus at ~3 MB/s
    /// on a ~6 MB/s path). Classic BBR checks once per round trip; do the same.
    bbr_probe_checked_ms: u64,
    /// Windowed minimum round-trip time (ms) and the time it was recorded.
    rtt_min: Option<(u32, u64)>,
}

struct RxState {
    rcv_nxt: u32,
    window: u32, // configured buffer size (bytes)
    read_buf: VecDeque<u8>,
    oo: BTreeMap<u32, Vec<u8>>, // out-of-order, keyed by seq (kept non-overlapping)
    oo_bytes: usize,
    peer_fin_seq: Option<u32>,
    eof: bool,
}

/// One endpoint of a reliable onion byte-stream.
pub struct StreamEngine {
    stream_id: u32,
    cfg: Config,
    phase: Phase,
    tx: TxState,
    rx: RxState,
    // outbound control flags
    send_syn: bool,
    send_synack: bool,
    syn_acked: bool, // our SYN/SYN_ACK has been acknowledged
    hs_deadline: Option<u64>,
    /// Consecutive handshake retransmits with no peer response (dead detection).
    hs_retries: u32,
    ack_pending: bool,
    /// Delayed-ACK state: ACK after the configured number of advancing DATA
    /// segments, or after a short timer. Gaps/duplicates/FIN are immediate.
    ack_eliciting: u8,
    ack_deadline: Option<u64>,
    rst_to_send: Option<u8>,
    /// Zero-window persist timer: when the peer advertises a 0 window and we have
    /// data to send, probe periodically so a re-opened window can't deadlock us.
    persist_deadline: Option<u64>,
    force_probe: bool,
    events: VecDeque<Event>,
}

impl StreamEngine {
    fn loss_decrease_window(&self, basis: u32, mss: u32) -> u32 {
        let beta = u64::from(self.cfg.loss_decrease_per_mille.clamp(1, 1000));
        ((u64::from(basis) * beta) / 1000)
            .max(u64::from(2 * mss))
            .min(u64::from(u32::MAX)) as u32
    }

    /// Initiator side: queues a SYN. `iss` = our initial send sequence.
    pub fn connect(stream_id: u32, cfg: Config, now: u64, iss: u32) -> Self {
        let mut e = Self::new(stream_id, cfg, iss);
        e.phase = Phase::SynSent;
        e.send_syn = true;
        e.tx.snd_nxt = iss.wrapping_add(1); // SYN consumes seq `iss`
        e.hs_deadline = Some(now + cfg.handshake_rto_ms);
        e
    }

    /// Responder side: waits for a SYN. `iss` = our initial send sequence.
    pub fn accept(stream_id: u32, cfg: Config, _now: u64, iss: u32) -> Self {
        let mut e = Self::new(stream_id, cfg, iss);
        e.phase = Phase::Listen;
        e
    }

    fn new(stream_id: u32, cfg: Config, iss: u32) -> Self {
        // Warm start: seed the delivery model from a previous stream to the
        // same peer so a follow-up bulk stream skips the estimator climb (the
        // cold ramp costs seconds per stream; see Config::warm_btl_bw). The
        // seed enters the same windowed-max filter as live samples, so it
        // expires like any sample once real data flows.
        let warm = cfg.bbr && cfg.warm_btl_bw > 0;
        let warm_rtt = (warm && cfg.warm_rtt_min_ms > 0).then_some((cfg.warm_rtt_min_ms, 0u64));
        let mut init_cwnd = cfg.init_cwnd.max(cfg.mss as u32);
        if let Some((rtt_ms, _)) = warm_rtt {
            // Open the first flight near the seeded BDP (capped: an unpaced
            // pre-first-ACK burst rides the carrier's token-bucket pacer, and
            // a bounded relay queue should never see a multi-MiB wall).
            let bdp = (cfg.warm_btl_bw.saturating_mul(rtt_ms as u64) / 1000)
                .min(1024 * 1024)
                .min(cfg.recv_window as u64) as u32;
            init_cwnd = init_cwnd.max(bdp);
        }
        Self {
            stream_id,
            cfg,
            phase: Phase::Listen,
            tx: TxState {
                iss,
                snd_una: iss,
                snd_nxt: iss,
                pending: VecDeque::new(),
                segs: VecDeque::new(),
                cwnd: init_cwnd,
                ssthresh: cfg.init_ssthresh,
                rwnd: cfg.mss as u32, // until the peer tells us, allow one segment
                dup_acks: 0,
                in_recovery: false,
                recover: iss,
                srtt: None,
                rttvar: 0,
                rto_ms: cfg.init_rto_ms,
                rto_deadline: None,
                consec_rto: 0,
                pace_next_ms: 0,
                pace_budget: 0,
                rewind_high: None,
                rewind_fin: false,
                fin_requested: false,
                fin_sent: false,
                fin_acked: false,
                delivered: 0,
                rate_samples: VecDeque::new(),
                bw_samples: if warm {
                    VecDeque::from([(0, cfg.warm_btl_bw)])
                } else {
                    VecDeque::new()
                },
                btl_bw: if warm { cfg.warm_btl_bw } else { 0 },
                // A warm stream STAYS in STARTUP, seeded: skipping it (the
                // first design) pinned every follow-up stream at 5/4 gain of
                // the cached model, which (a) is HALF the previous rate (the
                // mux seeds at 1/2 — so 2x STARTUP pacing of the seed probes
                // exactly the cached rate, not beyond it) and (b) can never
                // climb out of a model cached during a degraded minute (live:
                // ranged pulls crawled at 0.5-0.8 MB/s for 100s on a path
                // doing 5+ MB/s). Seeding bbr_bw_at_probe with the warm model
                // starts the plateau clock AT the cache: a path that does not
                // grow >=25%/round beyond it exits STARTUP within ~3 round
                // trips (bounded overshoot), a better path keeps the 2x climb.
                bbr_startup: true,
                bbr_bw_at_probe: if warm { cfg.warm_btl_bw } else { 0 },
                bbr_stall_rounds: 0,
                bbr_probe_checked_ms: 0,
                rtt_min: warm_rtt.map(|(r, t)| (r.max(1), t)),
            },
            rx: RxState {
                rcv_nxt: 0,
                window: cfg.recv_window,
                read_buf: VecDeque::new(),
                oo: BTreeMap::new(),
                oo_bytes: 0,
                peer_fin_seq: None,
                eof: false,
            },
            send_syn: false,
            send_synack: false,
            syn_acked: false,
            hs_deadline: None,
            hs_retries: 0,
            ack_pending: false,
            ack_eliciting: 0,
            ack_deadline: None,
            rst_to_send: None,
            persist_deadline: None,
            force_probe: false,
            events: VecDeque::new(),
        }
    }

    // ---- app surface ----------------------------------------------------

    /// Queue `data` for sending. Returns the bytes accepted (currently all).
    pub fn write(&mut self, data: &[u8]) -> usize {
        if self.phase == Phase::Closed || self.tx.fin_requested {
            return 0;
        }
        self.tx.pending.extend(data.iter().copied());
        data.len()
    }

    /// Half-close our send direction: a FIN follows the last queued byte.
    pub fn finish(&mut self) {
        self.tx.fin_requested = true;
    }

    /// Abort: queue a RST and move to terminal. The peer sees [`Event::Reset`].
    pub fn reset(&mut self, reason: u8) {
        if self.phase != Phase::Closed {
            self.rst_to_send = Some(reason);
            self.phase = Phase::Closed;
        }
    }

    /// Pull up to `buf.len()` delivered, in-order bytes. 0 = none available
    /// right now (check [`Self::is_eof`] to distinguish from clean EOF).
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.rx.read_buf.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.rx.read_buf.pop_front().unwrap();
        }
        n
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn is_established(&self) -> bool {
        self.phase == Phase::Established
    }
    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }
    /// EOF = peer FIN delivered AND all in-order bytes read out.
    pub fn is_eof(&self) -> bool {
        self.rx.eof && self.rx.read_buf.is_empty()
    }
    pub fn readable_len(&self) -> usize {
        self.rx.read_buf.len()
    }
    pub fn send_buffer_len(&self) -> usize {
        self.tx.pending.len()
    }
    /// All sent data + FIN acknowledged and nothing left to send.
    pub fn is_send_complete(&self) -> bool {
        self.tx.pending.is_empty()
            && self.tx.segs.is_empty()
            && (!self.tx.fin_requested || self.tx.fin_acked)
    }
    pub fn cwnd(&self) -> u32 {
        self.tx.cwnd
    }
    pub fn inflight_bytes(&self) -> u32 {
        self.tx.snd_nxt.wrapping_sub(self.tx.snd_una)
    }
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }
    /// Final BBR-lite delivery model, for warm-starting a follow-up stream to
    /// the same peer: `(btl_bw bytes/sec, rtt_min ms, delivered bytes)`.
    /// `btl_bw`/`rtt_min` are 0 when the model never warmed up.
    pub fn delivery_model(&self) -> (u64, u32, u64) {
        (
            self.tx.btl_bw,
            self.tx.rtt_min.map(|(r, _)| r).unwrap_or(0),
            self.tx.delivered,
        )
    }
    pub fn debug_summary_period_ms(&self) -> u64 {
        self.cfg.debug_summary_ms
    }

    /// Debug snapshot (for diagnostics / tests).
    pub fn debug_summary(&self) -> String {
        let sacked = self.tx.segs.iter().filter(|s| s.sacked).count();
        let resend = self.tx.segs.iter().filter(|s| s.needs_resend).count();
        let inflight = self.tx.snd_nxt.wrapping_sub(self.tx.snd_una);
        format!(
            "phase={:?} una={} nxt={} inflight={} cwnd={} ssth={} rwnd={} segs={}(sack={} resend={}) \
             pending={} dup={} recov={} consec_rto={} | rcv_nxt={} read_buf={} oo={} oo_bytes={} \
             adv={} ack_pending={} eof={} fin(req={},sent={},ack={}) \
             srtt={:?} rttvar={} rto={}ms pace_next={}ms delayed_ack={}/{:?} \
             rto_dl={:?} persist_dl={:?} bbr_bw={} bbr_rtt_min={:?} bbr_cap={:?}",
            self.phase,
            self.tx.snd_una,
            self.tx.snd_nxt,
            inflight,
            self.tx.cwnd,
            self.tx.ssthresh,
            self.tx.rwnd,
            self.tx.segs.len(),
            sacked,
            resend,
            self.tx.pending.len(),
            self.tx.dup_acks,
            self.tx.in_recovery,
            self.tx.consec_rto,
            self.rx.rcv_nxt,
            self.rx.read_buf.len(),
            self.rx.oo.len(),
            self.rx.oo_bytes,
            self.rx.advertised(),
            self.ack_pending,
            self.rx.eof,
            self.tx.fin_requested,
            self.tx.fin_sent,
            self.tx.fin_acked,
            self.tx.srtt,
            self.tx.rttvar,
            self.tx.rto_ms,
            self.tx.pace_next_ms,
            self.ack_eliciting,
            self.ack_deadline,
            self.tx.rto_deadline,
            self.persist_deadline,
            self.tx.btl_bw,
            self.tx.rtt_min.map(|(rtt, _)| rtt),
            self.tx.bbr_window_cap(&self.cfg),
        )
    }

    // ---- inbound --------------------------------------------------------

    /// Feed one received cell (the circuit's inner payload).
    pub fn on_cell(&mut self, cell: &[u8], now: u64) {
        let Some(frame) = Frame::decode(cell) else {
            return;
        };
        if frame.stream_id() != self.stream_id {
            return;
        }
        match frame {
            Frame::Syn { isn, win, .. } => self.on_syn(isn, win, now),
            Frame::SynAck { isn, win, ack, .. } => self.on_synack(isn, win, ack, now),
            Frame::Data {
                seq, win, payload, ..
            } => self.on_data(seq, win, payload, now),
            Frame::Ack {
                ack, win, sacks, ..
            } => self.on_ack(ack, win, &sacks, now),
            Frame::Fin { seq, .. } => self.on_peer_fin(seq, now),
            Frame::Rst { reason, .. } => self.on_rst(reason),
        }
    }

    fn on_syn(&mut self, isn: u32, win: u32, now: u64) {
        match self.phase {
            Phase::Listen => {
                self.rx.rcv_nxt = isn.wrapping_add(1); // SYN consumes one seq
                self.tx.rwnd = win;
                self.phase = Phase::Established;
                self.send_synack = true;
                self.hs_deadline = Some(now + self.cfg.handshake_rto_ms);
                self.hs_retries = 0;
                self.events.push_back(Event::Connected);
            }
            // Duplicate SYN after we're up → re-ack via SYN_ACK.
            Phase::Established => self.send_synack = true,
            _ => {}
        }
    }

    fn on_synack(&mut self, isn: u32, win: u32, ack: u32, _now: u64) {
        if self.phase == Phase::SynSent {
            if seq::geq(ack, self.tx.iss.wrapping_add(1)) {
                self.tx.snd_una = self.tx.iss.wrapping_add(1); // our SYN acked
            }
            self.tx.snd_nxt = seq::max(self.tx.snd_nxt, self.tx.snd_una);
            self.rx.rcv_nxt = isn; // SYN_ACK consumes no seq
            self.tx.rwnd = win;
            self.syn_acked = true;
            self.hs_deadline = None;
            self.hs_retries = 0;
            self.phase = Phase::Established;
            self.ack_now(); // tell the peer we're up (implicit SYN_ACK ack)
            self.events.push_back(Event::Connected);
        } else if self.phase == Phase::Established {
            self.ack_now();
        }
    }

    /// Any post-handshake frame from the peer confirms our SYN_ACK arrived.
    fn note_peer_progress(&mut self) {
        if self.phase == Phase::Established && !self.syn_acked {
            self.syn_acked = true;
            self.hs_deadline = None;
            self.hs_retries = 0;
        }
    }

    fn on_data(&mut self, seg_seq: u32, win: u32, payload: &[u8], now: u64) {
        if self.phase == Phase::Closed {
            return;
        }
        self.note_peer_progress();
        self.tx.rwnd = win; // piggy-backed reverse-direction window
        if payload.is_empty() {
            return;
        }
        let advanced = self.rx.accept(seg_seq, payload);
        self.ack_data(advanced, now);
    }

    fn on_peer_fin(&mut self, fin_seq: u32, now: u64) {
        if self.phase == Phase::Closed {
            return;
        }
        self.note_peer_progress();
        let _ = now;
        self.rx.peer_fin_seq = Some(fin_seq);
        self.rx.try_consume_fin();
        if self.rx.eof && !self.events.iter().any(|e| *e == Event::PeerFinished) {
            self.events.push_back(Event::PeerFinished);
        }
        self.ack_now();
    }

    fn on_rst(&mut self, reason: u8) {
        if self.phase != Phase::Closed {
            self.phase = Phase::Closed;
            self.events.push_back(Event::Reset(reason));
        }
    }

    fn on_ack(&mut self, ack: u32, win: u32, sacks: &SackVec, now: u64) {
        self.tx.rwnd = win;
        self.note_peer_progress();
        if self.phase == Phase::SynSent || self.phase == Phase::Closed {
            return;
        }
        // Never let a malformed/hostile cumulative ACK advance beyond bytes we
        // actually sent. Besides corrupting snd_una, that would turn byte-counted
        // congestion growth below into an arbitrary cwnd jump.
        if seq::gt(ack, self.tx.ack_limit()) {
            return;
        }
        // SACK: mark fully-covered unacked segments as RECEIVED so a later RTO /
        // fast-retransmit never resends them (the big source of duplicate cells
        // over the high-RTT onion path).
        for r in sacks.as_slice() {
            for s in self.tx.segs.iter_mut() {
                if seq::geq(s.seq, r.start) && seq::leq(s.end(), r.end) {
                    s.sacked = true;
                }
            }
        }
        let mss = self.cfg.mss as u32;

        if seq::gt(ack, self.tx.snd_una) {
            // ---- new data acknowledged ----
            let mut rtt_sample: Option<u32> = None;
            while let Some(front) = self.tx.segs.front() {
                if seq::leq(front.end(), ack) {
                    let s = self.tx.segs.pop_front().unwrap();
                    if !s.retransmitted {
                        rtt_sample = Some(now.saturating_sub(s.sent_ms) as u32);
                    }
                    if s.is_fin {
                        self.tx.fin_acked = true;
                    }
                } else {
                    break;
                }
            }
            let acked = ack.wrapping_sub(self.tx.snd_una);
            self.tx.snd_una = ack;
            self.tx.trim_rewound_pending_after_ack(ack);
            self.tx.dup_acks = 0;
            self.tx.consec_rto = 0; // progress: reset dead-link counter
            if self.cfg.bbr {
                self.tx.bbr_on_delivered(acked, now);
            }

            if self.tx.in_recovery {
                if seq::geq(ack, self.tx.recover) {
                    self.tx.in_recovery = false; // full recovery
                    self.tx.cwnd = self.tx.ssthresh.max(mss);
                } else {
                    // partial ACK: retransmit the remaining holes, deflate by acked.
                    self.tx.cwnd = self.tx.cwnd.saturating_sub(acked).max(mss);
                    self.mark_holes(true);
                    self.tx.cwnd = self.tx.cwnd.saturating_add(mss);
                }
            } else if self.tx.cwnd < self.tx.ssthresh {
                // Appropriate Byte Counting: cumulative/delayed ACKs represent
                // every newly acknowledged byte, not one synthetic MSS. This
                // keeps slow-start growth invariant when the receiver thins
                // fixed-size ACK cells (ACK×2 and ACK×32 should both roughly
                // double cwnd per RTT).
                self.tx.cwnd = self.tx.cwnd.saturating_add(acked);
            } else {
                // One MSS per cwnd bytes acknowledged, scaled by the actual
                // cumulative ACK span so delayed ACKs do not slow additive
                // increase merely by reducing packet count.
                let inc = ((mss as u64 * acked as u64) / self.tx.cwnd.max(1) as u64).max(1) as u32;
                self.tx.cwnd = self.tx.cwnd.saturating_add(inc); // congestion avoidance
            }

            if let Some(r) = rtt_sample {
                if self.cfg.bbr {
                    self.tx.bbr_on_rtt(r, now);
                }
                self.tx.update_rto(r, &self.cfg);
            }
            self.tx.arm_or_clear_rto(now);
        } else if ack == self.tx.snd_una && !self.tx.segs.is_empty() {
            // ---- duplicate ACK ----
            self.tx.dup_acks += 1;
            if self.tx.dup_acks == 3 && !self.tx.in_recovery {
                let flight = self.tx.snd_nxt.wrapping_sub(self.tx.snd_una);
                let fast_retx_basis = if self.cfg.rto_rewind_no_sack {
                    // Circuit rewind can make the current flight tiny: the
                    // lost burst has been moved back to `pending`, while stale
                    // dup-ACKs for the old hole may still arrive. Treat those
                    // dup-ACKs as a repair signal, but do not recut the already
                    // reduced RTO window down to a few MSS just because the
                    // post-rewind probe flight is small.
                    let effective_cwnd = self.tx.cwnd.min(self.tx.rwnd).max(mss);
                    let rewind_floor = if self.tx.rewind_high.is_some() {
                        self.tx.ssthresh.saturating_mul(2)
                    } else {
                        0
                    };
                    flight.max(effective_cwnd).max(rewind_floor)
                } else {
                    flight
                };
                self.tx.ssthresh = self.loss_decrease_window(fast_retx_basis, mss);
                self.mark_holes(true); // fast retransmit (SACK-aware)
                self.tx.cwnd = self.tx.ssthresh.saturating_add(3 * mss);
                self.tx.in_recovery = true;
                self.tx.recover = self.tx.snd_nxt;
            } else if self.tx.in_recovery {
                self.tx.cwnd = self.tx.cwnd.saturating_add(mss); // inflate
                // New dup-ACKs can carry fresh SACK blocks that expose additional
                // holes after the initial fast-retransmit decision. Re-scan those
                // SACKs while in recovery so we retransmit newly-proven losses
                // before the coarse onion RTO fires. Do not use the classic
                // "oldest unacked" fallback here: during recovery that would send
                // one speculative retransmit per dup-ACK and rebuild the duplicate
                // storm this SACK logic exists to avoid.
                self.mark_holes(false);
            }
        }
    }

    // ---- outbound -------------------------------------------------------

    /// Fill `out` with the next cell to send; `false` if nothing is pending.
    /// The driver loops this until it returns `false`.
    pub fn poll_transmit(&mut self, now: u64, out: &mut Vec<u8>) -> bool {
        // 1. RST is terminal + highest priority.
        if let Some(reason) = self.rst_to_send.take() {
            encode(
                Frame::Rst {
                    stream_id: self.stream_id,
                    reason,
                },
                out,
            );
            return true;
        }
        // 2. Handshake.
        if self.send_syn {
            self.send_syn = false;
            encode(
                Frame::Syn {
                    stream_id: self.stream_id,
                    isn: self.tx.iss,
                    win: self.rx.advertised(),
                },
                out,
            );
            return true;
        }
        if self.send_synack {
            self.send_synack = false;
            encode(
                Frame::SynAck {
                    stream_id: self.stream_id,
                    isn: self.tx.iss,
                    win: self.rx.advertised(),
                    ack: self.rx.rcv_nxt,
                },
                out,
            );
            return true;
        }
        if self.phase == Phase::Established {
            // 3. DATA retransmit/new-send path, paced. At rates above one
            //    segment/ms, refill a small per-tick budget instead of flattening
            //    every path to the old MSS/ms timer floor. Retransmits must share
            //    this budget too: SACK can mark hundreds of holes after one relay
            //    burst loss, and sending all repairs in one poll-loop simply
            //    rebuilds the burst that caused the loss.
            if now >= self.tx.pace_next_ms {
                let (interval, batch) = self.pace_params();
                // Scale the refill by how late the driver actually woke: one
                // nominal batch per REAL wake quantizes the send rate to
                // batch/wake-interval on coalesced mobile timers (live this
                // stalled the BBR estimator exactly at the quantized rate).
                // Catch-up is bounded to 8 nominal ticks and the overall
                // max_pacing_batch; the carrier's shared token-bucket pacer
                // still shapes the wire burst.
                let prev_refill = self.tx.pace_next_ms.saturating_sub(interval);
                let elapsed = now.saturating_sub(prev_refill).max(interval);
                let ticks = (elapsed / interval.max(1)).clamp(1, 8);
                self.tx.pace_budget = (batch as u64)
                    .saturating_mul(ticks)
                    .min(self.cfg.max_pacing_batch.max(1) as u64)
                    as u32;
                self.tx.pace_next_ms = now + interval;
            }
            // 3a. Retransmit a marked hole first — SACK-aware, so we never resend
            //     a segment the receiver already acknowledged out of order.
            if self.tx.pace_budget > 0
                && let Some(idx) = self.tx.segs.iter().position(|s| s.needs_resend)
            {
                self.tx.segs[idx].needs_resend = false;
                self.tx.segs[idx].retransmitted = true;
                self.tx.segs[idx].sent_ms = now;
                self.tx.pace_budget = self.tx.pace_budget.saturating_sub(1);
                self.encode_seg_at(idx, out);
                return true;
            }
            // 3b. New data / FIN, congestion + flow limited + paced.
            if (self.force_probe || self.tx.pace_budget > 0) && self.create_next_segment(now) {
                self.tx.pace_budget = self.tx.pace_budget.saturating_sub(1);
                self.encode_seg_at(self.tx.segs.len() - 1, out);
                return true;
            }
        }
        // 4. Standalone ACK.
        if self.ack_pending && self.phase != Phase::Closed {
            self.ack_pending = false;
            self.ack_eliciting = 0;
            self.ack_deadline = None;
            let f = self.make_ack();
            encode(f, out);
            return true;
        }
        // Nothing to send: if we're blocked on a zero peer-window with data
        // queued, arm the persist timer so a probe can later unstick us.
        if self.zero_window_blocked() {
            if self.persist_deadline.is_none() {
                self.persist_deadline = Some(now + self.tx.rto_ms.max(self.cfg.min_rto_ms));
            }
        } else {
            self.persist_deadline = None;
        }
        false
    }

    /// We have data (or a FIN) to send, nothing is in flight to elicit an ACK,
    /// and the peer's advertised window is 0 → a deadlock without a probe.
    fn zero_window_blocked(&self) -> bool {
        self.phase == Phase::Established
            && self.tx.segs.is_empty()
            && self.tx.rwnd == 0
            && (!self.tx.pending.is_empty() || (self.tx.fin_requested && !self.tx.fin_sent))
    }

    /// Send window for NEW data: min(cwnd, peer rwnd), further capped at
    /// 2x the measured BDP when BBR-lite shaping is active so a loss-free
    /// path does not park a full receive window in queues.
    fn effective_send_window(&self) -> u32 {
        let window = self.tx.cwnd.min(self.tx.rwnd);
        match self.tx.bbr_window_cap(&self.cfg) {
            Some(cap) => window.min(cap),
            None => window,
        }
    }

    /// Create the next DATA/FIN segment if the send window allows; returns true
    /// if one was pushed onto `segs` (the caller then encodes `segs.back()`).
    fn create_next_segment(&mut self, now: u64) -> bool {
        let mss = self.cfg.mss as u32;
        let window = self.effective_send_window();
        let inflight = self.tx.snd_nxt.wrapping_sub(self.tx.snd_una);
        let probe = self.force_probe;
        if !probe && seq::geq(inflight, window) {
            return false; // window full
        }
        // A persist probe is allowed exactly one byte past a closed window.
        let room = if probe {
            window.wrapping_sub(inflight).max(1)
        } else {
            window.wrapping_sub(inflight)
        };

        if !self.tx.pending.is_empty() {
            let take = (mss).min(room).min(self.tx.pending.len() as u32) as usize;
            if take == 0 {
                return false;
            }
            self.force_probe = false;
            let data: Vec<u8> = self.tx.pending.drain(..take).collect();
            let seq_no = self.tx.snd_nxt;
            self.tx.snd_nxt = self.tx.snd_nxt.wrapping_add(take as u32);
            self.tx.segs.push_back(Seg {
                seq: seq_no,
                data,
                is_fin: false,
                sent_ms: now,
                retransmitted: false,
                sacked: false,
                needs_resend: false,
            });
            if self.tx.rto_deadline.is_none() {
                self.tx.rto_deadline = Some(now + self.tx.rto_ms);
            }
            return true;
        }
        if self.tx.fin_requested && !self.tx.fin_sent && room >= 1 {
            self.force_probe = false;
            let seq_no = self.tx.snd_nxt;
            self.tx.snd_nxt = self.tx.snd_nxt.wrapping_add(1);
            self.tx.fin_sent = true;
            self.tx.segs.push_back(Seg {
                seq: seq_no,
                data: Vec::new(),
                is_fin: true,
                sent_ms: now,
                retransmitted: false,
                sacked: false,
                needs_resend: false,
            });
            if self.tx.rto_deadline.is_none() {
                self.tx.rto_deadline = Some(now + self.tx.rto_ms);
            }
            return true;
        }
        false
    }

    fn encode_seg_at(&self, idx: usize, out: &mut Vec<u8>) {
        let win = self.rx.advertised();
        let seg = &self.tx.segs[idx];
        let frame = if seg.is_fin {
            Frame::Fin {
                stream_id: self.stream_id,
                seq: seg.seq,
            }
        } else {
            Frame::Data {
                stream_id: self.stream_id,
                seq: seg.seq,
                win,
                payload: &seg.data,
            }
        };
        encode(frame, out);
    }

    /// Mark which unacked segments to retransmit (SACK-aware, RFC 6675 `IsLost`).
    /// A segment is treated as lost ONLY if at least `DUP_THRESH` higher-seq
    /// segments have been SACKed — otherwise it's most likely still in flight, so
    /// retransmitting it (as a naive "every hole below the highest SACK" would)
    /// floods the high-BDP onion path with thousands of premature duplicates.
    fn mark_holes(&mut self, fallback_oldest: bool) {
        const DUP_THRESH: usize = 3;
        // Segments are in ascending seq order; walking from the back, count the
        // SACKed segments seen so far (those with a higher seq than the current).
        let mut sacked_above = 0usize;
        let mut any = false;
        for s in self.tx.segs.iter_mut().rev() {
            if s.sacked {
                sacked_above += 1;
            } else if sacked_above >= DUP_THRESH && !s.retransmitted && !s.needs_resend {
                s.needs_resend = true;
                any = true;
            }
        }
        // Fallback (classic fast-retransmit): nothing meets the SACK loss bar yet
        // → retransmit just the oldest unacked segment.
        if !any
            && fallback_oldest
            && let Some(f) = self
                .tx
                .segs
                .iter_mut()
                .find(|s| !s.sacked && !s.retransmitted && !s.needs_resend)
        {
            f.needs_resend = true;
        }
    }

    fn mark_oldest_unsacked_for_rto(&mut self) {
        if let Some(s) = self.tx.segs.iter_mut().find(|s| !s.sacked) {
            // RTO means the current repair attempt itself may have been lost.
            // Unlike fast-retransmit's SACK scanner, do not skip a segment just
            // because it was retransmitted once already; the oldest unsacked
            // head-hole is exactly what keeps the receiver's out-of-order tail
            // from draining.
            s.needs_resend = true;
        }
    }

    fn make_ack(&self) -> Frame<'static> {
        let mut sacks = SackVec::new();
        for (start, end) in self.rx.sack_blocks() {
            if !sacks.push(SackRange { start, end }) {
                break;
            }
        }
        Frame::Ack {
            stream_id: self.stream_id,
            ack: self.rx.rcv_nxt,
            win: self.rx.advertised(),
            sacks,
        }
    }

    // ---- timers ---------------------------------------------------------

    /// Advance time-driven behaviour (RTO, handshake retransmit, dead-link give-up).
    pub fn on_timeout(&mut self, now: u64) {
        if self.phase == Phase::Closed {
            return;
        }
        if self.ack_deadline.is_some_and(|dl| now >= dl) {
            self.ack_now();
        }
        if self.syn_acked {
            self.hs_deadline = None; // stale once the handshake is confirmed
        }
        // Handshake retransmit + retry cap.
        if let Some(dl) = self.hs_deadline
            && now >= dl
            && !self.syn_acked
        {
            self.hs_retries += 1;
            if self.hs_retries > self.cfg.max_retransmits {
                self.declare_dead();
                return;
            }
            match self.phase {
                Phase::SynSent => self.send_syn = true,
                Phase::Established => self.send_synack = true,
                _ => {}
            }
            self.hs_deadline = Some(now + self.cfg.handshake_rto_ms);
        }
        // Data RTO + retry cap. If the deadline is stale (nothing left unacked),
        // CLEAR it — leaving a past deadline would make the driver's timer fire
        // every poll as sleep(0) and busy-spin.
        if let Some(dl) = self.tx.rto_deadline
            && now >= dl
            && self.tx.segs.is_empty()
        {
            self.tx.rto_deadline = None;
        } else if let Some(dl) = self.tx.rto_deadline
            && now >= dl
            && !self.tx.segs.is_empty()
        {
            self.tx.consec_rto += 1;
            if self.tx.consec_rto > self.cfg.max_retransmits {
                self.declare_dead();
                return;
            }
            self.events.push_back(Event::DataRto {
                consec_rto: self.tx.consec_rto,
                snd_una: self.tx.snd_una,
            });
            let mss = self.cfg.mss as u32;
            let flight = self.tx.snd_nxt.wrapping_sub(self.tx.snd_una);
            let no_sack_rewind = self.cfg.rto_rewind_no_sack
                && self.tx.segs.iter().all(|s| !s.sacked)
                && self.tx.segs.iter().any(|s| !s.is_fin);
            let rto_basis = if no_sack_rewind {
                // In the pinned circuit path we rewind no-SACK RTO flights back
                // into `pending`. A follow-up RTO can therefore fire while only
                // a tiny retransmission probe is in flight even though the path
                // had already earned a much larger usable window. Basing
                // ssthresh only on that probe collapses the stream into
                // congestion-avoidance at a few KiB and recreates the observed
                // ~135 KiB/s crawl. Use the effective pre-RTO window as the
                // congestion signal floor, capped by rwnd, while keeping classic
                // flight/2 behaviour for normal/SACK RTOs.
                let effective_cwnd = self.tx.cwnd.min(self.tx.rwnd).max(mss);
                flight.max(effective_cwnd)
            } else {
                flight
            };
            let ssthresh = if no_sack_rewind && self.tx.consec_rto == 1 {
                // The pinned circuit path can see one coarse no-SACK RTO from
                // ACK/route jitter even while the route is otherwise healthy
                // (live traces: no send failures / no local WouldBlock). Route
                // no-progress handling intentionally starts at the *second*
                // consecutive RTO; make the first one a softer signal too so a
                // single delayed ACK does not halve a multi-MiB earned window.
                // If the path is truly black-holed, the next RTO uses the
                // classic 1/2 cut and the carrier marks the route no-progress.
                ((rto_basis as u64 * 3) / 4).max((2 * mss) as u64) as u32
            } else if self.cfg.rto_rewind_no_sack && !no_sack_rewind {
                // Circuit transport with SACK feedback: repair only the proven
                // holes, but keep a softer multiplicative-decrease policy than
                // classic TCP. The receiver already has higher-sequence data, so
                // this is commonly a relay/session queue hiccup; halving the
                // window repeatedly leaves long single-stream transfers crawling.
                self.loss_decrease_window(rto_basis, mss)
            } else {
                (rto_basis / 2).max(2 * mss)
            };
            self.tx.ssthresh = ssthresh;
            self.tx.in_recovery = false;
            self.tx.dup_acks = 0;
            self.tx.rto_ms = (self.tx.rto_ms * 2).min(self.cfg.max_rto_ms); // backoff
            if no_sack_rewind {
                // No SACK feedback means the receiver has not reported any
                // higher-sequence data. In the pinned-circuit path this commonly
                // happens when an internal bounded queue drops a contiguous burst:
                // after the first RTO, keeping the whole lost burst counted as
                // in-flight leaves `inflight >> cwnd`, so the sender can only
                // retransmit one segment per exponentially-backed-off RTO
                // (observed as a 1-MSS/60s crawl). Rewind the unsacked flight
                // back into `pending` and let normal cwnd+pacing send it again.
                // Late originals become harmless duplicates at the receiver.
                self.requeue_unsacked_flight_for_rto();
                // This path is enabled only for the pinned circuit transport,
                // where no-SACK RTOs usually represent an internal contiguous
                // queue drop rather than broad network congestion. Cut the rate,
                // but keep enough cwnd to recover within a few RTTs instead of
                // restarting a multi-MB transfer at one 318-B segment.
                self.tx.cwnd = ssthresh.max(self.cfg.init_cwnd).min(self.tx.rwnd).max(mss);
                self.tx.pace_next_ms = now;
                self.tx.pace_budget = 0;
                self.tx.rto_deadline = None;
            } else if self.cfg.rto_rewind_no_sack {
                // Circuit transport, but we DO have SACK feedback. This is not
                // the "rewind the whole contiguous burst" case above: the
                // receiver already holds higher-sequence data, so replaying the
                // whole flight would create a duplicate storm. Still, classic
                // RTO collapse to 1 MSS is pathological here: the large SACKed
                // tail keeps `inflight` huge while only a few holes need repair,
                // and one-MSS pacing can leave the stream stuck for many RTOs.
                // Keep a reduced but usable cwnd and let the SACK loss scanner
                // mark the proven holes for paced retransmit.
                self.tx.cwnd = ssthresh.max(self.cfg.init_cwnd).min(self.tx.rwnd).max(mss);
                self.mark_holes(true);
                self.mark_oldest_unsacked_for_rto();
                self.tx.pace_next_ms = now;
                self.tx.pace_budget = 0;
                self.tx.rto_deadline = Some(now + self.tx.rto_ms);
            } else {
                self.tx.cwnd = mss; // classic RTO collapse to slow start
                // With SACK feedback, keep the selective-retransmit model: the
                // receiver may already hold high-sequence data, and mark_holes()
                // / later SACKs can repair without replaying the whole flight.
                if let Some(s) = self.tx.segs.iter_mut().find(|s| !s.sacked) {
                    s.needs_resend = true;
                }
                self.tx.rto_deadline = Some(now + self.tx.rto_ms);
            }
        }
        // Zero-window persist probe.
        if let Some(dl) = self.persist_deadline
            && now >= dl
        {
            if self.zero_window_blocked() {
                self.force_probe = true; // poll_transmit emits one probe byte
                self.persist_deadline = Some(now + self.tx.rto_ms.max(self.cfg.min_rto_ms));
            } else {
                self.persist_deadline = None;
            }
        }
    }

    /// Earliest time [`Self::on_timeout`] needs to run again.
    pub fn next_timeout(&self) -> Option<u64> {
        let mut t: Option<u64> = None;
        let mut merge = |x: Option<u64>| {
            if let Some(v) = x {
                t = Some(t.map_or(v, |c: u64| c.min(v)));
            }
        };
        merge(self.hs_deadline);
        merge(self.tx.rto_deadline);
        merge(self.persist_deadline);
        merge(self.ack_deadline);
        // If new data is ready but held back only by pacing, wake to release it.
        if self.phase == Phase::Established && self.paced_send_ready() {
            merge(Some(self.tx.pace_next_ms));
        }
        t
    }

    /// Pacing as `(tick_interval_ms, segments_per_tick)`. Sub-millisecond rates
    /// are represented by a small batch on a 1 ms tick; slower rates use one
    /// segment every N milliseconds.
    fn pace_params(&self) -> (u64, u32) {
        let Some(srtt) = self.tx.srtt else {
            return (0, u32::MAX);
        };
        // BBR-lite: once the delivery model is warm, pace at 5/4 of the
        // measured bottleneck rate — enough overdrive to keep probing for
        // more bandwidth while the 2xBDP window cap bounds the standing
        // queue. Window/srtt pacing below would chase its own queueing delay
        // (srtt inflates -> rate holds at the same self-built queue).
        if self.cfg.bbr
            && self.tx.btl_bw > 0
            && self.tx.rtt_min.is_some()
            && (self.tx.delivered >= BBR_ENGAGE_DELIVERED || self.cfg.warm_btl_bw > 0)
        {
            // STARTUP doubles the estimate each round trip; steady state
            // probes at 5/4 (see bbr_startup).
            let rate = if self.tx.bbr_startup {
                self.tx.btl_bw.saturating_mul(2)
            } else {
                self.tx.btl_bw.saturating_mul(5) / 4
            }; // bytes/sec
            let mss = self.cfg.mss.max(1) as u64;
            // Pick a tick long enough to release >=32 whole cells, then round
            // the per-tick budget UP: rounding down quantized the real rate to
            // a fraction of the target (live: half), which fed the estimator
            // slower samples than it paced for. The >=32 emission quantum
            // (was >=4) matters twice on a phone: 8x fewer driver wakes at the
            // same rate, and the carrier only fans a DATA run out across
            // multiple routes when a single emission is big enough to be worth
            // splitting (route striping; live the 4-cell runs never met the
            // stripe threshold). The carrier's shared token-bucket pacer still
            // shapes the wire burst, and one 32-cell tick (~130 KB) is far
            // below the relay-queue sizes that caused historic burst loss.
            let cells_per_sec = (rate / mss).max(1);
            let interval = (32_000 / cells_per_sec).clamp(1, 100);
            let batch = (rate.saturating_mul(interval))
                .div_ceil(1000 * mss)
                .clamp(1, self.cfg.max_pacing_batch.max(1) as u64) as u32;
            return (interval, batch);
        }
        // Spread the EFFECTIVE window (min of cwnd and the peer's rwnd) across one
        // RTT — never cwnd alone. When cwnd has run far past a smaller rwnd, pacing
        // off cwnd would send much faster than the window can ever drain, rebuilding
        // the very relay-queue backlog pacing exists to avoid.
        let win = self.tx.cwnd.min(self.tx.rwnd).max(self.cfg.mss as u32) as u64;
        let gain = if self.tx.cwnd < self.tx.ssthresh {
            2
        } else {
            1
        };
        let num = win.saturating_mul(gain);
        let den = (srtt as u64).max(1).saturating_mul(self.cfg.mss as u64);
        if num >= den {
            (
                1,
                (num / den).clamp(1, self.cfg.max_pacing_batch.max(1) as u64) as u32,
            )
        } else {
            (den.div_ceil(num).max(1), 1)
        }
    }

    /// Is there new data/FIN we could send right now (window allows), with only
    /// the pacing clock holding it back?
    fn paced_send_ready(&self) -> bool {
        if self.tx.segs.iter().any(|s| s.needs_resend) {
            return true;
        }
        let window = self.effective_send_window();
        let inflight = self.tx.snd_nxt.wrapping_sub(self.tx.snd_una);
        if seq::geq(inflight, window) {
            return false; // window-limited, not pace-limited
        }
        !self.tx.pending.is_empty() || (self.tx.fin_requested && !self.tx.fin_sent)
    }

    fn declare_dead(&mut self) {
        self.phase = Phase::Closed;
        self.rst_to_send = Some(reset_reason::TIMED_OUT);
        self.events.push_back(Event::Reset(reset_reason::TIMED_OUT));
    }

    /// RTO recovery for the no-SACK case: move every outstanding byte back in
    /// front of the app's pending bytes, then restart transmission at `snd_una`.
    /// This preserves the byte stream while dropping the phantom in-flight count
    /// that otherwise pins cwnd below the old lost flight for many minutes.
    fn requeue_unsacked_flight_for_rto(&mut self) {
        let rewind_high = self.tx.snd_nxt;
        let mut requeued = VecDeque::new();
        let mut rewound_fin = false;
        for seg in self.tx.segs.drain(..) {
            if seg.is_fin {
                rewound_fin = true;
                continue;
            }
            requeued.extend(seg.data);
        }
        requeued.append(&mut self.tx.pending);
        self.tx.pending = requeued;
        self.tx.snd_nxt = self.tx.snd_una;
        self.tx.rewind_high = Some(rewind_high);
        self.tx.rewind_fin = rewound_fin;
        if rewound_fin {
            self.tx.fin_sent = false;
        }
    }

    /// Queue an immediate cumulative ACK. Used for gaps, duplicates, FIN and
    /// handshake confirmation where waiting would delay recovery/progress.
    fn ack_now(&mut self) {
        self.ack_pending = true;
        self.ack_eliciting = 0;
        self.ack_deadline = None;
    }

    /// TCP-style delayed ACK: cumulatively acknowledge every configured group
    /// of advancing DATA segments, otherwise within the configured delay. A
    /// non-advancing segment is a gap/duplicate and must emit a dup-ACK
    /// immediately for fast retransmit.
    fn ack_data(&mut self, advanced: bool, now: u64) {
        if !advanced {
            self.ack_now();
            return;
        }
        self.ack_eliciting = self.ack_eliciting.saturating_add(1);
        if self.ack_eliciting >= self.cfg.ack_every.max(1) {
            self.ack_now();
        } else if self.ack_deadline.is_none() {
            self.ack_deadline = Some(now + self.cfg.ack_delay_ms.max(1));
        }
    }
}

fn encode(frame: Frame<'_>, out: &mut Vec<u8>) {
    frame.encode_into(out);
}

impl TxState {
    fn ack_limit(&self) -> u32 {
        self.rewind_high
            .map(|h| seq::max(self.snd_nxt, h))
            .unwrap_or(self.snd_nxt)
    }

    fn trim_rewound_pending_after_ack(&mut self, ack: u32) {
        if let Some(high) = self.rewind_high {
            if seq::gt(ack, self.snd_nxt) {
                let mut drop_bytes = ack.wrapping_sub(self.snd_nxt) as usize;
                if self.rewind_fin && seq::geq(ack, high) {
                    // FIN consumes one sequence number but has no byte in
                    // `pending`, so a late ACK for a rewound FIN must not drain
                    // one extra application byte.
                    drop_bytes = drop_bytes.saturating_sub(1);
                }
                let n = drop_bytes.min(self.pending.len());
                self.pending.drain(..n);
                self.snd_nxt = ack;
            }
            if seq::geq(ack, high) {
                if self.rewind_fin {
                    self.fin_acked = true;
                }
                self.rewind_high = None;
                self.rewind_fin = false;
            }
        }
    }

    /// Record newly delivered bytes and refresh the bottleneck-rate estimate
    /// over a sliding window of delivery checkpoints. Quiet/app-limited spans
    /// produce no qualifying sample and leave the estimate untouched.
    fn bbr_on_delivered(&mut self, acked: u32, now: u64) {
        self.delivered = self.delivered.saturating_add(acked as u64);
        let push = self
            .rate_samples
            .back()
            .is_none_or(|&(t, _)| now >= t + BBR_SAMPLE_SPACING_MS);
        if push {
            self.rate_samples.push_back((now, self.delivered));
        }
        while self.rate_samples.len() > 2 {
            let Some(&(t, _)) = self.rate_samples.front() else {
                break;
            };
            if now.saturating_sub(t) > BBR_RATE_WINDOW_MS {
                self.rate_samples.pop_front();
            } else {
                break;
            }
        }
        let (Some(&(t0, d0)), Some(&(t1, d1))) =
            (self.rate_samples.front(), self.rate_samples.back())
        else {
            return;
        };
        let span = t1.saturating_sub(t0);
        let bytes = d1.saturating_sub(d0);
        if span < BBR_MIN_SPAN_MS || bytes < BBR_MIN_DELIVERED {
            return;
        }
        let sample = bytes.saturating_mul(1000) / span.max(1);
        let store = self
            .bw_samples
            .back()
            .is_none_or(|&(t, _)| now >= t + BBR_BW_SAMPLE_SPACING_MS);
        if store {
            self.bw_samples.push_back((now, sample));
        } else if let Some(back) = self.bw_samples.back_mut() {
            back.1 = back.1.max(sample);
        }
        while let Some(&(t, _)) = self.bw_samples.front() {
            if now.saturating_sub(t) > BBR_BW_WINDOW_MS && self.bw_samples.len() > 1 {
                self.bw_samples.pop_front();
            } else {
                break;
            }
        }
        self.btl_bw = self
            .bw_samples
            .iter()
            .map(|&(_, rate)| rate)
            .max()
            .unwrap_or(0);
        // STARTUP plateau detection (classic BBR shape): stay at 2x pacing
        // gain until the estimate stops growing >=25% for three ROUND TRIPS,
        // then drop to the steady 5/4 probe gain. The cadence must be a round
        // trip (not a stored sample): samples land every ~100ms while the
        // windowed-average estimate needs a couple of seconds to reflect a
        // rate doubling, so a per-sample check spent its 3-stall budget in
        // ~300ms of estimator LAG and exited STARTUP at half the path rate
        // (live: stuck at ~3 MB/s on a path whose probe later reached ~6).
        if self.bbr_startup && store {
            let round_ms = (self.srtt.unwrap_or(0) as u64).max(BBR_MIN_SPAN_MS);
            if now >= self.bbr_probe_checked_ms.saturating_add(round_ms) {
                self.bbr_probe_checked_ms = now;
                if self.btl_bw > self.bbr_bw_at_probe.saturating_mul(5) / 4 {
                    self.bbr_bw_at_probe = self.btl_bw;
                    self.bbr_stall_rounds = 0;
                } else {
                    self.bbr_stall_rounds = self.bbr_stall_rounds.saturating_add(1);
                    if self.bbr_stall_rounds >= 3 {
                        self.bbr_startup = false;
                    }
                }
            }
        }
    }

    /// Windowed-minimum RTT: keep the smallest clean sample, but let the
    /// window expire so a route change eventually re-anchors the estimate.
    fn bbr_on_rtt(&mut self, r_ms: u32, now: u64) {
        let replace = match self.rtt_min {
            None => true,
            Some((min, stamp)) => r_ms <= min || now.saturating_sub(stamp) > BBR_MIN_RTT_WINDOW_MS,
        };
        if replace {
            self.rtt_min = Some((r_ms.max(1), now));
        }
    }

    /// Effective-window cap at a small multiple of the measured bandwidth-
    /// delay product, once both estimates exist. `None` (startup / bbr off)
    /// means no extra cap.
    fn bbr_window_cap(&self, cfg: &Config) -> Option<u32> {
        if !cfg.bbr
            || self.btl_bw == 0
            || (self.delivered < BBR_ENGAGE_DELIVERED && cfg.warm_btl_bw == 0)
        {
            return None;
        }
        let (rtt_min, _) = self.rtt_min?;
        let bdp = self.btl_bw.saturating_mul(rtt_min as u64) / 1000;
        let floor = (cfg.init_cwnd as u64).max(64 * cfg.mss as u64);
        // STARTUP paces at 2x the estimate; sustaining that probe needs
        // 2x btl_bw x srtt of flight, and with live srtt a notch above rtt_min
        // a 2x-BDP cap starves the very probe that is supposed to discover the
        // path rate (classic BBR runs cwnd_gain ~2.89 in STARTUP for the same
        // reason). Steady state keeps the tight 2x cap that bounds the
        // standing queue.
        let gain = if self.bbr_startup { 3 } else { 2 };
        Some(bdp.saturating_mul(gain).clamp(floor, u32::MAX as u64) as u32)
    }

    fn update_rto(&mut self, r_ms: u32, cfg: &Config) {
        match self.srtt {
            None => {
                self.srtt = Some(r_ms);
                self.rttvar = r_ms / 2;
            }
            Some(srtt) => {
                let delta = srtt.abs_diff(r_ms);
                self.rttvar = (self.rttvar * 3 + delta) / 4;
                self.srtt = Some((srtt * 7 + r_ms) / 8);
            }
        }
        let srtt = self.srtt.unwrap();
        let rto = srtt as u64 + (4 * self.rttvar.max(1)) as u64;
        self.rto_ms = rto.clamp(cfg.min_rto_ms, cfg.max_rto_ms);
    }

    fn arm_or_clear_rto(&mut self, now: u64) {
        if self.segs.is_empty() {
            self.rto_deadline = None;
        } else {
            self.rto_deadline = Some(now + self.rto_ms);
        }
    }
}

impl RxState {
    /// Advertised receive window = free buffer space.
    fn advertised(&self) -> u32 {
        let used = self.read_buf.len() + self.oo_bytes;
        self.window.saturating_sub(used as u32)
    }

    /// Accept a DATA segment; returns whether `rcv_nxt` advanced.
    fn accept(&mut self, mut seg_seq: u32, mut payload: &[u8]) -> bool {
        // Drop bytes at/below rcv_nxt (already delivered).
        if seq::lt(seg_seq, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seg_seq) as usize;
            if skip >= payload.len() {
                return false; // wholly duplicate
            }
            payload = &payload[skip..];
            seg_seq = self.rcv_nxt;
        }
        // Reject beyond the advertised window.
        let win_end = self.rcv_nxt.wrapping_add(self.window);
        if seq::geq(seg_seq, win_end) {
            return false;
        }
        if seg_seq == self.rcv_nxt {
            self.read_buf.extend(payload.iter().copied());
            self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            self.drain_oo();
            self.try_consume_fin();
            true
        } else {
            self.store_oo(seg_seq, payload);
            false
        }
    }

    fn store_oo(&mut self, seq_no: u32, payload: &[u8]) {
        if self.oo.contains_key(&seq_no) {
            return; // already have this block's start
        }
        let win_end = self.rcv_nxt.wrapping_add(self.window);
        let mut end = seq_no.wrapping_add(payload.len() as u32);
        if seq::gt(end, win_end) {
            end = win_end;
        }
        let len = end.wrapping_sub(seq_no) as usize;
        if len == 0 || len > payload.len() {
            return;
        }
        self.oo.insert(seq_no, payload[..len].to_vec());
        self.oo_bytes += len;
    }

    fn drain_oo(&mut self) {
        while let Some((&k, _)) = self.oo.range(..).next() {
            if seq::leq(k, self.rcv_nxt) {
                let v = self.oo.remove(&k).unwrap();
                self.oo_bytes -= v.len();
                if seq::lt(k, self.rcv_nxt) {
                    let skip = self.rcv_nxt.wrapping_sub(k) as usize;
                    if skip < v.len() {
                        self.read_buf.extend(v[skip..].iter().copied());
                        self.rcv_nxt = self.rcv_nxt.wrapping_add((v.len() - skip) as u32);
                    }
                } else {
                    self.read_buf.extend(v.iter().copied());
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(v.len() as u32);
                }
            } else {
                break;
            }
        }
    }

    fn try_consume_fin(&mut self) {
        if let Some(fin) = self.peer_fin_seq
            && !self.eof
            && self.rcv_nxt == fin
        {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.eof = true;
        }
    }

    /// Contiguous out-of-order blocks above `rcv_nxt`, for SACK.
    fn sack_blocks(&self) -> Vec<(u32, u32)> {
        let mut blocks: Vec<(u32, u32)> = Vec::new();
        for (&start, v) in self.oo.iter() {
            let end = start.wrapping_add(v.len() as u32);
            if let Some(last) = blocks.last_mut()
                && last.1 == start
            {
                last.1 = end;
            } else {
                blocks.push((start, end));
            }
        }
        blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bbr_rate_estimate_ratchets_up_and_ignores_thin_windows() {
        let cfg = Config {
            bbr: true,
            ..Config::default()
        };
        let mut e = StreamEngine::connect(7, cfg, 0, 10_000);
        // Deliver 1 MiB over 1s in 20ms steps -> ~1 MiB/s estimate.
        let step_bytes = (1024 * 1024) / 50;
        for i in 0..=50u64 {
            e.tx.bbr_on_delivered(step_bytes, i * 20);
        }
        let mib = 1024 * 1024;
        assert!(
            e.tx.btl_bw > mib * 8 / 10 && e.tx.btl_bw < mib * 12 / 10,
            "estimate ~1 MiB/s, got {}",
            e.tx.btl_bw
        );
        let before = e.tx.btl_bw;
        // A thin (app-limited) window: a trickle far below BBR_MIN_DELIVERED
        // must not crater the estimate.
        for i in 51..=80u64 {
            e.tx.bbr_on_delivered(100, i * 20);
        }
        assert!(
            e.tx.btl_bw >= before / 2,
            "thin window cratered the estimate: {} -> {}",
            before,
            e.tx.btl_bw
        );
    }

    #[test]
    fn bbr_window_cap_bounds_effective_window_at_two_bdp() {
        let cfg = Config {
            bbr: true,
            recv_window: 4 * 1024 * 1024,
            ..Config::default()
        };
        let mut e = StreamEngine::connect(7, cfg, 0, 10_000);
        e.tx.rwnd = cfg.recv_window;
        e.tx.cwnd = 16 * 1024 * 1024; // loss-free growth far past the path BDP
        e.tx.btl_bw = 3 * 1024 * 1024; // 3 MiB/s
        e.tx.delivered = BBR_ENGAGE_DELIVERED; // model warm
        e.tx.rtt_min = Some((200, 0)); // 200ms propagation
        let bdp = 3 * 1024 * 1024 * 200 / 1000;
        // While STARTUP still probes at 2x pacing, the cap must leave the
        // probe headroom (3x BDP).
        assert_eq!(e.tx.bbr_window_cap(&e.cfg), Some(3 * bdp));
        // Steady state: BDP = 3 MiB/s * 0.2s = 614.4 KiB; cap = 2x.
        e.tx.bbr_startup = false;
        let cap = e.tx.bbr_window_cap(&e.cfg).expect("model warm");
        assert_eq!(cap, 2 * bdp);
        assert_eq!(e.effective_send_window(), cap);
        // Without estimates the cap must vanish (startup behaves classically).
        e.tx.btl_bw = 0;
        assert_eq!(e.effective_send_window(), e.tx.cwnd.min(e.tx.rwnd));
    }

    #[test]
    fn warm_start_engages_bbr_from_the_first_byte() {
        let cfg = Config {
            bbr: true,
            recv_window: 4 * 1024 * 1024,
            warm_btl_bw: 6_000_000,
            warm_rtt_min_ms: 150,
            ..Config::default()
        };
        let e = StreamEngine::connect(7, cfg, 0, 10_000);
        // Model seeded, window cap live at zero bytes delivered (a cold
        // stream would return None until 1 MiB). STARTUP is KEPT, with the
        // plateau clock anchored at the seed: the mux caches half the
        // previous rate, so the 2x STARTUP pacing probes exactly the cached
        // rate and only a genuinely faster path keeps the climb alive.
        assert_eq!(e.tx.btl_bw, 6_000_000);
        assert!(e.tx.bbr_startup);
        assert_eq!(e.tx.bbr_bw_at_probe, 6_000_000);
        assert_eq!(e.tx.rtt_min.map(|(r, _)| r), Some(150));
        let bdp = 6_000_000u64 * 150 / 1000; // 900 KB
        // STARTUP window cap leaves probe headroom (3x BDP).
        assert_eq!(e.tx.bbr_window_cap(&e.cfg), Some(3 * bdp as u32));
        // First flight opens near the seeded BDP (capped at 1 MiB).
        assert_eq!(e.tx.cwnd, bdp as u32);
        // A cold config keeps the engage gate.
        let cold = Config {
            bbr: true,
            ..Config::default()
        };
        let c = StreamEngine::connect(8, cold, 0, 10_000);
        assert_eq!(c.tx.bbr_window_cap(&c.cfg), None);
        assert!(c.tx.bbr_startup);
    }

    #[test]
    fn warm_startup_climbs_past_the_seed_and_exits_on_a_degraded_path() {
        // Faster path than the cache: the seeded STARTUP must keep the 2x
        // climb well past the warm model instead of idling at 5/4 of it.
        let cfg = Config {
            bbr: true,
            warm_btl_bw: 1_500_000, // mux seeds HALF the previous ~3 MB/s
            warm_rtt_min_ms: 150,
            ..Config::default()
        };
        let mut e = StreamEngine::connect(7, cfg, 0, 10_000);
        e.tx.srtt = Some(150);
        assert!(e.tx.bbr_startup);
        // Path really sustains 12 MB/s: delivery doubles per 300ms round from
        // the probed (2x seed = cached) rate up to the ceiling.
        let rate_at = |t_ms: u64| -> u64 {
            let doublings = (t_ms as f64) / 300.0;
            ((3_000_000.0_f64) * doublings.exp2()).min(12_000_000.0) as u64
        };
        let mut t = 0u64;
        while t < 3_000 {
            t += 20;
            let bytes = rate_at(t) * 20 / 1000;
            e.tx.bbr_on_delivered(bytes as u32, t);
            if rate_at(t) < 12_000_000 {
                assert!(
                    e.tx.bbr_startup,
                    "warm STARTUP bailed mid-climb at t={t} (btl_bw={})",
                    e.tx.btl_bw
                );
            }
        }
        assert!(
            e.tx.btl_bw > 9_000_000,
            "warm stream should discover the faster path, got {}",
            e.tx.btl_bw
        );

        // Degraded path: real delivery never grows >=25%/round past the seed,
        // so STARTUP must exit within a few round trips (bounded overshoot).
        let cfg = Config {
            bbr: true,
            warm_btl_bw: 4_000_000,
            warm_rtt_min_ms: 150,
            ..Config::default()
        };
        let mut d = StreamEngine::connect(9, cfg, 0, 10_000);
        d.tx.srtt = Some(150);
        let mut t = 0u64;
        let mut exit_at = None;
        while t < 3_000 {
            t += 20;
            d.tx.bbr_on_delivered((800_000u64 * 20 / 1000) as u32, t);
            if !d.tx.bbr_startup && exit_at.is_none() {
                exit_at = Some(t);
            }
        }
        let exit = exit_at.expect("STARTUP never exited on a degraded path");
        assert!(
            exit <= 1_000,
            "degraded-path exit should take ~3 rounds, took {exit}ms"
        );
    }

    #[test]
    fn bbr_startup_survives_estimator_lag_and_exits_on_a_real_plateau() {
        let cfg = Config {
            bbr: true,
            ..Config::default()
        };
        let mut e = StreamEngine::connect(7, cfg, 0, 10_000);
        e.tx.srtt = Some(150);
        // Exponential ramp: the delivery rate doubles every 300ms round trip
        // (what 2x STARTUP pacing produces on an uncongested path), from
        // 500 KB/s up to a 6 MB/s ceiling, sampled in 20ms delivery steps.
        // The windowed-average estimator lags a doubling by ~a window, so a
        // per-sample plateau check would see three "no growth" samples within
        // ~300ms and bail out of STARTUP mid-climb; the per-round-trip check
        // must ride the whole ramp.
        let rate_at = |t_ms: u64| -> u64 {
            let doublings = (t_ms as f64) / 300.0;
            ((500_000.0_f64) * doublings.exp2()).min(6_000_000.0) as u64
        };
        let mut t = 0u64;
        let mut climb_exit: Option<u64> = None;
        while t < 3_000 {
            t += 20;
            let bytes = rate_at(t) * 20 / 1000;
            e.tx.bbr_on_delivered(bytes as u32, t);
            if !e.tx.bbr_startup && climb_exit.is_none() && rate_at(t) < 6_000_000 {
                climb_exit = Some(t);
            }
        }
        assert_eq!(
            climb_exit, None,
            "STARTUP exited mid-climb at t={climb_exit:?} (estimator lag misread as a plateau)"
        );
        // Hold the ceiling: the estimate converges and STARTUP must now exit.
        while t < 8_000 {
            t += 20;
            e.tx.bbr_on_delivered((6_000_000u64 * 20 / 1000) as u32, t);
        }
        assert!(
            !e.tx.bbr_startup,
            "STARTUP never exited on a genuine plateau"
        );
        assert!(
            e.tx.btl_bw > 4_500_000,
            "estimate should be near the 6 MB/s ceiling, got {}",
            e.tx.btl_bw
        );
    }

    #[test]
    fn bbr_min_rtt_keeps_min_until_window_expiry() {
        let cfg = Config {
            bbr: true,
            ..Config::default()
        };
        let mut e = StreamEngine::connect(7, cfg, 0, 10_000);
        e.tx.bbr_on_rtt(180, 0);
        e.tx.bbr_on_rtt(900, 1_000); // queue-inflated sample: ignored
        assert_eq!(e.tx.rtt_min.map(|(r, _)| r), Some(180));
        // After the window expires a fresh (even larger) sample re-anchors.
        e.tx.bbr_on_rtt(400, BBR_MIN_RTT_WINDOW_MS + 2_000);
        assert_eq!(e.tx.rtt_min.map(|(r, _)| r), Some(400));
    }

    fn engine_with_tiny_no_sack_flight(rto_rewind_no_sack: bool) -> StreamEngine {
        let mss = MSS as u32;
        let cfg = Config {
            mss: MSS,
            init_cwnd: 32 * mss,
            recv_window: 3 * 1024 * 1024,
            rto_rewind_no_sack,
            ..Config::default()
        };
        let mut e = StreamEngine::connect(7, cfg, 0, 10_000);
        e.phase = Phase::Established;
        e.syn_acked = true;
        e.tx.rwnd = cfg.recv_window;
        e.tx.cwnd = 1_400_000;
        e.tx.ssthresh = 1_400_000;
        e.tx.snd_una = 20_000;
        e.tx.snd_nxt = e.tx.snd_una + 4 * mss;
        e.tx.rto_deadline = Some(100);
        e.tx.pending.extend([0xaa, 0xbb, 0xcc]);
        for i in 0..4 {
            e.tx.segs.push_back(Seg {
                seq: e.tx.snd_una + i * mss,
                data: vec![i as u8; MSS],
                is_fin: false,
                sent_ms: 0,
                retransmitted: false,
                sacked: false,
                needs_resend: false,
            });
        }
        e
    }

    #[test]
    fn first_no_sack_rto_rewind_uses_soft_window_cut() {
        let mut e = engine_with_tiny_no_sack_flight(true);
        let old_pending = e.tx.pending.len();
        let old_una = e.tx.snd_una;

        e.on_timeout(100);

        assert_eq!(e.tx.ssthresh, 1_050_000);
        assert_eq!(e.tx.cwnd, 1_050_000);
        assert_eq!(e.tx.snd_nxt, old_una);
        assert!(e.tx.segs.is_empty());
        assert_eq!(e.tx.pending.len(), 4 * MSS + old_pending);
        assert_eq!(e.tx.rto_deadline, None);
    }

    #[test]
    fn repeated_no_sack_rto_rewind_uses_classic_half_cut() {
        let mut e = engine_with_tiny_no_sack_flight(true);
        e.tx.consec_rto = 1;

        e.on_timeout(100);

        assert_eq!(e.tx.ssthresh, 700_000);
        assert_eq!(e.tx.cwnd, 700_000);
    }

    #[test]
    fn dupacks_after_rewind_do_not_recut_ssthresh_to_tiny_flight() {
        let mut e = engine_with_tiny_no_sack_flight(true);
        let mss = MSS as u32;
        e.tx.cwnd = 1_050_000;
        e.tx.ssthresh = 1_050_000;
        e.tx.rewind_high = Some(e.tx.snd_nxt.wrapping_add(1_000_000));

        let mut dup = Vec::new();
        Frame::Ack {
            stream_id: e.stream_id,
            ack: e.tx.snd_una,
            win: e.cfg.recv_window,
            sacks: SackVec::new(),
        }
        .encode_into(&mut dup);

        e.on_cell(&dup, 10);
        e.on_cell(&dup, 11);
        e.on_cell(&dup, 12);

        assert!(e.tx.in_recovery);
        assert_eq!(e.tx.ssthresh, 1_050_000);
        assert_eq!(e.tx.cwnd, 1_050_000 + 3 * mss);
        assert!(
            e.tx.segs.iter().any(|s| s.needs_resend),
            "third dupACK should still trigger repair"
        );
    }

    #[test]
    fn no_sack_rto_rewind_handles_fin_tail() {
        let mut e = engine_with_tiny_no_sack_flight(true);
        let old_una = e.tx.snd_una;
        e.tx.pending.clear();
        e.tx.fin_requested = true;
        e.tx.fin_sent = true;
        let fin_seq = e.tx.snd_nxt;
        e.tx.snd_nxt = e.tx.snd_nxt.wrapping_add(1);
        let old_high = e.tx.snd_nxt;
        e.tx.segs.push_back(Seg {
            seq: fin_seq,
            data: Vec::new(),
            is_fin: true,
            sent_ms: 0,
            retransmitted: false,
            sacked: false,
            needs_resend: false,
        });

        e.on_timeout(100);

        assert_eq!(e.tx.snd_nxt, old_una);
        assert!(e.tx.segs.is_empty());
        assert_eq!(e.tx.pending.len(), 4 * MSS);
        assert!(e.tx.fin_requested);
        assert!(!e.tx.fin_sent, "rewound FIN must be sent again after DATA");
        assert!(!e.tx.fin_acked);
        assert_eq!(e.tx.rewind_high, Some(old_high));
        assert!(e.tx.rewind_fin);

        let mut ack = Vec::new();
        Frame::Ack {
            stream_id: e.stream_id,
            ack: old_high,
            win: e.cfg.recv_window,
            sacks: SackVec::new(),
        }
        .encode_into(&mut ack);
        e.on_cell(&ack, 101);

        assert_eq!(e.tx.pending.len(), 0);
        assert_eq!(e.tx.snd_una, old_high);
        assert_eq!(e.tx.snd_nxt, old_high);
        assert_eq!(e.tx.rewind_high, None);
        assert!(!e.tx.rewind_fin);
        assert!(e.tx.fin_acked);
        assert!(e.is_send_complete());
    }

    #[test]
    fn classic_rto_still_uses_flight_and_collapses_cwnd() {
        let mut e = engine_with_tiny_no_sack_flight(false);
        let mss = MSS as u32;

        e.on_timeout(100);

        assert_eq!(e.tx.ssthresh, 2 * mss);
        assert_eq!(e.tx.cwnd, mss);
        assert_eq!(e.tx.segs.len(), 4);
        assert!(e.tx.segs.front().unwrap().needs_resend);
        assert_eq!(e.tx.rto_deadline, Some(100 + e.tx.rto_ms));
    }

    #[test]
    fn circuit_sack_rto_keeps_repair_window_and_marks_holes() {
        let mss = MSS as u32;
        let cfg = Config {
            mss: MSS,
            init_cwnd: 32 * mss,
            recv_window: 3 * 1024 * 1024,
            rto_rewind_no_sack: true,
            ..Config::default()
        };
        let mut e = StreamEngine::connect(9, cfg, 0, 30_000);
        e.phase = Phase::Established;
        e.syn_acked = true;
        e.tx.rwnd = cfg.recv_window;
        e.tx.cwnd = 2_000_000;
        e.tx.ssthresh = 2_000_000;
        e.tx.snd_una = 40_000;
        e.tx.snd_nxt = e.tx.snd_una + 1024 * mss;
        e.tx.rto_deadline = Some(100);
        for i in 0..1024 {
            let missing_hole = i % 64 == 0;
            e.tx.segs.push_back(Seg {
                seq: e.tx.snd_una + i * mss,
                data: vec![i as u8; MSS],
                is_fin: false,
                sent_ms: 0,
                retransmitted: false,
                sacked: !missing_hole,
                needs_resend: false,
            });
        }

        e.on_timeout(100);

        assert_eq!(e.tx.ssthresh, 1024 * mss / 2);
        assert_eq!(e.tx.cwnd, e.tx.ssthresh);
        assert!(
            !e.tx.segs.is_empty(),
            "SACK RTO must not rewind the whole flight"
        );
        assert!(
            e.tx.segs.iter().any(|s| s.needs_resend),
            "SACK RTO should mark proven holes for paced repair"
        );
        assert_eq!(e.tx.rto_deadline, Some(100 + e.tx.rto_ms));
    }

    #[test]
    fn circuit_sack_rto_can_use_soft_loss_decrease() {
        let mss = MSS as u32;
        let cfg = Config {
            mss: MSS,
            init_cwnd: 32 * mss,
            recv_window: 3 * 1024 * 1024,
            rto_rewind_no_sack: true,
            loss_decrease_per_mille: 750,
            ..Config::default()
        };
        let mut e = StreamEngine::connect(10, cfg, 0, 30_000);
        e.phase = Phase::Established;
        e.syn_acked = true;
        e.tx.rwnd = cfg.recv_window;
        e.tx.cwnd = 2_000_000;
        e.tx.ssthresh = 2_000_000;
        e.tx.snd_una = 40_000;
        e.tx.snd_nxt = e.tx.snd_una + 1024 * mss;
        e.tx.rto_deadline = Some(100);
        for i in 0..1024 {
            let missing_hole = i % 64 == 0;
            e.tx.segs.push_back(Seg {
                seq: e.tx.snd_una + i * mss,
                data: vec![i as u8; MSS],
                is_fin: false,
                sent_ms: 0,
                retransmitted: false,
                sacked: !missing_hole,
                needs_resend: false,
            });
        }

        e.on_timeout(100);

        assert_eq!(e.tx.ssthresh, (1024 * mss * 3) / 4);
        assert_eq!(e.tx.cwnd, e.tx.ssthresh);
        assert!(
            e.tx.segs.iter().any(|s| s.needs_resend),
            "SACK RTO should still mark proven holes for paced repair"
        );
    }
}
