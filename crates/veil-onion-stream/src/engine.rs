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
    /// Maximum number of NEW-data segments released on one millisecond pacing
    /// tick. This bounds the microburst presented to the carrier while allowing
    /// rates above the old one-MSS-per-ms ceiling.
    pub max_pacing_batch: u32,
    /// Number of contiguous advancing DATA segments acknowledged by one
    /// cumulative ACK. Gaps, duplicates and FIN always ACK immediately.
    pub ack_every: u8,
    /// Maximum delay before acknowledging a partial [`Self::ack_every`] group.
    pub ack_delay_ms: u64,
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
            ack_every: 2,
            ack_delay_ms: 5,
        }
    }
}

/// Connection-level events surfaced to the driver / app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Handshake complete — the stream may carry data both ways.
    Connected,
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
    fin_requested: bool,
    fin_sent: bool,
    fin_acked: bool,
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
                cwnd: cfg.init_cwnd.max(cfg.mss as u32),
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
                fin_requested: false,
                fin_sent: false,
                fin_acked: false,
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
             rto_dl={:?} persist_dl={:?}",
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
        if seq::gt(ack, self.tx.snd_nxt) {
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
            self.tx.dup_acks = 0;
            self.tx.consec_rto = 0; // progress: reset dead-link counter

            if self.tx.in_recovery {
                if seq::geq(ack, self.tx.recover) {
                    self.tx.in_recovery = false; // full recovery
                    self.tx.cwnd = self.tx.ssthresh.max(mss);
                } else {
                    // partial ACK: retransmit the remaining holes, deflate by acked.
                    self.tx.cwnd = self.tx.cwnd.saturating_sub(acked).max(mss);
                    self.mark_holes();
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
                self.tx.update_rto(r, &self.cfg);
            }
            self.tx.arm_or_clear_rto(now);
        } else if ack == self.tx.snd_una && !self.tx.segs.is_empty() {
            // ---- duplicate ACK ----
            self.tx.dup_acks += 1;
            if self.tx.dup_acks == 3 && !self.tx.in_recovery {
                let flight = self.tx.snd_nxt.wrapping_sub(self.tx.snd_una);
                self.tx.ssthresh = (flight / 2).max(2 * mss);
                self.mark_holes(); // fast retransmit (SACK-aware)
                self.tx.cwnd = self.tx.ssthresh.saturating_add(3 * mss);
                self.tx.in_recovery = true;
                self.tx.recover = self.tx.snd_nxt;
            } else if self.tx.in_recovery {
                self.tx.cwnd = self.tx.cwnd.saturating_add(mss); // inflate
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
            // 3a. Retransmit a marked hole first — SACK-aware, so we never resend
            //     a segment the receiver already acknowledged out of order.
            if let Some(idx) = self.tx.segs.iter().position(|s| s.needs_resend) {
                self.tx.segs[idx].needs_resend = false;
                self.tx.segs[idx].retransmitted = true;
                self.tx.segs[idx].sent_ms = now;
                self.encode_seg_at(idx, out);
                return true;
            }
            // 3b. New data / FIN, congestion + flow limited + PACED. At rates
            //     above one segment/ms, refill a small per-tick budget instead of
            //     flattening every path to the old MSS/ms timer floor.
            if now >= self.tx.pace_next_ms {
                let (interval, batch) = self.pace_params();
                self.tx.pace_budget = batch;
                self.tx.pace_next_ms = now + interval;
            }
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

    /// Create the next DATA/FIN segment if the send window allows; returns true
    /// if one was pushed onto `segs` (the caller then encodes `segs.back()`).
    fn create_next_segment(&mut self, now: u64) -> bool {
        let mss = self.cfg.mss as u32;
        let window = self.tx.cwnd.min(self.tx.rwnd);
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
    fn mark_holes(&mut self) {
        const DUP_THRESH: usize = 3;
        // Segments are in ascending seq order; walking from the back, count the
        // SACKed segments seen so far (those with a higher seq than the current).
        let mut sacked_above = 0usize;
        let mut any = false;
        for s in self.tx.segs.iter_mut().rev() {
            if s.sacked {
                sacked_above += 1;
            } else if sacked_above >= DUP_THRESH {
                s.needs_resend = true;
                any = true;
            }
        }
        // Fallback (classic fast-retransmit): nothing meets the SACK loss bar yet
        // → retransmit just the oldest unacked segment.
        if !any && let Some(f) = self.tx.segs.front_mut() {
            f.needs_resend = true;
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
            let mss = self.cfg.mss as u32;
            let flight = self.tx.snd_nxt.wrapping_sub(self.tx.snd_una);
            self.tx.ssthresh = (flight / 2).max(2 * mss);
            self.tx.cwnd = mss; // collapse to slow start
            self.tx.in_recovery = false;
            self.tx.dup_acks = 0;
            // Retransmit the oldest UN-SACKed unacked segment (poll_transmit
            // stamps sent_ms/retransmitted when it actually re-sends it).
            if let Some(s) = self.tx.segs.iter_mut().find(|s| !s.sacked) {
                s.needs_resend = true;
            }
            self.tx.rto_ms = (self.tx.rto_ms * 2).min(self.cfg.max_rto_ms); // backoff
            self.tx.rto_deadline = Some(now + self.tx.rto_ms);
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
        let window = self.tx.cwnd.min(self.tx.rwnd);
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
