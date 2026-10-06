//! Bounded local sibling selection. Remote accepts see only generic proofs;
//! they dispatch through the canonical peer's existing budgets and identity.
use super::*;
use crate::parallel_binding::{HELLO_BYTES, ParallelKeys, ParallelParent, ParallelParentHandle};

#[path = "primary_recovery.rs"]
mod primary_recovery;
#[path = "parallel_recovery_trace.rs"]
mod recovery_trace;
#[path = "parallel_registry.rs"]
mod registry;
pub use registry::{ParallelPeekOutcome, ParallelRegistry};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use veil_transport::QuicParallelHandle;

const BIND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const SOURCE_SLOTS: usize = crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES.len();
const TRANSIT_SLOTS: usize = 2;
const TOTAL_SLOTS: usize = SOURCE_SLOTS + TRANSIT_SLOTS;

const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

/// Local observations, never wire fields or relay scheduling requests.
#[derive(Default)]
pub struct ParallelDiagnostics {
    sent: [AtomicU64; TOTAL_SLOTS],
    epoch_sent: [AtomicU64; TOTAL_SLOTS],
    rekeys: AtomicU64,
    active: AtomicUsize,
    replies: AtomicU64,
    recovery_attempts: AtomicU64,
    recovery_switches: AtomicU64,
}

impl ParallelDiagnostics {
    /// Successfully admitted frames on the selected independent connection.
    pub fn sent(&self, local_priority: u8) -> u64 {
        channel_index(local_priority).map_or(0, |index| self.sent[index].load(Ordering::Relaxed))
    }
    pub fn rekeys(&self) -> u64 {
        self.rekeys.load(Ordering::Acquire)
    }
    pub fn sent_this_generation(&self, local_priority: u8) -> u64 {
        channel_index(local_priority)
            .map_or(0, |index| self.epoch_sent[index].load(Ordering::Relaxed))
    }
    /// Forwarded cells on neutral shards, separate from source queue hints.
    pub fn transit_sent(&self) -> u64 {
        self.sent[SOURCE_SLOTS..]
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .sum()
    }
    pub fn transit_sent_this_generation(&self) -> u64 {
        self.epoch_sent[SOURCE_SLOTS..]
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .sum()
    }

    pub fn transit_shards_used_this_generation(&self) -> usize {
        self.epoch_sent[SOURCE_SLOTS..]
            .iter()
            .filter(|counter| counter.load(Ordering::Relaxed) != 0)
            .count()
    }

    pub fn recovery_attempts(&self) -> u64 {
        self.recovery_attempts.load(Ordering::Acquire)
    }
    pub fn recovery_switches(&self) -> u64 {
        self.recovery_switches.load(Ordering::Acquire)
    }

    pub fn replies(&self) -> u64 {
        self.replies.load(Ordering::Relaxed)
    }

    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
    pub(super) fn note_sent(&self, index: usize) {
        self.sent[index].fetch_add(1, Ordering::Relaxed);
        self.epoch_sent[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// Offered only after peer capability negotiation.
/// Clones retain the endpoint, but do not own session authorization.
#[derive(Clone)]
pub struct ParallelQuicOffer {
    handle: QuicParallelHandle,
    diagnostics: Arc<ParallelDiagnostics>,
    registry: Option<Arc<ParallelRegistry>>,
    duplex: bool,
}

impl ParallelQuicOffer {
    pub fn new(handle: QuicParallelHandle) -> Self {
        Self {
            handle,
            diagnostics: Arc::default(),
            registry: None,
            duplex: false,
        }
    }
    /// Use the runtime's single shared-listener dispatcher.
    pub fn with_registry(mut self, registry: Arc<ParallelRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Enable only after the peer explicitly negotiates duplex children.
    pub fn with_duplex(mut self) -> Self {
        self.duplex = true;
        self
    }

    pub fn diagnostics(&self) -> Arc<ParallelDiagnostics> {
        Arc::clone(&self.diagnostics)
    }
}

fn channel_index(priority: u8) -> Option<usize> {
    // INTERACTIVE/transit has no source slot and never requests one.
    crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES
        .iter()
        .position(|&lane| lane == priority)
}

struct Channel {
    handle: veil_transport::QuicDatagramHandle,
    stream: BoxIoStream,
    diagnostics: Option<Arc<ParallelDiagnostics>>,
}

impl Channel {
    fn new(
        connection: Box<dyn veil_transport::TransportConnection>,
        diagnostics: Arc<ParallelDiagnostics>,
    ) -> Result<Self, String> {
        let handle = connection
            .quic_datagrams()
            .ok_or("parallel transport has no datagrams")?;
        let stream = match connection.into_stream() {
            Ok(stream) => stream,
            Err(error) => {
                handle.close();
                return Err(error.to_string());
            }
        };
        diagnostics.active.fetch_add(1, Ordering::AcqRel);
        Ok(Self {
            handle,
            stream,
            diagnostics: Some(diagnostics),
        })
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.handle.close();
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

struct ReadySender {
    sender: Arc<Mutex<RealtimeSender>>,
    _receiver: Option<RealtimeReceiverTask>,
    _channel: Channel,
}

#[derive(Default)]
struct Slot {
    ready: Option<ReadySender>,
    warm: Option<(
        tokio::sync::oneshot::Receiver<ReadySender>,
        RealtimeReceiverTask,
    )>,
    retry_after: Option<std::time::Instant>,
    replacing: bool,
}

async fn connect_sender(
    offer: ParallelQuicOffer,
    parent: ParallelParentHandle,
    index: usize,
    context: RealtimeReceiverContext,
    trace: Option<&recovery_trace::Attempt>,
) -> Result<ReadySender, &'static str> {
    use recovery_trace::{Attempt, Phase};
    let connection = offer
        .handle
        .connect()
        .await
        .map_err(recovery_trace::connect_failure)?;
    Attempt::phase(trace, Phase::Channel);
    let mut channel =
        Channel::new(connection, Arc::clone(&offer.diagnostics)).map_err(|_| "channel_error")?;
    Attempt::phase(trace, Phase::Exporter);
    let exporter = channel
        .handle
        .channel_binding()
        .map_err(|_| "exporter_error")?;
    Attempt::phase(trace, Phase::Begin);
    let (hello, pending) = parent.begin(exporter).map_err(|_| "parent_retired")?;
    Attempt::phase(trace, Phase::HelloWrite);
    channel
        .stream
        .write_all(&hello)
        .await
        .map_err(|_| "hello_write_error")?;
    let mut ack = [0; 32];
    Attempt::phase(trace, Phase::AckRead);
    channel
        .stream
        .read_exact(&mut ack)
        .await
        .map_err(|_| "ack_read_error")?;
    Attempt::phase(trace, Phase::AckVerify);
    let keys = pending.finish(&ack).map_err(|error| match error {
        crate::parallel_binding::BindingError::Retired => "parent_retired",
        crate::parallel_binding::BindingError::InvalidProof => "invalid_ack_proof",
    })?;
    Attempt::phase(trace, Phase::DatagramCeiling);
    if channel
        .handle
        .max_size()
        .is_none_or(|size| size < crate::datagram_flows::MIN_FLOW_DATAGRAM_SIZE)
    {
        return Err("datagram_ceiling");
    }
    let tx = crate::datagram_flows::SessionDatagramTx::new(keys.tx_key(), &keys.session_id, true);
    let mut sender = RealtimeSender::new(channel.handle.clone(), tx);
    sender.sent_counter = Some((Arc::clone(&offer.diagnostics), index));
    let sender = Arc::new(Mutex::new(sender));
    let receiver = offer
        .duplex
        .then(|| spawn_child_receiver(&channel, &keys, parent, context, Arc::clone(&sender)));
    Attempt::phase(trace, Phase::Ready);
    Ok(ReadySender {
        sender,
        _receiver: receiver,
        _channel: channel,
    })
}

async fn receive_child(
    mut channel: Channel,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
    duplex: bool,
) {
    let authenticated = tokio::time::timeout(BIND_TIMEOUT, async {
        let mut hello = [0; HELLO_BYTES];
        channel.stream.read_exact(&mut hello).await.ok()?;
        let exporter = channel.handle.channel_binding().ok()?;
        let (ack, keys) = parent.accept(&hello, exporter).ok()?;
        channel.stream.write_all(&ack).await.ok()?;
        Some(keys)
    })
    .await;
    let Ok(Some(keys)) = authenticated else {
        return;
    };
    receive_authenticated(channel, keys, parent, context, duplex).await;
}

async fn receive_authenticated(
    channel: Channel,
    keys: ParallelKeys,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
    duplex: bool,
) {
    let rx = crate::datagram_flows::SessionDatagramRx::new(keys.rx_key(), &keys.session_id, true);
    let (_hold_tx, rekey_rx) = tokio::sync::watch::channel(None);
    let sender = duplex.then(|| {
        Arc::new(Mutex::new(RealtimeSender::new(
            channel.handle.clone(),
            crate::datagram_flows::SessionDatagramTx::new(keys.tx_key(), &keys.session_id, true),
        )))
    });
    let carrier = sender.map(|sender| make_carrier(&channel, sender, parent, context.peer_id));
    let mut receiver =
        spawn_realtime_receiver(channel.handle.clone(), rx, rekey_rx, context, carrier);
    tokio::select! {
        _ = channel.handle.closed() => {},
        _ = &mut receiver.0 => {},
    }
}

fn spawn_child_receiver(
    channel: &Channel,
    keys: &ParallelKeys,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
    sender: Arc<Mutex<RealtimeSender>>,
) -> RealtimeReceiverTask {
    let rx = crate::datagram_flows::SessionDatagramRx::new(keys.rx_key(), &keys.session_id, true);
    let (_hold_tx, rekey_rx) = tokio::sync::watch::channel(None);
    let carrier = make_carrier(channel, sender, parent, context.peer_id);
    spawn_realtime_receiver(channel.handle.clone(), rx, rekey_rx, context, Some(carrier))
}

fn make_carrier(
    channel: &Channel,
    sender: Arc<Mutex<RealtimeSender>>,
    parent: ParallelParentHandle,
    peer: NodeIdBytes,
) -> Arc<dyn veil_anonymity::circuit_carrier::DatagramCarrier> {
    Arc::new(ChildCarrier {
        sender,
        parent,
        peer,
        diagnostics: Arc::clone(channel.diagnostics.as_ref().expect("owned child")),
    })
}

struct ChildCarrier {
    sender: Arc<Mutex<RealtimeSender>>,
    parent: ParallelParentHandle,
    peer: NodeIdBytes,
    diagnostics: Arc<ParallelDiagnostics>,
}

impl veil_anonymity::circuit_carrier::DatagramCarrier for ChildCarrier {
    fn try_send(
        &self,
        peer: &NodeIdBytes,
        frame: &[u8],
        admit: &mut dyn FnMut(usize) -> bool,
    ) -> veil_anonymity::circuit_carrier::CarrierSend {
        use veil_anonymity::circuit_carrier::CarrierSend;
        if peer != &self.peer || !self.parent.is_active() {
            return CarrierSend::Unavailable;
        }
        let Some((header, body, RealtimeLaneFrameKind::CircuitDatagram)) =
            decode_realtime_lane_frame(frame)
        else {
            return CarrierSend::Unavailable;
        };
        if header.priority() != veil_proto::priority::INTERACTIVE {
            return CarrierSend::Unavailable;
        }
        let mut sender = lock!(self.sender);
        if sender.broken {
            return CarrierSend::Unavailable;
        }
        let max_size = sender.max_datagram_size;
        let datagrams = match sender.tx.encode_frame(
            local_datagram_flow(
                veil_proto::priority::INTERACTIVE,
                body,
                RealtimeLaneFrameKind::CircuitDatagram,
            ),
            frame,
            max_size,
        ) {
            Ok(datagrams) => datagrams,
            Err(_) => return CarrierSend::Unavailable,
        };
        let planned = datagrams.iter().map(Vec::len).sum::<usize>();
        if !local_datagram_fits(
            veil_proto::priority::INTERACTIVE,
            planned,
            sender.handle.send_buffer_space(),
        ) || !admit(planned)
        {
            return CarrierSend::Dropped { wire_bytes: 0 };
        }
        let mut wire_bytes = 0;
        for datagram in &datagrams {
            if let Err(error) = sender.handle.send(datagram) {
                if matches!(error, veil_transport::QuicDatagramSendError::TooLarge) {
                    if let Some(size) = sender.handle.max_size().filter(|size| *size > 40) {
                        sender.max_datagram_size = size;
                    }
                } else {
                    sender.broken = true;
                }
                // Admission already spent the shared budget, possibly sent a
                // prefix. Never duplicate this frame on the canonical channel.
                return CarrierSend::Dropped { wire_bytes };
            }
            wire_bytes += datagram.len() as u64;
        }
        self.diagnostics.replies.fetch_add(1, Ordering::Relaxed);
        CarrierSend::Sent { wire_bytes }
    }
}

fn spawn_acceptor(
    offer: ParallelQuicOffer,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
    mut incoming: tokio::sync::mpsc::Receiver<registry::BoundChild>,
) -> RealtimeReceiverTask {
    RealtimeReceiverTask(tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        let mut accepts = tokio::task::JoinSet::new();
        loop {
            // Two generic handshakes can progress independently. The shared
            // transport's eight-connection quota still bounds live children.
            // No producer role is inspected by this receiver.
            if offer.handle.has_exclusive_accept() {
                while accepts.len() < 2 {
                    let handle = offer.handle.clone();
                    accepts.spawn(async move {
                        let result = handle.accept().await;
                        if result.is_err() {
                            tokio::time::sleep(RETRY_DELAY).await;
                        }
                        result
                    });
                }
            }
            tokio::select! {
                _ = children.join_next(), if !children.is_empty() => {},
                Some(mut child) = incoming.recv() => {
                    let context = context.clone();
                    let duplex = offer.duplex;
                    children.spawn(async move {
                        if !child.parent.is_active() {
                            return;
                        }
                        if !matches!(tokio::time::timeout(BIND_TIMEOUT, child.channel.stream.write_all(&child.ack)).await, Ok(Ok(()))) {
                            return;
                        }
                        if !child.parent.is_active() {
                            return;
                        }
                        receive_authenticated(child.channel, child.keys, child.parent, context, duplex).await;
                    });
                },
                Some(accepted) = accepts.join_next(), if !accepts.is_empty() => {
                    if let Ok(Ok(connection)) = accepted
                        && let Ok(channel) = Channel::new(connection, Arc::clone(&offer.diagnostics)) {
                        children.spawn(receive_child(channel, parent.clone(), context.clone(), offer.duplex));
                    }
                },
                // A full registry or missing shared dispatcher leaves the
                // ordinary lane available; there is no accept source to poll.
                else => break,
            }
        }
    }))
}

pub(super) struct ParallelSession {
    offer: ParallelQuicOffer,
    context: RealtimeReceiverContext,
    parent: ParallelParent,
    readiness: Option<crate::local_datagram_status::LocalDatagramLease>,
    _acceptor: RealtimeReceiverTask,
    _registration: Option<registry::Registration>,
    slots: [Slot; TOTAL_SLOTS],
    transit_salt: [u8; 32],
    primary_recovery: primary_recovery::PrimaryRecovery,
}

impl ParallelSession {
    pub(super) fn new(
        offer: ParallelQuicOffer,
        tx: &[u8; 32],
        rx: &[u8; 32],
        sid: [u8; 32],
        context: RealtimeReceiverContext,
        status: Option<Arc<crate::local_datagram_status::LocalDatagramStatus>>,
    ) -> Self {
        let readiness = status
            .filter(|_| offer.duplex)
            .map(|status| status.activate());
        let parent = ParallelParent::new(sid, *tx, *rx);
        let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(8);
        let registration = offer
            .registry
            .as_ref()
            .and_then(|registry| registry.register(sid, parent.handle(), &offer, incoming_tx));
        let acceptor = spawn_acceptor(offer.clone(), parent.handle(), context.clone(), incoming_rx);
        Self {
            offer,
            context,
            parent,
            readiness,
            _acceptor: acceptor,
            _registration: registration,
            slots: Default::default(),
            transit_salt: blake3::derive_key("veil/transit-shard/v1", &sid),
            primary_recovery: Default::default(),
        }
    }

    pub(super) fn rekey(&mut self, tx: &[u8; 32], rx: &[u8; 32], sid: [u8; 32]) {
        for counter in &self.offer.diagnostics.epoch_sent {
            counter.store(0, Ordering::Relaxed);
        }
        self.offer
            .diagnostics
            .rekeys
            .fetch_add(1, Ordering::Release);
        self.parent.retire();
        self._registration = None;
        let status = self.readiness.as_ref().map(|lease| lease.status());
        *self = Self::new(
            self.offer.clone(),
            tx,
            rx,
            sid,
            self.context.clone(),
            status,
        );
    }

    /// Poll readiness and initiate warming without awaiting on the main
    /// session. Until authentication succeeds, frames use the current lane.
    pub(super) fn prepare(&mut self, priority: u8) -> bool {
        let Some(index) = channel_index(priority) else {
            return false;
        };
        self.prepare_index(index)
    }

    /// Called only after the ordinary FIFO selects this frame. Every transit
    /// circuit receives the same admission and service cost; its opaque per-link
    /// ID picks one bounded shard, never an application role or queue priority.
    pub(super) fn prepare_frame(
        &mut self,
        priority: u8,
        body: &[u8],
        kind: RealtimeLaneFrameKind,
    ) -> Option<usize> {
        // Only a locally selected primary frame can request replacement.
        // Neutral transit and the secondary/background producers cannot do so.
        if priority == veil_proto::priority::REALTIME {
            self.recover_primary(std::time::Instant::now());
        }
        let index = channel_index(priority).or_else(|| {
            (self.offer.duplex
                && priority == veil_proto::priority::INTERACTIVE
                && kind == RealtimeLaneFrameKind::CircuitDatagram)
                .then(|| transit_index(&self.transit_salt, body))
        })?;
        self.prepare_index(index).then_some(index)
    }

    fn prepare_index(&mut self, index: usize) -> bool {
        let slot = &mut self.slots[index];
        if slot
            .ready
            .as_ref()
            .is_some_and(|ready| lock!(ready.sender).broken)
        {
            slot.ready = None;
            slot.retry_after = Some(std::time::Instant::now() + RETRY_DELAY);
        }
        if let Some((rx, _)) = slot.warm.as_mut() {
            match rx.try_recv() {
                Ok(ready) => {
                    // connect_sender verified the live parent's exporter-bound
                    // ACK before returning ReadySender. Drop the old channel
                    // only now; a failed candidate never displaces it.
                    slot.ready = Some(ready);
                    slot.warm = None;
                    if std::mem::take(&mut slot.replacing) {
                        self.offer
                            .diagnostics
                            .recovery_switches
                            .fetch_add(1, Ordering::AcqRel);
                        self.primary_recovery.reset();
                        self.context.logger.info(
                            "session.parallel.recovery_switched",
                            format!(
                                "peer_id={} local_slot={}",
                                hex_short(&self.context.peer_id),
                                veil_proto::priority::REALTIME
                            ),
                        );
                    }
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    slot.warm = None;
                    slot.replacing = false;
                    slot.retry_after = Some(std::time::Instant::now() + RETRY_DELAY);
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            }
        }
        if let Some(lease) = &self.readiness
            && index < SOURCE_SLOTS
        {
            let priority = crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES[index];
            lease.mark(priority, slot.ready.is_some());
        }
        if slot.ready.is_some() {
            return true;
        }
        if slot.warm.is_none()
            && slot
                .retry_after
                .is_none_or(|deadline| std::time::Instant::now() >= deadline)
        {
            self.start_warm(index);
        }
        false
    }

    fn start_warm(&mut self, index: usize) {
        let offer = self.offer.clone();
        let parent = self.parent.handle();
        let context = self.context.clone();
        let status = self.readiness.as_ref().map(|lease| lease.status());
        let mut trace = self.slots[index]
            .replacing
            .then(|| recovery_trace::Attempt::new(&context, offer.handle.clone()));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = RealtimeReceiverTask(tokio::spawn(async move {
            match tokio::time::timeout(
                BIND_TIMEOUT,
                connect_sender(offer, parent, index, context, trace.as_ref()),
            )
            .await
            {
                Ok(Ok(ready)) => {
                    if let Some(trace) = trace.as_mut() {
                        trace.finish("verified", "authenticated");
                    }
                    let _ = tx.send(ready);
                }
                Ok(Err(reason)) => {
                    if let Some(trace) = trace.as_mut() {
                        trace.finish("failed", reason);
                    }
                }
                Err(_) => {
                    if let Some(trace) = trace.as_mut() {
                        trace.finish("timeout", "binding_deadline");
                    }
                }
            }
            if let Some(status) = status {
                status.wake();
            }
        }));
        self.slots[index].warm = Some((rx, task));
    }

    fn recover_primary(&mut self, now: std::time::Instant) {
        use primary_recovery::Action;
        let index = channel_index(veil_proto::priority::REALTIME).unwrap();
        let slot = &mut self.slots[index];
        let Some(ready) = &slot.ready else {
            self.primary_recovery.reset();
            return;
        };
        let stats = {
            let sender = lock!(ready.sender);
            if sender.broken {
                return;
            }
            sender.handle.path_stats()
        };
        match self.primary_recovery.observe(stats, now) {
            Action::Progress if slot.replacing => {
                // The old channel recovered while proof was pending. Reap the
                // redundant task/channel instead of churning a healthy sender.
                slot.warm = None;
                slot.replacing = false;
                self.context.logger.info(
                    "session.parallel.recovery_cancelled",
                    format!(
                        "peer_id={} local_slot={} reason=ack_progress",
                        hex_short(&self.context.peer_id),
                        veil_proto::priority::REALTIME,
                    ),
                );
            }
            Action::Probe if slot.warm.is_none() => {
                self.primary_recovery.attempted(now);
                slot.replacing = true;
                self.offer
                    .diagnostics
                    .recovery_attempts
                    .fetch_add(1, Ordering::AcqRel);
                self.context.logger.info(
                    "session.parallel.recovery_started",
                    format!(
                        "peer_id={} local_slot={} pto_count={} expired={}",
                        hex_short(&self.context.peer_id),
                        veil_proto::priority::REALTIME,
                        stats.pto_count,
                        stats.expired_outgoing_datagrams
                    ),
                );
                self.start_warm(index);
            }
            _ => {}
        }
    }

    pub(super) fn sender(&self, index: usize) -> std::sync::MutexGuard<'_, RealtimeSender> {
        lock!(
            self.slots[index]
                .ready
                .as_ref()
                .expect("prepared sender")
                .sender
        )
    }
}

// The caller has validated the CircuitDataPayload. Only its existing per-link
// ID participates; ciphertext, sender hints and claimed priority never do.
fn transit_index(salt: &[u8; 32], body: &[u8]) -> usize {
    SOURCE_SLOTS + usize::from(blake3::keyed_hash(salt, &body[..4]).as_bytes()[0]) % TRANSIT_SLOTS
}

#[cfg(test)]
mod transit_tests {
    use super::*;

    #[test]
    fn neutral_shards_are_bounded_stable_and_ignore_contents() {
        let salt = blake3::derive_key("veil/transit-shard/v1", &[7; 32]);
        let mut seen = [false; TRANSIT_SLOTS];
        for cid in 0..256u32 {
            let mut body = cid.to_be_bytes().to_vec();
            body.extend_from_slice(&[0; 128]);
            let index = transit_index(&salt, &body);
            assert!((SOURCE_SLOTS..TOTAL_SLOTS).contains(&index));
            seen[index - SOURCE_SLOTS] = true;
            body[4..].fill(255);
            assert_eq!(transit_index(&salt, &body), index);
        }
        assert!(seen.into_iter().all(|present| present));
        assert_eq!(channel_index(veil_proto::priority::INTERACTIVE), None);
    }

    #[test]
    fn transit_observations_do_not_claim_source_channels() {
        let diagnostics = ParallelDiagnostics::default();
        diagnostics.note_sent(SOURCE_SLOTS);
        diagnostics.note_sent(SOURCE_SLOTS + 1);
        assert_eq!(diagnostics.transit_sent(), 2);
        assert_eq!(diagnostics.transit_sent_this_generation(), 2);
        assert_eq!(diagnostics.sent(0), 0);
        assert_eq!(diagnostics.sent(2), 0);
    }
}
