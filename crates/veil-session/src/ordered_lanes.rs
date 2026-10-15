//! Fixed-size, mutually authenticated duplex children for an ordered parent.
//! Only the original TCP dialer opens children. Both endpoints assign their
//! own source slots locally; the peer sees generic proofs and opaque records,
//! never a producer role, requested priority or slot number.
use super::*;
use crate::local_datagram_status::{LocalDatagramLease, LocalDatagramStatus};
use crate::parallel_binding::{BoundOrderedChannel, ParallelParent, ParallelParentHandle};
use std::sync::Weak;
use tokio::io::AsyncReadExt;
use veil_transport::stream_parallel::StreamParallelHandle;

// Ordered parents already carry signaling separately from their independent
// media/data children. Keep their original pool and replacement allowance.
const ORDERED_PRIORITIES: &[u8] = &[
    veil_proto::priority::REALTIME,
    veil_proto::priority::BULK,
    veil_proto::priority::BACKGROUND,
    veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
];
const SOURCE_SLOTS: usize = ORDERED_PRIORITIES.len();
const TRANSIT_SLOTS: usize = 2;
const TOTAL_SLOTS: usize = SOURCE_SLOTS + TRANSIT_SLOTS;
const BIND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
const _: () = assert!(TOTAL_SLOTS + 1 < StreamParallelHandle::CONNECTIONS_PER_DIRECTION);

#[derive(Clone)]
pub struct ParallelOrderedOffer {
    handle: StreamParallelHandle,
    registry: Arc<ParallelRegistry>,
    diagnostics: Arc<ParallelDiagnostics>,
    reliable: bool,
}

impl ParallelOrderedOffer {
    /// Call only after explicit ordered-child capability negotiation on the
    /// canonical OVL1 handshake. This offer alone grants no peer authority.
    pub fn new(handle: StreamParallelHandle, registry: Arc<ParallelRegistry>) -> Self {
        Self {
            handle,
            registry,
            diagnostics: Arc::default(),
            reliable: false,
        }
    }
    pub fn diagnostics(&self) -> Arc<ParallelDiagnostics> {
        self.diagnostics.clone()
    }
    /// Enable only after the independent reliable-child capability is agreed.
    pub fn with_reliable(mut self) -> Self {
        self.reliable = true;
        self
    }
}

enum Owner {
    Outgoing(BoundOrderedChannel),
    Incoming(RegisteredOrderedChannel),
}

impl Owner {
    fn keys(&self) -> &crate::parallel_binding::ParallelKeys {
        match self {
            Self::Outgoing(c) => &c.keys,
            Self::Incoming(c) => c.keys(),
        }
    }
    fn handle(&self) -> crate::parallel_binding::BoundOrderedHandle {
        match self {
            Self::Outgoing(c) => c.handle(),
            Self::Incoming(c) => c.handle(),
        }
    }
}

struct OutgoingLease(Arc<ParallelDiagnostics>);
impl Drop for OutgoingLease {
    fn drop(&mut self) {
        self.0.connection_closed();
    }
}

struct Ready {
    sender: Arc<Mutex<RealtimeSender>>,
    receiver: RealtimeReceiverTask,
    _owner: Owner,
    _outgoing: Option<OutgoingLease>,
}

impl Ready {
    fn new(
        owner: Owner,
        parent: ParallelParentHandle,
        context: RealtimeReceiverContext,
        diagnostics: Arc<ParallelDiagnostics>,
    ) -> Self {
        let keys = owner.keys();
        let handle = owner.handle();
        let sender = Arc::new(Mutex::new(RealtimeSender::new(
            handle.clone(),
            crate::datagram_flows::SessionDatagramTx::new(keys.tx_key(), &keys.session_id, true),
        )));
        let rx =
            crate::datagram_flows::SessionDatagramRx::new(keys.rx_key(), &keys.session_id, true);
        let carrier =
            parallel_lanes::make_carrier(&diagnostics, sender.clone(), parent, context.peer_id);
        let (_hold, rekeys) = tokio::sync::watch::channel(None);
        let receiver = spawn_realtime_receiver(handle, rx, rekeys, context, Some(carrier));
        let outgoing = matches!(&owner, Owner::Outgoing(_)).then(|| {
            diagnostics.connection_opened();
            OutgoingLease(diagnostics)
        });
        Self {
            sender,
            receiver,
            _owner: owner,
            _outgoing: outgoing,
        }
    }
    fn alive(&self) -> bool {
        let sender = lock!(self.sender);
        !sender.broken && sender.handle.max_size().is_some() && !self.receiver.0.is_finished()
    }
}

#[derive(Default)]
struct Pool {
    slots: [Option<Ready>; TOTAL_SLOTS],
    // Incoming proofs may consume only their bounded directional
    // leases. They cannot displace the dialer's outgoing source slots.
    incoming: Vec<Ready>,
    assignments: channel_assignments::ChannelAssignments<TOTAL_SLOTS>,
}

async fn connect(
    offer: ParallelOrderedOffer,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
) -> Result<Ready, &'static str> {
    let connection = offer
        .handle
        .connect()
        .await
        .map_err(|_| "ordered child connect failed")?;
    let exporter = connection
        .stream_channel_binding()
        .ok_or("ordered child binding unavailable")?;
    let mut stream = connection
        .into_stream()
        .map_err(|_| "ordered child stream unavailable")?;
    let (hello, pending) = parent
        .begin(exporter)
        .map_err(|_| "parallel parent retired")?;
    stream
        .write_all(&hello)
        .await
        .map_err(|_| "ordered child proof write failed")?;
    stream
        .flush()
        .await
        .map_err(|_| "ordered child proof flush failed")?;
    let mut ack = [0; 32];
    stream
        .read_exact(&mut ack)
        .await
        .map_err(|_| "ordered child acknowledgement failed")?;
    let keys = pending
        .finish(&ack)
        .map_err(|_| "ordered child acknowledgement rejected")?;
    let channel = keys
        .into_ordered(stream)
        .map_err(|_| "parallel parent retired")?;
    Ok(Ready::new(
        Owner::Outgoing(channel),
        parent,
        context,
        offer.diagnostics,
    ))
}

fn mark(pool: &mut Pool, readiness: &Weak<LocalDatagramLease>) {
    if let Some(lease) = readiness.upgrade() {
        let status = lease.status();
        let mut changed = false;
        for (index, priority) in ORDERED_PRIORITIES.iter().enumerate() {
            if status.pending() & (1 << index) != 0 {
                pool.assignments.source(index);
            }
            let ready = pool
                .assignments
                .source_physical(index)
                .is_some_and(|physical| pool.slots[physical].as_ref().is_some_and(Ready::alive));
            changed |=
                (status.state(*priority) == crate::LocalDatagramChannelState::Ready) != ready;
            lease.mark(*priority, ready);
        }
        if changed {
            status.wake();
        }
    }
}

fn worker(
    offer: ParallelOrderedOffer,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
    pool: Arc<Mutex<Pool>>,
    readiness: Weak<LocalDatagramLease>,
    mut incoming: mpsc::Receiver<BoundOrderedChild>,
) -> RealtimeReceiverTask {
    RealtimeReceiverTask(tokio::spawn(async move {
        let mut attempts = tokio::task::JoinSet::new();
        let mut attempt_slots: std::collections::HashMap<tokio::task::Id, usize> =
            std::collections::HashMap::new();
        let mut warming = [false; TOTAL_SLOTS];
        let mut retries = [std::time::Instant::now(); TOTAL_SLOTS];
        let mut backoffs = [RETRY_DELAY; TOTAL_SLOTS];
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = parent.retired() => break,
                _ = offer.handle.closed() => break,
                Some(child) = incoming.recv() => {
                    // Finish the already verified proof on its same fresh
                    // transport. Parent retirement wakes this bounded flight.
                    if let Ok(channel) = child.finish().await {
                        let ready = Ready::new(Owner::Incoming(channel), parent.clone(), context.clone(), offer.diagnostics.clone());
                        let mut pool = lock!(pool);
                        if !offer.handle.can_connect() && let Some(slot) = pool.slots.iter_mut().find(|slot| slot.is_none()) {
                            *slot = Some(ready);
                        } else {
                            // Real directional leases, not this vector, bound
                            // these neutral receive/return owners.
                            pool.incoming.push(ready);
                        }
                        mark(&mut pool, &readiness);
                    }
                },
                Some(result) = attempts.join_next_with_id(), if !attempts.is_empty() => {
                    let (index, result) = match result {
                        Ok((id, (index, result))) => { attempt_slots.remove(&id); (index, result) },
                        Err(error) => {
                            let Some(index) = attempt_slots.remove(&error.id()) else { continue; };
                            (index, Err("ordered child task failed"))
                        },
                    };
                        warming[index] = false;
                        backoffs[index] = if result.is_ok() { RETRY_DELAY } else {
                            (backoffs[index] * 2).min(std::time::Duration::from_secs(30))
                        };
                        retries[index] = std::time::Instant::now() + backoffs[index];
                        if let Ok(ready) = result {
                            let mut pool = lock!(pool);
                            pool.slots[index] = Some(ready);
                            mark(&mut pool, &readiness);
                        }
                },
                _ = tick.tick() => {
                    let mut pool = lock!(pool);
                    for slot in &mut pool.slots {
                        if slot.as_ref().is_some_and(|ready| !ready.alive()) { *slot = None; }
                    }
                    pool.incoming.retain(Ready::alive);
                    if !offer.handle.can_connect() {
                        // A generic replacement proof need not reveal which
                        // source used the old connection. Reclaim the empty
                        // local slot from any verified surviving child.
                        for index in 0..TOTAL_SLOTS {
                            if pool.slots[index].is_none() { pool.slots[index] = pool.incoming.pop(); }
                        }
                    } else {
                        for index in 0..TOTAL_SLOTS {
                            if pool.slots[index].is_none() && !warming[index] && std::time::Instant::now() >= retries[index] {
                                warming[index] = true;
                                let offer = offer.clone(); let parent = parent.clone(); let context = context.clone();
                                let task = attempts.spawn(async move {
                                    let result = tokio::time::timeout(BIND_TIMEOUT, connect(offer, parent, context)).await
                                        .unwrap_or(Err("ordered child binding timeout"));
                                    (index, result)
                                });
                                attempt_slots.insert(task.id(), index);
                            }
                        }
                    }
                    mark(&mut pool, &readiness);
                },
            }
        }
    }))
}

pub(super) struct OrderedSession {
    offer: ParallelOrderedOffer,
    context: RealtimeReceiverContext,
    parent: ParallelParent,
    pool: Arc<Mutex<Pool>>,
    readiness: Option<Arc<LocalDatagramLease>>,
    registration: Option<ParallelRegistration>,
    _worker: RealtimeReceiverTask,
    transit_salt: [u8; 32],
    reliable: Option<super::reliable_session::ReliableSession>,
}

impl OrderedSession {
    pub(super) fn note_reliable_frame(&self, canonical_full: bool) -> bool {
        self.offer.diagnostics.note_reliable_frame(canonical_full)
    }
    pub(super) fn reliable(&self) -> Option<&super::reliable_session::ReliableSession> {
        self.reliable.as_ref()
    }
    pub(super) fn new(
        offer: ParallelOrderedOffer,
        tx: &[u8; 32],
        rx: &[u8; 32],
        sid: [u8; 32],
        context: RealtimeReceiverContext,
        status: Option<Arc<LocalDatagramStatus>>,
    ) -> Self {
        let parent = ParallelParent::new(sid, *tx, *rx);

        let pool = Arc::new(Mutex::new(Pool::default()));
        let (incoming, incoming_rx) =
            mpsc::channel(StreamParallelHandle::CONNECTIONS_PER_DIRECTION);
        let registration = offer.registry.register_ordered(
            sid,
            parent.handle(),
            offer.handle.clone(),
            offer.diagnostics.clone(),
            incoming,
        );
        let (reliable_tx, reliable_rx) = mpsc::channel(1);
        let reliable = (offer.reliable
            && registration
                .as_ref()
                .is_some_and(|r| r.enable_reliable(reliable_tx)))
        .then(|| {
            super::reliable_session::ReliableSession::new(
                super::reliable_session::ReliableTransport::Ordered(offer.handle.clone()),
                parent.handle(),
                offer.diagnostics.clone(),
                reliable_rx,
            )
        });
        let readiness = status
            .filter(|_| registration.is_some())
            .map(|status| Arc::new(status.activate_without_signaling()));
        let worker = if registration.is_some() {
            worker(
                offer.clone(),
                parent.handle(),
                context.clone(),
                pool.clone(),
                readiness.as_ref().map(Arc::downgrade).unwrap_or_default(),
                incoming_rx,
            )
        } else {
            // A missing canonical registration cannot warm one-way children.
            RealtimeReceiverTask(tokio::spawn(async {}))
        };
        Self {
            offer,
            context,
            parent,
            pool,
            readiness,
            registration,
            _worker: worker,
            transit_salt: blake3::derive_key("veil/transit-shard/v1", &sid),
            reliable,
        }
    }

    pub(super) fn rekey(&mut self, tx: &[u8; 32], rx: &[u8; 32], sid: [u8; 32]) {
        let status = self.readiness.as_ref().map(|lease| lease.status());
        self.parent.retire();
        self.registration = None;
        *self = Self::new(
            self.offer.clone(),
            tx,
            rx,
            sid,
            self.context.clone(),
            status,
        );
        self.offer.diagnostics.rotate_generation();
    }

    pub(super) fn sender_with_carrier(
        &self,
        priority: u8,
        body: &[u8],
        kind: RealtimeLaneFrameKind,
        ingress: Option<&veil_anonymity::circuit_carrier::Carrier>,
    ) -> Option<Arc<Mutex<RealtimeSender>>> {
        lock!(self.pool).selected_sender(
            priority,
            body,
            kind,
            ingress,
            &self.transit_salt,
            &self.offer.diagnostics,
        )
    }
}

impl Drop for OrderedSession {
    fn drop(&mut self) {
        self.parent.retire();
        self.reliable = None;
        self.registration = None;
        let mut pool = lock!(self.pool);
        pool.slots = Default::default();
        pool.incoming.clear();
    }
}

impl Pool {
    fn selected_sender(
        &mut self,
        priority: u8,
        body: &[u8],
        kind: RealtimeLaneFrameKind,
        ingress: Option<&veil_anonymity::circuit_carrier::Carrier>,
        salt: &[u8; 32],
        diagnostics: &Arc<ParallelDiagnostics>,
    ) -> Option<Arc<Mutex<RealtimeSender>>> {
        let selected = if let Some(source) = ORDERED_PRIORITIES.iter().position(|&p| p == priority)
        {
            self.assignments.source(source)?
        } else {
            if priority != veil_proto::priority::INTERACTIVE {
                return None;
            }
            let bucket = parallel_lanes::neutral_transit_index(salt, body, kind)?;
            let ingress = parallel_lanes::transit_witness(kind, ingress);
            self.assignments.transit(ingress, bucket)?
        };
        let ready = self.slots[selected.physical]
            .as_ref()
            .filter(|ready| ready.alive())?;
        let mut sender = lock!(ready.sender);
        sender.sent_counter = Some((diagnostics.clone(), selected.counter));
        Some(ready.sender.clone())
    }
}

#[cfg(test)]
#[path = "forward_channel_isolation_tests.rs"]
mod forward_channel_isolation_tests;

#[cfg(test)]
#[path = "circuit_channel_isolation_tests.rs"]
mod circuit_channel_isolation_tests;
