//! Independent session datagram channels with opaque wire identifiers.
//!
//! Flow selection is a local handle, never a wire priority or application role.
//! Each channel has its own key, sequence, replay window and assembly quota.
//! Intermediaries receive no instruction to schedule one channel over another.
//! All channels still share the negotiated QUIC connection's congestion budget.

use std::{
    collections::{HashMap, VecDeque},
    time::Instant,
};

use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

use crate::realtime_datagram::{
    MAX_ASSEMBLIES, MAX_ASSEMBLY_BYTES, MAX_REALTIME_FRAME, REALTIME_REKEY_GRACE,
    RealtimeDatagramError, RealtimeDatagramRx, RealtimeDatagramTx,
};

const MAGIC: [u8; 4] = *b"VDF1";
const PREFIX_LEN: usize = 20;
const MAX_FLOWS: usize = 16;
// Endpoint-only lanes. Circuit handles occupy a disjoint namespace, so every
// transit circuit gets the same bounded LRU treatment, without a media role.
const LOCAL_LANES: [u64; 2] = [0, 2];
const KDF_CONTEXT: &str = "veil/session/opaque-datagram-flow/v1";
pub(crate) const MIN_FLOW_DATAGRAM_SIZE: usize = PREFIX_LEN + 41;
/// A complete frame, including every permitted fragment's encryption/header
/// and opaque-flow prefix. Also bounds the legacy codec without that prefix.
pub(crate) const MAX_FRAME_WIRE_BYTES: usize = MAX_REALTIME_FRAME
    + crate::realtime_datagram::MAX_FRAGMENTS
        * (PREFIX_LEN + crate::realtime_datagram::FRAGMENT_OVERHEAD);

type FlowId = [u8; 16];

fn flow_key(raw: &[u8; 32], session: &[u8; 32], id: &FlowId) -> Zeroizing<[u8; 32]> {
    let mut material = Zeroizing::new([0u8; 80]);
    material[..32].copy_from_slice(raw);
    material[32..64].copy_from_slice(session);
    material[64..].copy_from_slice(id);
    Zeroizing::new(blake3::derive_key(KDF_CONTEXT, material.as_ref()))
}

struct TxFlow {
    id: FlowId,
    codec: RealtimeDatagramTx,
}

pub(crate) struct FlowDatagramTx {
    key: Zeroizing<[u8; 32]>,
    session: [u8; 32],
    flows: HashMap<u64, TxFlow>,
    reusable: VecDeque<u64>,
}

impl FlowDatagramTx {
    fn new(key: &[u8; 32], session: &[u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(*key),
            session: *session,
            flows: HashMap::new(),
            reusable: VecDeque::new(),
        }
    }

    fn encode_frame(
        &mut self,
        local_flow: u64,
        frame: &[u8],
        ceiling: usize,
    ) -> Result<Vec<Vec<u8>>, RealtimeDatagramError> {
        if frame.is_empty() || frame.len() > MAX_REALTIME_FRAME {
            return Err(RealtimeDatagramError::FrameSize(frame.len()));
        }
        let inner_ceiling = ceiling
            .checked_sub(PREFIX_LEN)
            .filter(|size| *size >= 41)
            .ok_or(RealtimeDatagramError::DatagramTooSmall(ceiling))?;
        let fragment_count = frame
            .len()
            .div_ceil(inner_ceiling - crate::realtime_datagram::FRAGMENT_OVERHEAD);
        if fragment_count > crate::realtime_datagram::MAX_FRAGMENTS {
            return Err(RealtimeDatagramError::TooManyFragments(fragment_count));
        }
        if !self.flows.contains_key(&local_flow) {
            let absent_lanes = LOCAL_LANES
                .iter()
                .filter(|lane| **lane != local_flow && !self.flows.contains_key(*lane))
                .count();
            let flow = if self.flows.len() >= MAX_FLOWS - absent_lanes {
                let oldest = self
                    .reusable
                    .pop_front()
                    .expect("capacity includes reusable slots");
                // Rebind the local handle, retaining the wire id, AEAD key and
                // all message/nonce counters. Never allocate a seventeenth id
                // or reset a nonce when a circuit ends or a slot is reused.
                self.flows.remove(&oldest).expect("LRU slot exists")
            } else {
                let mut id = [0u8; 16];
                loop {
                    OsRng.fill_bytes(&mut id);
                    if id != [0; 16] && self.flows.values().all(|flow| flow.id != id) {
                        break;
                    }
                }
                let key = flow_key(&self.key, &self.session, &id);
                TxFlow {
                    id,
                    codec: RealtimeDatagramTx::new(&key, &self.session),
                }
            };
            self.flows.insert(local_flow, flow);
        }
        if !LOCAL_LANES.contains(&local_flow) {
            self.reusable.retain(|key| *key != local_flow);
            self.reusable.push_back(local_flow);
        }
        let flow = self
            .flows
            .get_mut(&local_flow)
            .expect("flow inserted above");
        flow.codec
            .encode_frame(frame, inner_ceiling)
            .map(|packets| {
                packets
                    .into_iter()
                    .map(|packet| {
                        let mut encoded = Vec::with_capacity(PREFIX_LEN + packet.len());
                        encoded.extend_from_slice(&MAGIC);
                        encoded.extend_from_slice(&flow.id);
                        encoded.extend_from_slice(&packet);
                        encoded
                    })
                    .collect()
            })
    }

    fn rekey(&mut self, key: &[u8; 32], session: &[u8; 32]) {
        self.key = Zeroizing::new(*key);
        self.session = *session;
        for flow in self.flows.values_mut() {
            flow.codec.rekey(&flow_key(key, session, &flow.id), session);
        }
    }
}

struct RetiredKey {
    key: Zeroizing<[u8; 32]>,
    session: [u8; 32],
    rotated_at: Instant,
}

pub(crate) struct FlowDatagramRx {
    key: Zeroizing<[u8; 32]>,
    session: [u8; 32],
    previous: Option<RetiredKey>,
    flows: HashMap<FlowId, RealtimeDatagramRx>,
}

impl FlowDatagramRx {
    fn new(key: &[u8; 32], session: &[u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(*key),
            session: *session,
            previous: None,
            flows: HashMap::new(),
        }
    }

    fn fresh_receiver(&self, id: &FlowId) -> RealtimeDatagramRx {
        let make = |key: &[u8; 32], session: &[u8; 32]| {
            RealtimeDatagramRx::with_limits(
                &flow_key(key, session, id),
                session,
                MAX_ASSEMBLIES / MAX_FLOWS,
                MAX_ASSEMBLY_BYTES / MAX_FLOWS,
            )
        };
        let current = flow_key(&self.key, &self.session, id);
        if let Some(old) = &self.previous {
            let mut rx = make(&old.key, &old.session);
            // Preserve the actual rotation deadline; a late first packet must
            // not extend the old key's grace by opening a new channel.
            rx.rekey(&current, &self.session, old.rotated_at);
            rx
        } else {
            make(&self.key, &self.session)
        }
    }

    fn decode_datagram(
        &mut self,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, RealtimeDatagramError> {
        for rx in self.flows.values_mut() {
            rx.prune(now);
        }
        if self.previous.as_ref().is_some_and(|old| {
            now.saturating_duration_since(old.rotated_at) >= REALTIME_REKEY_GRACE
        }) {
            self.previous = None;
        }
        if packet.len() < MIN_FLOW_DATAGRAM_SIZE || packet[..4] != MAGIC {
            return Err(RealtimeDatagramError::Malformed);
        }
        let id: FlowId = packet[4..PREFIX_LEN].try_into().unwrap();
        if id == [0; 16] {
            return Err(RealtimeDatagramError::Malformed);
        }
        if let Some(rx) = self.flows.get_mut(&id) {
            return rx.decode_datagram(&packet[PREFIX_LEN..], now);
        }
        if self.flows.len() >= MAX_FLOWS {
            return Err(RealtimeDatagramError::FlowCapacity);
        }
        let mut rx = self.fresh_receiver(&id);
        // An unauthenticated identifier never occupies a channel slot or
        // evicts another channel. AEAD keys bind the opaque id to this session.
        let frame = rx.decode_datagram(&packet[PREFIX_LEN..], now)?;
        self.flows.insert(id, rx);
        Ok(frame)
    }

    fn rekey(&mut self, key: &[u8; 32], session: &[u8; 32], now: Instant) {
        let old = std::mem::replace(&mut self.key, Zeroizing::new(*key));
        self.previous = Some(RetiredKey {
            key: old,
            session: self.session,
            rotated_at: now,
        });
        self.session = *session;
        for (id, rx) in &mut self.flows {
            rx.rekey(&flow_key(key, session, id), session, now);
        }
    }
}

/// Capability negotiation selects exactly one wire format for a session.
pub(crate) enum SessionDatagramTx {
    Legacy(RealtimeDatagramTx),
    Flows(FlowDatagramTx),
}

impl SessionDatagramTx {
    pub(crate) fn new(key: &[u8; 32], session: &[u8; 32], flows: bool) -> Self {
        if flows {
            Self::Flows(FlowDatagramTx::new(key, session))
        } else {
            Self::Legacy(RealtimeDatagramTx::new(key, session))
        }
    }
    pub(crate) fn encode_frame(
        &mut self,
        local_flow: u64,
        frame: &[u8],
        ceiling: usize,
    ) -> Result<Vec<Vec<u8>>, RealtimeDatagramError> {
        match self {
            Self::Legacy(tx) => tx.encode_frame(frame, ceiling),
            Self::Flows(tx) => tx.encode_frame(local_flow, frame, ceiling),
        }
    }
    pub(crate) fn rekey(&mut self, key: &[u8; 32], session: &[u8; 32]) {
        match self {
            Self::Legacy(tx) => tx.rekey(key, session),
            Self::Flows(tx) => tx.rekey(key, session),
        }
    }
}

pub(crate) enum SessionDatagramRx {
    Legacy(RealtimeDatagramRx),
    Flows(FlowDatagramRx),
}

impl SessionDatagramRx {
    pub(crate) fn new(key: &[u8; 32], session: &[u8; 32], flows: bool) -> Self {
        if flows {
            Self::Flows(FlowDatagramRx::new(key, session))
        } else {
            Self::Legacy(RealtimeDatagramRx::new(key, session))
        }
    }
    pub(crate) fn decode_datagram(
        &mut self,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, RealtimeDatagramError> {
        match self {
            Self::Legacy(rx) => rx.decode_datagram(packet, now),
            Self::Flows(rx) => rx.decode_datagram(packet, now),
        }
    }
    pub(crate) fn rekey(&mut self, key: &[u8; 32], session: &[u8; 32], now: Instant) {
        match self {
            Self::Legacy(rx) => rx.rekey(key, session, now),
            Self::Flows(rx) => rx.rekey(key, session, now),
        }
    }
}

#[cfg(test)]
mod tests;
