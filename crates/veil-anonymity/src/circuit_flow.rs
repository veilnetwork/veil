//! One relay-local circuit direction. Kept by the installed circuit, never by
//! a queued weak witness. Return observations do not change its flow identity.
use crate::circuit_carrier::{Carrier, CarrierSend, DatagramCarrier, LocalCircuitFlow};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Default)]
struct Observation {
    sequence: u32,
    carrier: Option<Carrier>,
}

#[derive(Debug)]
pub(crate) struct CircuitFlow {
    active: AtomicBool,
    peer: Option<[u8; 32]>,
    observed: Mutex<Observation>,
}

impl CircuitFlow {
    pub(crate) fn new(peer: Option<[u8; 32]>) -> Self {
        Self {
            active: AtomicBool::new(true),
            peer,
            observed: Mutex::default(),
        }
    }

    pub(crate) fn retire(&self) {
        self.active.store(false, Ordering::Release);
    }

    pub(crate) fn observe(&self, sequence: u32, carrier: Option<&Carrier>) {
        let mut observed = self.observed.lock().unwrap_or_else(|e| e.into_inner());
        if self.active.load(Ordering::Acquire) && sequence > observed.sequence {
            observed.sequence = sequence;
            observed.carrier = carrier.cloned();
        }
    }

    pub(crate) fn observed_carrier(&self) -> Option<Carrier> {
        self.observed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .carrier
            .clone()
    }
}

impl DatagramCarrier for CircuitFlow {
    fn local_circuit_flow(&self) -> Option<LocalCircuitFlow> {
        (self.active.load(Ordering::Acquire) && self.peer.is_some())
            .then_some(LocalCircuitFlow(self as *const Self as usize))
    }

    fn try_send(
        &self,
        peer: &[u8; 32],
        frame: &[u8],
        admit: &mut dyn FnMut(usize) -> bool,
    ) -> CarrierSend {
        if !self.active.load(Ordering::Acquire) || self.peer.as_ref() != Some(peer) {
            return CarrierSend::Unavailable;
        }
        // The session carrier still validates frame family, neutral class,
        // credential lifetime and capacity. This wrapper grants no new send authority.
        match self.observed_carrier().and_then(|c| c.upgrade()) {
            Some(carrier) => carrier.try_send(peer, frame, admit),
            None => CarrierSend::Unavailable,
        }
    }
}
