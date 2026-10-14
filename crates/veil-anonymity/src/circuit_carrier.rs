//! Process-local flow ownership and return transport, never a wire role or priority.
//! The session invokes it ONLY after the ordinary peer queue selects the cell.

/// Exact result of one loss-tolerant frame admission. A partial send must not
/// be retried on another transport; the circuit's end-to-end engine recovers.
pub enum CarrierSend {
    Sent {
        wire_bytes: u64,
    },
    Dropped {
        wire_bytes: u64,
    },
    /// No budget was spent and no datagram sent. Use the canonical transport.
    Unavailable,
}

/// Bound to one authenticated canonical peer and credential lifetime. One
/// sender/counter state is shared by all producers on that child connection.
pub trait DatagramCarrier: Send + Sync {
    /// Opaque process-local ownership of an authenticated incoming connection.
    /// No application role, priority or wire identifier comes from this value.
    /// Retired parents must return None. Legacy carriers have no observation.
    fn local_ingress_flow(&self) -> Option<LocalIngressFlow> {
        None
    }

    /// Circuit-lifetime ownership, independent of the observed return pipe.
    /// It is deliberately a different identity namespace from ingress handles.
    fn local_circuit_flow(&self) -> Option<LocalCircuitFlow> {
        None
    }

    fn local_transit_flow(&self) -> Option<LocalTransitFlow> {
        self.local_circuit_flow()
            .map(LocalTransitFlow::Circuit)
            .or_else(|| self.local_ingress_flow().map(LocalTransitFlow::Ingress))
    }

    fn try_send(
        &self,
        peer: &[u8; 32],
        frame: &[u8],
        admit: &mut dyn FnMut(usize) -> bool,
    ) -> CarrierSend;
}

/// Local allocation identities, never serialized or printed as addresses.
/// The weak carrier witness keeps the selection tied to its authenticated
/// lifetime; a raw value alone must never authorize or schedule a frame.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LocalIngressFlow {
    pub parent: usize,
    pub connection: usize,
}

impl std::fmt::Debug for LocalIngressFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalIngressFlow(<local ownership>)")
    }
}

pub type Carrier = std::sync::Weak<dyn DatagramCarrier>;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LocalCircuitFlow(pub(crate) usize);

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum LocalTransitFlow {
    Ingress(LocalIngressFlow),
    Circuit(LocalCircuitFlow),
}

impl std::fmt::Debug for LocalTransitFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalTransitFlow(<local ownership>)")
    }
}
