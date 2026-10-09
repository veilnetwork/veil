//! Process-local return transport for a circuit, never a wire role or priority.
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
