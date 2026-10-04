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
    fn try_send(
        &self,
        peer: &[u8; 32],
        frame: &[u8],
        admit: &mut dyn FnMut(usize) -> bool,
    ) -> CarrierSend;
}

pub type Carrier = std::sync::Weak<dyn DatagramCarrier>;
