//! Local cost of an authenticated source child. Not a wire QoS request.
use crate::datagram_flows::{PREFIX_LEN, flow_fragment_count};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPacketFraming {
    QuicDatagram { ceiling: usize },
    Obfs4Record,
}

impl LocalPacketFraming {
    /// Expected bytes multiplied by two, excluding QUIC/TCP/IP. The obfs4
    /// padding expectation is fractional; encryption/padding stays unchanged.
    pub fn frame_bytes_x2(self, frame_bytes: usize) -> Option<usize> {
        let ceiling = match self {
            Self::QuicDatagram { ceiling } => ceiling,
            Self::Obfs4Record => veil_transport::ordered_records::MAX_RECORD_BYTES,
        };
        let count = flow_fragment_count(frame_bytes, ceiling).ok()?;
        let overhead = PREFIX_LEN + crate::realtime_datagram::FRAGMENT_OVERHEAD;
        let flow_bytes = frame_bytes.checked_add(count.checked_mul(overhead)?)?;
        match self {
            Self::QuicDatagram { .. } => flow_bytes.checked_mul(2),
            // Each opaque datagram is one length-prefixed stream record.
            // Records fit one obfs4 write; its mean padding is accounted by
            // the transport helper, using the real padding-range constants.
            Self::Obfs4Record => flow_bytes.checked_mul(2)?.checked_add(
                count.checked_mul(4 + veil_transport::obfs4_tcp::mean_frame_overhead_x2())?,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_flows::SessionDatagramTx;

    #[test]
    fn cost_matches_real_flow_encryption_and_fragmentation() {
        for ceiling in [1200, 1382] {
            for len in [1, 300, 1140, 1141, 1322, 1323, 4000] {
                let mut tx = SessionDatagramTx::new(&[1; 32], &[2; 32], true);
                let packets = tx.encode_frame(0, &vec![9; len], ceiling).unwrap();
                let actual: usize = packets.iter().map(Vec::len).sum();
                assert_eq!(
                    LocalPacketFraming::QuicDatagram { ceiling }.frame_bytes_x2(len),
                    Some(2 * actual)
                );
                if ceiling == 1200 {
                    assert_eq!(
                        LocalPacketFraming::Obfs4Record.frame_bytes_x2(len),
                        Some(
                            2 * actual
                                + packets.len()
                                    * (4 + veil_transport::obfs4_tcp::mean_frame_overhead_x2())
                        )
                    );
                }
            }
        }
        assert_eq!(
            LocalPacketFraming::QuicDatagram { ceiling: 60 }.frame_bytes_x2(10),
            None
        );
        assert_eq!(LocalPacketFraming::Obfs4Record.frame_bytes_x2(0), None);
    }
}
