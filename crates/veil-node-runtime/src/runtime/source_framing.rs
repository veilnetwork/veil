use super::*;
use veil_types::FrameBroadcaster;

impl NodeServices {
    /// Endpoint-local snapshot of the children selected for an existing lossy
    /// source. No probe, channel preparation, discovery or frame is sent.
    /// None means the relevant child/link does not have a truthful ready model.
    pub fn local_source_framing(
        &self,
        peer: &[u8; 32],
        local_lane: u8,
        relayed: bool,
        copies_limit: usize,
    ) -> Option<Vec<veil_session::LocalPacketFraming>> {
        let registry =
            veil_session::glue::SessionTxBroadcaster::new(self.session_tx_registry.clone())
                .with_sessions(self.session_registry.clone());
        let mut peers = if relayed {
            veil_ipc::source_paths::sealed_relay_hops(
                peer,
                Some(&self.dispatcher.route_cache),
                &registry,
            )
        } else {
            let devices = registry.devices_of(peer);
            if devices.is_empty() {
                vec![*peer]
            } else {
                devices
            }
        };
        if relayed {
            // A datagram admission suppresses subsequent ordered copies in
            // the actual sender. Do not charge an unused ordered fallback.
            if peers
                .first()
                .is_some_and(|p| registry.has_neutral_forward_datagram_transport(p))
            {
                peers.retain(|p| registry.has_neutral_forward_datagram_transport(p));
            }
            peers.truncate(copies_limit);
        }
        if peers.is_empty() {
            return None;
        }
        let sessions = self.session_tx_registry.try_read().ok()?;
        peers
            .iter()
            .map(|p| sessions.get_sender(p)?.local_packet_framing(local_lane))
            .collect()
    }
}
