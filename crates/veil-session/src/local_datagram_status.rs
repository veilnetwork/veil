//! Endpoint-local readiness. Nothing here is encoded on the wire or requested
//! from a relay. A lease belongs to one canonical runner credential generation.
use std::sync::{Arc, Mutex, Weak};
use veil_util::lock;

pub(crate) const LOCAL_DATAGRAM_PRIORITIES: [u8; 3] = [
    veil_proto::priority::REALTIME,
    veil_proto::priority::BULK,
    veil_proto::priority::BACKGROUND,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalDatagramChannelState {
    Unsupported,
    Warming,
    Ready,
}

#[derive(Debug, Default)]
pub(crate) struct LocalDatagramStatus {
    state: Mutex<State>,
    notify: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct State {
    owner: Weak<()>,
    transport_owner: Weak<()>,
    neutral_forwards: bool,
    ready: u8,
    requested: u8,
}

fn bit(local_lane: u8) -> Option<u8> {
    LOCAL_DATAGRAM_PRIORITIES
        .iter()
        .position(|&lane| lane == local_lane)
        .map(|index| 1 << index)
}

impl LocalDatagramStatus {
    pub(crate) fn has_datagram_transport(&self) -> bool {
        lock!(self.state).transport_owner.strong_count() != 0
    }

    pub(crate) fn has_neutral_forward_datagram_transport(&self) -> bool {
        let state = lock!(self.state);
        state.transport_owner.strong_count() != 0 && state.neutral_forwards
    }

    pub(crate) fn activate_transport(
        self: &Arc<Self>,
        neutral_forwards: bool,
    ) -> DatagramTransportLease {
        let owner = Arc::new(());
        let mut state = lock!(self.state);
        state.transport_owner = Arc::downgrade(&owner);
        state.neutral_forwards = neutral_forwards;
        DatagramTransportLease { _owner: owner }
    }

    pub(crate) fn state(&self, local_lane: u8) -> LocalDatagramChannelState {
        let Some(bit) = bit(local_lane) else {
            return LocalDatagramChannelState::Unsupported;
        };
        let state = lock!(self.state);
        if state.owner.strong_count() == 0 {
            LocalDatagramChannelState::Unsupported
        } else if state.ready & bit != 0 {
            LocalDatagramChannelState::Ready
        } else {
            LocalDatagramChannelState::Warming
        }
    }

    pub(crate) fn request(&self, local_lane: u8) -> LocalDatagramChannelState {
        let current = self.state(local_lane);
        if current == LocalDatagramChannelState::Warming {
            if let Some(bit) = bit(local_lane) {
                lock!(self.state).requested |= bit;
            }
            self.notify.notify_one();
        }
        current
    }

    pub(crate) fn pending(&self) -> u8 {
        lock!(self.state).requested
    }
    pub(crate) async fn notified(&self) {
        self.notify.notified().await;
    }
    pub(crate) fn wake(&self) {
        self.notify.notify_one();
    }

    pub(crate) fn activate(self: &Arc<Self>) -> LocalDatagramLease {
        let owner = Arc::new(());
        let mut state = lock!(self.state);
        state.owner = Arc::downgrade(&owner);
        state.ready = 0;
        state.requested = 0;
        LocalDatagramLease {
            status: Arc::clone(self),
            owner,
        }
    }
}

/// Readiness of the existing generic QUIC transport, not of an independent
/// child connection. A retired runner cannot clear its replacement's lease.
pub struct DatagramTransportLease {
    _owner: Arc<()>,
}

pub(crate) struct LocalDatagramLease {
    status: Arc<LocalDatagramStatus>,
    owner: Arc<()>,
}

impl LocalDatagramLease {
    pub(crate) fn mark(&self, local_lane: u8, ready: bool) {
        let Some(bit) = bit(local_lane) else {
            return;
        };
        let mut state = lock!(self.status.state);
        if Weak::ptr_eq(&state.owner, &Arc::downgrade(&self.owner)) {
            if ready {
                state.ready |= bit;
                state.requested &= !bit;
            } else {
                state.ready &= !bit;
            }
        }
    }
    pub(crate) fn status(&self) -> Arc<LocalDatagramStatus> {
        Arc::clone(&self.status)
    }
}

impl Drop for LocalDatagramLease {
    fn drop(&mut self) {
        let mut state = lock!(self.status.state);
        if Weak::ptr_eq(&state.owner, &Arc::downgrade(&self.owner)) {
            state.owner = Weak::new();
            state.ready = 0;
            state.requested = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use LocalDatagramChannelState::*;

    #[test]
    fn generic_transport_readiness_expires_and_does_not_claim_independent_support() {
        let status = Arc::new(LocalDatagramStatus::default());
        assert!(!status.has_datagram_transport());
        let old = status.activate_transport(false);
        assert!(status.has_datagram_transport());
        assert_eq!(status.state(0), Unsupported);
        let replacement = status.activate_transport(false);
        drop(old);
        assert!(status.has_datagram_transport());
        let independent = status.activate();
        independent.mark(0, true);
        drop(independent);
        assert!(status.has_datagram_transport());
        drop(replacement);
        assert!(!status.has_datagram_transport());
    }

    #[test]
    fn neutral_forward_readiness_requires_current_negotiation_and_live_transport() {
        let status = Arc::new(LocalDatagramStatus::default());
        assert!(!status.has_neutral_forward_datagram_transport());
        let legacy = status.activate_transport(false);
        assert!(status.has_datagram_transport());
        assert!(!status.has_neutral_forward_datagram_transport());
        let negotiated = status.activate_transport(true);
        drop(legacy);
        assert!(status.has_neutral_forward_datagram_transport());
        let replacement = status.activate_transport(false);
        drop(negotiated);
        assert!(status.has_datagram_transport());
        assert!(!status.has_neutral_forward_datagram_transport());
        drop(replacement);
        let negotiated = status.activate_transport(true);
        assert!(status.has_neutral_forward_datagram_transport());
        drop(negotiated);
        assert!(!status.has_datagram_transport());
        assert!(!status.has_neutral_forward_datagram_transport());
    }

    #[test]
    fn source_readiness_is_independent_and_never_applies_to_transit() {
        let status = Arc::new(LocalDatagramStatus::default());
        assert_eq!(status.state(0), Unsupported);
        let lease = status.activate();
        assert_eq!(status.state(0), Warming);
        assert_eq!(status.state(2), Warming);
        assert_eq!(status.request(3), Warming);
        assert_eq!(status.pending(), 4);
        lease.mark(3, true);
        assert_eq!(status.state(3), Ready);
        assert_eq!(status.request(1), Unsupported);
        assert_eq!(status.pending(), 0);
        assert_eq!(status.request(0), Warming);
        assert_eq!(status.pending(), 1);
        lease.mark(0, true);
        assert_eq!(status.pending(), 0);
        assert_eq!(status.state(0), Ready);
        assert_eq!(status.state(2), Warming);
        lease.mark(1, true);
        assert_eq!(status.state(1), Unsupported);
        lease.mark(0, false);
        assert_eq!(status.state(0), Warming);
        drop(lease);
        assert_eq!(status.state(0), Unsupported);
    }

    #[test]
    fn retired_lease_cannot_publish_or_clear_a_replacement() {
        let status = Arc::new(LocalDatagramStatus::default());
        let old = status.activate();
        old.mark(0, true);
        let new = status.activate();
        assert_eq!(status.state(0), Warming);
        old.mark(0, true);
        assert_eq!(status.state(0), Warming);
        new.mark(2, true);
        drop(old);
        assert_eq!(status.state(2), Ready);
        drop(new);
        assert_eq!(status.state(2), Unsupported);
    }
}
