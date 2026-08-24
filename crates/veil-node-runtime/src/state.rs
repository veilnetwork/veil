use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    time::Instant,
};

use crate::types::{
    ListenConfigEntry, ListenId, NodeId, NodeRole, NodeSummary, PeerConfigEntry, PeerId,
};

#[derive(Clone, Debug)]
pub struct NodeState {
    pub node_id: NodeId,
    pub role: NodeRole,
    pub config_path: PathBuf,
    pub foreground_mode: bool,
    pub started_at: Instant,
    pub metrics_active: bool,
    pub metrics_endpoint: Option<String>,
    pub peers: BTreeMap<PeerId, PeerConfigEntry>,
    pub listens: BTreeMap<ListenId, ListenConfigEntry>,
    /// Whether the ML-KEM key on disk is stored in the form the configuration
    /// asks for.
    ///
    /// Set at startup from the loader's outcome (see
    /// `identity_local::mlkem_dk::load_or_derive`), and NOT a constructor
    /// argument because a node that never loads a key file — a fresh install
    /// before identity resolution, or the bootstrap-join helper — is
    /// `AsConfigured` by definition: nothing is stored, so nothing is stored
    /// wrongly.
    ///
    /// It lives in node state rather than only in a log line because the thing
    /// it records is a lasting property of the node, not an event. An operator
    /// who missed one warning at startup would otherwise have no way to ask
    /// whether their key is actually encrypted at rest (audit report7 V-02).
    /// node_ids we have completed at least one OVL1 handshake with in this
    /// process (or restored from a snapshot that was written under the same
    /// rule).
    ///
    /// The discovered-peers snapshot exists to answer one question on a cold
    /// start: "who did we actually reach last time?" Peer-exchange used to
    /// write its gossip straight to that file the moment a peer was learned —
    /// before any dial, let alone a successful one — so a transport nobody
    /// here can ever reach was persisted and re-dialled on every subsequent
    /// start, forever. A production seed carried four such entries pointing at
    /// a different network's port; deleting them by hand brought them back
    /// within two hours.
    ///
    /// Membership here is the proof that the entry earned its place. Peers the
    /// operator configured are exempt: they are policy, not discovery, and
    /// `persist_discovered_peers` never wrote them anyway.
    pub handshaked: HashSet<[u8; 32]>,
    pub mlkem_key_at_rest: veil_e2e::MlKemKeyAtRest,
}

impl NodeState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: NodeId,
        role: NodeRole,
        config_path: PathBuf,
        foreground_mode: bool,
        started_at: Instant,
        metrics_active: bool,
        metrics_endpoint: Option<String>,
        peers: impl IntoIterator<Item = PeerConfigEntry>,
        listens: impl IntoIterator<Item = ListenConfigEntry>,
    ) -> Self {
        Self {
            node_id,
            role,
            config_path,
            foreground_mode,
            started_at,
            metrics_active,
            metrics_endpoint,
            peers: peers
                .into_iter()
                .map(|entry| (entry.peer_id, entry))
                .collect(),
            listens: listens
                .into_iter()
                .map(|entry| (entry.listen_id, entry))
                .collect(),
            mlkem_key_at_rest: veil_e2e::MlKemKeyAtRest::AsConfigured,
            handshaked: HashSet::new(),
        }
    }

    /// Build a summary snapshot. The live-sessions count lives on
    /// `NodeRuntime` (see `live_sessions` field) rather than here — pass
    /// it in so the snapshot reflects the runtime's session map, not a
    /// stale copy in state.
    pub fn summary(&self, sessions_active: usize) -> NodeSummary {
        NodeSummary {
            node_id: self.node_id,
            role: self.role,
            config_path: self.config_path.clone(),
            foreground_mode: self.foreground_mode,
            started_at: self.started_at,
            metrics_active: self.metrics_active,
            metrics_endpoint: self.metrics_endpoint.clone(),
            peers_configured: self.peers.len(),
            listens_configured: self.listens.len(),
            listens_active: self.listens.values().filter(|listen| listen.active).count(),
            sessions_active,
        }
    }
}
