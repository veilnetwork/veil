use std::{collections::BTreeMap, path::PathBuf, time::Instant};

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
