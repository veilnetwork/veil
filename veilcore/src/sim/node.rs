//! A single simulated veil node.
//!
//! `SimNode` wraps a `NodeRuntime` together with the metadata needed to
//! describe it as a peer to other nodes (listen address, public key, nonce).

use std::{path::PathBuf, time::Duration};

use crate::{
    cfg::{Config, NodeRole, PeerConfig},
    node::NodeRuntime,
};
use veil_cfg::PeerId;

// ── SimNodeId ─────────────────────────────────────────────────────────────────

/// Index of a simulated node within a `SimNetwork`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SimNodeId(pub usize);

impl std::fmt::Display for SimNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node{}", self.0)
    }
}

// ── SimNode ───────────────────────────────────────────────────────────────────

/// A live simulated veil node.
pub struct SimNode {
    pub id: SimNodeId,
    pub runtime: NodeRuntime,
    pub config: Config,
    pub config_path: PathBuf,
    /// TCP listen address resolved after start (e.g. "127.0.0.1:54321").
    pub listen_addr: String,
    /// Node role.
    pub role: NodeRole,
}

impl SimNode {
    /// Start a new node with the given config.
    pub async fn start(
        id: SimNodeId,
        config: Config,
        config_path: PathBuf,
    ) -> crate::node::Result<Self> {
        let runtime = NodeRuntime::start(&config_path, true).await?;
        // Resolve the actual bound address (port 0 → OS-assigned port).
        let listen_addr = runtime
            .listens()
            .into_iter()
            .find_map(|l| l.local_addr)
            .unwrap_or_default();
        let role = config
            .identity
            .as_ref()
            .map(|i| i.role)
            .unwrap_or(NodeRole::Core);
        Ok(Self {
            id,
            runtime,
            config,
            config_path,
            listen_addr,
            role,
        })
    }

    /// Reload the node with an updated config (topology change).
    ///
    /// Fixes the listen transport to use the current bound port so that
    /// rebind after reload uses the same address instead of a new ephemeral port.
    pub async fn reload_with(&mut self, config: Config) -> crate::node::Result<()> {
        let mut config = config;
        // Pin the listen transport to the already-known port so peer configs remain valid.
        let fixed_addr = format!("tcp://{}", self.listen_addr);
        for listen in &mut config.listen {
            if listen.transport.ends_with(":0") {
                listen.transport = fixed_addr.clone();
            }
        }
        self.config = config;
        crate::cfg::save_config(&self.config_path, &self.config)?;
        self.runtime.reload().await
    }

    /// Block until this node has `expected_sessions` sessions, up to `timeout`.
    pub async fn wait_sessions(&self, expected: usize, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.runtime.sessions().len() >= expected {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// block until this node has **at most** `max` sessions, up
    /// to `timeout`. Use after `disconnect`/`partition` to wait for the
    /// async cleanup to actually take effect — replaces over-provisioned
    /// `tokio::time::sleep(2s)` patterns in scenario tests with positive
    /// edge-triggered polling. Returns `true` if the bound was reached
    /// before the timeout.
    pub async fn wait_sessions_at_most(&self, max: usize, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.runtime.sessions().len() <= max {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// block until this node has **no** session to `peer_node_id`
    /// up to `timeout`. Mirror of `wait_session_to` for the disconnect side.
    pub async fn wait_no_session_to(&self, peer_node_id: [u8; 32], timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let still_present = self
                .runtime
                .sessions()
                .iter()
                .any(|s| s.node_id.as_ref().map(|n| *n.as_bytes()) == Some(peer_node_id));
            if !still_present {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Block until this node has at least one session to `peer_node_id`.
    pub async fn wait_session_to(&self, peer_node_id: [u8; 32], timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let found = self
                .runtime
                .sessions()
                .iter()
                .any(|s| s.node_id.as_ref().map(|n| *n.as_bytes()) == Some(peer_node_id));
            if found {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The local node_id bytes.
    pub fn node_id(&self) -> [u8; 32] {
        *self.runtime.summary().node_id.as_bytes()
    }

    /// Return the public key and nonce for this node (for peer config of others).
    pub fn peer_identity(&self) -> Option<(String, String)> {
        self.config
            .identity
            .as_ref()
            .map(|id| (id.public_key.clone(), id.nonce.clone()))
    }

    /// Build a `PeerConfig` entry describing this node (to be added to another node's config).
    pub fn as_peer_config(&self, peer_id: PeerId) -> Option<PeerConfig> {
        let (pk, nonce) = self.peer_identity()?;
        Some(PeerConfig {
            peer_id,
            public_key: pk,
            nonce,
            transport: format!("tcp://{}", self.listen_addr),
            algo: Default::default(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            alt_uri: None,
        })
    }
}
