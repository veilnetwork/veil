//! Disk persistence для runtime state — discovered peers и manual bans.
//!
//! Both stores live alongside `config.toml` (one file per category) и use
//! atomic-write semantics so а crash mid-write leaves the previous
//! snapshot intact.  Loaders silently no-op when the file is missing
//! (fresh install) или when JSON deserialization fails (operator edited
//! и broke it — better к drop the stale snapshot than refuse к start).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use veil_util::lock;

use super::uri_helpers::is_wildcard_transport;
use super::{NodeServices, NodeState, lock_state};
use crate::types::{PeerConfigEntry, PeerSource};
use veil_abuse::BanList;
use veil_cfg;

// ── Discovered peers ────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
pub struct DiscoveredPeerSnapshot {
    node_id: String,
    public_key: String,
    nonce: String,
    transport: String,
    source: PeerSource,
}

/// Path для the discovered-peers file, derived от config path.
pub fn discovered_peers_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("peers_discovered.json")
}

/// Persist all non-configured peers from `state.peers` к disk.
///
/// Wildcard transports (`tcp://0.0.0.0:5555`, `[::]:...`) are stripped at
/// persist time so а stale snapshot from before the wildcard filters
/// landed can't poison the next startup [`load_discovered_peers`].
pub fn persist_discovered_peers(state: &Arc<Mutex<NodeState>>, config_path: &Path) {
    let entries: Vec<DiscoveredPeerSnapshot> = {
        let st = lock_state(state);
        st.peers
            .values()
            .filter(|e| !matches!(e.source, PeerSource::Configured))
            .filter(|e| !e.bootstrap_only)
            .filter(|e| !is_wildcard_transport(&e.transport))
            .map(|e| DiscoveredPeerSnapshot {
                node_id: e.node_id.to_string(),
                public_key: e.public_key.clone(),
                nonce: e.nonce.clone(),
                transport: e.transport.clone(),
                source: e.source,
            })
            .collect()
    };
    let path = discovered_peers_path(config_path);
    let json = match serde_json::to_string_pretty(&entries) {
        Ok(j) => j,
        Err(_) => return,
    };
    let _ = veil_util::atomic_write(&path, json.as_bytes());
}

/// Load previously-discovered peers from disk и spawn outbound connections.
pub fn load_discovered_peers(
    config_path: &Path,
    state: &Arc<Mutex<NodeState>>,
    access: &NodeServices,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) {
    let path = discovered_peers_path(config_path);
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return,
    };
    let snapshots: Vec<DiscoveredPeerSnapshot> = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut peer_id_counter: u32 = 0xE000_0000;
    let active = {
        let reg = access
            .session_tx_registry
            .write()
            .unwrap_or_else(|p| p.into_inner());
        reg.active_node_ids()
    };
    for snap in snapshots {
        let Ok(node_id) = snap.node_id.parse::<veil_cfg::NodeId>() else {
            continue;
        };
        if active.contains(node_id.as_bytes()) {
            continue;
        }
        // Drop stale wildcard snapshots — same defence as the PEX-receive
        // и PEX-persist filters.  Без этого а snapshot saved before those
        // filters landed would seed every restart с unreachable
        // 0.0.0.0:5555 dial targets that self-connect к our own listener.
        if is_wildcard_transport(&snap.transport) {
            continue;
        }
        let peer_id = veil_cfg::PeerId::new(peer_id_counter);
        peer_id_counter = peer_id_counter.wrapping_add(1);
        let entry = PeerConfigEntry {
            peer_id,
            node_id,
            public_key: snap.public_key,
            nonce: snap.nonce,
            transport: snap.transport,
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            bootstrap_only: false,
            source: snap.source,
        };
        lock_state(state).peers.insert(peer_id, entry.clone());
        let _ = crate::outbound_connector::spawn_outbound_peers(vec![entry], access, shutdown_tx);
    }
}

// ── Ban persistence ─────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BanSnapshot {
    node_id: String,
    reason: String,
}

pub fn bans_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("bans.json")
}

/// Persist manual bans к disk.
pub fn persist_bans(ban_list: &Arc<Mutex<BanList>>, config_path: &Path) {
    let entries: Vec<BanSnapshot> = {
        let bl = lock!(ban_list);
        bl.manual_bans()
            .into_iter()
            .map(|e| BanSnapshot {
                node_id: veil_util::hex_str(&e.peer_id),
                reason: e.reason.clone(),
            })
            .collect()
    };
    let path = bans_path(config_path);
    if let Ok(json) = serde_json::to_string_pretty(&entries) {
        let _ = veil_util::atomic_write(&path, json.as_bytes());
    }
}

/// Load manual bans from disk into the ban list.
pub fn load_bans(ban_list: &Arc<Mutex<BanList>>, config_path: &Path) {
    let path = bans_path(config_path);
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return,
    };
    let snaps: Vec<BanSnapshot> = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut bl = lock!(ban_list);
    for s in snaps {
        let Ok(node_id) = s.node_id.parse::<veil_cfg::NodeId>() else {
            continue;
        };
        let node_id = *node_id.as_bytes();
        bl.ban_manual(node_id, s.reason);
    }
}
