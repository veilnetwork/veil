//! Disk persistence for runtime state — discovered peers and manual bans.
//!
//! Both stores live alongside `config.toml` (one file per category) and use
//! atomic-write semantics so a crash mid-write leaves the previous
//! snapshot intact.
//!
//! # Outcomes are reported, never swallowed
//!
//! Every write here used to be `let _ = atomic_write(...)` and every load used
//! to `return` on any error, so a ban that could not be written looked
//! identical to one that was, and a `bans.json` an operator had hand-edited
//! into invalid JSON looked identical to a fresh install with no file at all.
//! The admin `ban` command could not have reported either, because it returned
//! nothing (audit report7 V-03).
//!
//! Two rules now:
//!
//! * writes return [`PersistOutcome`] and log the failure at the site that
//!   knows the path — the caller decides how loudly to surface it;
//! * "file is absent" stays silent (that IS a fresh install), but "file is
//!   present and unreadable" is logged. An operator who edits the file and
//!   breaks it must not lose the whole ban list without a word.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use veil_util::lock;

use super::uri_helpers::{is_undialable_from_here, is_wildcard_transport};
use super::{NodeServices, NodeState, lock_state};
use crate::types::{PeerConfigEntry, PeerSource};
use veil_abuse::BanList;
use veil_cfg;

/// What a persist attempt actually achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistOutcome {
    /// The snapshot is on disk (atomic write, fsynced). It will survive a
    /// restart.
    Durable,
    /// The snapshot could NOT be written. The in-memory change stands, and is
    /// all there is: a restart loses it.
    Volatile {
        /// Why the write failed, for the operator-facing answer.
        reason: String,
    },
}

impl PersistOutcome {
    /// Whether the change reached disk.
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::Durable)
    }

    /// The failure reason, if any.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Durable => None,
            Self::Volatile { reason } => Some(reason),
        }
    }
}

/// What a load attempt found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadOutcome {
    /// No file. A fresh install — expected, and deliberately not logged.
    Absent,
    /// `count` entries were restored.
    Loaded {
        /// Entries applied to the in-memory store.
        count: usize,
    },
    /// The file is THERE and could not be used: unreadable, or not the JSON
    /// this store writes. Distinct from [`Self::Absent`] on purpose — the two
    /// were indistinguishable, and the difference is the whole list.
    Unreadable {
        /// Why, for the log line.
        reason: String,
    },
}

// ── Discovered peers ────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
pub struct DiscoveredPeerSnapshot {
    node_id: String,
    public_key: String,
    nonce: String,
    transport: String,
    source: PeerSource,
}

/// The slot this node already occupies in `NodeState::peers`, if any.
///
/// The map is keyed by `PeerId` — a local slot number — so nothing about its
/// shape stops the same node_id appearing many times, and nothing did: a
/// production seed reached 919 entries for 21 distinct nodes because the
/// peer-exchange path minted a fresh slot on every gossip round. Both the
/// gossip path and the snapshot loader ask this first and write into the slot
/// they get back.
///
/// Linear in the map, which is the point: bounded by the number of DISTINCT
/// peers once callers use it, and called once per newly-learned peer rather
/// than per frame.
pub(crate) fn existing_slot_for(
    peers: &std::collections::BTreeMap<veil_cfg::PeerId, PeerConfigEntry>,
    node_id: &[u8; 32],
) -> Option<veil_cfg::PeerId> {
    peers
        .iter()
        .find(|(_, e)| e.node_id.as_bytes() == node_id)
        .map(|(id, _)| *id)
}

/// Path for the discovered-peers file, derived from config path.
pub fn discovered_peers_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("peers_discovered.json")
}

/// Does this node present a PRIVATE address to its peers?
///
/// Read from our own listeners, because that is what we tell the network we
/// are. A node advertising `192.168.1.5` lives on a LAN and a neighbour's
/// `192.168.1.7` is plausibly its to dial; a node advertising a public address
/// can never reach either. `advertise` wins over `transport` when set — it is
/// the address peers are actually given — and a wildcard bind says nothing
/// about where we are, so it does not count.
fn we_are_site_local(st: &NodeState) -> bool {
    st.listens.values().any(|l| {
        let uri = l.advertise.as_deref().unwrap_or(&l.transport);
        !is_wildcard_transport(uri)
            && matches!(
                super::uri_helpers::host_reach(uri),
                super::uri_helpers::HostReach::SiteLocal
            )
    })
}

/// Persist all non-configured peers from `state.peers` to disk.
///
/// Wildcard transports (`tcp://0.0.0.0:5555`, `[::]:...`) are stripped at
/// persist time so a stale snapshot from before the wildcard filters
/// landed can't poison the next startup [`load_discovered_peers`].
pub fn persist_discovered_peers(
    state: &Arc<Mutex<NodeState>>,
    config_path: &Path,
) -> PersistOutcome {
    let entries: Vec<DiscoveredPeerSnapshot> = {
        let st = lock_state(state);
        // Same gate as the wildcard filter beside it, and for the same reason
        // spelled out there: a snapshot must not seed the next startup with
        // dial targets nobody here can reach.
        let site_local = we_are_site_local(&st);
        st.peers
            .values()
            .filter(|e| !matches!(e.source, PeerSource::Configured))
            .filter(|e| !e.bootstrap_only)
            .filter(|e| !is_wildcard_transport(&e.transport))
            .filter(|e| !is_undialable_from_here(&e.transport, site_local))
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
    write_snapshot(&path, &entries, "discovered peers")
}

/// Load previously-discovered peers from disk and spawn outbound connections.
pub fn load_discovered_peers(
    config_path: &Path,
    state: &Arc<Mutex<NodeState>>,
    access: &NodeServices,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) -> LoadOutcome {
    let path = discovered_peers_path(config_path);
    let snapshots: Vec<DiscoveredPeerSnapshot> = match read_snapshot(&path, "discovered peers") {
        Ok(Some(v)) => v,
        Ok(None) => return LoadOutcome::Absent,
        Err(reason) => return LoadOutcome::Unreadable { reason },
    };
    let mut restored = 0usize;
    let mut peer_id_counter: u32 = crate::types::synthetic_peer_id::PERSISTENCE_BASE;
    // A snapshot written before the gossip path stopped minting a slot per
    // round holds the same node many times over — 919 entries for 21 nodes on
    // one production seed. Loading it verbatim would restore the bloat and dial
    // every copy, so an entry whose node is already placed is skipped. Asking
    // the live map rather than a private set also covers a node that arrived
    // some other way while the load was running.
    let active = {
        let reg = access
            .session_tx_registry
            .write()
            .unwrap_or_else(|p| p.into_inner());
        reg.active_node_ids()
    };
    // Our own posture, read once: the loop below asks it per snapshot.
    let site_local = we_are_site_local(&lock_state(state));
    for snap in snapshots {
        let Ok(node_id) = snap.node_id.parse::<veil_cfg::NodeId>() else {
            continue;
        };
        if active.contains(node_id.as_bytes()) {
            continue;
        }
        // Drop stale wildcard snapshots — same defence as the PEX-receive
        // and PEX-persist filters.  Without this a snapshot saved before those
        // filters landed would seed every restart with unreachable
        // 0.0.0.0:5555 dial targets that self-connect to our own listener.
        if is_wildcard_transport(&snap.transport) {
            continue;
        }
        // And the same for addresses that are real but not real HERE. Filtering
        // only on write would leave every snapshot taken before this landed
        // untouched: a production seed carried 573 loopback entries and 149 for
        // one stranger's LAN, and each is an outbound dial on startup.
        if is_undialable_from_here(&snap.transport, site_local) {
            continue;
        }
        if existing_slot_for(&lock_state(state).peers, node_id.as_bytes()).is_some() {
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
        restored += 1;
    }
    LoadOutcome::Loaded { count: restored }
}

// ── Snapshot I/O ────────────────────────────────────────────────────────────

/// Serialise and atomically write `entries`, logging (and reporting) any
/// failure. `what` names the store for the log line.
pub(crate) fn write_snapshot<T: serde::Serialize>(
    path: &Path,
    entries: &T,
    what: &str,
) -> PersistOutcome {
    let json = match serde_json::to_string_pretty(entries) {
        Ok(j) => j,
        Err(e) => {
            log::warn!(
                "veil-persistence: cannot serialise {what} for {}: {e}",
                path.display()
            );
            return PersistOutcome::Volatile {
                reason: format!("serialise failed: {e}"),
            };
        }
    };
    match veil_util::atomic_write(path, json.as_bytes()) {
        Ok(()) => PersistOutcome::Durable,
        Err(e) => {
            log::warn!(
                "veil-persistence: {what} could NOT be written to {} ({e}) — the \
                 change is in memory only and will not survive a restart",
                path.display(),
            );
            PersistOutcome::Volatile {
                reason: format!("write failed: {e}"),
            }
        }
    }
}

/// Read and parse a snapshot. `Ok(None)` means "no file" — a fresh install,
/// and the one case that stays silent. Anything else is reported: a file that
/// exists and cannot be parsed used to look exactly like no file at all, so an
/// operator who hand-edited it into invalid JSON lost the entire store without
/// a single line saying so.
pub(crate) fn read_snapshot<T: serde::de::DeserializeOwned>(
    path: &Path,
    what: &str,
) -> Result<Option<T>, String> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            log::warn!(
                "veil-persistence: {what} at {} exists but could not be read ({e}) — \
                 the stored entries are NOT in effect",
                path.display(),
            );
            return Err(format!("read failed: {e}"));
        }
    };
    match serde_json::from_str(&data) {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            log::warn!(
                "veil-persistence: {what} at {} is present but not valid JSON ({e}) — \
                 the stored entries are NOT in effect. Fix or delete the file.",
                path.display(),
            );
            Err(format!("parse failed: {e}"))
        }
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

/// Persist manual bans to disk.
///
/// A ban that only exists in memory is a ban the peer outlives by restarting
/// the daemon — so whether this reached disk is exactly what the operator who
/// issued it needs to be told. It used to be discarded (`let _ =`), and the
/// admin path that calls it had no return value to carry the answer anyway
/// (audit report7 V-03).
#[must_use = "a ban that was not written back is lost on the next restart"]
pub fn persist_bans(ban_list: &Arc<Mutex<BanList>>, config_path: &Path) -> PersistOutcome {
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
    write_snapshot(&bans_path(config_path), &entries, "ban list")
}

/// Load manual bans from disk into the ban list.
pub fn load_bans(ban_list: &Arc<Mutex<BanList>>, config_path: &Path) -> LoadOutcome {
    let path = bans_path(config_path);
    let snaps: Vec<BanSnapshot> = match read_snapshot(&path, "ban list") {
        Ok(Some(v)) => v,
        Ok(None) => return LoadOutcome::Absent,
        Err(reason) => return LoadOutcome::Unreadable { reason },
    };
    let mut restored = 0usize;
    let mut bl = lock!(ban_list);
    for s in snaps {
        let Ok(node_id) = s.node_id.parse::<veil_cfg::NodeId>() else {
            log::warn!(
                "veil-persistence: ban list at {} carries an unparseable node id \
                 ({}) — that entry is NOT in effect",
                path.display(),
                s.node_id,
            );
            continue;
        };
        let node_id = *node_id.as_bytes();
        bl.ban_manual(node_id, s.reason);
        restored += 1;
    }
    LoadOutcome::Loaded { count: restored }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_entry(slot: u32, node_id: [u8; 32], transport: &str) -> PeerConfigEntry {
        PeerConfigEntry {
            peer_id: veil_cfg::PeerId::new(slot),
            node_id: veil_cfg::NodeId::from(node_id),
            public_key: String::new(),
            nonce: String::new(),
            transport: transport.to_string(),
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            bootstrap_only: false,
            source: crate::types::PeerSource::Exchanged,
        }
    }

    fn listen_entry(transport: &str, advertise: Option<&str>) -> crate::types::ListenConfigEntry {
        crate::types::ListenConfigEntry {
            listen_id: crate::types::ListenId::new(1),
            listener_handle: None,
            transport: transport.to_owned(),
            advertise: advertise.map(str::to_owned),
            relay: None,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            psk_file: None,
            visibility: veil_cfg::Visibility::Public,
            allowlist_node_ids: vec![],
            group_label: None,
            ephemeral: None,
            on_demand: None,
            local_addr: None,
            active: false,
        }
    }

    fn state_with(
        listens: Vec<crate::types::ListenConfigEntry>,
        peers: Vec<PeerConfigEntry>,
        config_path: &Path,
    ) -> Arc<Mutex<NodeState>> {
        Arc::new(Mutex::new(NodeState::new(
            veil_cfg::NodeId::from([0xAAu8; 32]),
            crate::types::NodeRole::Core,
            config_path.to_path_buf(),
            true,
            std::time::Instant::now(),
            false,
            None,
            peers,
            listens,
        )))
    }

    /// Our posture comes from what we ADVERTISE, not from what we bind.
    #[test]
    fn a_wildcard_bind_does_not_make_us_a_lan_node() {
        let dir = std::env::temp_dir().join("veil-posture-test");
        let public = state_with(
            vec![listen_entry(
                "obfs4-tcp://0.0.0.0:5556",
                Some("tcp://198.51.100.11:5556"),
            )],
            vec![],
            &dir,
        );
        assert!(
            !we_are_site_local(&lock_state(&public)),
            "a seed advertising a public address is not on anybody's LAN"
        );

        let bind_only = state_with(vec![listen_entry("tcp://0.0.0.0:9000", None)], vec![], &dir);
        assert!(
            !we_are_site_local(&lock_state(&bind_only)),
            "a wildcard bind says nothing about where we are"
        );

        let lan = state_with(
            vec![listen_entry("tcp://192.168.1.5:9000", None)],
            vec![],
            &dir,
        );
        assert!(
            we_are_site_local(&lock_state(&lan)),
            "a node listening on a LAN address is a LAN node"
        );
    }

    /// The decision, not the predicate: an address nobody here can dial must
    /// not reach the file.
    ///
    /// A production seed's `peers_discovered.json` held 573 loopback entries
    /// and 149 for one stranger's home network, and every one of them becomes
    /// an outbound dial on the next start. Break-check: drop the
    /// `is_undialable_from_here` filter in `persist_discovered_peers` and the
    /// two junk entries come back.
    #[test]
    fn a_public_node_does_not_persist_what_it_could_never_dial() {
        let dir = std::env::temp_dir().join(format!("veil-persist-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let config_path = dir.join("node.toml");

        let state = state_with(
            vec![listen_entry(
                "obfs4-tcp://0.0.0.0:5556",
                Some("tcp://198.51.100.11:5556"),
            )],
            vec![
                peer_entry(1, [0x01u8; 32], "tcp://127.0.0.1:9000"),
                peer_entry(2, [0x02u8; 32], "obfs4-tcp://192.168.1.70:5599"),
                peer_entry(3, [0x03u8; 32], "obfs4-tcp://198.51.100.11:5556"),
            ],
            &config_path,
        );

        persist_discovered_peers(&state, &config_path);
        let written =
            std::fs::read_to_string(discovered_peers_path(&config_path)).expect("snapshot written");
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            written.contains("198.51.100.11"),
            "a reachable peer must survive: {written}"
        );
        assert!(
            !written.contains("127.0.0.1"),
            "loopback cannot name another node: {written}"
        );
        assert!(
            !written.contains("192.168.1.70"),
            "a public node can never reach somebody else's LAN: {written}"
        );
    }

    /// A node already in the map is found by node_id, whatever slot it sits in.
    ///
    /// The map is keyed by slot, so "is this peer known" cannot be answered by
    /// a key lookup and nothing was answering it another way: every gossip
    /// round minted a new slot for a peer already present, and one production
    /// seed reached 919 entries for 21 distinct nodes. Break-check: return
    /// `None` unconditionally and both callers mint again.
    #[test]
    fn a_peer_already_in_the_map_is_found_by_its_node_id() {
        let mut peers = std::collections::BTreeMap::new();
        let known = [0x11u8; 32];
        // Slots deliberately not starting at zero and not contiguous — the
        // answer must not depend on where the entry happens to sit.
        peers.insert(veil_cfg::PeerId::new(7), peer_entry(7, known, "tcp://a:1"));
        peers.insert(
            veil_cfg::PeerId::new(99),
            peer_entry(99, [0x22u8; 32], "tcp://b:2"),
        );

        assert_eq!(
            existing_slot_for(&peers, &known),
            Some(veil_cfg::PeerId::new(7)),
            "a known node must resolve to the slot it already occupies"
        );
        assert_eq!(
            existing_slot_for(&peers, &[0x33u8; 32]),
            None,
            "a node nobody has seen has no slot to reuse"
        );
    }

    /// The same node under a NEW transport reuses its slot rather than adding.
    ///
    /// A peer that changed address is still one peer; minting a second slot is
    /// how the store came to hold the same node under several addresses at
    /// once, dialling all of them forever.
    #[test]
    fn a_changed_address_does_not_earn_a_second_slot() {
        let mut peers = std::collections::BTreeMap::new();
        let node = [0x44u8; 32];
        peers.insert(veil_cfg::PeerId::new(3), peer_entry(3, node, "tcp://old:1"));

        let slot = existing_slot_for(&peers, &node).expect("known node");
        peers.insert(slot, peer_entry(slot.get(), node, "tcp://new:2"));

        assert_eq!(peers.len(), 1, "one node, one slot");
        assert_eq!(peers[&slot].transport, "tcp://new:2", "and the new address");
    }

    fn ban_list_with(ids: &[[u8; 32]]) -> Arc<Mutex<BanList>> {
        let bl = Arc::new(Mutex::new(BanList::default()));
        for id in ids {
            lock!(bl).ban_manual(*id, "test");
        }
        bl
    }

    /// A ban list that could not be written must SAY it could not be written.
    ///
    /// The write was `let _ = atomic_write(...)`, so an admin `ban` on a node
    /// whose config directory it cannot write reported success and lost the ban
    /// at the next restart — the peer simply reconnected (audit report7 V-03).
    #[cfg(unix)]
    #[test]
    fn v03_a_ban_that_cannot_be_written_is_reported_volatile() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let bans = ban_list_with(&[[0x42u8; 32]]);

        // Control first: with a writable directory it IS durable, so the
        // assertion below is about the failed write and not about every call.
        assert_eq!(persist_bans(&bans, &config_path), PersistOutcome::Durable);
        assert!(bans_path(&config_path).exists());

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        if std::fs::File::create(dir.path().join(".probe")).is_ok() {
            let _ = std::fs::remove_file(dir.path().join(".probe"));
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            eprintln!("SKIP: this user can write into a 0o500 directory (root?)");
            return;
        }

        let bans = ban_list_with(&[[0x42u8; 32], [0x43u8; 32]]);
        let outcome = persist_bans(&bans, &config_path);
        assert!(
            !outcome.is_durable(),
            "a write that could not happen must not report success"
        );
        assert!(
            outcome.reason().is_some_and(|r| !r.is_empty()),
            "the outcome must carry WHY, so the admin reply can say it"
        );

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// "No file" and "file I cannot parse" are different answers.
    ///
    /// Both used to `return` silently, so an operator who hand-edited
    /// `bans.json` and broke the JSON lost every ban with nothing logged and
    /// nothing to distinguish it from a fresh install.
    #[test]
    fn v03_a_corrupt_ban_file_is_not_mistaken_for_a_fresh_install() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        // Fresh install: silent, and explicitly Absent.
        let bans = Arc::new(Mutex::new(BanList::default()));
        assert_eq!(load_bans(&bans, &config_path), LoadOutcome::Absent);

        // A real snapshot round-trips with a count.
        let victim = [0x42u8; 32];
        let saved = ban_list_with(&[victim]);
        assert!(persist_bans(&saved, &config_path).is_durable());
        let restored = Arc::new(Mutex::new(BanList::default()));
        assert_eq!(
            load_bans(&restored, &config_path),
            LoadOutcome::Loaded { count: 1 }
        );
        assert!(lock!(restored).is_banned(&victim));

        // Now the operator edits it and breaks it.
        std::fs::write(bans_path(&config_path), "{ not json at all").unwrap();
        let after = Arc::new(Mutex::new(BanList::default()));
        match load_bans(&after, &config_path) {
            LoadOutcome::Unreadable { reason } => {
                assert!(!reason.is_empty(), "the reason must name the parse failure");
            }
            other => panic!(
                "a present-but-unparseable ban list must be distinguishable from \
                 no ban list at all, got {other:?}"
            ),
        }
        assert!(
            !lock!(after).is_banned(&victim),
            "precondition: nothing was restored — which is exactly why it has \
             to be reported"
        );
    }

    /// The same two answers for the discovered-peer store, whose writes were
    /// discarded identically.
    #[test]
    fn v03_discovered_peer_snapshot_reports_its_outcomes() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        // Empty is still a snapshot — an empty file is how a drained store is
        // recorded, and it must be durable rather than skipped.
        let entries: Vec<DiscoveredPeerSnapshot> = Vec::new();
        assert_eq!(
            write_snapshot(&discovered_peers_path(&config_path), &entries, "test"),
            PersistOutcome::Durable
        );
        std::fs::write(discovered_peers_path(&config_path), "]]not json[[").unwrap();
        assert!(
            read_snapshot::<Vec<DiscoveredPeerSnapshot>>(
                &discovered_peers_path(&config_path),
                "test"
            )
            .is_err(),
            "a corrupt peer snapshot must report, not vanish"
        );
    }
}
