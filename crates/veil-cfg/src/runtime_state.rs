//! Learned state the node writes about itself, kept OUT of the config file.
//!
//! ## Why this file exists
//!
//! Two things mutate at runtime and used to be written straight back into
//! `config.toml`: the identity PoW nonce the lazy miner upgrades, and the
//! per-peer nonce relearned when a peer re-mines its own. Both went through
//! `save_config`, which rewrites the file — and rewriting a SIGNED config
//! invalidates its signature. The node therefore bricked itself: it stripped
//! the signature header it could not reproduce, and the next boot under
//! `require_signed_config` refused to start. The daemon defeating its own
//! tamper protection on a timer is worse than not having it.
//!
//! Splitting by ownership fixes it at the root rather than papering over the
//! write:
//!
//!   * `config.toml` is **operator policy**. Signed offline, never touched by
//!     the running node, byte-stable for as long as the operator leaves it
//!     alone.
//!   * this sidecar is **learned state**. Written by the node, never signed,
//!     never authored by a human, and disposable — deleting it costs one PoW
//!     re-mine and one nonce-mismatch round per peer.
//!
//! It is the same shape `persist_discovered_peers` already uses for peers
//! learned off the wire; this extends it to the two fields that were still
//! going the wrong way.
//!
//! ## The overlay is not a second config
//!
//! [`apply`] can only write two fields, because those are the only two the
//! struct has. Someone who can rewrite this file gains nothing they could not
//! already do with write access to the directory it sits in: a bogus identity
//! nonce lowers only this node's own PoW score, and a bogus peer nonce is
//! rejected at the next handshake and relearned. It is deliberately NOT a
//! place to smuggle policy past the signature.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Config, Result};

/// Cap on remembered peer nonces.
///
/// The writer only ever records peers that are already in the config, so this
/// is not the bound that matters in practice — it is the bound that keeps a
/// bug (or a file someone else grew) from turning into unbounded parse work at
/// every boot.
pub const MAX_PEER_NONCES: usize = 1024;

/// Sidecar path for `config_path`: `…/config.toml` → `…/config.runtime-state.toml`.
pub fn runtime_state_path(config_path: &Path) -> PathBuf {
    let stem = config_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config".to_owned());
    config_path.with_file_name(format!("{stem}.runtime-state.toml"))
}

/// The two mutable values, and nothing else.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeState {
    /// PoW nonce for this node's own identity, as upgraded by the lazy miner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_nonce: Option<String>,
    /// The public key [`identity_nonce`] was mined FOR.
    ///
    /// A PoW nonce is only meaningful against one keypair — the score is over
    /// `(public_key, nonce)`. Without this, a config whose identity was
    /// replaced picked up the previous identity's nonce from the sidecar and
    /// failed validation with "must produce at least 16 leading zero bits",
    /// which reads as a corrupt config rather than as stale cache. Worse, it is
    /// the same shape as the bug the ML-KEM/X25519 work was about: key material
    /// derived for one identity surviving into another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_public_key: Option<String>,
    /// Peer public key (base64, exactly as it appears in `[[peers]]`) → the
    /// nonce last seen from that peer. Keyed by public key rather than
    /// `peer_id` so reordering the peer list in the config does not silently
    /// reassign learned nonces to the wrong peers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_nonces: BTreeMap<String, String>,
}

/// Read the sidecar. A missing, unreadable, or malformed file yields the empty
/// state — this is disposable cache, and failing a boot over it would hand
/// anyone with write access to the directory a denial of service.
pub fn load(config_path: &Path) -> RuntimeState {
    let path = runtime_state_path(config_path);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return RuntimeState::default();
    };
    match toml::from_str::<RuntimeState>(&raw) {
        Ok(mut state) => {
            if state.peer_nonces.len() > MAX_PEER_NONCES {
                log::warn!(
                    "veil_cfg.runtime_state_truncated \
                     '{}' holds {} peer nonces (cap {MAX_PEER_NONCES}); ignoring the file",
                    path.display(),
                    state.peer_nonces.len(),
                );
                state.peer_nonces.clear();
            }
            state
        }
        Err(e) => {
            log::warn!(
                "veil_cfg.runtime_state_unparsable \
                 '{}' could not be parsed ({e}); continuing with the values from the config",
                path.display(),
            );
            RuntimeState::default()
        }
    }
}

/// Overlay learned state onto a freshly-parsed config.
///
/// Runs AFTER signature verification, deliberately: the bytes that were signed
/// are the ones that got verified, and this is not part of them.
pub fn apply(config: &mut Config, state: &RuntimeState) {
    if let (Some(nonce), Some(identity)) = (state.identity_nonce.as_ref(), config.identity.as_mut())
        // Only for the key it was mined for. A nonce from a previous identity
        // is not merely useless against a new one — it FAILS the PoW floor and
        // takes the whole config down with it.
        && state.identity_public_key.as_deref() == Some(identity.public_key.as_str())
    {
        identity.nonce = nonce.clone();
    }
    if state.peer_nonces.is_empty() {
        return;
    }
    for peer in config.peers.iter_mut() {
        if let Some(nonce) = state.peer_nonces.get(&peer.public_key) {
            peer.nonce = nonce.clone();
        }
    }
}

/// Read-modify-write the sidecar under `f`.
///
/// Callers already hold [`crate::config_write_guard`] around their own
/// load-modify-save sequences; taking it here too keeps two writers of this
/// file from clobbering each other's field the way they used to clobber each
/// other's field in the config.
fn update(config_path: &Path, f: impl FnOnce(&mut RuntimeState)) -> Result<()> {
    let _guard = crate::config_write_guard();
    let mut state = load(config_path);
    f(&mut state);
    let rendered = toml::to_string_pretty(&state)
        .map_err(|e| crate::ConfigError::CommandFailed(format!("render runtime state: {e}")))?;
    let body = format!(
        "# Written by the veil node itself — learned state, NOT operator policy.\n\
         # Safe to delete: the identity nonce is re-mined and peer nonces are\n\
         # relearned at the next handshake. Never signed, never loaded as policy.\n\
         {rendered}"
    );
    veil_util::atomic_write(&runtime_state_path(config_path), body.as_bytes())?;
    Ok(())
}

/// Persist an upgraded identity PoW nonce, bound to the key it was mined for.
pub fn record_identity_nonce(
    config_path: &Path,
    identity_public_key: &str,
    nonce_b64: &str,
) -> Result<()> {
    update(config_path, |state| {
        state.identity_nonce = Some(nonce_b64.to_owned());
        state.identity_public_key = Some(identity_public_key.to_owned());
    })
}

/// Persist a peer's newly-observed PoW nonce.
///
/// Refuses to grow past [`MAX_PEER_NONCES`] rather than evicting: there is no
/// meaningful recency order in the file, and dropping the write costs one
/// re-learn while evicting the wrong entry costs the same thing plus a lie
/// about what is remembered.
pub fn record_peer_nonce(config_path: &Path, peer_public_key: &str, nonce_b64: &str) -> Result<()> {
    update(config_path, |state| {
        if !state.peer_nonces.contains_key(peer_public_key)
            && state.peer_nonces.len() >= MAX_PEER_NONCES
        {
            log::warn!(
                "veil_cfg.runtime_state_full \
                 refusing to remember another peer nonce (cap {MAX_PEER_NONCES} reached)"
            );
            return;
        }
        state
            .peer_nonces
            .insert(peer_public_key.to_owned(), nonce_b64.to_owned());
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PeerConfig, PeerId};

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("veil-runtime-state-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.join("config.toml")
    }

    #[test]
    fn the_sidecar_sits_beside_the_config_not_inside_it() {
        let p = runtime_state_path(Path::new("/etc/veil/config.toml"));
        assert_eq!(p, PathBuf::from("/etc/veil/config.runtime-state.toml"));
    }

    #[test]
    fn a_recorded_identity_nonce_survives_a_reload() {
        let cfg = scratch("identity");
        record_identity_nonce(&cfg, "PK", "bm9uY2U=").expect("record");
        let state = load(&cfg);
        assert_eq!(state.identity_nonce.as_deref(), Some("bm9uY2U="));
        assert_eq!(state.identity_public_key.as_deref(), Some("PK"));
    }

    /// A PoW nonce is only valid against the key it was mined for. Carried onto
    /// a different identity it does not merely fail to help — it fails the
    /// difficulty floor, and the config then refuses to load with
    /// "identity.nonce: must produce at least 16 leading zero bits", which
    /// reads as a corrupt config rather than as stale cache.
    ///
    /// This is not hypothetical: the first version of this module had no
    /// binding, and `pex_survives_reload_m2` — whose config path is stable
    /// across runs, so the sidecar outlived the identity beside it — went red
    /// on exactly that message.
    #[test]
    fn a_nonce_mined_for_another_identity_is_not_applied() {
        let cfg = scratch("rebound");
        record_identity_nonce(&cfg, "OLD-PK", "bm9uY2U=").expect("record");
        let state = load(&cfg);

        let mut config = Config {
            identity: Some(crate::IdentityConfig {
                public_key: "NEW-PK".to_owned(),
                nonce: "fresh".to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        };
        apply(&mut config, &state);
        assert_eq!(
            config.identity.as_ref().expect("identity").nonce,
            "fresh",
            "a nonce from a different identity must be ignored, not applied"
        );

        // And it IS applied when the key matches — the binding must not turn
        // the whole sidecar into a no-op.
        config.identity.as_mut().expect("identity").public_key = "OLD-PK".to_owned();
        apply(&mut config, &state);
        assert_eq!(config.identity.expect("identity").nonce, "bm9uY2U=");
    }

    #[test]
    fn peer_nonces_are_keyed_by_public_key_not_position() {
        // The whole point of keying by public key: an operator who reorders
        // `[[peers]]` must not have the learned nonces follow the OLD slots.
        let cfg = scratch("peers");
        record_peer_nonce(&cfg, "PK-A", "a").expect("record a");
        record_peer_nonce(&cfg, "PK-B", "b").expect("record b");

        let mut config = Config {
            peers: vec![
                PeerConfig {
                    peer_id: PeerId::default(),
                    public_key: "PK-B".to_owned(),
                    nonce: "stale".to_owned(),
                    ..Default::default()
                },
                PeerConfig {
                    peer_id: PeerId::default(),
                    public_key: "PK-A".to_owned(),
                    nonce: "stale".to_owned(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        apply(&mut config, &load(&cfg));
        assert_eq!(config.peers[0].nonce, "b");
        assert_eq!(config.peers[1].nonce, "a");
    }

    #[test]
    fn an_unparsable_sidecar_leaves_the_config_alone() {
        // Disposable cache: a corrupt file must cost a re-mine, not a boot.
        let cfg = scratch("corrupt");
        std::fs::write(runtime_state_path(&cfg), "this is not toml {{{").expect("write junk");
        let state = load(&cfg);
        assert_eq!(state, RuntimeState::default());

        let mut config = Config::default();
        let before = config.peers.clone();
        apply(&mut config, &state);
        assert_eq!(config.peers, before);
    }

    #[test]
    fn the_overlay_touches_nothing_but_the_two_nonces() {
        // If this file ever grew a way to set policy, it would be a hole
        // straight through the config signature.
        let mut config = Config::default();
        config.global.require_signed_config = true;
        let baseline = config.clone();

        let state = RuntimeState {
            identity_nonce: Some("x".to_owned()),
            identity_public_key: Some("PK".to_owned()),
            peer_nonces: BTreeMap::from([("PK".to_owned(), "y".to_owned())]),
        };
        apply(&mut config, &state);

        assert_eq!(
            config.global, baseline.global,
            "the sidecar must not be able to move policy"
        );
        assert_eq!(config.listen, baseline.listen);
    }

    #[test]
    fn the_peer_nonce_table_refuses_to_grow_without_bound() {
        let cfg = scratch("cap");
        let mut state = RuntimeState::default();
        for i in 0..MAX_PEER_NONCES {
            state.peer_nonces.insert(format!("PK-{i}"), "n".to_owned());
        }
        std::fs::write(
            runtime_state_path(&cfg),
            toml::to_string_pretty(&state).expect("render"),
        )
        .expect("seed");

        record_peer_nonce(&cfg, "PK-overflow", "n").expect("record");
        let after = load(&cfg);
        assert_eq!(after.peer_nonces.len(), MAX_PEER_NONCES);
        assert!(!after.peer_nonces.contains_key("PK-overflow"));

        // An UPDATE to a peer already known still lands — the cap is on new
        // entries, not on keeping the existing ones current.
        record_peer_nonce(&cfg, "PK-0", "fresh").expect("update");
        assert_eq!(load(&cfg).peer_nonces.get("PK-0").map(String::as_str), Some("fresh"));
    }
}
