//! IPC `app_id` derivation for ogate endpoints.
//!
//! The veil IPC layer assigns each named binding a 32-byte `app_id`
//! computed as `BLAKE3(node_id || namespace || name)`. Two peers that
//! share the same `(namespace, name)` pair can pre-compute each other's
//! `app_id` locally — no harvest / peer-list-exchange step is required.
//!
//! ogate picks the IPC `(namespace, name)` pair deterministically from
//! the operator's `network` + `app` fields:
//!
//! * `namespace = "ogate." + network`
//! * `name      = app`              (default: `"ogate"`)

/// Build the IPC namespace string for the given network.
pub fn namespace_for(network: &str) -> String {
    format!("ogate.{network}")
}

/// Compute the named `app_id` for a peer, given their `node_id` and
/// the local `network` + `app` settings.
///
/// Mirrors `veil_app::address::app_id`. Pre-computing peers' app_ids
/// locally avoids the chat_node-style "harvest app_id from each peer
/// then distribute peer-list" dance.
pub fn derive_app_id(peer_node_id: &[u8; 32], network: &str, app: &str) -> [u8; 32] {
    let namespace = namespace_for(network);
    veil_app::address::app_id(peer_node_id, &namespace, app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_includes_network() {
        assert_eq!(namespace_for("homenet"), "ogate.homenet");
        assert_eq!(namespace_for("corp"), "ogate.corp");
    }

    #[test]
    fn same_inputs_same_app_id() {
        let nid = [0xaau8; 32];
        let a = derive_app_id(&nid, "homenet", "ogate");
        let b = derive_app_id(&nid, "homenet", "ogate");
        assert_eq!(a, b);
    }

    #[test]
    fn different_network_different_app_id() {
        let nid = [0xaau8; 32];
        let a = derive_app_id(&nid, "homenet", "ogate");
        let b = derive_app_id(&nid, "corp", "ogate");
        assert_ne!(a, b);
    }

    #[test]
    fn different_app_different_app_id() {
        let nid = [0xaau8; 32];
        let a = derive_app_id(&nid, "homenet", "ogate");
        let b = derive_app_id(&nid, "homenet", "voip");
        assert_ne!(a, b);
    }

    #[test]
    fn different_node_id_different_app_id() {
        let a = derive_app_id(&[0xaau8; 32], "homenet", "ogate");
        let b = derive_app_id(&[0xbbu8; 32], "homenet", "ogate");
        assert_ne!(a, b);
    }
}
