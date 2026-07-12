//! Application addressing.
//!
//! ## `app_id` derivation (v1)
//!
//! ```text
//! app_id = BLAKE3-derive_key(
//! context = "veil.app_id.v1"
//! ikm = node_id || ns_len_be32 || namespace || name_len_be32 || name
//! //! ```
//!
//! The `node_id` binds the application to a specific node; `namespace` and
//! `name` allow one node to host multiple logically independent apps.
//!
//! **Length prefixes are mandatory.** Without them a naive concatenation of
//! `namespace` and `name` is ambiguous: e.g. `("foo", "bar")` and
//! `("fo", "obar")` would collide into the same digest. Each variable-length
//! field is therefore prefixed by its 4-byte big-endian length.
//!
//! The BLAKE3 `derive_key` mode adds a domain-separation context string so
//! that `app_id` outputs can't collide with any other BLAKE3-based hash in
//! the protocol.
//!
//! ## `AppAddress`
//!
//! An `AppAddress` fully identifies a single application endpoint:
//! ```text
//! AppAddress { node_id: [u8; 32], app_id: [u8; 32], endpoint_id: u32 }
//! ```

/// Domain-separation context [`app_id`] — BLAKE3 `derive_key` string.
const APP_ID_CONTEXT: &str = "veil.app_id.v1";

/// Domain-separation context [`ephemeral_app_id`].
const EPHEMERAL_APP_ID_CONTEXT: &str = "veil.ephemeral_app_id.v1";

/// per-field caps so a malicious
/// IPC client cannot trigger a multi-GiB allocation by passing a
/// `namespace` or `name` longer than memory. 256 bytes per field is
/// generous for any realistic identifier (well-known services use
/// reverse-DNS strings ≤ 64 chars; user apps are bounded by UI).
/// Inputs that exceed the cap are silently truncated to the cap —
/// derivation is deterministic for a given byte sequence, so two
/// callers passing identical bytes still produce the same `app_id`.
pub const MAX_NAMESPACE_LEN: usize = 256;
pub const MAX_NAME_LEN: usize = 256;

/// Build the length-prefixed IKM for an app_id derivation.
///
/// Layout: `node_id(32) || ns_len_be32 || namespace || name_len_be32 || name`.
/// For the ephemeral variant the 16-byte `client_token` is inserted between
/// `node_id` and the namespace-prefix block.
///
/// caller-supplied `namespace` / `name`
/// are truncated [`MAX_NAMESPACE_LEN`] / [`MAX_NAME_LEN`] before
/// extending the IKM, bounding the resulting Vec at
/// `32 + 16 + 4 + 256 + 4 + 256 = 568` bytes.
fn build_app_id_ikm(
    node_id: &[u8; 32],
    client_token: Option<&[u8; 16]>,
    namespace: &str,
    name: &str,
) -> Vec<u8> {
    let ns_bytes_full = namespace.as_bytes();
    let name_bytes_full = name.as_bytes();
    let ns_bytes = &ns_bytes_full[..ns_bytes_full.len().min(MAX_NAMESPACE_LEN)];
    let name_bytes = &name_bytes_full[..name_bytes_full.len().min(MAX_NAME_LEN)];
    let mut ikm = Vec::with_capacity(
        32 + client_token.map_or(0, |_| 16) + 4 + ns_bytes.len() + 4 + name_bytes.len(),
    );
    ikm.extend_from_slice(node_id);
    if let Some(tok) = client_token {
        ikm.extend_from_slice(tok);
    }
    ikm.extend_from_slice(&(ns_bytes.len() as u32).to_be_bytes());
    ikm.extend_from_slice(ns_bytes);
    ikm.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
    ikm.extend_from_slice(name_bytes);
    ikm
}

/// Derive a stable `app_id` from a node identity, application namespace, and name.
///
/// # Arguments
/// * `node_id` — 32-byte node identifier (`BLAKE3(public_key)`)
/// * `namespace` — logical namespace (e.g., `"veil.chat"`)
/// * `name` — application name within the namespace (e.g., `"main"`)
///
/// # Returns
/// 32-byte `app_id` — see module-level docs for the exact derivation.
pub fn app_id(node_id: &[u8; 32], namespace: &str, name: &str) -> [u8; 32] {
    let ikm = build_app_id_ikm(node_id, None, namespace, name);
    blake3::derive_key(APP_ID_CONTEXT, &ikm)
}

/// Derive an **ephemeral** `app_id` that is unique per IPC connection.
///
/// The `client_token` (16 random bytes issued in `APP_HELLO_OK`) is mixed into
/// the derivation so that two processes binding the same `(namespace, name)`
/// on the same node each obtain a distinct `app_id`.
///
/// Uses a separate domain-separation context (`"veil.ephemeral_app_id.v1"`)
/// so that ephemeral outputs can never collide with the stable [`app_id`]
/// output — even in the degenerate case `client_token == [0u8; 16]`.
///
/// # When to use
/// Use this for user-facing applications or any scenario where multiple instances
/// of the same app should coexist on one node. For well-known services that need
/// a stable, node-scoped address, use [`app_id`] instead.
pub fn ephemeral_app_id(
    node_id: &[u8; 32],
    client_token: &[u8; 16],
    namespace: &str,
    name: &str,
) -> [u8; 32] {
    let ikm = build_app_id_ikm(node_id, Some(client_token), namespace, name);
    blake3::derive_key(EPHEMERAL_APP_ID_CONTEXT, &ikm)
}

/// Derive a stable capability-scoped app id shared across sovereign nodes.
/// Callers must feed a high-entropy secret alias as [name]; the result is opaque
/// and deliberately contains no node identity input.
pub fn capability_app_id(namespace: &str, name: &str) -> [u8; 32] {
    let zero_node = [0u8; 32];
    let ikm = build_app_id_ikm(&zero_node, None, namespace, name);
    blake3::derive_key("veil.capability_app_id.v1", &ikm[32..])
}

// ── AppAddress ────────────────────────────────────────────────────────────────

/// A fully-qualified address for a single application endpoint on a node.
///
/// An endpoint is the leaf-level routing destination: one app can expose
/// multiple endpoints (e.g., different service ports within the same app).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AppAddress {
    /// Target node — 32-byte `BLAKE3(public_key)`.
    pub node_id: [u8; 32],
    /// Application identifier — 32-byte `BLAKE3(node_id || namespace || name)`.
    pub app_id: [u8; 32],
    /// Endpoint discriminator within the application.
    pub endpoint_id: u32,
}

impl AppAddress {
    pub fn new(node_id: [u8; 32], app_id: [u8; 32], endpoint_id: u32) -> Self {
        Self {
            node_id,
            app_id,
            endpoint_id,
        }
    }

    /// Convenience constructor that derives `app_id` inline.
    pub fn derive(node_id: [u8; 32], namespace: &str, name: &str, endpoint_id: u32) -> Self {
        Self {
            node_id,
            app_id: app_id(&node_id, namespace, name),
            endpoint_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> [u8; 32] {
        [0x01u8; 32]
    }

    #[test]
    fn app_id_matches_derive_key_formula() {
        let id = app_id(&node(), "veil.chat", "main");

        // Recompute manually: derive_key("veil.app_id.v1"
        // node_id ‖ ns_len(4 BE) ‖ ns ‖ name_len(4 BE) ‖ name)
        let ns = b"veil.chat";
        let name = b"main";
        let mut ikm = Vec::new();
        ikm.extend_from_slice(&node());
        ikm.extend_from_slice(&(ns.len() as u32).to_be_bytes());
        ikm.extend_from_slice(ns);
        ikm.extend_from_slice(&(name.len() as u32).to_be_bytes());
        ikm.extend_from_slice(name);
        let expected = blake3::derive_key("veil.app_id.v1", &ikm);

        assert_eq!(id, expected);
    }

    #[test]
    fn app_id_differs_for_different_namespace() {
        let id1 = app_id(&node(), "ns_a", "app");
        let id2 = app_id(&node(), "ns_b", "app");
        assert_ne!(id1, id2);
    }

    #[test]
    fn app_id_differs_for_different_name() {
        let id1 = app_id(&node(), "ns", "app_a");
        let id2 = app_id(&node(), "ns", "app_b");
        assert_ne!(id1, id2);
    }

    #[test]
    fn app_id_differs_for_different_node() {
        let id1 = app_id(&[0x01u8; 32], "ns", "app");
        let id2 = app_id(&[0x02u8; 32], "ns", "app");
        assert_ne!(id1, id2);
    }

    /// regression: concat-shift collision.
    ///
    /// Pre-fix formula `BLAKE3(node_id ‖ ns ‖ name)` had no separator, so
    /// `("foo","bar")`, `("fo","obar")`, `("","foobar")` etc. all produced
    /// the same digest. The length-prefixed derivation must prevent this.
    #[test]
    fn app_id_no_concat_shift_collision() {
        let n = node();
        let base = app_id(&n, "foo", "bar");
        let shift_1 = app_id(&n, "fo", "obar");
        let shift_2 = app_id(&n, "f", "oobar");
        let shift_0 = app_id(&n, "", "foobar");
        let shift_3 = app_id(&n, "foob", "ar");

        assert_ne!(base, shift_1);
        assert_ne!(base, shift_2);
        assert_ne!(base, shift_0);
        assert_ne!(base, shift_3);
        // and distinct among themselves too
        assert_ne!(shift_1, shift_2);
        assert_ne!(shift_2, shift_0);
    }

    /// same regression for the ephemeral variant.
    #[test]
    fn ephemeral_app_id_no_concat_shift_collision() {
        let n = node();
        let tok = [0xABu8; 16];
        let base = ephemeral_app_id(&n, &tok, "foo", "bar");
        let shift_1 = ephemeral_app_id(&n, &tok, "fo", "obar");
        let shift_0 = ephemeral_app_id(&n, &tok, "", "foobar");

        assert_ne!(base, shift_1);
        assert_ne!(base, shift_0);
        assert_ne!(shift_1, shift_0);
    }

    /// domain separation — stable and ephemeral outputs never
    /// collide, even if the ephemeral client_token is all-zero (which is the
    /// only IKM difference otherwise).
    #[test]
    fn app_id_and_ephemeral_app_id_have_different_domains() {
        let n = node();
        let zero_tok = [0u8; 16];
        let stable = app_id(&n, "ns", "app");
        let ephemeral = ephemeral_app_id(&n, &zero_tok, "ns", "app");
        assert_ne!(stable, ephemeral);
    }

    #[test]
    fn ephemeral_app_id_differs_per_token() {
        let n = node();
        let t1 = [0x11u8; 16];
        let t2 = [0x22u8; 16];
        assert_ne!(
            ephemeral_app_id(&n, &t1, "ns", "app"),
            ephemeral_app_id(&n, &t2, "ns", "app"),
        );
    }

    #[test]
    fn capability_app_id_is_node_independent_and_domain_separated() {
        let capability = capability_app_id("xveil.cloud", "secret-alias");
        assert_eq!(
            capability,
            capability_app_id("xveil.cloud", "secret-alias")
        );
        assert_ne!(capability, capability_app_id("xveil.cloud", "other"));
        assert_ne!(capability, app_id(&[0u8; 32], "xveil.cloud", "secret-alias"));
        assert_ne!(capability, app_id(&[9u8; 32], "xveil.cloud", "secret-alias"));
    }

    #[test]
    fn app_address_derive_matches_manual() {
        let node_id = node();
        let addr = AppAddress::derive(node_id, "my.service", "rpc", 5);
        let expected_app = app_id(&node_id, "my.service", "rpc");
        assert_eq!(addr.app_id, expected_app);
        assert_eq!(addr.endpoint_id, 5);
    }

    #[test]
    fn app_address_equality() {
        let addr1 = AppAddress::derive([0u8; 32], "ns", "app", 1);
        let addr2 = AppAddress::derive([0u8; 32], "ns", "app", 1);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn app_address_inequality_on_endpoint() {
        let addr1 = AppAddress::derive([0u8; 32], "ns", "app", 1);
        let addr2 = AppAddress::derive([0u8; 32], "ns", "app", 2);
        assert_ne!(addr1, addr2);
    }

    /// namespace/name fields are
    /// truncated to per-field caps so a malicious IPC client cannot
    /// trigger a multi-GiB allocation by passing huge strings.
    /// Derivation is deterministic for a given byte sequence; two
    /// callers passing identical (truncated) bytes produce the same
    /// app_id.
    #[test]
    fn phase647_routing_med1_oversized_namespace_truncated() {
        let node_id = node();
        // ~10 MiB string. Without the cap this would allocate at
        // least 10 MiB into the IKM Vec; with the cap, ≤ 568 B total.
        let huge: String = "x".repeat(10 * 1024 * 1024);
        let truncated = "x".repeat(MAX_NAMESPACE_LEN);
        let id_huge = app_id(&node_id, &huge, "name");
        let id_trunc = app_id(&node_id, &truncated, "name");
        assert_eq!(
            id_huge, id_trunc,
            "huge namespace must derive the same app_id as the truncated one"
        );
    }

    #[test]
    fn phase647_routing_med1_oversized_name_truncated() {
        let node_id = node();
        let huge: String = "n".repeat(10 * 1024 * 1024);
        let truncated = "n".repeat(MAX_NAME_LEN);
        let id_huge = app_id(&node_id, "ns", &huge);
        let id_trunc = app_id(&node_id, "ns", &truncated);
        assert_eq!(id_huge, id_trunc);
    }
}
