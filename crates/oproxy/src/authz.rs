//! Node-id allowlist для the server-side acceptor.
//!
//! Empty list = **allow all** when paired с explicit `allow_all = true`
//! (см. ServerConfig docs).  Otherwise оператор should populate the list
//! к gate callers.  Non-empty list = **strict allowlist** — only matching
//! node_ids may use this server.
//!
//! # Note on `[0u8; 32]` (audit batch 2026-05-24, L5)
//!
//! The all-zeros node_id is treated as а **literal entry** — добавляя
//! `"0000...0000"` к `allowed_node_ids` does NOT mean "wildcard"; it
//! permits only а peer whose actual `node_id` is zero.  Such а peer is
//! cryptographically infeasible (BLAKE3 collision к 32 zero bytes ≈
//! 2^256 expected tries), но the schema doesn't special-case the value.
//! For "allow any peer" use `allow_all = true` instead.

use std::collections::HashSet;

/// Allowlist guard.  Constructed once at startup от config; cheap O(1)
/// lookups thereafter.
#[derive(Debug, Clone)]
pub struct NodeAllowlist {
    /// `None` ⇒ allow all callers (no restriction).  `Some(set)` ⇒
    /// only node_ids в the set ара permitted.
    set: Option<HashSet<[u8; 32]>>,
}

impl NodeAllowlist {
    /// Build от raw hex strings (64 chars each, ignoring case + `0x`
    /// prefix).  Empty vec ⇒ allow-all.
    pub fn from_hex_list(hex_ids: &[String]) -> Result<Self, String> {
        if hex_ids.is_empty() {
            return Ok(Self { set: None });
        }
        let mut set = HashSet::with_capacity(hex_ids.len());
        for raw in hex_ids {
            let trimmed = raw.trim().trim_start_matches("0x");
            if trimmed.len() != 64 {
                return Err(format!(
                    "node_id `{raw}` must be exactly 64 hex chars (got {})",
                    trimmed.len()
                ));
            }
            let mut id = [0u8; 32];
            for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
                let s = std::str::from_utf8(chunk).map_err(|e| format!("hex utf8 `{raw}`: {e}"))?;
                id[i] = u8::from_str_radix(s, 16).map_err(|e| format!("hex parse `{raw}`: {e}"))?;
            }
            set.insert(id);
        }
        Ok(Self { set: Some(set) })
    }

    /// Check whether `node_id` is permitted.
    pub fn permits(&self, node_id: &[u8; 32]) -> bool {
        match &self.set {
            None => true, // allow-all
            Some(s) => s.contains(node_id),
        }
    }

    /// Whether the allowlist is in restrictive mode (some IDs only)
    /// vs allow-all.  Surfaced для startup logging.
    pub fn is_restrictive(&self) -> bool {
        self.set.is_some()
    }

    /// Number of permitted node_ids.  `0` indicates allow-all.
    pub fn size(&self) -> usize {
        self.set.as_ref().map(|s| s.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_allows_all() {
        let a = NodeAllowlist::from_hex_list(&[]).unwrap();
        assert!(!a.is_restrictive());
        assert!(a.permits(&[0u8; 32]));
        assert!(a.permits(&[0xFFu8; 32]));
    }

    #[test]
    fn restrictive_list_permits_only_matches() {
        let hex = "0".repeat(63) + "1"; // 0x00..01
        let a = NodeAllowlist::from_hex_list(&[hex]).unwrap();
        assert!(a.is_restrictive());
        assert_eq!(a.size(), 1);

        let mut allowed = [0u8; 32];
        allowed[31] = 0x01;
        assert!(a.permits(&allowed));
        assert!(!a.permits(&[0u8; 32]));
        assert!(!a.permits(&[0xFFu8; 32]));
    }

    #[test]
    fn hex_parse_rejects_wrong_length() {
        let err = NodeAllowlist::from_hex_list(&["abcd".to_string()]).unwrap_err();
        assert!(err.contains("64 hex chars"));
    }

    #[test]
    fn hex_parse_accepts_0x_prefix() {
        let hex = "0x".to_string() + &"a".repeat(64);
        let a = NodeAllowlist::from_hex_list(&[hex]).unwrap();
        assert_eq!(a.size(), 1);
        assert!(a.permits(&[0xaa; 32]));
    }

    #[test]
    fn hex_parse_rejects_invalid_chars() {
        let bad = "z".repeat(64);
        let err = NodeAllowlist::from_hex_list(&[bad]).unwrap_err();
        assert!(err.contains("hex parse"));
    }
}
