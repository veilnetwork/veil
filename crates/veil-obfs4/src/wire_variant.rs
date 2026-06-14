//! Wire-format variant registry — anti-censorship strategy P2 #6.
//!
//! ## Why this exists
//!
//! Even after a DPI-fingerprint regression suite ([`veil-fingerprint`])
//! and Chrome-mimic crypto layers (`tls-boring`, QUIC Chrome transport
//! params), a sufficiently determined adversary targeting OVL1
//! specifically may publish a fingerprint that matches our exact obfs4
//! variant.  Possible vectors:
//!
//! * Length-distribution fingerprint of the obfs4 padding (our padding
//!   constants leak a small but measurable statistical signal).
//! * Initial handshake byte-pattern fingerprint (elligator2 representative
//!   bytes have a specific Curve25519-affine structure).
//! * Timing signatures of the handshake retransmission pattern.
//!
//! When such a fingerprint surfaces, we want to **rotate to a fresh
//! variant** without a binary rebuild + global redeployment cycle:
//!
//! 1. Operator flips a config flag selecting a different variant.
//! 2. Server immediately advertises both old + new on listen.
//! 3. Clients pre-loaded with the new variant connect on the new wire.
//! 4. Once enough clients have migrated, operator drops the old.
//!
//! ## What this module ships **today** (Phase 1)
//!
//! * The variant enum — currently has one variant `V1` (the obfs4
//!   format shipped in Phase 1b/c, 2025).  Adding a `V2` is a matter
//!   of adding the enum variant + setting different HKDF labels +
//!   different padding constants.
//! * Domain-separation labels keyed by variant (`auth_mac_context`,
//!   `hkdf_auth_key_info`) — so a V2 variant's auth-key derivation
//!   produces different keys from V1, guaranteeing wire-level
//!   distinction even if the surface byte layout is identical.
//!
//! ## What lands in the future epic when triggered (Phase 2)
//!
//! * Multiple concurrent variant accept on the server side
//!   (`HandshakePolicy::AcceptAll([V1, V2])`).
//! * Client-side variant probe + fallback (try V2 first, drop to V1
//!   if server doesn't acknowledge within timeout).
//! * Per-variant padding constants overrides (different distribution
//!   shapes to break the length-fingerprint correlation).
//! * Operator-config selection: `[transport] obfs4_variant = "v2"`.
//!
//! See [`docs/internal/PLAN_WIRE_FORMAT_KILL_SWITCH.md`](../../../docs/internal/PLAN_WIRE_FORMAT_KILL_SWITCH.md)
//! for the design + activation playbook.

/// Wire-format variant identifier.  Currently has a single variant —
/// **the kill-switch architecture is a Phase-1 landing pad**.  Future
/// variants are added by extending the enum + the lookup tables in
/// `auth_mac_context` / `hkdf_auth_key_info`.
///
/// `#[non_exhaustive]` allows callers to match on the enum without forcing
/// a downstream rebuild when a new variant lands (defensive against
/// the variant-rotation use case).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WireFormatVariant {
    /// Obfs4 as shipped in Phase 1b/c (2025).  Domain-separation
    /// labels: `b"obfs4-auth-key-v1"` / `b"obfs4-auth-v1:"`.  Client's
    /// first-frame MAC has **no variant tag** (backwards compat —
    /// pre-kill-switch wire format).  Padding range: 0..=128.
    #[default]
    V1,
    /// Obfs4 V2 — Phase 2 kill-switch variant.  Distinct from V1 by:
    /// * Different HKDF auth-key info label (`b"obfs4-auth-key-v2"`)
    /// * Different AUTH MAC context (`b"obfs4-auth-v2:"`)
    /// * Client first-frame MAC includes a variant tag (`b"obfs4-v2:"`)
    ///   prefixed to the HMAC input — V1 server cannot validate a V2
    ///   client's MAC (silent-drop), and V2 server can identify V2
    ///   clients on first frame.
    /// * Padding range tightened to 0..=96 (from V1's 0..=128) — breaks
    ///   length-distribution fingerprint correlation across variants.
    ///
    /// Ship-when-activated: only enable on production hosts when a
    /// fingerprint-signature trigger fires (see
    /// `docs/internal/PLAN_WIRE_FORMAT_KILL_SWITCH.md`).  Mixed-version
    /// rollout supported through the server's `accept_variants` config
    /// and the client's `variant_fallback_chain`.
    V2,
}

impl WireFormatVariant {
    /// HKDF "info" string used to derive the auth-key from the shared
    /// secret.  Different per variant — guarantees that a V2 client
    /// connecting to a V1 server produces incompatible auth-keys even
    /// if the surface byte layout were identical, so the server's
    /// silent-drop on MAC failure protects both sides from
    /// version-mismatch issues.
    pub const fn hkdf_auth_key_info(&self) -> &'static [u8] {
        match self {
            Self::V1 => b"obfs4-auth-key-v1",
            Self::V2 => b"obfs4-auth-key-v2",
        }
    }

    /// HMAC context prefix for the server's AUTH field.  Different
    /// per variant — see [`hkdf_auth_key_info`].
    pub const fn auth_mac_context(&self) -> &'static [u8] {
        match self {
            Self::V1 => b"obfs4-auth-v1:",
            Self::V2 => b"obfs4-auth-v2:",
        }
    }

    /// Variant tag prefixed to the HMAC input for the client's first
    /// frame.  V1 returns an empty slice (no tag — backwards compat
    /// with pre-kill-switch wire format).  V2+ include a variant-specific
    /// tag so that a V1 server's MAC computation differs from a V2
    /// client's, and vice versa — on MAC verify mismatch the server
    /// silent-drops.
    ///
    /// **Wire-level distinguisher** between variants on the very first
    /// flight — no need for a separate version byte on the wire,
    /// preserves the obfs4 "first frame looks random" property.
    pub const fn first_frame_mac_tag(&self) -> &'static [u8] {
        match self {
            Self::V1 => b"",
            Self::V2 => b"obfs4-v2:",
        }
    }

    /// Maximum random-padding length added to handshake messages.  V1
    /// uses 128; V2 uses 96 to break length-distribution fingerprint
    /// correlation across variants (different overall message-length
    /// distribution).
    pub const fn max_handshake_padding(&self) -> usize {
        match self {
            Self::V1 => 128,
            Self::V2 => 96,
        }
    }

    /// Human-readable variant name — for operator-config strings
    /// and log lines.
    pub fn name(&self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }

    /// Parse a config-string identifier.  Operators set
    /// `[transport] obfs4_variant = "v1"` (or "v2" once Phase 2
    /// activated).
    pub fn from_config_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "v1" | "obfs4-v1" | "obfs4" => Some(Self::V1),
            "v2" | "obfs4-v2" => Some(Self::V2),
            _ => None,
        }
    }

    /// All known variants, ordered from newest to oldest — used by
    /// servers configured to "advertise everything we support" via
    /// `accept_variants = ["v2", "v1"]`.
    pub fn all() -> &'static [Self] {
        &[Self::V2, Self::V1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anchor test — pins the v1 labels to the bytes currently used
    /// in `ntor.rs`.  Adding a v2 must not change v1's labels (would
    /// break cross-version handshake-by-MAC-silent-drop guarantee).
    #[test]
    fn v1_labels_match_legacy_constants() {
        assert_eq!(
            WireFormatVariant::V1.hkdf_auth_key_info(),
            b"obfs4-auth-key-v1"
        );
        assert_eq!(WireFormatVariant::V1.auth_mac_context(), b"obfs4-auth-v1:");
    }

    #[test]
    fn default_is_v1() {
        assert_eq!(WireFormatVariant::default(), WireFormatVariant::V1);
    }

    #[test]
    fn config_parse_accepts_aliases() {
        assert_eq!(
            WireFormatVariant::from_config_str("v1"),
            Some(WireFormatVariant::V1)
        );
        assert_eq!(
            WireFormatVariant::from_config_str("V1"),
            Some(WireFormatVariant::V1)
        );
        assert_eq!(
            WireFormatVariant::from_config_str(" obfs4-v1 "),
            Some(WireFormatVariant::V1)
        );
        assert_eq!(
            WireFormatVariant::from_config_str("obfs4"),
            Some(WireFormatVariant::V1)
        );
    }

    #[test]
    fn config_parse_rejects_unknown() {
        assert_eq!(WireFormatVariant::from_config_str(""), None);
        assert_eq!(WireFormatVariant::from_config_str("xyz"), None);
        assert_eq!(WireFormatVariant::from_config_str("v3"), None);
    }

    #[test]
    fn config_parse_accepts_v2() {
        assert_eq!(
            WireFormatVariant::from_config_str("v2"),
            Some(WireFormatVariant::V2)
        );
        assert_eq!(
            WireFormatVariant::from_config_str("V2"),
            Some(WireFormatVariant::V2)
        );
        assert_eq!(
            WireFormatVariant::from_config_str("obfs4-v2"),
            Some(WireFormatVariant::V2)
        );
    }

    #[test]
    fn all_includes_both_variants() {
        let variants = WireFormatVariant::all();
        assert!(variants.contains(&WireFormatVariant::V1));
        assert!(variants.contains(&WireFormatVariant::V2));
        assert_eq!(variants.len(), 2);
        // Newest-first ordering matters: server's `accept_variants =
        // WireFormatVariant::all()` defaults to preferring V2 over V1
        // (matches the kill-switch activation expectation — V2 ships
        // when trigger fires, V1 stays accepted for grace period).
        assert_eq!(variants[0], WireFormatVariant::V2);
        assert_eq!(variants[1], WireFormatVariant::V1);
    }

    #[test]
    fn v1_first_frame_mac_tag_is_empty() {
        // Backwards-compat anchor: pre-kill-switch wire format
        // included NO tag in the first-frame MAC.  V2 cannot regress
        // V1's wire shape.
        assert_eq!(WireFormatVariant::V1.first_frame_mac_tag(), b"");
    }

    #[test]
    fn v2_first_frame_mac_tag_distinguishes_from_v1() {
        // V2 MUST have a non-empty distinct tag — otherwise V1 server
        // would accept V2 client (same MAC input → same expected MAC).
        let v2_tag = WireFormatVariant::V2.first_frame_mac_tag();
        assert!(!v2_tag.is_empty());
        assert_ne!(v2_tag, WireFormatVariant::V1.first_frame_mac_tag());
    }

    #[test]
    fn v2_labels_distinguish_from_v1() {
        // All three label surfaces must be distinct between V1 and V2 —
        // anchor the kill-switch's "different variants produce
        // incompatible keys + MACs" invariant.
        assert_ne!(
            WireFormatVariant::V1.hkdf_auth_key_info(),
            WireFormatVariant::V2.hkdf_auth_key_info(),
        );
        assert_ne!(
            WireFormatVariant::V1.auth_mac_context(),
            WireFormatVariant::V2.auth_mac_context(),
        );
        assert_ne!(
            WireFormatVariant::V1.first_frame_mac_tag(),
            WireFormatVariant::V2.first_frame_mac_tag(),
        );
    }

    #[test]
    fn v2_padding_differs_from_v1() {
        // Distinct max-padding breaks length-distribution fingerprint
        // correlation across variants.
        assert_ne!(
            WireFormatVariant::V1.max_handshake_padding(),
            WireFormatVariant::V2.max_handshake_padding(),
        );
    }

    #[test]
    fn name_round_trip() {
        for &variant in WireFormatVariant::all() {
            let name = variant.name();
            assert_eq!(WireFormatVariant::from_config_str(name), Some(variant));
        }
    }
}
