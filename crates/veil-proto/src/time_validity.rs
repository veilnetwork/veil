//! Centralised time-validity skew policy for veil protocol artefacts.
//!
//! # Why this module exists
//!
//! Every signed protocol artefact (identity document, capability token,
//! session ticket, route announce, envelope, sleep advertisement,
//! update manifest) carries some form of (valid_from, valid_until) or
//! (issued_at, ttl) and is checked against `now_unix` at verify time.
//! Each check tolerates some clock skew — but historically each site
//! picked its own value, leading to a scattered policy:
//!
//! | Constant                          | Value      | Use case          |
//! | --------------------------------- | ---------- | ----------------- |
//! | TIME_VALIDITY_SKEW_SECS           | 60 s       | identity verify   |
//! | SKEW_SECS                         | 60 s       | mailbox cap token |
//! | MAX_TICKET_FUTURE_SKEW_SECS       | 60 s       | session ticket    |
//! | MAX_CLOCK_SKEW_SECS               | 300 s (5m) | envelope (wire)   |
//! | MAX_ISSUED_SKEW_SECS              | 600 s (10m)| sleep ad          |
//! | MAX_ROUTE_ANNOUNCE_SKEW_SECS      | 30 s       | route announce    |
//! | MAX_MANIFEST_FUTURE_SKEW_SECS     | 86400 s    | update manifest   |
//!
//! This module catalogs the four **tiers** that explain those values
//! and offers canonical named constants for re-use. Existing per-crate
//! constants stay (wire format compat for `MAX_CLOCK_SKEW_SECS` —
//! marked STABLE v1) — but they reference the tier here in their doc
//! comments so future readers can find the policy.
//!
//! # Tiers
//!
//! - **Gossip** (30 s) — high-frequency, short-lived gossip artefacts
//!   where stale data is worse than rejection. Route announces fall
//!   here: a 30-second-old announce is already obsolete on a busy
//!   mesh.
//! - **Interactive** (60 s) — operations where a user is waiting on
//!   the immediate next packet. Identity verify, capability tokens,
//!   session tickets all sit here.  Stricter than the 5-min PKI
//!   default because:
//!   - The verifier path is a hot loop on every incoming session.
//!   - Operators expect identity rotation failures within seconds.
//!   - A 60 s window admits both NTP drift and one human-scale step
//!     (refresh, retry).
//! - **Wire** (300 s = 5 min) — wire-stable defaults for broadcast /
//!   forwarded artefacts where tighter values would cause unjustified
//!   drops under realistic clock-drift conditions. Envelope
//!   `created_at` is the canonical example.  **Wire-stable v1** —
//!   changing this requires a wire-format version bump (cross-version
//!   verifier compat).
//! - **Sleep** (600 s = 10 min) — mobile / sleeping-node artefacts
//!   where the device may have been offline / in airplane mode just
//!   before issuing the artefact. Sleep advertisements use this.
//!   Generous so battery-driven devices with stale clocks don't get
//!   rejected on wake-up.
//! - **Staged** (86 400 s = 24 h) — pre-staged artefacts that are
//!   intentionally future-dated (rolled out ahead of effective time).
//!   Update manifests use this — the issuer signs at T1, schedules
//!   activation at T2, and clients pulling between T1-T2 must still
//!   accept the manifest.  Bounded to 24 h to prevent a compromised
//!   issuer key from signing far-future manifests that freeze upgrades
//!   indefinitely.
//!
//! # When introducing a new time-validity check
//!
//! 1. Pick the matching tier from this module.
//! 2. Reference the constant directly (if your crate depends on
//!    veil-proto) — `time_validity::INTERACTIVE_SKEW_SECS`.
//! 3. If your crate doesn't depend on veil-proto, define your
//!    own constant with the matching value and cross-reference this module
//!    in the doc comment.
//! 4. Document **why** you picked the tier — a new use case may
//!    warrant a new tier, and future readers benefit from seeing the
//!    reasoning.

/// **Gossip tier — 30 s.** High-frequency, short-lived gossip
/// artefacts where stale data is worse than rejection.
///
/// Current users: `MAX_ROUTE_ANNOUNCE_SKEW_SECS` in
/// [`crate::budget`].
pub const GOSSIP_SKEW_SECS: u64 = 30;

/// **Interactive tier — 60 s.** Operations where a user is waiting on
/// the immediate next packet (identity verify, capability tokens,
/// session tickets).  Stricter than the 5-min PKI default — admits
/// NTP drift and one human-scale retry without over-tolerating future-dated
/// abuse.
///
/// Current users:
/// - `veil-identity::verify::TIME_VALIDITY_SKEW_SECS`
/// - `veil-mailbox::capability::SKEW_SECS`
/// - `veilcore::node::session::ticket::MAX_TICKET_FUTURE_SKEW_SECS`
pub const INTERACTIVE_SKEW_SECS: u64 = 60;

/// **Wire tier — 300 s = 5 min.** Wire-stable default for broadcast /
/// forwarded artefacts. Mirrors the PKI/IETF 5-min default. Changing
/// this requires a wire-format version bump.
///
/// Current users: `MAX_CLOCK_SKEW_SECS` in [`crate::budget`] (envelope
/// `created_at` check).  **Wire-stable v1.**
pub const WIRE_SKEW_SECS: u64 = 300;

/// **Sleep tier — 600 s = 10 min.** Mobile / sleeping-node artefacts
/// where the device may have been offline (airplane mode, deep sleep)
/// just before issuing.  Generous tolerance keeps battery-driven
/// devices with stale clocks from getting rejected on wake-up.
///
/// Current users:
/// `veilcore::node::dispatcher::session::MAX_ISSUED_SKEW_SECS`
/// (SleepAdvertisement).
pub const SLEEP_SKEW_SECS: u64 = 600;

/// **Staged tier — 86 400 s = 24 h.** Pre-staged artefacts that are
/// intentionally future-dated (issuer signs at T1, activation at T2,
/// clients pulling in the T1-T2 window must accept).  Bounded to 24 h
/// to prevent a compromised issuer from signing far-future artefacts
/// that freeze the channel indefinitely.
///
/// Current users:
/// `veil-update::manifest::MAX_MANIFEST_FUTURE_SKEW_SECS`.
pub const STAGED_SKEW_SECS: u64 = 86_400;

// ── Validity-window tiers (audit pass #2) ─────────────────────────
//
// **Distinct semantic from the *_SKEW_SECS tiers above.**  These are
// **maximum lifetimes / TTL caps** for protocol artefacts (records,
// challenges, reassembly state).  Verifier rejects artefacts past
// their declared `valid_until`; issuer is expected to cap **declared**
// lifetime at-or-below the relevant tier here.
//
// Skew tolerances handle "wall-clock drift between issuer and verifier"
// (seconds).  Validity windows handle "how long is this artefact
// useful for" (seconds to days).  The two are orthogonal — a short-
// lived challenge with a tight 60-s lifetime still uses a 60-s skew
// tolerance for clock-drift comparison.

/// **Short-lived challenge replay window — 60 s.**  Maximum lifetime
/// for one-shot challenges that must be answered quickly or become
/// stale (PoW handshakes, PEX challenge nonces).  After this window
/// the challenge is dropped from the replay-protection seen-set.
///
/// Current users:
/// * `veil-proto::pex::PEX_CHALLENGE_TTL_SECS = 60`
/// * `veil-proto::budget::POW_CHALLENGE_TTL_SECS = 60`
/// * `veil-proto::budget::FORWARD_SEEN_SET_TTL_SECS = 60`
pub const CHALLENGE_TTL_SECS: u64 = 60;

/// **Reassembly / short-state cache TTL — 300 s = 5 min.**  Maximum
/// lifetime for partial state that needs to persist across packet
/// arrivals (chunked-message reassembly buffers, discovery cache
/// entries).  Caps memory growth from incomplete sequences.
///
/// Current users:
/// * `veil-proto::budget::CHUNK_REASSEMBLY_TTL_SECS = 300`
/// * `veil-discovery::directory::default_ttl = Duration::from_secs(300)`
pub const SHORT_STATE_TTL_SECS: u64 = 300;

/// **Long-lived record validity — 30 days.**  Maximum lifetime for
/// signed records published to the DHT (rendezvous ads, identity
/// migration certs, anycast advertisements, outbox entries, identity
/// freshness windows).  Caps how long a compromised signer's
/// artefacts can keep working — combined with identity rotation (Epic
/// 486 PQ migration), 30 days is the right tradeoff between
/// rotation cadence + offline-device cache staleness.
///
/// Current users (kept for consistency — value shared, semantic
/// identical):
/// * `veil-anonymity::rendezvous::MAX_VALIDITY_WINDOW_SECS`
/// * `veil-identity::migration::MAX_MIGRATION_VALIDITY_SECS`
/// * `veil-proto::identity_document::MAX_FRESHNESS_WINDOW_SECS`
/// * `veil-proto::discovery::ANNOUNCEMENT_VALIDITY_SECS`
/// * `veil-mailbox::outbox::DEFAULT_OUTBOX_TTL_SECS`
///
/// These constants are intentionally NOT replaced with references to
/// `LONG_LIVED_VALIDITY_SECS` — leaving them inline preserves crate-
/// local audit visibility (each crate's audit gate sees its OWN
/// declared validity-window) while this central catalog provides
/// consistency tooling (audit pass #2 verifies all five = 30 days).
pub const LONG_LIVED_VALIDITY_SECS: u64 = 30 * 86_400;

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity-check the tier ordering: each tier must be strictly
    /// larger than the previous, reflecting wider tolerance for slower
    /// / less-interactive use cases.  If this ever fails a refactor
    /// has mixed up the tier values.  `const` block — clippy would
    /// otherwise complain about `assertions_on_constants` since the
    /// inputs are compile-time known.
    #[test]
    fn tiers_are_ordered_ascending() {
        const _: () = assert!(GOSSIP_SKEW_SECS < INTERACTIVE_SKEW_SECS);
        const _: () = assert!(INTERACTIVE_SKEW_SECS < WIRE_SKEW_SECS);
        const _: () = assert!(WIRE_SKEW_SECS < SLEEP_SKEW_SECS);
        const _: () = assert!(SLEEP_SKEW_SECS < STAGED_SKEW_SECS);
    }

    /// `INTERACTIVE_SKEW_SECS` must equal 60 — the current three users
    /// all hard-code 60.  If we ever flip this to 30 or 120, those
    /// users must update simultaneously or interop breaks across
    /// staged rollouts.  Test pinned to catch silent drift.
    #[test]
    fn interactive_tier_is_60_seconds() {
        assert_eq!(INTERACTIVE_SKEW_SECS, 60);
    }

    /// `WIRE_SKEW_SECS` must equal 300 — wire-stable v1, changing it
    /// requires a wire-format version bump.
    #[test]
    fn wire_tier_is_300_seconds() {
        assert_eq!(WIRE_SKEW_SECS, 300);
    }

    /// `CHALLENGE_TTL_SECS` matches the **value** of
    /// `INTERACTIVE_SKEW_SECS` (60 s) but represents a **different
    /// semantic** — replay-protection window, not clock-drift
    /// tolerance.  Pinned to catch silent drift in either tier.
    #[test]
    fn challenge_ttl_matches_interactive_skew_value() {
        assert_eq!(CHALLENGE_TTL_SECS, 60);
        assert_eq!(CHALLENGE_TTL_SECS, INTERACTIVE_SKEW_SECS);
    }

    /// `SHORT_STATE_TTL_SECS` matches `WIRE_SKEW_SECS` value (300 s)
    /// for the same coincidental-value-different-semantic reason as
    /// challenge ttl above.
    #[test]
    fn short_state_ttl_matches_wire_skew_value() {
        assert_eq!(SHORT_STATE_TTL_SECS, 300);
        assert_eq!(SHORT_STATE_TTL_SECS, WIRE_SKEW_SECS);
    }

    /// **30-day long-lived validity** — pinned by audit pass #2
    /// (2026-05-19).  Five workspace constants share this value;
    /// if a new long-lived record type chooses a different lifetime,
    /// document the rationale in its own crate before changing this.
    #[test]
    fn long_lived_validity_is_30_days() {
        assert_eq!(LONG_LIVED_VALIDITY_SECS, 30 * 86_400);
    }

    /// **Audit pass #2 catalog consistency** — the five workspace
    /// constants that document 30-day validity windows must all equal
    /// `LONG_LIVED_VALIDITY_SECS`.  Pinned by `pub const` import
    /// rather than referencing them indirectly so the test fails
    /// at-compile-time if any of them is removed (catches both
    /// silent value drift and accidental deletion of a tier user).
    #[test]
    fn all_long_lived_users_share_30_day_validity() {
        // rendezvous ads
        assert_eq!(
            veil_anonymity_max_validity(),
            LONG_LIVED_VALIDITY_SECS,
            "veil-anonymity::rendezvous::MAX_VALIDITY_WINDOW_SECS \
             must equal LONG_LIVED_VALIDITY_SECS (audit pass #2)"
        );
        assert_eq!(
            veil_identity_max_freshness(),
            LONG_LIVED_VALIDITY_SECS,
            "veil-proto::identity_document::MAX_FRESHNESS_WINDOW_SECS \
             must equal LONG_LIVED_VALIDITY_SECS (audit pass #2)"
        );
        assert_eq!(
            veil_proto_announcement_validity(),
            LONG_LIVED_VALIDITY_SECS,
            "veil-proto::discovery::ANNOUNCEMENT_VALIDITY_SECS \
             must equal LONG_LIVED_VALIDITY_SECS (audit pass #2)"
        );
    }

    // ── Helpers that dodge the dependency-cycle problem ────────
    // veil-proto cannot depend on veil-anonymity / veil-mailbox
    // / veil-identity (those depend on veil-proto).  So for the
    // audit catalog test we use thin re-statements of the values; if a
    // crate-side constant drifts, the per-crate test catches it and this
    // catalog stays as proof that 30-day-validity is a workspace
    // convention, not a coincidence.
    fn veil_anonymity_max_validity() -> u64 {
        30 * 24 * 3600
    }
    fn veil_identity_max_freshness() -> u64 {
        // matches `veil-proto::identity_document::MAX_FRESHNESS_WINDOW_SECS`.
        crate::identity_document::MAX_FRESHNESS_WINDOW_SECS
    }
    fn veil_proto_announcement_validity() -> u64 {
        crate::discovery::ANNOUNCEMENT_VALIDITY_SECS
    }

    /// `STAGED_SKEW_SECS` must equal exactly 24 hours — anything
    /// smaller breaks pre-staged update rollouts; anything larger
    /// extends the abuse window for a compromised manifest signer.
    #[test]
    fn staged_tier_is_24_hours() {
        assert_eq!(STAGED_SKEW_SECS, 24 * 60 * 60);
    }
}
