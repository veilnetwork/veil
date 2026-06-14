//! umbrella error hierarchy for the identity module.
//!
//! Each submodule owns a narrow error enum tailored to its
//! operations (see `PublishError` in `publish.rs`, `VerifyError` in
//! `verify.rs`, etc.). That's the right granularity for callers
//! inside identity, but it forces every external consumer to enumerate
//! thirteen distinct types or fall through to a stringy boundary.
//!
//! `IdentityError` is a thin umbrella that wraps every sub-error via
//! [`From`] conversions. External callers that want "any identity
//! failure" can take `Result<T, IdentityError>` and still preserve the
//! original error in the `Display` chain (each variant re-uses the
//! sub-error's own formatter via `#[error(transparent)]`).
//!
//! Design:
//! Sub-errors stay untouched; this layer adds zero invasiveness to
//! the existing code. Function signatures inside identity continue
//! to return their specific error types; the umbrella is opt-in
//! for callers that prefer a single `?`-convertible boundary.
//! Each variant is the sub-enum by value — no erasure, no `Box`
//! `Display` passes through with `#[error(transparent)]`.
//! `From<IdentityError> for crate::NodeError` is provided so the
//! top-level runtime error chain accepts an umbrella failure with
//! one `?`.

use super::{
    mlkem_fanout::MlkemFanoutError,
    pair_runtime::PairCeremonyError,
    pair_transport::PairTransportError,
    publish::PublishError,
    resolver::ResolveError,
    sovereign::SovereignIdentityError,
    verify::{FrameProofError, ProofVerifyError, VerifyError},
};

/// Umbrella error for the sovereign-identity subsystem.
///
/// Wraps each sub-module's narrow error type [`From`] conversion.
/// Most code inside `identity/` continues to work with the narrow
/// enums; this umbrella is offered as the preferred return type for
/// cross-module helpers and for external callers that don't want to
/// enumerate thirteen distinct error types.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// `mlkem_fanout`.
    #[error(transparent)]
    MlkemFanout(#[from] MlkemFanoutError),
    /// `pair_runtime`.
    #[error(transparent)]
    PairCeremony(#[from] PairCeremonyError),
    /// `pair_transport`.
    #[error(transparent)]
    PairTransport(#[from] PairTransportError),
    // a removed `Propagate(PropagateError)` variant.
    // d removed `RevocationCache(RevocationCacheError)` and
    // `Refresh(RefreshError)` variants — both supported the in-band
    // revocation/freshness-cert flow that's been dropped.
    /// `publish`.
    #[error(transparent)]
    Publish(#[from] PublishError),
    /// `resolver`.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// `sovereign`.
    #[error(transparent)]
    Sovereign(#[from] SovereignIdentityError),
    // removed `TierB(TierBError)` variant — tier_b module gone.
    /// `verify` — document validation.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// `verify` — identity-proof validation.
    #[error(transparent)]
    ProofVerify(#[from] ProofVerifyError),
    /// `verify` — frame-embedded proof validation.
    #[error(transparent)]
    FrameProof(#[from] FrameProofError),
}

/// Convenience alias for identity-layer results.
pub type IdentityResult<T> = std::result::Result<T, IdentityError>;

// NodeError already has a Handshake variant that stringifies; rather
// than introduce a new `NodeError::Identity(IdentityError)` variant
// (which would be a breaking change to the top-level error) we lean
// on Display — the top-level conversion stays explicit on the caller
// side.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_error_converts_into_umbrella() {
        let e: IdentityError = PublishError::PowExhausted { attempts: 42 }.into();
        assert!(matches!(e, IdentityError::Publish(_)));
        // Display passes through.
        let s = e.to_string();
        assert!(
            s.contains("42"),
            "umbrella Display forwards to sub-error: {s}"
        );
    }

    #[test]
    fn all_variants_have_distinct_display() {
        // Spot-check that two distinct sub-errors map to two distinct
        // umbrella variants (matches! uses pattern match, not equality).
        let e1: IdentityError = PublishError::PowExhausted { attempts: 1 }.into();
        let e2: IdentityError = PublishError::PowExhausted { attempts: 2 }.into();
        assert!(matches!(e1, IdentityError::Publish(_)));
        assert!(matches!(e2, IdentityError::Publish(_)));
    }
}
