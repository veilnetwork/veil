//! Self-update infrastructure.
//!
//! Operators ship signed update manifests pointing at multi-endpoint
//! binary URLs. Clients fetch the manifest, verify the issuer
//! signature, check anti-downgrade timestamp, then download + verify
//! binary SHA-256 before swapping the running binary.
//!
//! # Why multi-endpoint matters for censorship resistance
//!
//! An authoritarian-state censor can take down a single distribution
//! endpoint (block the operator's GitHub Releases URL, blackhole the
//! AWS S3 bucket, DNS-poison the operator's domain). When `binary_urls`
//! carries N URLs across diverse providers (CDN1, CDN2, IPFS gateway
//!.onion mirror) the censor must take down ALL of them simultaneously
//! to halt the network's update flow. Each URL is independent —
//! client tries them in order, accepts the first one whose body
//! matches the signed `binary_sha256`.
//!
//! # Currently shipped
//!
//! * [`manifest`] — signed update-manifest primitive: wire format
//!   sign/decode/verify, anti-downgrade timestamp, anti-tamper
//!   signature binding. No HTTPS fetch / no in-place restart yet
//!   — those are separate slices.

pub mod apply;
pub mod check_task;
pub mod checker;
pub mod fetch;
pub mod installed_version;
pub mod manifest;

/// Structured logger surface used by the periodic check task.
///
/// extraction: implemented by veilcore's `NodeLogger` so this
/// crate can emit `update.check.*` events without depending on the
/// observability layer.
pub trait UpdateLogger: Send + Sync {
    fn info(&self, event: &str, message: &str);
    fn warn(&self, event: &str, message: &str);
}
