//! Push-notification dispatch for the veil mailbox pipeline.
//!
//!.4 P3. Splits the push pipeline into:
//!
//! 1. **Token format** ([`PushToken`]) — the plaintext shape that
//!    sits inside the sealed envelope on the wire. Carries the
//!    provider tag (FCM / APNs) plus the actual provider-specific
//!    token bytes.
//! 2. **Dispatcher trait** ([`PushDispatcher`]) — the actual call
//!    out to FCM / APNs / UnifiedPush. Async because every real
//!    provider is HTTP-based.
//! 3. **Default impl** ([`LogOnlyDispatcher`]) — does not contact any
//!    third party; just logs. Wired by the daemon when the operator
//!    has not configured real push credentials yet. Useful in tests
//!    and as a deny-by-default safety net so a misconfigured node
//!    cannot leak push tokens to a wrong provider.
//!
//! ## Why a separate crate
//!
//! Keeps the FCM/APNs HTTP+JWT machinery (P3b, future) out of
//! `veilcore`'s already-large dependency graph.
//! Lets the operator-side push relay (when we eventually ship it)
//! reuse the trait + token parser without depending on
//! `veil-mailbox` or any node runtime internals.
//! Lets unit tests for trigger flow stub the trait without spinning
//! up a real HTTP server.
//!
//! ## What this crate ships
//!
//! **`FcmDispatcher`** — FCM HTTP v1 client with JWT-signed service-
//! account auth (re-exported from `mod fcm`).
//! **`ApnsDispatcher`** — APNs HTTP/2 client with `.p8` ES256 JWT
//! (re-exported from `mod apns`).
//! **`LogOnlyDispatcher`** — default dev/test fallback that just
//! logs the wake-up without contacting third parties.
//!
//! ## What this crate does **not** do
//!
//! No retry / circuit-breaker — each call goes directly to the
//! trait. Higher-level orchestration (rate-limit per token, retry
//! with backoff) lives in the runtime push task.
//! These dispatchers take a `wake_payload: &[u8]` and, when non-empty,
//! base64-encode it into the provider DATA field under key `"w"` (FCM
//! `message.data["w"]` / APNs top-level `"w"`); an empty slice preserves the
//! legacy wake-only body. The relay-side MINT is now wired (Epic 489.10 slice
//! 4.4): `runtime::push_dispatch_task` unseals the sender-forwarded
//! `WakeHmacKey` envelope and computes the 72-byte authenticated payload via
//! `veil_crypto::wake_hmac` before calling `dispatch`. On any wake-envelope
//! problem (absent / unsealable) it falls back to the empty wake-only payload,
//! so a push is never dropped. (Earlier this doc said minting was deferred —
//! that landed; receiver-side verify is `VeilPush.handleWakeup(requireAuth:
//! true)`.)

#![deny(missing_docs)]

pub mod router;
pub mod token;

#[cfg(feature = "fcm")]
pub mod fcm;
#[cfg(feature = "fcm")]
pub use fcm::FcmDispatcher;

#[cfg(feature = "apns")]
pub mod apns;
#[cfg(feature = "apns")]
pub use apns::{ApnsDispatcher, ApnsEnvironment};

pub use router::ProviderRouter;
pub use token::{MAX_PROVIDER_TOKEN_LEN, PushProvider, PushToken};

use async_trait::async_trait;

/// Dispatch errors. All variants are non-fatal at the runtime level
/// — the push task logs and moves on; an undelivered push is the
/// caller's problem to retry, not the relay's.
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    /// Provider-specific transport error (HTTP failure, timeout
    /// connection refused).
    #[error("transport error: {0}")]
    Transport(String),
    /// Provider rejected the token (revoked, malformed, wrong project).
    /// Permanent — caller should drop the registration.
    #[error("token invalid: {0}")]
    InvalidToken(String),
    /// Provider rate-limited us. Caller should back off; do not
    /// drop the registration.
    #[error("rate limited by provider")]
    RateLimited,
    /// Operator did not configure credentials for the requested
    /// provider — the dispatcher exists but is non-functional.
    #[error("provider {0:?} not configured")]
    ProviderNotConfigured(PushProvider),
}

/// The contract a push backend implements. Production deployments
/// wire either [`LogOnlyDispatcher`] (default), a real
/// `FcmDispatcher` / `ApnsDispatcher` (P3b), or operator-supplied
/// `dyn PushDispatcher` (e.g. UnifiedPush for vendor-lock-in-averse
/// setups).
#[async_trait]
pub trait PushDispatcher: Send + Sync {
    /// Dispatch a single wake-up push to `token`. The token's
    /// `provider` field tells the dispatcher which back-end to call.
    /// Implementations that don't support a given provider should
    /// return [`PushError::ProviderNotConfigured`].
    ///
    /// `wake_payload` is the authenticated wake-HMAC payload (Epic 489.10
    /// slice 4.4) the relay minted for this push — when non-empty it is
    /// base64-encoded into the provider DATA field under key `"w"` so the
    /// receiver's plugin can verify the tag before reconnecting. An empty
    /// slice preserves the legacy wake-only push (back-compat).
    async fn dispatch(&self, token: &PushToken, wake_payload: &[u8]) -> Result<(), PushError>;
}

/// Implementation that does not contact any third-party service.
/// Logs each dispatch at INFO and returns Ok. Default when the
/// operator has not configured FCM/APNs credentials.
///
/// The operator can spot "would have pushed" log lines to verify
/// the trigger path is wired without committing to vendor lock-in.
pub struct LogOnlyDispatcher;

#[async_trait]
impl PushDispatcher for LogOnlyDispatcher {
    async fn dispatch(&self, token: &PushToken, wake_payload: &[u8]) -> Result<(), PushError> {
        log::info!(
            "veil-push: would dispatch to provider={:?} token_len={} wake_payload_len={}",
            token.provider,
            token.token.len(),
            wake_payload.len(),
        );
        Ok(())
    }
}

impl<T: PushDispatcher + ?Sized> PushDispatcher for std::sync::Arc<T> {
    fn dispatch<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        token: &'life1 PushToken,
        wake_payload: &'life2 [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), PushError>> + Send + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        (**self).dispatch(token, wake_payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn t1_4_p3a_log_only_returns_ok() {
        let d = LogOnlyDispatcher;
        let token = PushToken {
            provider: PushProvider::Fcm,
            token: b"fake-fcm-token".to_vec(),
        };
        d.dispatch(&token, &[]).await.unwrap();
    }

    #[tokio::test]
    async fn t1_4_p3a_arc_proxy_dispatches() {
        let d: std::sync::Arc<dyn PushDispatcher> = std::sync::Arc::new(LogOnlyDispatcher);
        let token = PushToken {
            provider: PushProvider::Apns,
            token: vec![0u8; 32],
        };
        d.dispatch(&token, &[]).await.unwrap();
    }
}
