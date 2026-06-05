//! Multi-provider [`PushDispatcher`] that routes by `PushToken.provider`.
//!
//!.4 P6. Operators who configure both
//! FCM (для Android) and APNs (для iOS) need a single
//! [`PushDispatcher`] handle the runtime can wire into the push task.
//! [`ProviderRouter`] holds optional dispatchers for each provider
//! and dispatches based on the token tag.
//!
//! Tokens whose provider has no configured dispatcher get
//! [`PushError::ProviderNotConfigured`] back; the push task logs at
//! WARN and moves on (peer-sync handles eventual delivery).
//!
//! ## Why a separate type
//!
//! Keeps the `PushDispatcher` trait simple (single token in, single
//! error out — no per-provider branching).
//! Lets operators ship Android-only or iOS-only deployments
//! without an `unimplemented!` placeholder dispatcher.
//! Tests can swap individual provider impls без touching the
//! router itself.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{PushDispatcher, PushError, PushProvider, PushToken};

/// A `PushDispatcher` that demultiplexes by [`PushProvider`]. Cheap
/// to clone via `Arc`.
pub struct ProviderRouter {
    /// Dispatcher [`PushProvider::Fcm`]. `None` → tokens for
    /// Android receivers fail с `ProviderNotConfigured(Fcm)`.
    fcm: Option<Arc<dyn PushDispatcher>>,
    /// Dispatcher [`PushProvider::Apns`].
    apns: Option<Arc<dyn PushDispatcher>>,
}

impl ProviderRouter {
    /// Build a router from optional per-provider dispatchers. At
    /// least one should be `Some` for the router to be useful;
    /// callers wanting a fully no-op dispatcher should use
    /// [`crate::LogOnlyDispatcher`] instead.
    pub fn new(
        fcm: Option<Arc<dyn PushDispatcher>>,
        apns: Option<Arc<dyn PushDispatcher>>,
    ) -> Self {
        Self { fcm, apns }
    }

    /// True if the FCM provider is configured.
    pub fn has_fcm(&self) -> bool {
        self.fcm.is_some()
    }

    /// True if the APNs provider is configured.
    pub fn has_apns(&self) -> bool {
        self.apns.is_some()
    }
}

#[async_trait]
impl PushDispatcher for ProviderRouter {
    async fn dispatch(&self, token: &PushToken, wake_payload: &[u8]) -> Result<(), PushError> {
        match token.provider {
            PushProvider::Fcm => match &self.fcm {
                Some(d) => d.dispatch(token, wake_payload).await,
                None => Err(PushError::ProviderNotConfigured(PushProvider::Fcm)),
            },
            PushProvider::Apns => match &self.apns {
                Some(d) => d.dispatch(token, wake_payload).await,
                None => Err(PushError::ProviderNotConfigured(PushProvider::Apns)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LogOnlyDispatcher;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test dispatcher that counts calls per-provider.
    struct CountingDispatcher {
        expected_provider: PushProvider,
        count: AtomicUsize,
    }

    #[async_trait]
    impl PushDispatcher for CountingDispatcher {
        async fn dispatch(&self, token: &PushToken, _wake_payload: &[u8]) -> Result<(), PushError> {
            assert_eq!(token.provider, self.expected_provider);
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn t1_4_p6_router_dispatches_fcm_to_fcm_only() {
        let fcm = Arc::new(CountingDispatcher {
            expected_provider: PushProvider::Fcm,
            count: AtomicUsize::new(0),
        });
        let apns = Arc::new(CountingDispatcher {
            expected_provider: PushProvider::Apns,
            count: AtomicUsize::new(0),
        });
        let router = ProviderRouter::new(
            Some(Arc::clone(&fcm) as Arc<dyn PushDispatcher>),
            Some(Arc::clone(&apns) as Arc<dyn PushDispatcher>),
        );
        let token = PushToken {
            provider: PushProvider::Fcm,
            token: b"fcm-tok".to_vec(),
        };
        router.dispatch(&token, &[]).await.unwrap();
        assert_eq!(fcm.count.load(Ordering::SeqCst), 1);
        assert_eq!(apns.count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn t1_4_p6_router_dispatches_apns_to_apns_only() {
        let fcm = Arc::new(CountingDispatcher {
            expected_provider: PushProvider::Fcm,
            count: AtomicUsize::new(0),
        });
        let apns = Arc::new(CountingDispatcher {
            expected_provider: PushProvider::Apns,
            count: AtomicUsize::new(0),
        });
        let router = ProviderRouter::new(
            Some(Arc::clone(&fcm) as Arc<dyn PushDispatcher>),
            Some(Arc::clone(&apns) as Arc<dyn PushDispatcher>),
        );
        let token = PushToken {
            provider: PushProvider::Apns,
            token: b"apns-tok".to_vec(),
        };
        router.dispatch(&token, &[]).await.unwrap();
        assert_eq!(fcm.count.load(Ordering::SeqCst), 0);
        assert_eq!(apns.count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn t1_4_p6_router_returns_not_configured_when_provider_absent() {
        let log: Arc<dyn PushDispatcher> = Arc::new(LogOnlyDispatcher);
        // FCM only, APNs missing.
        let router = ProviderRouter::new(Some(log), None);
        let apns_token = PushToken {
            provider: PushProvider::Apns,
            token: b"x".to_vec(),
        };
        let err = router.dispatch(&apns_token, &[]).await.unwrap_err();
        assert!(matches!(
            err,
            PushError::ProviderNotConfigured(PushProvider::Apns)
        ));
    }

    #[tokio::test]
    async fn t1_4_p6_router_with_neither_provider_fails_for_both() {
        let router = ProviderRouter::new(None, None);
        for p in [PushProvider::Fcm, PushProvider::Apns] {
            let token = PushToken {
                provider: p,
                token: vec![0u8],
            };
            let err = router.dispatch(&token, &[]).await.unwrap_err();
            assert!(matches!(err, PushError::ProviderNotConfigured(_)));
        }
    }

    #[test]
    fn t1_4_p6_router_has_provider_flags() {
        let log: Arc<dyn PushDispatcher> = Arc::new(LogOnlyDispatcher);
        let router = ProviderRouter::new(Some(log), None);
        assert!(router.has_fcm());
        assert!(!router.has_apns());
    }
}
