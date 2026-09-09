//! Push: how a message that arrived for a sleeping phone becomes a wake.
//!
//! One lifecycle, three pieces that only make sense together:
//!
//!  * [`build_push_dispatcher`] reads the operator's credentials and decides
//!    what the node can actually do — FCM, APNs, both, or nothing but a log
//!    line. A half-filled provider block degrades that provider, never the
//!    daemon.
//!  * [`HotReloadDispatcher`] plus `push_creds_watch_task` keep that decision
//!    current. Credentials are files, files get rotated, and a daemon that
//!    read them once at startup goes quietly deaf the day the key changes.
//!  * `mint_wake_payload` and `push_dispatch_task` are the delivery end: a
//!    trigger arrives, the wake payload is authenticated against the relay's
//!    key, and the token is handed to whichever dispatcher is installed at
//!    that instant.
//!
//! The two ends meet at the `Arc<dyn PushDispatcher>` the hot-reload wrapper
//! holds: the watch task swaps what is inside it, the dispatch task reads
//! through it, and neither knows the other exists. Splitting them apart would
//! separate the swap from the read — which is the one relationship worth
//! keeping in one file.
//!
//! Moved verbatim out of `service_tasks.rs` (report24 RUNTIME-3: a
//! ten-thousand-line module nobody can hold in their head). Behaviour is
//! unchanged; only the visibility of the items `service_tasks.rs` still calls
//! was widened from private to `pub(crate)`.

use std::sync::Arc;

use crate::builtin::PushTrigger;

use super::service_tasks::hex_short;

// ── T1.4 P6: build push dispatcher from operator config ────────
//
// Returns a `LogOnlyDispatcher` if neither FCM nor APNs creds are
// configured (default — operator did not opt into real push), or a
// `ProviderRouter` wrapping the configured providers otherwise.
//
// Per-provider failures (file not found, malformed key) downgrade
// that provider to "absent" but don't fail the daemon — operator
// sees a WARN log and the other provider (if configured) keeps
// working. Worst case: both providers fail to load, daemon falls
// back to LogOnly.

pub fn build_push_dispatcher(
    cfg: &veil_cfg::MailboxPushConfig,
) -> Arc<dyn veil_push::PushDispatcher> {
    // Loud startup signal for a partial APNs credential set. `apns_enabled()`
    // is all-or-nothing, so a half-filled APNs block (e.g. only `apns_p8_path`)
    // silently disables real push and falls back to LogOnly — wake delivery is
    // lost with no error. `veil-cli config validate` rejects this
    // (mailbox_push_apns_partial_config), but the daemon doesn't run full
    // validation at startup, so warn here too.
    {
        let apns_fields_set = [
            !cfg.apns_p8_path.is_empty(),
            !cfg.apns_key_id.is_empty(),
            !cfg.apns_team_id.is_empty(),
            !cfg.apns_bundle_id.is_empty(),
        ]
        .iter()
        .filter(|x| **x)
        .count();
        if apns_fields_set != 0 && apns_fields_set != 4 {
            log::warn!(
                "veil-push: APNs config is PARTIAL ({apns_fields_set}/4 of \
                 apns_p8_path/apns_key_id/apns_team_id/apns_bundle_id set) — \
                 APNs push is DISABLED and the daemon is falling back to \
                 log-only for APNs tokens. Set all four fields, or clear them \
                 all to silence this. Run `veil-cli config validate`.",
            );
        }
    }
    let fcm_dispatcher = build_fcm_dispatcher(cfg);
    let apns_dispatcher = build_apns_dispatcher(cfg);

    if fcm_dispatcher.is_none() && apns_dispatcher.is_none() {
        log::info!("veil-push: no provider credentials configured — falling back to LogOnly",);
        return Arc::new(veil_push::LogOnlyDispatcher);
    }
    log::info!(
        "veil-push: provider router (fcm={}, apns={})",
        fcm_dispatcher.is_some(),
        apns_dispatcher.is_some(),
    );
    Arc::new(veil_push::ProviderRouter::new(
        fcm_dispatcher,
        apns_dispatcher,
    ))
}

pub fn build_fcm_dispatcher(
    cfg: &veil_cfg::MailboxPushConfig,
) -> Option<Arc<dyn veil_push::PushDispatcher>> {
    if !cfg.fcm_enabled() {
        return None;
    }
    match veil_push::FcmDispatcher::from_service_account_path(&cfg.fcm_credentials_path) {
        Ok(d) => {
            log::info!(
                "veil-push: FCM dispatcher loaded from {}",
                cfg.fcm_credentials_path,
            );
            Some(d as Arc<dyn veil_push::PushDispatcher>)
        }
        Err(e) => {
            log::warn!(
                "veil-push: FCM credentials at {} failed to load: {e} — provider disabled",
                cfg.fcm_credentials_path,
            );
            None
        }
    }
}

pub fn build_apns_dispatcher(
    cfg: &veil_cfg::MailboxPushConfig,
) -> Option<Arc<dyn veil_push::PushDispatcher>> {
    if !cfg.apns_enabled() {
        return None;
    }
    let env = match cfg.apns_environment.as_str() {
        "" | "production" | "prod" => veil_push::ApnsEnvironment::Production,
        "sandbox" | "dev" | "development" => veil_push::ApnsEnvironment::Sandbox,
        other => {
            log::warn!("veil-push: unknown apns_environment {other:?}, defaulting to production",);
            veil_push::ApnsEnvironment::Production
        }
    };
    match veil_push::ApnsDispatcher::from_p8_path(
        &cfg.apns_p8_path,
        cfg.apns_key_id.clone(),
        cfg.apns_team_id.clone(),
        cfg.apns_bundle_id.clone(),
        env,
    ) {
        Ok(d) => {
            log::info!(
                "veil-push: APNs dispatcher loaded (key_id={}, team_id={}, env={:?})",
                cfg.apns_key_id,
                cfg.apns_team_id,
                env,
            );
            Some(d as Arc<dyn veil_push::PushDispatcher>)
        }
        Err(e) => {
            log::warn!(
                "veil-push: APNs key at {} failed to load: {e} — provider disabled",
                cfg.apns_p8_path,
            );
            None
        }
    }
}

// ── T1.4 followup: hot-reload of FCM/APNs credentials ──────────
//
// Wraps the configured `PushDispatcher` in a tokio RwLock so the
// inner dispatcher can be atomically swapped in/out at runtime when
// the operator rotates credentials. An mtime-watch task polls the
// credential file paths every 60 s; on detected change it rebuilds
// the dispatcher and swaps it in.
//
// This is a deliberate poll-not-notify design: filesystem-watch APIs
// (inotify on Linux, kqueue on BSD) introduce platform-specific
// dependencies and edge cases (file replaced via atomic-rename loses
// the watch). Polling mtime every 60 s is plenty fast for a
// credential rotation operation that operators trigger maybe once a
// quarter, and survives any rename / atomic-replace tactic.

pub struct HotReloadDispatcher {
    inner: tokio::sync::RwLock<Arc<dyn veil_push::PushDispatcher>>,
}

impl HotReloadDispatcher {
    pub(crate) fn new(initial: Arc<dyn veil_push::PushDispatcher>) -> Self {
        Self {
            inner: tokio::sync::RwLock::new(initial),
        }
    }

    pub(crate) async fn swap(&self, new: Arc<dyn veil_push::PushDispatcher>) {
        let mut g = self.inner.write().await;
        *g = new;
    }
}

#[async_trait::async_trait]
impl veil_push::PushDispatcher for HotReloadDispatcher {
    async fn dispatch(
        &self,
        token: &veil_push::PushToken,
        wake_payload: &[u8],
    ) -> Result<(), veil_push::PushError> {
        // Read-lock + clone the Arc — RwLock not held across the
        // potentially-long HTTP call. Push triggers are rare events
        // (per-blob, not per-frame) so the lock contention here is
        // negligible.
        let dispatcher = {
            let g = self.inner.read().await;
            Arc::clone(&*g)
        };
        dispatcher.dispatch(token, wake_payload).await
    }
}

/// Modification time of `path` in seconds since UNIX_EPOCH, or 0 if
/// the file is missing / metadata read failed. Treats missing-file vs
/// present-file as different mtimes so a credential file appearing
/// or disappearing triggers a swap.
pub fn file_mtime_secs(path: &str) -> u64 {
    if path.is_empty() {
        return 0;
    }
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Background task that polls the FCM/APNs credential file mtimes
/// every 60 s and rebuilds the dispatcher when either changes.
/// Returns when `shutdown` fires.
pub(crate) async fn push_creds_watch_task(
    cfg: veil_cfg::MailboxPushConfig,
    hot_reload: Arc<HotReloadDispatcher>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut last_fcm = file_mtime_secs(&cfg.fcm_credentials_path);
    let mut last_apns = file_mtime_secs(&cfg.apns_p8_path);
    let interval = std::time::Duration::from_secs(60);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let cur_fcm = file_mtime_secs(&cfg.fcm_credentials_path);
                let cur_apns = file_mtime_secs(&cfg.apns_p8_path);
                if cur_fcm != last_fcm || cur_apns != last_apns {
                    log::info!(
                        "veil-push: credential mtime changed (fcm: {last_fcm} → {cur_fcm}, \
                         apns: {last_apns} → {cur_apns}) — rebuilding dispatcher",
                    );
                    let new_dispatcher = build_push_dispatcher(&cfg);
                    hot_reload.swap(new_dispatcher).await;
                    last_fcm = cur_fcm;
                    last_apns = cur_apns;
                }
            }
            _ = shutdown.changed() => {
                log::info!("veil-push: cred-watch task stopping");
                break;
            }
        }
    }
}

/// Mint an authenticated wake payload (Epic 489.10 slice 4.4) from a sealed
/// `WakeHmacKey` envelope.
///
/// Returns the 72-byte `ts || content_id || hmac` payload on success, or an
/// EMPTY `Vec` (wake-only fallback) when there is no envelope, the envelope
/// unseals to the wrong key length, or the unseal fails — a wake-envelope
/// problem must never drop the trigger, only degrade to the legacy wake-only
/// push. `ts` is taken as a parameter so this stays a pure, testable function;
/// the live caller passes `SystemTime::now()`.
fn mint_wake_payload(
    wake_hmac_envelope: Option<&[u8]>,
    relay_sk: &x25519_dalek::StaticSecret,
    content_id: &[u8; 32],
    receiver_id: &[u8; 32],
    ts: u64,
) -> Vec<u8> {
    match wake_hmac_envelope {
        Some(env) if !env.is_empty() => {
            match veil_anonymity::push_envelope::unseal_push_envelope(env, relay_sk) {
                Ok(mut kb) if kb.len() == veil_crypto::wake_hmac::WAKE_HMAC_KEY_LEN => {
                    use zeroize::Zeroize as _;
                    let mut key_arr = [0u8; veil_crypto::wake_hmac::WAKE_HMAC_KEY_LEN];
                    key_arr.copy_from_slice(&kb);
                    // Scrub the heap copy returned by `unseal_push_envelope` as
                    // soon as it's transferred into the fixed array — otherwise
                    // the receiver's long-lived wake key lingers in freed heap.
                    kb.zeroize();
                    let key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes(key_arr);
                    // `from_bytes` took `key_arr` by Copy, so the stack array
                    // still holds the key; scrub it too. Only `key`
                    // (ZeroizeOnDrop) may carry the secret past this point —
                    // matching `wake_hmac.rs`'s own zeroization guarantee.
                    key_arr.zeroize();
                    let tag = veil_crypto::wake_hmac::compute_wake_hmac(
                        &key,
                        ts,
                        content_id,
                        receiver_id,
                    );
                    veil_crypto::wake_hmac::encode_wake_payload(ts, content_id, &tag).to_vec()
                }
                Ok(_) => {
                    log::warn!(
                        "veil-push: wake envelope unsealed to wrong key length for receiver {} — wake-only fallback",
                        hex_short(receiver_id),
                    );
                    Vec::new()
                }
                Err(e) => {
                    log::warn!(
                        "veil-push: wake envelope unseal failed for receiver {}: {e} — wake-only fallback",
                        hex_short(receiver_id),
                    );
                    Vec::new()
                }
            }
        }
        _ => Vec::new(),
    }
}

/// Background task that consumes [`PushTrigger`]s, unseals each
/// envelope with the relay's X25519 secret, and dispatches the recovered
/// FCM/APNs token [`veil_push::PushDispatcher`].
///
/// Errors at every step are logged at WARN and the task moves on to
/// the next trigger — a malformed envelope on one push must not stall
/// the rest. The relay does not retry: undelivered pushes are the
/// sender's problem (peer-sync in P4 will retransmit anyway).
pub(crate) async fn push_dispatch_task(
    mut rx: tokio::sync::mpsc::Receiver<PushTrigger>,
    relay_sk: Arc<x25519_dalek::StaticSecret>,
    dispatcher: Arc<dyn veil_push::PushDispatcher>,
    require_wake_hmac: bool,
) {
    while let Some(trigger) = rx.recv().await {
        let plaintext =
            match veil_anonymity::push_envelope::unseal_push_envelope(&trigger.envelope, &relay_sk)
            {
                Ok(p) => p,
                Err(e) => {
                    log::warn!(
                        "veil-push: unseal failed for receiver {}: {e}",
                        hex_short(&trigger.receiver_id),
                    );
                    continue;
                }
            };
        let token = match veil_push::PushToken::decode(&plaintext) {
            Ok(t) => t,
            Err(e) => {
                log::warn!(
                    "veil-push: token decode failed for receiver {}: {e}",
                    hex_short(&trigger.receiver_id),
                );
                continue;
            }
        };
        // Mint an authenticated wake payload when the sender forwarded a sealed
        // WakeHmacKey envelope; otherwise fall back to the legacy wake-only push
        // (empty payload) — never drop the trigger on a wake-envelope problem.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let wake_payload: Vec<u8> = mint_wake_payload(
            trigger.wake_hmac_envelope.as_deref(),
            &relay_sk,
            &trigger.content_id,
            &trigger.receiver_id,
            ts,
        );
        // Production gate (audit cycle-2): when the operator requires
        // authenticated wakes, refuse to emit the legacy wake-only push
        // (empty payload) — an unauthenticated wake is forgeable by anyone who
        // learns the push token and is a battery-drain/nuisance vector. The
        // receiver must opt into wake-HMAC (upload a sealed envelope) to be
        // woken under this policy.
        if require_wake_hmac && wake_payload.is_empty() {
            log::warn!(
                "veil-push: dropping unauthenticated wake-only push for receiver {} \
                 (require_wake_hmac=true; receiver has not uploaded a wake-HMAC envelope)",
                hex_short(&trigger.receiver_id),
            );
            continue;
        }
        if let Err(e) = dispatcher.dispatch(&token, &wake_payload).await {
            log::warn!(
                "veil-push: dispatch failed for receiver {} provider {:?}: {e}",
                hex_short(&trigger.receiver_id),
                token.provider,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Hot-reload of FCM/APNs creds (T1.4 followup) ────────────────────

    use std::sync::atomic::{AtomicUsize, Ordering};
    use veil_push::{LogOnlyDispatcher, PushDispatcher, PushProvider, PushToken};

    /// Counts dispatch invocations so the test can assert which
    /// dispatcher served which call after a swap.
    struct CountingDispatcher {
        tag: &'static str,
        count: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl PushDispatcher for CountingDispatcher {
        async fn dispatch(
            &self,
            _token: &PushToken,
            _wake_payload: &[u8],
        ) -> Result<(), veil_push::PushError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            log::info!("counting-dispatcher: tag={}", self.tag);
            Ok(())
        }
    }

    fn fake_token() -> PushToken {
        PushToken {
            provider: PushProvider::Fcm,
            token: b"fake".to_vec(),
        }
    }

    #[tokio::test]
    async fn t1_4_followup_hot_reload_initial_dispatcher_handles_calls() {
        let counting = Arc::new(CountingDispatcher {
            tag: "initial",
            count: AtomicUsize::new(0),
        });
        let hot = Arc::new(HotReloadDispatcher::new(
            Arc::clone(&counting) as Arc<dyn PushDispatcher>
        ));
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        assert_eq!(counting.count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn t1_4_followup_hot_reload_swap_redirects_calls() {
        let first = Arc::new(CountingDispatcher {
            tag: "first",
            count: AtomicUsize::new(0),
        });
        let second = Arc::new(CountingDispatcher {
            tag: "second",
            count: AtomicUsize::new(0),
        });
        let hot = Arc::new(HotReloadDispatcher::new(
            Arc::clone(&first) as Arc<dyn PushDispatcher>
        ));
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        // Swap.
        hot.swap(Arc::clone(&second) as Arc<dyn PushDispatcher>)
            .await;
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        // First saw exactly 1 call, second saw 2.
        assert_eq!(first.count.load(Ordering::SeqCst), 1);
        assert_eq!(second.count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn t1_4_followup_hot_reload_swap_to_log_only_keeps_dispatcher_alive() {
        // Edge case: operator deletes both creds files between
        // checks → mtime change → rebuild gives LogOnly.
        // Verify the wrapper continues serving without panic.
        let initial: Arc<dyn PushDispatcher> = Arc::new(LogOnlyDispatcher);
        let hot = Arc::new(HotReloadDispatcher::new(initial));
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        let new: Arc<dyn PushDispatcher> = Arc::new(LogOnlyDispatcher);
        hot.swap(new).await;
        hot.dispatch(&fake_token(), &[]).await.unwrap();
        // No panic = test passes.
    }

    #[test]
    fn t1_4_followup_file_mtime_secs_returns_zero_on_missing() {
        assert_eq!(file_mtime_secs(""), 0);
        assert_eq!(file_mtime_secs("/this/path/definitely/does/not/exist"), 0);
    }

    #[test]
    fn t1_4_followup_file_mtime_secs_changes_when_file_touched() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_string_lossy().into_owned();
        let m1 = file_mtime_secs(&path);
        // Touch the file (write resets mtime to now). Sleep enough
        // that a 1-second-resolution filesystem (e.g. ext4) sees a
        // change.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(&path, b"changed").unwrap();
        let m2 = file_mtime_secs(&path);
        assert!(m2 > m1, "mtime should increase after touch ({m1} → {m2})");
    }

    // ── Epic 489.10 slice 4.4: relay-side wake-HMAC mint ────────────────

    fn fixture_relay_x25519() -> (x25519_dalek::StaticSecret, [u8; 32]) {
        use rand_core::OsRng;
        let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    #[test]
    fn t489_10_mint_round_trip_verifies_valid_with_content_id() {
        use veil_crypto::wake_hmac::{WakeHmacKey, WakePayloadVerdict, verify_wake_payload};

        let (relay_sk, relay_pk) = fixture_relay_x25519();
        // Receiver generates a wake-HMAC key and seals it to the relay's
        // X25519 pubkey (slice 4.3.2). Keep a copy of the key bytes so the
        // test can act as the verifying receiver.
        let key = WakeHmacKey::generate();
        let key_bytes = *key.as_bytes();
        let envelope =
            veil_anonymity::push_envelope::seal_push_envelope(&key_bytes, &relay_pk).unwrap();

        let content_id = [0x42u8; 32];
        let receiver_id = [0x99u8; 32];
        let ts = 1_700_000_000u64;

        // Relay mints the authenticated wake payload.
        let payload = mint_wake_payload(Some(&envelope), &relay_sk, &content_id, &receiver_id, ts);
        assert_eq!(
            payload.len(),
            veil_crypto::wake_hmac::WAKE_PAYLOAD_LEN,
            "mint must yield a 72-byte wake payload"
        );

        // Receiver verifies with its own copy of the key.
        let verify_key = WakeHmacKey::from_bytes(key_bytes);
        let verdict = verify_wake_payload(&verify_key, &payload, &receiver_id, ts + 10);
        assert_eq!(
            verdict,
            WakePayloadVerdict::Valid { ts, content_id },
            "minted payload must verify Valid with the bound content_id"
        );
    }

    #[test]
    fn t489_10_mint_none_envelope_yields_empty_wake_only() {
        let (relay_sk, _relay_pk) = fixture_relay_x25519();
        let payload = mint_wake_payload(None, &relay_sk, &[0u8; 32], &[1u8; 32], 1_700_000_000);
        assert!(
            payload.is_empty(),
            "None envelope must fall back to wake-only (empty payload)"
        );
        // Empty slice (sender sent an empty envelope) is also wake-only.
        let payload_empty =
            mint_wake_payload(Some(&[]), &relay_sk, &[0u8; 32], &[1u8; 32], 1_700_000_000);
        assert!(payload_empty.is_empty());
    }

    #[test]
    fn t489_10_mint_wrong_relay_key_yields_empty_wake_only() {
        use veil_crypto::wake_hmac::WakeHmacKey;
        // Envelope sealed to one relay; a different relay sk cannot unseal it,
        // so the mint degrades to wake-only rather than dropping the trigger.
        let (_relay_sk, relay_pk) = fixture_relay_x25519();
        let (attacker_sk, _attacker_pk) = fixture_relay_x25519();
        let key_bytes = *WakeHmacKey::generate().as_bytes();
        let envelope =
            veil_anonymity::push_envelope::seal_push_envelope(&key_bytes, &relay_pk).unwrap();
        let payload = mint_wake_payload(Some(&envelope), &attacker_sk, &[7u8; 32], &[8u8; 32], 123);
        assert!(
            payload.is_empty(),
            "unseal failure (wrong relay key) must fall back to wake-only"
        );
    }

    /// Drive `push_dispatch_task` with a trigger that has NO wake-HMAC envelope
    /// (→ empty/wake-only payload) and assert the dispatch count under each
    /// `require_wake_hmac` setting.
    async fn run_wake_only_trigger(require_wake_hmac: bool) -> usize {
        let (relay_sk, relay_pk) = fixture_relay_x25519();
        // Seal a valid push token so unseal + decode succeed and we reach the gate.
        let envelope =
            veil_anonymity::push_envelope::seal_push_envelope(&fake_token().encode(), &relay_pk)
                .unwrap();
        let counting = Arc::new(CountingDispatcher {
            tag: "gate",
            count: AtomicUsize::new(0),
        });
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(push_dispatch_task(
            rx,
            Arc::new(relay_sk),
            Arc::clone(&counting) as Arc<dyn PushDispatcher>,
            require_wake_hmac,
        ));
        tx.send(PushTrigger {
            receiver_id: [1u8; 32],
            envelope,
            content_id: [2u8; 32],
            wake_hmac_envelope: None, // legacy wake-only
        })
        .await
        .unwrap();
        drop(tx); // close the channel so the task loop terminates
        task.await.unwrap();
        counting.count.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn require_wake_hmac_drops_unauthenticated_wake_only_push() {
        assert_eq!(
            run_wake_only_trigger(true).await,
            0,
            "gate ON: an unauthenticated wake-only push must be dropped"
        );
    }

    #[tokio::test]
    async fn wake_only_push_dispatched_when_gate_off() {
        assert_eq!(
            run_wake_only_trigger(false).await,
            1,
            "gate OFF: legacy wake-only push is still dispatched (back-compat)"
        );
    }
}
