//! Finding a receiver's meeting point again, and sending through it.
//!
//! A rendezvous ad says where a receiver can be reached, and the hard part is
//! not reading one — it is noticing that the one you hold has stopped being
//! true. A receiver rotates relays long before its signed ad expires, so a
//! still-valid local mirror is exactly the wrong thing to trust; the resolver
//! here compares independently-served DHT values instead of accepting the
//! mirror forever.
//!
//! Three pieces, and they are one because the freshness rule is:
//!
//!  * [`RendezvousResolverImpl`] answers `LookupRendezvousReplicas` for the
//!    app, through the IPC server.
//!  * `resolve_fresh_rendezvous_ads` and `replicas_from_freshest_ads` are the
//!    rule itself — newest generation first, KEM-bearing preferred, one
//!    replica per relay, capped.
//!  * [`RuntimeAnonOnionSender`] is the caller that has to be right about it:
//!    a send down a stale replica reaches a relay the receiver has left.
//!
//! Moved verbatim out of `service_tasks.rs` (report24 RUNTIME-3), tests
//! included — the freshness rule and the tests that pin its order belong in
//! one place, and `test_rendezvous_ad` exists for nothing else.

use std::sync::Arc;

use veil_util::lock;

use super::service_tasks::{
    peer_advertised_anonymity_relay, rendezvous_register_publisher_with_kem,
    warm_connected_relay_directory,
};

// ── T1.4 P5c: rendezvous-replica resolver ──────────────────────
//
// Replica-aware lookup for the receiver's RendezvousAd. Apps call
// `LocalAppMsg::LookupRendezvousReplicas` → IPC server → this impl, which
// periodically compares independently-served DHT values instead of accepting
// one still-valid local mirror forever. This matters because receiver relay
// rotation invalidates reachability before the old signed ad itself expires.

pub struct RendezvousResolverImpl {
    dht: Arc<veil_dht::KademliaService>,
    // Shared refs for the recursive DHT walk (so resolve_replicas can find a
    // receiver's rendezvous ad CROSS-NODE, not just in the local mirror cache).
    session_tx_registry: Arc<std::sync::RwLock<veil_session::SessionTxRegistry>>,
    pending_recursive: Arc<
        std::sync::Mutex<std::collections::HashMap<[u8; 16], veil_dispatcher::PendingRecursive>>,
    >,
    local_node_id: [u8; 32],
    resolve_cache: Arc<super::anonymity_state::RendezvousResolveCache>,
    logger: Arc<veil_observability::NodeLogger>,
}

impl RendezvousResolverImpl {
    pub(crate) fn new(
        dht: Arc<veil_dht::KademliaService>,
        session_tx_registry: Arc<std::sync::RwLock<veil_session::SessionTxRegistry>>,
        pending_recursive: Arc<
            std::sync::Mutex<
                std::collections::HashMap<[u8; 16], veil_dispatcher::PendingRecursive>,
            >,
        >,
        local_node_id: [u8; 32],
        resolve_cache: Arc<super::anonymity_state::RendezvousResolveCache>,
        logger: Arc<veil_observability::NodeLogger>,
    ) -> Self {
        Self {
            dht,
            session_tx_registry,
            pending_recursive,
            local_node_id,
            resolve_cache,
            logger,
        }
    }
}

/// Enrol a send-path receiver in the refresh-ahead set — unless it is us.
///
/// The proactive set exists to spare the SEND path a synchronous DHT walk, and
/// no send goes to our own rendezvous ad: reaching ourselves needs no route.
/// Enrolling self turns a one-off self-resolve into a standing subscription,
/// because the refresher re-walks every member once per cache TTL forever.
///
/// Measured 23.08 on an idle phone with zero contacts: **2536** FIND_VALUE
/// walks of its OWN eight ad slots in 80 minutes, dead on 15.0s, **53%** of
/// every DHT frame it exchanged. The refresh task's own doc promises "a node
/// that stops messaging adds zero steady-state DHT load"; for the single
/// receiver id that can never be messaged, that promise was inverted.
///
/// Self still resolves on demand — the mailbox drain's cold path needs it. It
/// just does not buy a standing subscription.
fn note_send_target(
    resolve_cache: &Arc<super::anonymity_state::RendezvousResolveCache>,
    receiver_id: [u8; 32],
    local_node_id: [u8; 32],
) {
    if receiver_id == local_node_id {
        // WHICH caller resolves self was not answerable from any log —
        // measurement could name the frames and the keys, never the origin.
        // Left as an instrument rather than another guess.
        log::debug!(
            "rendezvous.resolve.self receiver={} — walking, not enrolling in refresh-ahead",
            veil_util::hex_short(&receiver_id),
        );
        return;
    }
    resolve_cache.note_send_use(receiver_id);
}

/// Resolve every requested rendezvous-ad slot from independent connected DHT
/// peers, compare all still-valid signed candidates by publication time, and
/// write the winner for each slot back into the local mirror.  A plain
/// `recursive_dht_get` cannot do this: its valid-local fast path returns an old
/// ad immediately, even after the receiver moved to another relay, so the
/// sender keeps producing `cookie_unknown` until the ad expires.
#[allow(clippy::too_many_arguments)]
pub(super) async fn resolve_fresh_rendezvous_ads(
    dht: &Arc<veil_dht::KademliaService>,
    session_tx_registry: &Arc<std::sync::RwLock<veil_session::SessionTxRegistry>>,
    pending_recursive: &Arc<
        std::sync::Mutex<std::collections::HashMap<[u8; 16], veil_dispatcher::PendingRecursive>>,
    >,
    local_node_id: [u8; 32],
    resolve_cache: &Arc<super::anonymity_state::RendezvousResolveCache>,
    logger: &Arc<veil_observability::NodeLogger>,
    receiver_id: [u8; 32],
    timeout: std::time::Duration,
    // `true` for the background refresh-ahead task: bypass the cache
    // fast-paths (the entry is still TTL-fresh — that's WHY it can be
    // re-walked before a send hits an expired one) and don't mark the
    // receiver as send-active (the refresher must not keep itself alive).
    force_refresh: bool,
) -> Vec<veil_anonymity::rendezvous::RendezvousAd> {
    use veil_anonymity::rendezvous::{
        MAX_RENDEZVOUS_AD_SLOTS, decode_rendezvous_ad, is_currently_valid,
        rendezvous_ad_dht_key_at, verify_rendezvous_ad,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if !force_refresh {
        // Feed the refresh-ahead task: this receiver is being actively sent
        // to, keep its route warm for the activity window.
        //
        // OURSELF never qualifies. The proactive set exists to spare the SEND
        // path a synchronous walk, and no send goes to our own rendezvous ad —
        // reaching ourselves needs no route. Enrolling self turned a one-off
        // self-resolve into a permanent 8-walks-per-TTL loop: measured 23.08 on
        // an idle phone with zero contacts, 2536 FIND_VALUE walks of its OWN ad
        // slots in 80 minutes, dead on 15.0s, 53% of every DHT frame it
        // exchanged. The doc on the refresh task promises "a node that stops
        // messaging adds zero steady-state DHT load"; for the one receiver id
        // that can never be messaged, that promise was inverted.
        //
        // Resolving self still WORKS — the walk below runs as asked, and the
        // mailbox drain's cold path depends on it. It just does not buy a
        // standing subscription to re-walk forever.
        note_send_target(resolve_cache, receiver_id, local_node_id);
        if let Some(ads) = resolve_cache.get(&receiver_id, now) {
            return ads;
        }
    }
    let _refresh_guard = resolve_cache.lock_refresh(receiver_id).await;
    // Another send may have completed the refresh while this one waited for
    // the per-recipient single-flight lock.
    if !force_refresh && let Some(ads) = resolve_cache.get(&receiver_id, now) {
        return ads;
    }

    // Always fill the cache from every system slot. The IPC caller may request
    // only one returned replica, but caching that partial lookup would hide a
    // fresher ad in another slot from the live send path for the cache TTL.
    // OUR OWN ad needs no network. The walk exists because a cached ad can be
    // stale — the receiver may have moved to another relay since it was
    // resolved. For our own ad that cannot happen: we ARE the receiver, and
    // the local mirror is exactly what we wrote when we published. Asking the
    // network where our own advertisement is means asking strangers what we
    // just told them.
    //
    // Measured 23.08 on an idle node: the pinned-circuit refresh
    // (`CIRCUIT_IDLE_REFRESH_AFTER`) drove one full 8-slot walk of our OWN
    // slots every ~304 s, forever — the node's log shows one of them starting
    // 22 s after `rendezvous_ad.published` wrote the very ads it went looking
    // for. That was about half of all recursive DHT traffic an idle phone
    // exchanged.
    //
    // Falls through to the walk when the mirror holds nothing: the mailbox
    // drain's cold path (not registered anywhere yet) depends on it, and so
    // does a node whose ads have expired.
    let mut ads = Vec::new();
    if receiver_id == local_node_id {
        ads.extend(
            (0..MAX_RENDEZVOUS_AD_SLOTS)
                .filter_map(|idx| dht.get_local(&rendezvous_ad_dht_key_at(&receiver_id, idx)))
                .filter_map(|bytes| decode_rendezvous_ad(&bytes).ok())
                .filter(|ad| ad.receiver_node_id == receiver_id)
                .filter(|ad| verify_rendezvous_ad(ad).is_ok())
                .filter(|ad| is_currently_valid(ad, now).is_ok()),
        );
    }
    let from_local_mirror = !ads.is_empty();

    let walks = (0..MAX_RENDEZVOUS_AD_SLOTS).map(|idx| {
        let key = rendezvous_ad_dht_key_at(&receiver_id, idx);
        async move {
            let candidates = crate::mlkem_resolver::recursive_dht_get_candidates(
                dht,
                session_tx_registry,
                pending_recursive,
                local_node_id,
                key,
                timeout,
                // Query every normal replication holder we can reach directly.
                // On the three-seed production topology this deliberately asks
                // all three instead of accepting whichever seed replies first.
                veil_proto::budget::DHT_REPLICATION_K,
                |bytes| {
                    decode_rendezvous_ad(bytes)
                        .ok()
                        .filter(|ad| ad.receiver_node_id == receiver_id)
                        .filter(|ad| verify_rendezvous_ad(ad).is_ok())
                        .filter(|ad| is_currently_valid(ad, now).is_ok())
                        .is_some()
                },
            )
            .await;
            (idx, key, candidates)
        }
    });

    for (_idx, key, candidates) in if ads.is_empty() {
        futures::future::join_all(walks).await
    } else {
        Vec::new()
    } {
        let mut decoded: Vec<_> = candidates
            .into_iter()
            .filter_map(|bytes| decode_rendezvous_ad(&bytes).ok().map(|ad| (ad, bytes)))
            .collect();
        // Repair the ordinary local DHT mirror with this slot's newest
        // publication. The short resolve cache still controls when the next
        // network comparison happens; the local write merely keeps other DHT
        // consumers from seeing a known-older value meanwhile.
        decoded.sort_by_key(|(ad, _)| std::cmp::Reverse(ad.valid_from_unix));
        if let Some((_, bytes)) = decoded.first() {
            dht.store_local(key, bytes.clone());
        }
        ads.extend(decoded.into_iter().map(|(ad, _)| ad));
    }

    // Dedupe identical signed ads returned by several replica holders, while
    // preserving distinct relay/slot publications for the caller's policy.
    ads.sort_by(|a, b| {
        b.valid_from_unix
            .cmp(&a.valid_from_unix)
            .then_with(|| a.rendezvous_node_id.cmp(&b.rendezvous_node_id))
            .then_with(|| a.auth_cookie.cmp(&b.auth_cookie))
    });
    ads.dedup_by(|a, b| {
        a.valid_from_unix == b.valid_from_unix
            && a.rendezvous_node_id == b.rendezvous_node_id
            && a.auth_cookie == b.auth_cookie
    });

    if !ads.is_empty() {
        logger.info(
            "anonymity.rendezvous.resolve.refreshed",
            format!(
                "receiver={} source={} candidates={} freshest_relay={} valid_from={}",
                veil_util::hex_short(&receiver_id),
                // Say WHERE the ads came from. Without this the line reads
                // "refreshed" for a purely local read and an operator counting
                // it would see a DHT walk that never happened — the instrument
                // lying by its own name.
                if from_local_mirror { "local" } else { "dht" },
                ads.len(),
                veil_util::hex_short(&ads[0].rendezvous_node_id),
                ads[0].valid_from_unix,
            ),
        );
        resolve_cache.put(receiver_id, ads.clone());
    }
    ads
}

/// Adapts the runtime's `NodeServices` to the IPC-layer [`veil_types::
/// AnonOnionSender`] trait, so the `anonymous_authenticated` send flag can
/// originate an authenticated anonymous onion send without veil-ipc depending
/// on veil-node-runtime. Holds the access bundle + the configured hop count.
pub(crate) struct RuntimeAnonOnionSender {
    access: super::NodeServices,
    hop_count: usize,
}

impl RuntimeAnonOnionSender {
    pub(crate) fn new(access: super::NodeServices, hop_count: usize) -> Self {
        Self { access, hop_count }
    }
}

fn replicas_from_freshest_ads(
    mut ads: Vec<veil_anonymity::rendezvous::RendezvousAd>,
    cap: usize,
) -> Vec<veil_ipc::ResolvedReplica> {
    // GENERATION gate (mirrors the live-introduce spread): the receiver
    // re-signs all its plain ads together with one shared valid_from stamp
    // (see tick_publish_rendezvous_ads), so the newest stamp identifies its
    // CURRENT relay set. Depositing at a relay from an older generation puts
    // the blob where the receiver may no longer be registered or drain —
    // wasted (or lost, if every copy lands stale). Small skew tolerance for
    // ads fetched from lagging replicas mid-republish.
    const DEPOSIT_GENERATION_SKEW_SECS: u64 = 30;
    if let Some(newest) = ads.iter().map(|a| a.valid_from_unix).max() {
        let gated: Vec<_> = ads
            .iter()
            .filter(|a| {
                a.valid_from_unix
                    .saturating_add(DEPOSIT_GENERATION_SKEW_SECS)
                    >= newest
            })
            .cloned()
            .collect();
        // Never gate down to nothing usable: an all-stale view (resolver hit
        // only lagging replicas) still deposits somewhere rather than failing.
        if !gated.is_empty() {
            ads = gated;
        }
    }
    ads.sort_by(|a, b| {
        // Prefer an ad that carries a usable KEM key. A KEM-less ad (empty
        // `rendezvous_kem_pk`) can never be sealed to for offline delivery, so it
        // must lose to ANY KEM-bearing ad regardless of recency — otherwise a
        // stale, long-lived KEM-less ad (e.g. a pre-KEM-preserve publisher's 24h
        // ad) outranks the publisher's fresh but shorter-lived KEM ad purely by
        // `valid_until`, the sender resolves the KEM-less one, and offline
        // delivery to that receiver silently fails (usable(KEM)=0 at the sender).
        // Only when NO KEM-bearing ad exists do we fall back to a KEM-less one.
        let a_kemless = a.rendezvous_kem_pk.is_empty();
        let b_kemless = b.rendezvous_kem_pk.is_empty();
        a_kemless
            .cmp(&b_kemless) // false (KEM-bearing) sorts before true (KEM-less)
            // Then prefer the most-recently-PUBLISHED ad, by `valid_from_unix`
            // (set to now_unix at publish — see maintenance.rs) — NOT
            // `valid_until_unix`. The ad's `auth_cookie` is PER-PERIOD
            // (derive_onion_auth_cookie(seed, now/86400)), so an ad published in a
            // previous period carries an OLD cookie that no longer matches what the
            // receiver currently registers at its relay. Ranking by `valid_until`
            // preferred a yesterday-published 24h ad (old cookie, long window) over
            // today's 1h ad (fresh cookie, short window): the sender copied the old
            // cookie into its introduce and the relay dropped EVERY introduce with
            // `cookie_unknown` (observed ~95-98% loss on the onion content path).
            // `valid_from` makes the current-period ad win, so its cookie matches
            // the receiver's live registration.
            .then_with(|| b.valid_from_unix.cmp(&a.valid_from_unix))
            .then_with(|| a.rendezvous_node_id.cmp(&b.rendezvous_node_id))
    });

    let mut out = Vec::with_capacity(cap);
    let mut seen_relays: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for ad in ads {
        if !seen_relays.insert(ad.rendezvous_node_id) {
            continue;
        }
        out.push(veil_ipc::ResolvedReplica {
            relay_node_id: ad.rendezvous_node_id,
            valid_until_unix: ad.valid_until_unix,
            push_envelope: ad.push_envelope,
            capability_token: ad.capability_token,
            wake_hmac_envelope: ad.wake_hmac_envelope,
            rendezvous_kem_algo: ad.rendezvous_kem_algo,
            rendezvous_kem_pk: ad.rendezvous_kem_pk,
        });
        if out.len() >= cap {
            break;
        }
    }
    out
}

impl veil_types::AnonOnionSender for RuntimeAnonOnionSender {
    fn send_authenticated<'a>(
        &'a self,
        receiver_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_anonymous_authenticated_to(
                    receiver_node_id,
                    app_id,
                    endpoint_id,
                    data,
                    self.hop_count,
                    None,
                )
                .await
        })
    }

    fn send_authenticated_with_reply<'a>(
        &'a self,
        receiver_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
        reply_app_id: [u8; 32],
        reply_endpoint_id: u32,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_anonymous_authenticated_to(
                    receiver_node_id,
                    app_id,
                    endpoint_id,
                    data,
                    self.hop_count,
                    Some((reply_app_id, reply_endpoint_id)),
                )
                .await
        })
    }

    fn send_authenticated_direct_with_reply<'a>(
        &'a self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
        reply: Option<([u8; 32], u32)>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            // Cold-boot / no-session gate: the reply-path warm below and
            // `select_onion_relay_path` resolve relay directories OVER live
            // sessions. On the FIRST drain tick right after arm — before any
            // handshake completes — there are zero active sessions, so the warm
            // is a no-op and select returns have:0, emitting a spurious
            // `reply_path_failed` / `send_failed` WARN (device-observed: exactly
            // one per cold boot, then the next tick succeeds once a session is
            // up). Skip this round quietly and return NoRelays (NOT Ok, so the
            // caller does not mark the relay drained) — the drain retries and,
            // with a session up, the RD warms in one direct hop and the fetch
            // lands.
            {
                let active = lock!(self.access.live_sessions)
                    .values()
                    .filter(|i| i.state == crate::types::SessionState::Active)
                    .count();
                if active == 0 {
                    log::debug!(
                        "mailbox.fetch skipped for {}: no active session yet (cold boot)",
                        veil_util::hex_short(&target_node_id),
                    );
                    return Err(veil_types::AnonOnionSendError::NoRelays);
                }
            }
            // The FETCH's reply path builds an onion circuit, which needs the
            // connected relays' relay-directory entries (R terminus + middles)
            // fresh in the LOCAL store. Those cached entries expire between the
            // relays' republish rounds, so a whole drain pass used to fail
            // bursty NoRelays ("status 2") until a republish drifted in.
            // Actively re-warm first — the exact pre-warm the ad-resolving
            // send path already runs; no-op (zero RPC) when everything is
            // cached and fresh.
            let outbox: Arc<dyn veil_dht::FrameRouter> =
                Arc::clone(&self.access.session_outbox) as Arc<dyn veil_dht::FrameRouter>;
            warm_connected_relay_directory(
                &self.access.live_sessions,
                &self.access.dht,
                &outbox,
                &self.access.logger,
                Some(&self.access.dispatcher.crypto.peer_cap_flags),
            )
            .await;
            // Reverse-leg RD-staleness fix: the reply block's circuit
            // (`select_onion_relay_path`) needs R + `REPLY_CIRCUIT_HOPS-1` middles
            // with fresh RDs. The connected warm above caches only session-backed
            // relays' RDs — one on mobile — so the reply path fails
            // `middles_insufficient` / `have: 0` and the drain's ACK never returns.
            // Additionally pull the KNOWN relay set's RDs over whatever session
            // exists (bounded + freshness-gated → no-op when already warm).
            {
                let mut relays: Vec<[u8; 32]> = self
                    .access
                    .dht
                    .routing_table_contacts()
                    .into_iter()
                    .map(|c| c.node_id)
                    .collect();
                // Union in the ACTIVE live-session relays. The reply circuit's
                // middle selection (`select_onion_relay_path_to`) draws candidates
                // from routing_table ∪ live_sessions, but this warm sourced only the
                // routing table. On mobile the seeds are frequently present as live
                // sessions yet ABSENT from the routing table (it thins across Doze),
                // so their RD was never fetched here → the middle selection filtered
                // them as missing → `middles_insufficient` → the drain's reply circuit
                // never built and desktop→phone stalled intermittently. Mirror the
                // selector's candidate set so every relay it might pick as a middle
                // gets its RD warmed first. Freshness-gated + capped ⇒ a no-op (zero
                // RPC) whenever those RDs are already fresh, so no extra radio wakeups.
                {
                    let g = lock!(self.access.live_sessions);
                    relays.extend(
                        g.values()
                            .filter(|i| i.state == crate::types::SessionState::Active)
                            .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes())),
                    );
                }
                relays.sort_unstable();
                relays.dedup();
                relays.retain(|n| {
                    peer_advertised_anonymity_relay(
                        &self.access.dispatcher.crypto.peer_cap_flags,
                        n,
                    )
                });
                self.access
                    .warm_known_relay_directory(&relays, 6, std::time::Duration::from_secs(5))
                    .await;
            }
            // The KEM-key-given direct send: a source-routed onion straight to
            // the known relay (NO ad resolve), authenticated. With `reply` a
            // one-time block rides along so the relay answers over our return
            // circuit (the mailbox FETCH); without it nothing comes back and no
            // reply circuit is built (the ACK).
            self.access
                .send_anonymous_authenticated_direct_with_reply(
                    target_node_id,
                    target_x25519_pk,
                    app_id,
                    endpoint_id,
                    data,
                    self.hop_count,
                    reply,
                )
                .await
                .map_err(|e| {
                    // Every daemon-side FETCH rejection funnels through here
                    // before the coarse AnonOnionSendError→u16 collapse the
                    // client reports as "status 2" — log the real SenderError
                    // so failure bursts are diagnosable.
                    match &e {
                        veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                            ..
                        } => log::debug!(
                            "mailbox.fetch.route_unavailable relay={} err={e:?}",
                            veil_util::hex_short(&target_node_id),
                        ),
                        _ => log::warn!(
                            "mailbox.fetch.send_failed relay={} err={e:?}",
                            veil_util::hex_short(&target_node_id),
                        ),
                    }
                    super::map_sender_err(e)
                })
        })
    }

    fn send_reply<'a>(
        &'a self,
        reply_id: u64,
        data: &'a [u8],
        src_app_id: [u8; 32],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_reply(reply_id, data, self.hop_count, src_app_id)
                .await
        })
    }

    fn register_onion_service<'a>(
        &'a self,
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .register_onion_service(hop_count)
                .map(|_cookie| ())
        })
    }

    fn register_rendezvous_publisher(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        validity_window_secs: u64,
        relay_kem_algo: u8,
        relay_kem_pk: Vec<u8>,
        relay_kem_valid_until_unix: u64,
    ) -> bool {
        rendezvous_register_publisher_with_kem(
            &self.access.anonymity,
            &rendezvous_node_id,
            auth_cookie,
            validity_window_secs,
            relay_kem_algo,
            relay_kem_pk,
            relay_kem_valid_until_unix,
        )
    }

    fn send_to_onion_service<'a>(
        &'a self,
        service_identity_vk: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_to_onion_service(
                    service_identity_vk,
                    app_id,
                    endpoint_id,
                    data,
                    hop_count,
                    None,
                )
                .await
        })
    }

    fn send_to_onion_service_anonymous<'a>(
        &'a self,
        service_identity_vk: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &'a [u8],
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_to_onion_service_anonymous(
                    service_identity_vk,
                    app_id,
                    endpoint_id,
                    src_app_id,
                    data,
                    hop_count,
                )
                .await
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn send_anonymous_direct<'a>(
        &'a self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &'a [u8],
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.access
                .send_anonymous(
                    target_node_id,
                    target_x25519_pk,
                    target_app_id,
                    target_endpoint_id,
                    src_app_id,
                    data,
                    hop_count,
                )
                .map_err(super::map_sender_err)
        })
    }
}

impl veil_ipc::RendezvousReplicaResolver for RendezvousResolverImpl {
    fn resolve_replicas<'a>(
        &'a self,
        receiver_id: [u8; 32],
        max_replicas: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Vec<veil_ipc::ResolvedReplica>> + Send + 'a>,
    > {
        Box::pin(async move {
            // Walk every slot up to caller's cap or system max
            // whichever is lower. Slot 0 produces the same key as
            // legacy single-key publishers, so pre-T1.4 senders still
            // see one entry; new senders see all K configured slots.
            let cap = max_replicas
                .max(1)
                .min(veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS as usize);
            // Walk all slots CONCURRENTLY — bounded total ≈ ONE walk's timeout,
            // not cap × timeout — so resolve_replicas returns within the IPC
            // reply window (5s) even when every slot misses (e.g. the ad hasn't
            // replicated yet). The local-fast-path validator only trusts a cached
            // ad that decodes, verifies, names this receiver, and is currently
            // valid (mirror-cache-poison resistant); remote results re-verified.
            let mut ads = resolve_fresh_rendezvous_ads(
                &self.dht,
                &self.session_tx_registry,
                &self.pending_recursive,
                self.local_node_id,
                &self.resolve_cache,
                &self.logger,
                receiver_id,
                std::time::Duration::from_millis(3500),
                false,
            )
            .await;
            // The DHT copy of a receiver's ads disappears as soon as it stops
            // republishing them, and a dozing phone stops within minutes — the
            // very recipient the offline mailbox is for. An empty walk is not
            // evidence the relay set moved; the ad we already hold is signed
            // good for 24 hours. See `last_known_valid` for why this is the
            // deposit path's call to make and never the live path's.
            if ads.is_empty() {
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if let Some(stale) = self.resolve_cache.last_known_valid(&receiver_id, now_unix) {
                    self.logger.info(
                        "anonymity.rendezvous.resolve.last_known",
                        format!(
                            "receiver={} no live ad in the DHT; depositing at {} \
                             previously-validated replica(s) still inside their \
                             signed validity",
                            veil_util::hex_short(&receiver_id),
                            stale.len(),
                        ),
                    );
                    ads = stale;
                }
            }
            // Prefer the freshest signed ad before relay dedup. This avoids
            // returning a stale pre-cookie-fix ad just because it was in a
            // lower-numbered slot for the same relay.
            replicas_from_freshest_ads(ads, cap)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rendezvous_ad(
        relay_tag: u8,
        valid_until_unix: u64,
        kem_tag: u8,
    ) -> veil_anonymity::rendezvous::RendezvousAd {
        veil_anonymity::rendezvous::RendezvousAd {
            receiver_node_id: [0x11; 32],
            rendezvous_node_id: [relay_tag; 32],
            auth_cookie: [0x22; 16],
            receiver_x25519_pk: [0x33; 32],
            // Freshness now ranks by valid_from (publish time); make the helper's
            // valid_from track its valid_until so the existing "higher rank wins"
            // tests still express the same ordering. The dedicated divergence test
            // below sets valid_from / valid_until independently.
            valid_from_unix: 1_700_000_000 + valid_until_unix,
            valid_until_unix,
            issuer_pk: String::new(),
            issuer_algo: veil_types::SignatureAlgorithm::Ed25519,
            signature: Vec::new(),
            push_envelope: Vec::new(),
            capability_token: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: vec![kem_tag; 32],
            wire_version: 5,
        }
    }

    #[test]
    fn rendezvous_replicas_prefer_freshest_before_relay_dedup() {
        // Same-generation stamps (within the deposit skew window): the same
        // relay's freshest ad wins the dedup, the other relay stays.
        let stale_same_relay = test_rendezvous_ad(0xA1, 280, 1);
        let fresh_other_relay = test_rendezvous_ad(0xB2, 290, 2);
        let fresh_same_relay = test_rendezvous_ad(0xA1, 300, 3);

        let out = replicas_from_freshest_ads(
            vec![stale_same_relay, fresh_other_relay, fresh_same_relay],
            8,
        );

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].relay_node_id, [0xA1; 32]);
        assert_eq!(out[0].valid_until_unix, 300);
        assert_eq!(out[0].rendezvous_kem_pk, vec![3; 32]);
        assert_eq!(out[1].relay_node_id, [0xB2; 32]);
        assert_eq!(out[1].valid_until_unix, 290);
    }

    #[test]
    fn rendezvous_replicas_gate_out_older_generations() {
        // The receiver batch-stamps all its plain ads with one valid_from (see
        // tick_publish_rendezvous_ads), so a much older stamp is a PREVIOUS
        // relay set — depositing there wastes (or loses) the blob. The gate
        // drops it, but never gates down to an empty result.
        let old_generation = test_rendezvous_ad(0xA1, 100, 1);
        let current = test_rendezvous_ad(0xB2, 300, 2);

        let out = replicas_from_freshest_ads(vec![old_generation.clone(), current], 8);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].relay_node_id, [0xB2; 32]);

        // An all-stale view (resolver hit only lagging replicas) still
        // deposits somewhere rather than failing.
        let out = replicas_from_freshest_ads(vec![old_generation], 8);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].relay_node_id, [0xA1; 32]);
    }

    #[test]
    fn rendezvous_replicas_prefer_kem_bearing_over_a_fresher_kemless() {
        // The on-device regression: a stale KEM-LESS ad with a LATER valid_until
        // must NOT shadow a fresh KEM-bearing ad — sealing offline mail needs the
        // KEM key, so a KEM-less winner means usable(KEM)=0 and delivery fails.
        let stale_kemless = veil_anonymity::rendezvous::RendezvousAd {
            rendezvous_kem_pk: Vec::new(), // no relay KEM key
            ..test_rendezvous_ad(0xA1, 120, 0)
        };
        // Slightly earlier stamp, same generation (within the deposit skew
        // window) — a KEM-bearing ad must still outrank the KEM-less one.
        let fresh_kem = test_rendezvous_ad(0xB2, 100, 7);

        let out = replicas_from_freshest_ads(vec![stale_kemless, fresh_kem], 8);

        assert_eq!(out.len(), 2);
        // The KEM-bearing ad wins despite its EARLIER valid_until.
        assert_eq!(out[0].relay_node_id, [0xB2; 32]);
        assert_eq!(out[0].rendezvous_kem_pk, vec![7; 32]);
        // The KEM-less ad is still returned, but only as the last-resort fallback.
        assert_eq!(out[1].relay_node_id, [0xA1; 32]);
        assert!(out[1].rendezvous_kem_pk.is_empty());
    }

    #[test]
    fn rendezvous_replicas_prefer_freshest_published_not_longest_valid() {
        // THE cookie_unknown root cause. The auth_cookie is per-PERIOD, so the ad
        // PUBLISHED most recently (highest valid_from) carries the cookie that
        // matches the receiver's current registration. A stale ad published in a
        // previous period but with a LONGER validity window (later valid_until)
        // carries an OLD cookie. Selection must prefer the fresh-publish ad even
        // though it expires sooner — otherwise the sender's introduce is dropped
        // with cookie_unknown. Same relay so dedup keeps exactly one.
        let now = 1_700_000_000u64;
        let stale_long = veil_anonymity::rendezvous::RendezvousAd {
            rendezvous_node_id: [0xA1; 32],
            valid_from_unix: now - 86_400, // published yesterday (old-period cookie)
            valid_until_unix: now + 3600,  // ...but a long 24h-ish window
            rendezvous_kem_pk: vec![1; 32],
            ..test_rendezvous_ad(0xA1, 0, 1)
        };
        let fresh_short = veil_anonymity::rendezvous::RendezvousAd {
            rendezvous_node_id: [0xA1; 32],
            valid_from_unix: now,        // published now (current-period cookie)
            valid_until_unix: now + 600, // ...short window — would LOSE on valid_until
            rendezvous_kem_pk: vec![2; 32],
            ..test_rendezvous_ad(0xA1, 0, 2)
        };
        let out = replicas_from_freshest_ads(vec![stale_long, fresh_short], 8);
        assert_eq!(out.len(), 1, "same relay dedups to one");
        assert_eq!(
            out[0].rendezvous_kem_pk,
            vec![2; 32],
            "the freshest-PUBLISHED ad (current-period cookie) must win, not the \
             longest-valid stale one",
        );
    }

    #[test]
    fn rendezvous_replicas_respect_cap_after_freshness_sort() {
        let out = replicas_from_freshest_ads(
            vec![
                test_rendezvous_ad(0xA1, 100, 1),
                test_rendezvous_ad(0xB2, 300, 2),
                test_rendezvous_ad(0xC3, 200, 3),
            ],
            1,
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].relay_node_id, [0xB2; 32]);
        assert_eq!(out[0].valid_until_unix, 300);
    }

    /// The refresh-ahead set must never contain us.
    ///
    /// Asserted through the CACHE, not through the predicate: what matters is
    /// that the background refresher gets no candidate, and that a real peer
    /// still does. A predicate-only test would pass just as happily if the
    /// call site had the arms the wrong way round.
    #[test]
    fn resolving_our_own_ad_does_not_subscribe_us_to_refresh_ahead() {
        let me = [1u8; 32];
        let peer = [2u8; 32];
        let cache = Arc::new(super::super::anonymity_state::RendezvousResolveCache::new());
        let window = std::time::Duration::from_secs(300);
        let margin = std::time::Duration::from_secs(6);

        super::note_send_target(&cache, me, me);
        assert!(
            cache.refresh_candidates(window, margin).is_empty(),
            "self-resolve enrolled us; the refresher would re-walk our own 8 ad \
             slots once per TTL forever"
        );

        super::note_send_target(&cache, peer, me);
        assert_eq!(
            cache.refresh_candidates(window, margin),
            vec![peer],
            "a genuine send target must still be kept warm — the whole point of \
             the proactive set"
        );
    }
}
