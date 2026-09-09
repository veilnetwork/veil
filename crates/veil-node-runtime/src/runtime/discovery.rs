//! The three meeting points, and nothing else.
//!
//! A node that knows nobody has to be told about somebody, and this is where
//! that asking happens: BitTorrent's Mainline DHT (layer 7), Nostr relays
//! (layer 8) and the local network (layer 9). They are one lifecycle by every
//! measure that matters — each is a loop that decides WHETHER to look
//! (`meeting_policy`), looks, and publishes about this node only when
//! `global.bootstrap` says to; each reads the same announcement of what a
//! stranger could dial; and a change to what this node says about itself has
//! to land in all three or it lands in none.
//!
//! They lived in `service_tasks.rs` among fifteen unrelated lifecycles, which
//! is how the last defect here happened: the announcement was captured once
//! before the loop in every one of them, and a listener that rotated left all
//! three publishing a port that had closed (report24 RUNTIME-3). Finding that
//! meant reading three widely separated stretches of a ten-thousand-line file
//! and noticing they were the same shape.
//!
//! What stayed behind, deliberately: the helpers these call
//! (`current_announcement`, `admit_lan_peer`, `dial_and_learn`, the rendezvous
//! address rules) are shared with bootstrap and its watchdog, so moving them
//! would have split THEIR lifecycle instead. Extraction without behaviour
//! change is the whole of this commit — every line below is the line that was
//! there, and the tests that read this source moved with it.

use std::sync::Arc;
use veil_util::lock;

use crate::types::{PeerConfigEntry, PeerId};

use super::service_tasks::{
    LAN_CANDIDATE_GRACE, LanCandidate, MAX_LAN_PEERS, MAX_RENDEZVOUS_ATTEMPTS,
    MAX_RENDEZVOUS_PEERS, RENDEZVOUS_INTERVAL, addresses_we_already_hold, admit_lan_peer,
    bound_ports, current_announcement, dial_and_learn, evict_lan_candidate, free_lan_slot,
    lan_announce_for, rendezvous_address_is_new, rendezvous_address_is_self,
    rendezvous_destination_is_dialable, rendezvous_dial_scheme, stale_lan_candidates,
    we_should_place_the_call,
};
use super::{
    NodeRuntime, derive_node_id_from_bootstrap_peer, lock_state, lock_tasks, supervised_spawn,
};

impl NodeRuntime {
    pub fn spawn_mainline_discovery_task(&mut self, config: &veil_cfg::Config) {
        if !config
            .global
            .meeting_points
            .includes(veil_cfg::MeetingPoint::DhtBitTorrent)
        {
            return;
        }
        let my_pubkey = self.identity.local_identity.public_key.clone();

        // What we would tell the LAN about ourselves answers the same question
        // here: which listener a stranger could dial. The DHT carries no scheme,
        // so the one we advertise is the one we expect of others -- a network
        // runs one transport.
        //
        // Recomputed INSIDE the loop, from the listener table, because a
        // listener rotates: captured here once, it was published for the life
        // of the process, and the port it named closed with the old listener's
        // grace (report24 RUNTIME-3).
        let my_nonce = self.identity.local_identity.nonce.clone();
        let announce_config = config.clone();
        let network = if cfg!(feature = "testnet-seeds") {
            veil_mainline::rendezvous::Network::Testnet
        } else {
            veil_mainline::rendezvous::Network::Production
        };
        let announce_self = config.global.bootstrap;
        let policy = config.global.meeting_policy;
        let want_peers = config.global.meeting_min_peers;
        let live_sessions = Arc::clone(&self.live_sessions);
        let dial_scheme = rendezvous_dial_scheme(config);

        let logger = self.logger.clone();
        let access = self.access();
        let state = Arc::clone(&self.state);

        let Some(shutdown_tx) = self.shutdown_tx.clone() else {
            return;
        };
        let handle = supervised_spawn(Arc::clone(&self.logger), "mainline_discovery", async move {
            use veil_mainline::client::{Client, PUBLIC_ROUTERS, random_node_id};
            use veil_mainline::lookup::{Limits, announce, find_peers};
            use veil_mainline::rendezvous::current_infohashes;

            let client = match Client::bind(random_node_id()).await {
                Ok(c) => c,
                Err(e) => {
                    logger.warn(
                        "mainline.bind_failed",
                        format!("layer 7 is off for this run: {e}"),
                    );
                    return;
                }
            };
            let mut seeds = Vec::new();
            for router in PUBLIC_ROUTERS {
                if let Ok(addrs) = tokio::net::lookup_host(*router).await {
                    // BOTH families. The filter that used to stand here dropped
                    // every AAAA the routers publish, and the reason had never
                    // been written down: the client simply could not parse an
                    // IPv6 contact. It can now, so a host with IPv6 uses it and
                    // a host without one is unaffected -- the client keeps only
                    // the families it managed to bind.
                    seeds.extend(addrs.filter(|a| a.is_ipv4() || client.has_ipv6()));
                }
            }
            if seeds.is_empty() {
                logger.warn(
                    "mainline.no_routers",
                    "no public DHT router resolved; layer 7 has no way in",
                );
                return;
            }

            let mut ticker = tokio::time::interval(RENDEZVOUS_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                // WHERE, asked once per pass for the same reason WHEN is: the
                // listener a stranger could dial is a fact about now, not about
                // startup.
                let (me, my_address) =
                    current_announcement(&state, &announce_config, &my_pubkey, &my_nonce);
                // WHEN, as opposed to where. Asked once per pass rather than at
                // spawn: at spawn this node has no sessions yet, so a startup
                // check would always read "nobody" and `fallback` would mean
                // nothing at all.
                let live_peers = lock!(live_sessions).len();
                if !policy.permits_looking(live_peers, want_peers, announce_self) {
                    // NEXT pass, not never. A node that has peers now may have
                    // none in fifteen minutes, and that is exactly the case
                    // `fallback` exists for.
                    logger.debug(
                        "mainline.not_needed",
                        format!(
                            "{live_peers} peer(s), wanted {want_peers}, policy \
                             {policy}: the rendezvous is not asked this round"
                        ),
                    );
                    continue;
                }

                let net = (&client, std::time::Duration::from_secs(4));
                let mut taken = 0usize;
                // Every dial spends budget, success or not. See MAX_RENDEZVOUS_ATTEMPTS.
                let mut tried = 0usize;
                let mut already_had = 0usize;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                for info_hash in current_infohashes(network, now) {
                    let found = find_peers(&net, info_hash, &seeds, Limits::default()).await;
                    logger.info(
                        "mainline.looked",
                        format!(
                            "{} quer(ies), {} DHT node(s) answered, {} address(es) at the rendezvous",
                            found.queries,
                            found.closest.len(),
                            found.peers.len()
                        ),
                    );

                    if announce_self && let Some(ref me) = me {
                        let accepted = announce(&net, info_hash, me.port, &found.closest).await;
                        logger.info(
                            "mainline.announced",
                            format!(
                                "this node is listed at port {} with {accepted} of {} DHT node(s)",
                                me.port,
                                found.closest.len()
                            ),
                        );
                    }

                    // NOT gated on `me`. Announcing needs something to announce;
                    // dialling needs only a scheme, and a node with no listener --
                    // every client -- has one to dial with and nothing to offer.
                    for addr in found.peers.iter().take(MAX_RENDEZVOUS_ATTEMPTS) {
                        if taken >= MAX_RENDEZVOUS_PEERS || tried >= MAX_RENDEZVOUS_ATTEMPTS {
                            break;
                        }
                        if !rendezvous_destination_is_dialable(&addr.ip().to_string()) {
                            logger.debug(
                                "mainline.not_dialable",
                                format!("{addr} is not a public address; not dialled"),
                            );
                            continue;
                        }
                        let transport = format!("{dial_scheme}://{addr}");
                        if rendezvous_address_is_self(my_address.as_ref(), &transport) {
                            logger.debug(
                                "mainline.self",
                                format!("{transport} is this node's own announcement"),
                            );
                            continue;
                        }
                        // Already ours, by any route. See `rendezvous_address_is_new`.
                        let known: Vec<PeerConfigEntry> =
                            lock_state(&state).peers.values().cloned().collect();
                        let live = addresses_we_already_hold(
                            &live_sessions,
                            &access.discovered_peers_cache,
                        );
                        if !rendezvous_address_is_new(&known, &live, &transport) {
                            already_had += 1;
                            logger.debug(
                                "mainline.already_known",
                                format!("{transport} is already a peer; not dialled"),
                            );
                            continue;
                        }
                        if !we_should_place_the_call(
                            &access.local_node_id,
                            &access.discovered_peers_cache,
                            &transport,
                        ) {
                            logger.debug(
                                "mainline.theirs_to_call",
                                format!("{transport} keeps the outbound; not dialled"),
                            );
                            continue;
                        }
                        tried += 1;
                        match dial_and_learn(&access, &state, &transport, &shutdown_tx).await {
                            Ok(node) => {
                                taken += 1;
                                logger.info(
                                    "mainline.met",
                                    format!(
                                        "met {node} at {transport}, learned from the rendezvous"
                                    ),
                                );
                            }
                            Err(e) => {
                                logger.debug("mainline.unreachable", format!("{transport}: {e}"))
                            }
                        }
                    }
                }

                if taken == 0 {
                    // Two different facts, and the old message told the wrong one:
                    // a node already in session with everybody at the rendezvous
                    // was reported as unable to reach anyone.
                    if already_had > 0 {
                        logger.info(
                            "mainline.already_connected",
                            format!(
                                "everybody at the rendezvous ({already_had}) is \
                                 already a peer of this node"
                            ),
                        );
                    } else {
                        logger.info(
                            "mainline.nobody",
                            "the rendezvous named nobody this node could reach",
                        );
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Bootstrap layer 8: find peers through public Nostr relays.
    ///
    /// The same shape as layer 7 and for a different network: a node posts a
    /// small signed record under a rendezvous label that moves daily, and
    /// reads the records other nodes posted under it. What this one buys that
    /// the DHT does not is TLS on 443 — the DHT is UDP, and a network that
    /// drops UDP leaves layers 6 and 7 with nothing.
    ///
    /// Announcing stays with `global.bootstrap`, as it does at every meeting
    /// point: looking costs exposure to the relays asked, being listed costs
    /// exposure to anyone who reads them.
    pub fn spawn_nostr_discovery_task(&mut self, config: &veil_cfg::Config) {
        if !config
            .global
            .meeting_points
            .includes(veil_cfg::MeetingPoint::Nostr)
        {
            return;
        }
        // What this node ADVERTISES is no longer consulted for how it DIALS —
        // see `rendezvous_dial_scheme`. Only the address it publishes about
        // itself is still needed here, and it is read per pass rather than at
        // spawn: a rotated listener leaves a captured one naming a closed port
        // (report24 RUNTIME-3).
        let my_pubkey = self.identity.local_identity.public_key.clone();
        let my_nonce = self.identity.local_identity.nonce.clone();
        let announce_config = config.clone();
        let network = if cfg!(feature = "testnet-seeds") {
            veil_nostr::rendezvous::Network::Testnet
        } else {
            veil_nostr::rendezvous::Network::Production
        };
        let announce_self = config.global.bootstrap;
        let policy = config.global.meeting_policy;
        let want_peers = config.global.meeting_min_peers;
        let live_sessions = Arc::clone(&self.live_sessions);
        let dial_scheme = rendezvous_dial_scheme(config);
        let secret = self.identity.local_identity.private_key.clone();

        let logger = self.logger.clone();
        let access = self.access();
        let state = Arc::clone(&self.state);
        let ctx = Arc::clone(&self.transport_ctx);

        let Some(shutdown_tx) = self.shutdown_tx.clone() else {
            return;
        };
        let handle = supervised_spawn(Arc::clone(&self.logger), "nostr_discovery", async move {
            use veil_nostr::client::{DEFAULT_TIMEOUT, PUBLIC_RELAYS, publish, query};
            use veil_nostr::event::{KIND_APP_DATA, hex_lower, sign};
            use veil_nostr::rendezvous::{current_labels, epoch_of, identity_from_seed};

            let mut ticker = tokio::time::interval(RENDEZVOUS_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                // The listener a stranger could dial, as it is now.
                let (_, my_address) =
                    current_announcement(&state, &announce_config, &my_pubkey, &my_nonce);
                // Per pass, not at spawn: at spawn there are no sessions yet,
                // so `fallback` would read "nobody" every time and mean nothing.
                let live_peers = lock!(live_sessions).len();
                if !policy.permits_looking(live_peers, want_peers, announce_self) {
                    logger.debug(
                        "nostr.not_needed",
                        format!(
                            "{live_peers} peer(s), wanted {want_peers}, policy \
                             {policy}: the relays are not asked this round"
                        ),
                    );
                    continue;
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let labels = current_labels(network, now);
                // One per label, because the previous epoch's record was signed
                // by the previous epoch's key -- which is the whole point of
                // rotating it, and the reason a single author would not match.
                let epoch = epoch_of(now);
                let my_authors: Vec<String> = (0..labels.len() as u64)
                    .map(|back| {
                        hex_lower(
                            &identity_from_seed(secret.as_bytes(), epoch.saturating_sub(back))
                                .verifying_key()
                                .to_bytes(),
                        )
                    })
                    .collect();

                if announce_self && let Some((ref host, port)) = my_address {
                    // Under THIS epoch's label only. Re-posting under the
                    // previous one would leave this node's address at a
                    // rendezvous it has already left.
                    let key = identity_from_seed(secret.as_bytes(), epoch_of(now));
                    let event = sign(
                        &key,
                        now as i64,
                        KIND_APP_DATA,
                        vec![vec!["d".to_owned(), labels[0].clone()]],
                        // Through `SocketAddr`, so a v6 address keeps its
                        // brackets. `public_address_for` strips them, and
                        // `{host}:{port}` then produced `2001:db8::1:5556` —
                        // a string whose last colon is part of the address, so
                        // every receiver split it in the wrong place and the
                        // record was unusable (report21 V20-M3b).
                        &match host.parse::<std::net::IpAddr>() {
                            Ok(ip) => std::net::SocketAddr::new(ip, port).to_string(),
                            Err(_) => format!("{host}:{port}"),
                        },
                    );
                    let mut stored = 0usize;
                    for relay in PUBLIC_RELAYS {
                        match publish(&ctx, relay, &event, DEFAULT_TIMEOUT).await {
                            Ok(()) => stored += 1,
                            Err(e) => logger.debug("nostr.publish_failed", format!("{relay}: {e}")),
                        }
                    }
                    logger.info(
                        "nostr.announced",
                        format!(
                            "this node is listed as {host}:{port} with {stored} of {} relay(s)",
                            PUBLIC_RELAYS.len()
                        ),
                    );
                }

                let mut taken = 0usize;
                // Every dial spends budget, success or not. See MAX_RENDEZVOUS_ATTEMPTS.
                let mut tried = 0usize;
                let mut already_had = 0usize;
                let mut seen = std::collections::HashSet::new();
                for label in &labels {
                    for relay in PUBLIC_RELAYS {
                        let events = match query(
                            &ctx,
                            relay,
                            KIND_APP_DATA,
                            label,
                            MAX_RENDEZVOUS_PEERS * 4,
                            DEFAULT_TIMEOUT,
                        )
                        .await
                        {
                            Ok(events) => events,
                            Err(e) => {
                                logger.debug("nostr.query_failed", format!("{relay}: {e}"));
                                continue;
                            }
                        };
                        logger.info(
                            "nostr.looked",
                            format!("{relay}: {} record(s) at the rendezvous", events.len()),
                        );

                        for event in events {
                            if taken >= MAX_RENDEZVOUS_PEERS || tried >= MAX_RENDEZVOUS_ATTEMPTS {
                                break;
                            }
                            // A relay is a stranger's server and the content is
                            // whatever somebody signed. Take an address from it
                            // and nothing else: the scheme is OURS, as it is at
                            // the DHT, because a network runs one transport and
                            // a stranger does not get to choose ours.
                            let Some((host, port)) = event.content.rsplit_once(':') else {
                                continue;
                            };
                            if host.is_empty() || port.parse::<u16>().is_err() {
                                continue;
                            }
                            if !rendezvous_destination_is_dialable(host) {
                                logger.debug(
                                    "nostr.not_dialable",
                                    format!("{host} is not a public address; not dialled"),
                                );
                                continue;
                            }
                            let transport = format!("{dial_scheme}://{host}:{port}");
                            if !seen.insert(transport.clone()) {
                                continue;
                            }
                            // Ours, by the one field that says so exactly. The
                            // address check below catches it too, but only when
                            // this node has an address to compare -- and a node
                            // that announces always has an author.
                            if my_authors.contains(&event.pubkey) {
                                logger.debug(
                                    "nostr.self",
                                    format!("{transport} is this node's own record"),
                                );
                                continue;
                            }
                            if rendezvous_address_is_self(my_address.as_ref(), &transport) {
                                logger.debug(
                                    "nostr.self",
                                    format!("{transport} is this node's own address"),
                                );
                                continue;
                            }
                            let known: Vec<PeerConfigEntry> =
                                lock_state(&state).peers.values().cloned().collect();
                            let live = addresses_we_already_hold(
                                &live_sessions,
                                &access.discovered_peers_cache,
                            );
                            if !rendezvous_address_is_new(&known, &live, &transport) {
                                already_had += 1;
                                logger.debug(
                                    "nostr.already_known",
                                    format!("{transport} is already a peer; not dialled"),
                                );
                                continue;
                            }
                            if !we_should_place_the_call(
                                &access.local_node_id,
                                &access.discovered_peers_cache,
                                &transport,
                            ) {
                                logger.debug(
                                    "nostr.theirs_to_call",
                                    format!("{transport} keeps the outbound; not dialled"),
                                );
                                continue;
                            }
                            tried += 1;
                            match dial_and_learn(&access, &state, &transport, &shutdown_tx).await {
                                Ok(node) => {
                                    taken += 1;
                                    logger.info(
                                        "nostr.met",
                                        format!("met {node} at {transport}, learned from a relay"),
                                    );
                                }
                                Err(e) => {
                                    logger.debug("nostr.unreachable", format!("{transport}: {e}"))
                                }
                            }
                        }
                    }
                }

                if taken == 0 {
                    if already_had > 0 {
                        logger.info(
                            "nostr.already_connected",
                            format!(
                                "everybody at the rendezvous ({already_had}) is \
                                 already a peer of this node"
                            ),
                        );
                    } else {
                        logger.info(
                            "nostr.nobody",
                            "the relays named nobody this node could reach",
                        );
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Bootstrap layer 6: look for peers on the local network, and tell it we
    /// are here.
    ///
    /// Off unless `global.local_discovery` says otherwise, and that default is
    /// the point rather than caution — announcing tells whatever network this
    /// machine is plugged into that a machine on it runs veil, and only the
    /// person at the keyboard knows whose network that is.
    ///
    /// Unlike the DNS and HTTPS layers this one does not stop after a first
    /// answer: a laptop that joins a LAN an hour after boot should still find
    /// the node that was already there, and the node already there should hear
    /// the laptop. It runs for the life of the node, capped at
    /// [`MAX_LAN_PEERS`] contributions so a talkative neighbour cannot fill
    /// the peer table by itself.
    pub fn spawn_lan_discovery_task(&mut self, config: &veil_cfg::Config) {
        if !config
            .global
            .meeting_points
            .includes(veil_cfg::MeetingPoint::LocalNetwork)
        {
            return;
        }
        let my_pubkey = self.identity.local_identity.public_key.clone();
        let announce = lan_announce_for(
            config,
            &my_pubkey,
            &self.identity.local_identity.nonce,
            &bound_ports(&self.listens()),
        );
        if announce.is_none() {
            // Not a reason to stop. Having nothing to SAY is not having
            // nothing to HEAR: an outbound-only node, or one whose identity
            // key the LAN payload cannot carry, still wants to find the
            // neighbour that does listen. Returning here made passive
            // discovery depend on the ability to announce, which is the
            // opposite of what the rule below says (report21 V20-M4).
            self.logger.info(
                "lan_discovery.nothing_to_say",
                "local discovery is on and no listener of this node is \
                 reachable from the wire: listening without announcing",
            );
        }

        // `global.bootstrap` governs THE ANNOUNCE, in its own words, and "a node
        // with this off still USES the permissionless layers -- it asks and it
        // listens. Only publishing is opt-in." Layers 7 and 8 honoured that;
        // this one transmitted regardless, putting a stable identity key, PoW
        // nonce, port and scheme on the wire for every machine on the segment.
        let announce_self = config.global.bootstrap && announce.is_some();
        // What is announced is refreshed per pass — a listener rotates, and
        // the payload built here names the port it had at startup
        // (report24 RUNTIME-3).
        let my_pubkey = self.identity.local_identity.public_key.clone();
        let my_nonce = self.identity.local_identity.nonce.clone();
        let announce_config = config.clone();
        let logger = self.logger.clone();
        let state = Arc::clone(&self.state);
        let dht = Arc::clone(&self.dht);
        let access = self.access();
        let shutdown_tx = self.shutdown_tx.clone();
        let tasks = Arc::clone(&self.tasks);

        let handle = supervised_spawn(Arc::clone(&self.logger), "lan_discovery", async move {
            let bound = match announce {
                Some(a) => veil_bootstrap::LanDiscovery::bind(a).await,
                None => veil_bootstrap::LanDiscovery::bind_listen_only().await,
            };
            let mut discovery = match bound {
                Ok(d) => d,
                Err(e) => {
                    // A host with no multicast-capable interface, or a port
                    // held by something that refuses to share it. Neither is
                    // this node's fault and neither should end its startup.
                    logger.warn(
                        "lan_discovery.bind_failed",
                        format!("local discovery is off for this run: {e}"),
                    );
                    return;
                }
            };
            logger.info(
                "lan_discovery.listening",
                format!(
                    "announcing on the local network: a few times in the first \
                     minute, then every {}s",
                    veil_bootstrap::DEFAULT_ANNOUNCE_INTERVAL.as_secs()
                ),
            );

            // The loop is driven HERE rather than inside veil-bootstrap. A
            // driver spawned from in there would be owned by a `JoinHandle`,
            // and a handle dropped when this task is aborted DETACHES rather
            // than aborting -- which is how a socket outlives the node that
            // opened it. Aborting this one task stops everything.
            let mut seen: std::collections::BTreeMap<String, LanCandidate> =
                std::collections::BTreeMap::new();
            let mut capped_logged = false;
            let mut sent: u32 = 0;
            // Absolute deadlines rather than a repeating timer: the receive
            // branch runs between them, and an absolute deadline cannot drift
            // however long a datagram takes to handle.
            let mut next_announce = tokio::time::Instant::now();
            loop {
                let bp = tokio::select! {
                    _ = tokio::time::sleep_until(next_announce), if announce_self => {
                        // The listener may have rotated since the last one.
                        // Set whatever is current, including nothing: a stale
                        // port is worse than a pass that says nothing, because
                        // a neighbour acts on it.
                        let (fresh, _) = current_announcement(
                            &state,
                            &announce_config,
                            &my_pubkey,
                            &my_nonce,
                        );
                        discovery.set_announce(fresh);
                        if let Err(e) = discovery.announce_once().await {
                            // A LAN that will not take a multicast datagram is
                            // an ordinary state (no route, interface down, a
                            // laptop with the lid shut). It must not end the
                            // layer -- the next tick may find the wire back.
                            logger.debug(
                                "lan_discovery.announce_failed",
                                format!("{e}"),
                            );
                        }
                        sent = sent.saturating_add(1);
                        next_announce =
                            tokio::time::Instant::now() + veil_bootstrap::announce_delay(sent);
                        continue;
                    }
                    heard = discovery.recv_peer() => match heard {
                        Ok(Some(bp)) => bp,
                        Ok(None) => continue,
                        Err(e) => {
                            logger.warn(
                                "lan_discovery.recv_failed",
                                format!("local discovery is off for this run: {e}"),
                            );
                            return;
                        }
                    },
                };

                // Give back the slots of announces that never became peers,
                // BEFORE deciding on this one: otherwise eight datagrams are
                // all it takes to close local discovery for the run.
                if !seen.is_empty() {
                    let connected: std::collections::HashSet<[u8; 32]> = {
                        let g = lock!(access.live_sessions);
                        g.values()
                            .filter(|i| i.state == crate::types::SessionState::Active)
                            .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes()))
                            .collect()
                    };
                    for key in stale_lan_candidates(
                        &seen,
                        &connected,
                        LAN_CANDIDATE_GRACE,
                        std::time::Instant::now(),
                    ) {
                        let Some(candidate) = seen.remove(&key) else {
                            continue;
                        };
                        {
                            let mut st = lock_state(&state);
                            evict_lan_candidate(
                                &mut st.peers,
                                candidate,
                                |id| dht.remove_contact(id),
                                |id| {
                                    crate::outbound_connector::release_connector_claim(
                                        &access.outbound_connector_refresh,
                                        id,
                                    );
                                },
                            );
                        }
                        logger.debug(
                            "lan_discovery.slot_reclaimed",
                            "an announced neighbour never connected; its row, \
                             contact and reconnect task are gone with its slot",
                        );
                    }
                }
                if !admit_lan_peer(&bp.public_key, &my_pubkey, &seen) {
                    // Said once, at the ceiling, and then not again: the whole
                    // point of a cap is that the log does not grow with the
                    // thing it is capping.
                    if seen.len() >= MAX_LAN_PEERS && !capped_logged {
                        capped_logged = true;
                        logger.warn(
                            "lan_discovery.capped",
                            format!(
                                "already took {MAX_LAN_PEERS} peer(s) from this \
                                 network; ignoring further announces"
                            ),
                        );
                    }
                    continue;
                }
                // Derive FIRST: an announce this node cannot turn into an
                // identity is not a neighbour and must not spend a slot.
                let Some(node_id_bytes) = derive_node_id_from_bootstrap_peer(&bp) else {
                    continue;
                };
                let Some(slot) = free_lan_slot(&seen) else {
                    continue;
                };
                // Inserted below, once the row and the task exist: the
                // candidate is the record of what this admission owns.
                let admitted_at = std::time::Instant::now();
                let hex = veil_util::hex_str(&node_id_bytes);
                let Ok(node_id) = <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex) else {
                    continue;
                };
                logger.info(
                    "lan_discovery.found",
                    format!(
                        "a peer on the local network: {} at {}",
                        &hex[..16],
                        bp.transport
                    ),
                );

                dht.add_contact(veil_dht::routing::Contact::new(
                    node_id_bytes,
                    &bp.transport,
                ));

                // Its own PeerId range. The other bootstrap sources share
                // 0x8000_0000 because they are mutually exclusive within
                // `spawn_bootstrap_task`; this one runs alongside all of them,
                // so reusing that base would overwrite their entries.
                let peer_id = PeerId::new(0x9000_0000u32.wrapping_add(slot));
                let entry = PeerConfigEntry {
                    peer_id,
                    node_id,
                    public_key: bp.public_key.clone(),
                    nonce: bp.nonce.clone(),
                    transport: bp.transport.clone(),
                    algo: bp.algo,
                    tls_cert: bp.tls_cert.clone(),
                    tls_key: None,
                    tls_ca_cert: bp.tls_ca_cert.clone(),
                    bootstrap_only: true,
                    // Its own source. As `Bootstrap` this row was the
                    // operator's as far as every other rule was concerned, so
                    // an identity mismatch could not retire it.
                    source: crate::types::PeerSource::Lan,
                };
                lock_state(&state).peers.insert(peer_id, entry.clone());
                let mut abort = None;
                if let Some(ref stx) = shutdown_tx {
                    let handles =
                        crate::outbound_connector::spawn_outbound_peers(vec![entry], &access, stx);
                    // The abort handle stays with the candidate; the join
                    // handle stays with the task list, so shutdown still
                    // waits for it.
                    abort = handles.first().map(|h| h.abort_handle());
                    lock_tasks(&tasks).sessions.extend(handles);
                }
                seen.insert(
                    bp.public_key.clone(),
                    LanCandidate {
                        node_id: node_id_bytes,
                        slot,
                        admitted: admitted_at,
                        peer_id,
                        abort,
                    },
                );
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}

#[cfg(test)]
mod tests {
    /// Production half of this file, so a guard cannot be satisfied by the
    /// tests below quoting the very string they look for.
    ///
    /// Its own copy of three lines rather than a path into another module's
    /// test scope: these guards moved here with the code they read, and a
    /// cross-module reach would tie them back to the file they just left.
    fn production_source(file: &str) -> &str {
        file.split("#[cfg(test)]").next().unwrap_or(file)
    }

    #[test]
    fn every_meeting_point_asks_freely_and_publishes_only_on_opt_in() {
        // `global.bootstrap` says of itself: "This flag governs the ANNOUNCE
        // and nothing else... A node with this off still USES the
        // permissionless layers -- it asks and it listens. Only publishing is
        // opt-in." Layers 7 and 8 read it; layer 6 transmitted regardless,
        // putting a stable identity key, PoW nonce, port and scheme on the
        // wire for every machine on the segment.
        //
        // Read from the source, so a layer that stops consulting the flag
        // fails here rather than on somebody's network.
        let src = include_str!("discovery.rs");
        let span = |name: &str| {
            let at = src
                .find(name)
                .unwrap_or_else(|| panic!("{name} is gone; this guard is stale"));
            let body = &src[at..];
            let end = body.find("\n    }\n").unwrap_or(body.len());
            &body[..end]
        };
        for task in [
            "pub fn spawn_lan_discovery_task",
            "pub fn spawn_mainline_discovery_task",
            "pub fn spawn_nostr_discovery_task",
        ] {
            assert!(
                span(task).contains("config.global.bootstrap"),
                "{task} never consults `global.bootstrap`, so it publishes \
                 whether or not the operator opted in"
            );
        }
        // ...and the LAN transmit specifically is conditioned on it, rather
        // than merely mentioning it somewhere.
        assert!(
            span("pub fn spawn_lan_discovery_task").contains("if announce_self"),
            "the LAN announce timer is not gated on the opt-in"
        );
    }

    /// report21 V20-M4: having nothing to announce does not switch the layer
    /// off.
    ///
    /// The task returned before binding when `lan_announce_for` said `None` —
    /// no advertisable listener, or an identity key the payload cannot carry —
    /// so a node that only wanted to FIND the machine down the hall found
    /// nothing, because it had nothing to offer. That is the opposite of the
    /// rule stated two lines below it.
    #[test]
    fn nothing_to_announce_is_not_a_reason_to_stop_listening() {
        let src = production_source(include_str!("discovery.rs"));
        let spawn = src
            .split("pub fn spawn_lan_discovery_task")
            .nth(1)
            .and_then(|t| t.split("\npub ").next())
            .expect("the lan task");
        let head = spawn.split("supervised_spawn").next().unwrap_or_default();
        assert!(
            head.contains("lan_announce_for("),
            "the task no longer composes an announce; re-aim this guard"
        );
        assert!(
            !head.contains("let Some(announce) = lan_announce_for("),
            "having nothing to announce ends the task again, so passive \
             discovery depends on the ability to publish"
        );
        assert!(
            spawn.contains("bind_listen_only()"),
            "there is no receive-only path left, so a node with no \
             advertisable listener never binds the socket"
        );
        assert!(
            head.contains("config.global.bootstrap && announce.is_some()"),
            "the announce ticker no longer requires something to announce: it \
             will call announce_once on a node that has nothing to say"
        );
    }

    /// And the tasks ASK per pass rather than carrying an answer in.
    ///
    /// The helper above cannot prove that by itself: a task that called it once
    /// before its loop would pass every assertion there and still publish one
    /// port forever. Driving three long-lived discovery tasks to a second pass
    /// is not something a unit test can do, so this reads where the call is.
    #[test]
    fn the_discovery_tasks_ask_for_the_announcement_inside_their_loop() {
        let src = production_source(include_str!("discovery.rs"));
        for task in [
            "pub fn spawn_mainline_discovery_task",
            "pub fn spawn_nostr_discovery_task",
            "pub fn spawn_lan_discovery_task",
        ] {
            let body = src
                .split(task)
                .nth(1)
                .and_then(|t| t.split("\npub ").next())
                .unwrap_or_else(|| panic!("{task} is in this file"));
            let spawned = body
                .split("supervised_spawn")
                .nth(1)
                .unwrap_or_else(|| panic!("{task} spawns nothing"));
            assert!(
                spawned.contains("current_announcement("),
                "{task} does not recompute what it publishes, so a rotated \
                 listener leaves it announcing a closed port",
            );
            let head = body.split("supervised_spawn").next().unwrap_or_default();
            assert!(
                !head.contains("current_announcement("),
                "{task} computes the announcement before spawning, which is \
                 the capture this replaced",
            );
        }
    }
}
