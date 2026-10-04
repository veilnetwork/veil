//! Private per-call receive addresses. Every control byte below travels inside
//! the call's existing directional AEAD; none is a relay scheduling instruction.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) const CONTROL_MAGIC: &[u8; 4] = b"VMR1";
const ROUTE_BYTES: usize = 81;
const REFRESH_AFTER: Duration = Duration::from_secs(240);
const PRIVATE_RETIRE_GRACE: Duration = Duration::from_secs(30);
const PROBE_STALE_AFTER: Duration = Duration::from_secs(12);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiveAddress {
    plane: u8,
    relay: [u8; 32],
    cookie: [u8; 16],
    intro_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Offer {
    channel: u64,
    revision: u64,
    routes: Vec<ReceiveAddress>,
}

impl Offer {
    fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(21 + ROUTE_BYTES * self.routes.len());
        body.extend_from_slice(CONTROL_MAGIC);
        body.extend_from_slice(&self.channel.to_be_bytes());
        body.extend_from_slice(&self.revision.to_be_bytes());
        body.push(self.routes.len() as u8);
        for route in &self.routes {
            body.push(route.plane);
            body.extend_from_slice(&route.relay);
            body.extend_from_slice(&route.cookie);
            body.extend_from_slice(&route.intro_key);
        }
        body
    }

    fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 21 || !body.starts_with(CONTROL_MAGIC) {
            return None;
        }
        let count = body[20] as usize;
        if !(1..=2).contains(&count) || body.len() != 21 + ROUTE_BYTES * count {
            return None;
        }
        let channel = u64::from_be_bytes(body[4..12].try_into().ok()?);
        let revision = u64::from_be_bytes(body[12..20].try_into().ok()?);
        if channel == 0 || revision == 0 {
            return None;
        }
        let mut routes = Vec::with_capacity(count);
        let mut seen = 0u8;
        for entry in body[21..].chunks_exact(ROUTE_BYTES) {
            let plane = entry[0];
            if plane > 1 || seen & (1 << plane) != 0 {
                return None;
            }
            seen |= 1 << plane;
            let relay = entry[1..33].try_into().ok()?;
            let cookie = entry[33..49].try_into().ok()?;
            let intro_key = entry[49..81].try_into().ok()?;
            if relay == [0; 32] || cookie == [0; 16] || intro_key == [0; 32] {
                return None;
            }
            routes.push(ReceiveAddress {
                plane,
                relay,
                cookie,
                intro_key,
            });
        }
        // An offer always includes its primary receive path. Video may follow
        // later without delaying audio while its circuit is being constructed.
        routes.sort_unstable_by_key(|route| route.plane);
        (seen & 1 != 0).then_some(Self {
            channel,
            revision,
            routes,
        })
    }
}

#[derive(Default)]
struct OfferInbox {
    highest: Option<Offer>,
}

impl OfferInbox {
    fn accept(&mut self, offer: Offer) {
        if let Some(highest) = &self.highest {
            let generation = (offer.channel, offer.revision);
            let current = (highest.channel, highest.revision);
            if generation < current || (generation == current && offer != *highest) {
                return;
            }
        }
        // Identical offers retry a failed/expired route. A conflicting address
        // must use a new revision; it cannot reuse the current generation.
        self.highest = Some(offer.clone());
    }

    fn is_current(&self, offer: &Offer) -> bool {
        self.highest.as_ref() == Some(offer)
    }
}

struct PinnedRoute {
    services: veil_node_runtime::NodeServices,
    circuit: Arc<veil_node_runtime::DataCircuit>,
    feed: tokio::task::JoinHandle<()>,
    cookie: [u8; 16],
    relay: [u8; 32],
    created: Instant,
    close_generation: u64,
    last_echo: Mutex<Instant>,
    probe_echo: Arc<AtomicBool>,
}

impl PinnedRoute {
    fn is_live(&self) -> bool {
        let mut last_echo = self.last_echo.lock().unwrap_or_else(|p| p.into_inner());
        if self.probe_echo.swap(false, Ordering::AcqRel) {
            *last_echo = Instant::now();
        }
        self.created.elapsed() < REFRESH_AFTER
            && last_echo.elapsed() < PROBE_STALE_AFTER
            && self.services.has_live_session(&self.circuit.first_hop())
            && self
                .services
                .session_close_generation(&self.circuit.first_hop())
                == self.close_generation
    }

    fn probe(&self) {
        let mut body = self.cookie.to_vec();
        body.extend_from_slice(veil_anonymity::circuit_data::CIRCUIT_PROBE_MAGIC);
        let _ = self
            .services
            .send_circuit_cell_detailed(&self.circuit, &body);
    }
}

impl Drop for PinnedRoute {
    fn drop(&mut self) {
        self.feed.abort();
        self.services.retire_data_circuit(&self.circuit);
    }
}

/// A circuit becomes owned before its first confirmation await. Cancellation
/// during a probe closes the receive sink and feed instead of orphaning them.
async fn open_private_route(
    core: &CircuitCells,
    relay: [u8; 32],
    owner: &MediaRoutes,
) -> Option<PinnedRoute> {
    let registration = outbound_registration(&core.reg_kp, &core.epoch, true).ok()?;
    let (circuit, rx) = core
        .services
        .open_stream_circuit_to_rendezvous_relay(
            relay,
            &registration.keypair,
            &registration.epoch,
            CIRCUIT_HOPS,
        )
        .await
        .ok()?;
    let circuit = Arc::new(circuit);
    let probe_echo = Arc::new(AtomicBool::new(false));
    let feed = tokio::spawn(run_circuit_feed(
        core.services.clone(),
        rx,
        core.in_tx.clone(),
        None,
        None,
        Arc::clone(&core.peer_tags),
        Some(circuit.confirmed_flag()),
        CircuitFeedMode::Media {
            peer: owner.peer,
            channel: owner.channel,
            cipher: Arc::clone(&owner.cipher),
            probe_echo: Arc::clone(&probe_echo),
        },
    ));
    let close_generation = core.services.session_close_generation(&circuit.first_hop());
    let owned = PinnedRoute {
        services: core.services.clone(),
        circuit,
        feed,
        cookie: registration.cookie,
        relay,
        created: Instant::now(),
        close_generation,
        last_echo: Mutex::new(Instant::now()),
        probe_echo,
    };
    confirm_circuit_with_probe(&core.services, &owned.circuit, &owned.cookie)
        .await
        .then_some(owned)
}

/// The fallback pools are used only while a peer is older or a private route
/// is not yet ready. Dedicated send/receive handles belong to this call.
pub(crate) struct MediaRoutes {
    peer: [u8; 32],
    channel: u64,
    cores: [CircuitCells; 2],
    cipher: Arc<crate::media::MediaCipher>,
    outgoing: [tokio::sync::Mutex<Option<(ReceiveAddress, PinnedRoute, u64)>>; 2],
    repair_generation: [AtomicU64; 2],
    offers: Mutex<OfferInbox>,
    closed: AtomicBool,
    incoming: Mutex<([Option<ReceiveAddress>; 2], u64)>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl MediaRoutes {
    pub(super) fn new(
        peer: [u8; 32],
        channel: u64,
        cores: [CircuitCells; 2],
        cipher: Arc<crate::media::MediaCipher>,
    ) -> Arc<Self> {
        Arc::new(Self {
            peer,
            channel,
            cores,
            cipher,
            outgoing: std::array::from_fn(|_| tokio::sync::Mutex::new(None)),
            repair_generation: std::array::from_fn(|_| AtomicU64::new(0)),
            offers: Mutex::new(OfferInbox::default()),
            closed: AtomicBool::new(false),
            incoming: Mutex::new(([None, None], 0)),
            tasks: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn start(self: &Arc<Self>, runtime: &tokio::runtime::Handle) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|p| p.into_inner());
        if !tasks.is_empty() || self.closed.load(Ordering::Acquire) {
            return;
        }
        for plane in 0..2 {
            let routes = Arc::clone(self);
            tasks.push(runtime.spawn(routes.run_plane(plane)));
        }
        let routes = Arc::clone(self);
        tasks.push(runtime.spawn(routes.advertise()));
    }

    pub(crate) fn accept_control(&self, body: &[u8]) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let Some(offer) = Offer::decode(body) else {
            return;
        };
        let mut offers = self.offers.lock().unwrap_or_else(|p| p.into_inner());
        if !self.closed.load(Ordering::Acquire) {
            offers.accept(offer);
        }
    }

    pub(crate) fn stop(&self) {
        self.closed.store(true, Ordering::Release);
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain(..)
        {
            task.abort();
        }
        for route in &self.outgoing {
            if let Ok(mut route) = route.try_lock() {
                route.take();
            }
        }
    }

    pub(crate) async fn warm(&self, plane: LocalMediaPlane) {
        let i = plane_index(plane);
        self.cores[i]
            .ensure_outbound_opening(self.peer, RouteClass::Bulk)
            .await;
    }

    pub(crate) fn repair(&self) {
        for i in 0..2 {
            self.repair_generation[i].fetch_add(1, Ordering::AcqRel);
            if let Ok(mut route) = self.outgoing[i].try_lock() {
                route.take();
            }
        }
    }

    pub(crate) async fn send(&self, plane: LocalMediaPlane, sealed: &SealedMediaCell) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        let i = plane_index(plane);
        let core = &self.cores[i];
        let Some(mut outgoing) = sealed.lock_while_fresh(&self.outgoing[i]).await else {
            // Expiry at the endpoint must not look like a route failure.
            return true;
        };
        if outgoing.as_ref().is_some_and(|(_, route, generation)| {
            !route.is_live() || *generation != self.repair_generation[i].load(Ordering::Acquire)
        }) {
            outgoing.take();
        }
        if let Some((address, owned, _)) = outgoing.as_ref() {
            let route = CircuitRoute {
                circuit: Arc::clone(&owned.circuit),
                rendezvous_node: Some(address.relay),
                first_hop_close_generation: owned.close_generation,
                peer_cookie: address.cookie,
                envelope: CircuitEnvelope::ProtectedIntro {
                    peer_tag: outbound_peer_tag(&core.outbound_peer_tags, self.peer),
                    receiver_x25519_pk: address.intro_key,
                },
                stats: None,
            };
            let mut cell = vec![crate::media::MEDIA_MAGIC];
            cell.extend_from_slice(sealed.as_bytes());
            let Ok(env) = core.stream_envelope(&route, &cell, true) else {
                return false;
            };
            match core.services.send_circuit_datagram_on_local_lane_detailed(
                &route.circuit,
                &env,
                core.local_datagram_lane,
            ) {
                Ok(()) => return true,
                Err(
                    veil_node_runtime::DataCircuitSendError::QueueFull
                    | veil_node_runtime::DataCircuitSendError::PayloadTooLarge,
                ) => {
                    // Local congestion drops this lossy cell, not the circuit.
                    // Retrying via another pool would amplify the same backlog.
                    return false;
                }
                Err(veil_node_runtime::DataCircuitSendError::NoRelays) => {}
            }
            // The next repeated authenticated offer retries construction.
            outgoing.take();
        }
        drop(outgoing);
        core.send_datagram(self.peer, sealed).await
    }

    /// Construction, repair and expiry are independent for each local producer.
    /// A stalled secondary build cannot delay the primary offer or its repair.
    async fn run_plane(self: Arc<Self>, i: usize) {
        let core = &self.cores[i];
        let Some(intro_key) = core.services.stream_peer_intro_public_key() else {
            return;
        };
        let mut incoming: Option<PinnedRoute> = None;
        let mut retired = Vec::<(Instant, PinnedRoute)>::new();
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            let offer = self
                .offers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .highest
                .clone();
            if let Some(offer) = offer
                && let Some(address) = offer.routes.iter().find(|r| r.plane as usize == i)
            {
                let repair_generation = self.repair_generation[i].load(Ordering::Acquire);
                let ready = self.outgoing[i].lock().await.as_ref().is_some_and(
                    |(old, route, generation)| {
                        old == address && route.is_live() && *generation == repair_generation
                    },
                );
                if ready && let Some((_, route, _)) = self.outgoing[i].lock().await.as_ref() {
                    route.probe();
                }
                if !ready && let Some(route) = open_private_route(core, address.relay, &self).await
                {
                    let mut outgoing = self.outgoing[i].lock().await;
                    let offers = self.offers.lock().unwrap_or_else(|p| p.into_inner());
                    if offers.is_current(&offer)
                        && !self.closed.load(Ordering::Acquire)
                        && self.repair_generation[i].load(Ordering::Acquire) == repair_generation
                    {
                        *outgoing = Some((address.clone(), route, repair_generation));
                    }
                }
            }
            retired.retain(|(since, _)| since.elapsed() < PRIVATE_RETIRE_GRACE);
            if !incoming.as_ref().is_some_and(PinnedRoute::is_live) {
                for relay in core.services.local_published_rendezvous_relays() {
                    if let Some(route) = open_private_route(core, relay, &self).await {
                        let address = ReceiveAddress {
                            plane: i as u8,
                            relay: route.relay,
                            cookie: route.cookie,
                            intro_key,
                        };
                        if let Some(old) = incoming.replace(route) {
                            // A bounded grace period admits packets still travelling
                            // through the old address. Drop retires the receive sink.
                            if retired.len() == 2 {
                                retired.remove(0);
                            }
                            retired.push((Instant::now(), old));
                        }
                        let mut published = self.incoming.lock().unwrap_or_else(|p| p.into_inner());
                        published.0[i] = Some(address);
                        published.1 += 1;
                        break;
                    }
                }
            }
            if let Some(route) = &incoming {
                route.probe();
            }
        }
    }

    /// Address control is sealed by this call's cipher, with no new public wire
    /// marker, media role or relay privilege. Repetition also reaches old routes
    /// during migration and retries a lost offer without using a mailbox.
    async fn advertise(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            let offer = {
                let published = self.incoming.lock().unwrap_or_else(|p| p.into_inner());
                if published.0[0].is_none() {
                    continue;
                }
                Offer {
                    channel: self.channel,
                    revision: published.1,
                    routes: published.0.iter().flatten().cloned().collect(),
                }
            };
            if let Some(sealed) = self
                .cipher
                .seal_on_plane(LocalMediaPlane::Primary, &offer.encode())
            {
                let _ = self.send(LocalMediaPlane::Primary, &sealed).await;
            }
        }
    }
}

fn plane_index(plane: LocalMediaPlane) -> usize {
    match plane {
        LocalMediaPlane::Primary => 0,
        LocalMediaPlane::Secondary => 1,
    }
}

#[cfg(test)]
pub(crate) async fn fixture(
    peer: [u8; 32],
    channel: u64,
    cipher: Arc<crate::media::MediaCipher>,
) -> (
    tempfile::TempDir,
    veil_node_runtime::NodeRuntime,
    Arc<MediaRoutes>,
) {
    let (dir, runtime, services) = super::tests::offline_feed_fixture().await;
    let (tx, _rx) = mpsc::channel(1);
    let core = super::try_open_circuit(
        services.local_node_id(),
        tx,
        CircuitMode::PublishedRendezvous,
    )
    .unwrap();
    let routes = MediaRoutes::new(peer, channel, [core.clone(), core], cipher);
    (dir, runtime, routes)
}

#[cfg(test)]
impl MediaRoutes {
    pub(crate) fn received_offer_for_test(&self) -> Option<Vec<u8>> {
        self.offers
            .lock()
            .unwrap()
            .highest
            .as_ref()
            .map(Offer::encode)
    }
}

#[cfg(all(test, feature = "test-low-difficulty"))]
pub(crate) struct RouteSnapshot {
    pub plane: u8,
    pub origin: u32,
    pub destination_cookie: [u8; 16],
    pub return_cookie: [u8; 16],
}

#[cfg(all(test, feature = "test-low-difficulty"))]
impl MediaRoutes {
    pub(crate) fn on_node_for_test(
        me: [u8; 32],
        peer: [u8; 32],
        channel: u64,
        cipher: Arc<crate::media::MediaCipher>,
    ) -> (Arc<Self>, mpsc::Receiver<(Addr, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel(1);
        let core = super::try_open_circuit(me, tx, CircuitMode::PublishedRendezvous).unwrap();
        let cores = [
            core.isolated_producer(LocalMediaPlane::Primary),
            core.isolated_producer(LocalMediaPlane::Secondary),
        ];
        (Self::new(peer, channel, cores, cipher), rx)
    }

    pub(crate) fn receive_addresses_for_test(&self) -> Vec<(u8, [u8; 16])> {
        self.incoming
            .lock()
            .unwrap()
            .0
            .iter()
            .flatten()
            .map(|r| (r.plane, r.cookie))
            .collect()
    }

    pub(crate) async fn outgoing_for_test(&self) -> Vec<RouteSnapshot> {
        let mut routes = Vec::new();
        for i in 0..2 {
            if let Some((address, route, _)) = self.outgoing[i].lock().await.as_ref() {
                routes.push(RouteSnapshot {
                    plane: i as u8,
                    origin: route.circuit.origin_circuit_id(),
                    destination_cookie: address.cookie,
                    return_cookie: route.cookie,
                });
            }
        }
        routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(channel: u64, revision: u64) -> Offer {
        Offer {
            channel,
            revision,
            routes: (0..2)
                .map(|plane| ReceiveAddress {
                    plane,
                    relay: [0x21; 32],
                    cookie: [plane + 1; 16],
                    intro_key: [0x31; 32],
                })
                .collect(),
        }
    }

    #[test]
    fn offers_have_exact_bounded_shape_and_canonical_order() {
        let valid = offer(1, 1);
        let body = valid.encode();
        assert_eq!(body.len(), 183);
        assert_eq!(Offer::decode(&body), Some(valid.clone()));
        let mut reversed = valid.clone();
        reversed.routes.reverse();
        assert_eq!(Offer::decode(&reversed.encode()), Some(valid.clone()));
        let mut primary = valid.clone();
        primary.routes.pop();
        assert_eq!(Offer::decode(&primary.encode()), Some(primary));
        for len in 0..body.len() {
            assert!(Offer::decode(&body[..len]).is_none());
        }
        let mut trailing = body.clone();
        trailing.push(0);
        assert!(Offer::decode(&trailing).is_none());
        for count in [0, 3, 255] {
            let mut bad = body.clone();
            bad[20] = count;
            assert!(Offer::decode(&bad).is_none());
        }
        for field in [4..12, 12..20, 22..54, 54..70, 70..102] {
            let mut bad = body.clone();
            bad[field].fill(0);
            assert!(Offer::decode(&bad).is_none());
        }
        let mut duplicate = valid.clone();
        duplicate.routes[1].plane = 0;
        assert!(Offer::decode(&duplicate.encode()).is_none());
        let mut secondary = valid.clone();
        secondary.routes.remove(0);
        assert!(Offer::decode(&secondary.encode()).is_none());
        let mut unknown = valid;
        unknown.routes[0].plane = 2;
        assert!(Offer::decode(&unknown.encode()).is_none());
    }

    #[test]
    fn stale_and_conflicting_offers_cannot_retarget_a_route() {
        let mut inbox = OfferInbox::default();
        let old = offer(1, 1);
        inbox.accept(old.clone());
        let newer = offer(1, 2);
        inbox.accept(newer.clone());
        inbox.accept(old);
        assert!(inbox.is_current(&newer));
        let mut conflict = newer.clone();
        conflict.routes[0].cookie = [0x72; 16];
        inbox.accept(conflict);
        assert!(inbox.is_current(&newer));
        inbox.accept(newer.clone()); // Retry is idempotent.
        assert!(inbox.is_current(&newer));
        let rebuilt = offer(2, 1);
        inbox.accept(rebuilt.clone());
        inbox.accept(offer(1, u64::MAX));
        assert!(inbox.is_current(&rebuilt));
    }

    #[tokio::test]
    async fn stopping_routes_cancels_workers_and_prevents_restart() {
        let peer = [0xe8; 32];
        let cipher =
            Arc::new(crate::media::cipher_for_test(&peer, &[0x21; 32], &[0x22; 32]).unwrap());
        let (_dir, mut node, routes) = fixture(peer, 0xe801, cipher).await;
        routes.start(&tokio::runtime::Handle::current());
        let aborts: Vec<_> = routes
            .tasks
            .lock()
            .unwrap()
            .iter()
            .map(|t| t.abort_handle())
            .collect();
        assert_eq!(aborts.len(), 3);
        routes.stop();
        routes.accept_control(&offer(1, 1).encode());
        assert!(routes.received_offer_for_test().is_none());
        routes.start(&tokio::runtime::Handle::current());
        assert!(routes.tasks.lock().unwrap().is_empty());
        let weak = Arc::downgrade(&routes);
        drop(routes);
        tokio::time::timeout(Duration::from_secs(1), async {
            while aborts.iter().any(|h| !h.is_finished()) || weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        node.stop().await.unwrap();
    }
}
