//! Private per-call receive addresses. Every control byte below travels inside
//! the call's existing directional AEAD; none is a relay scheduling instruction.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) const CONTROL_MAGIC: &[u8; 4] = b"VMR1";
const ROUTE_BYTES: usize = 81;
const REFRESH_AFTER: Duration = Duration::from_secs(240);
const PRIVATE_RETIRE_GRACE: Duration = Duration::from_secs(30);
const PROBE_STALE_AFTER: Duration = Duration::from_secs(12);
const DATAGRAM_WARM_TIMEOUT: Duration = Duration::from_secs(3);

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

    fn separate_auxiliary(&self) -> bool {
        self.routes.iter().any(|route| route.plane >= 2)
    }

    fn legacy(&self) -> Self {
        Self {
            channel: self.channel,
            revision: self.revision,
            routes: self
                .routes
                .iter()
                .filter(|r| r.plane < 2)
                .cloned()
                .collect(),
        }
    }

    fn receive_address(&self, source: usize) -> Option<&ReceiveAddress> {
        let index = if self.separate_auxiliary() {
            source
        } else {
            receive_plane_index(source)
        };
        self.routes.iter().find(|r| r.plane as usize == index)
    }

    fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 21 || !body.starts_with(CONTROL_MAGIC) {
            return None;
        }
        let count = body[20] as usize;
        if !(1..=4).contains(&count) || body.len() != 21 + ROUTE_BYTES * count {
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
            if plane > 3 || seen & (1 << plane) != 0 {
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
            if generation < current {
                return;
            }
            // Once this channel proves the extended decoder, its compatibility
            // copy must not collapse auxiliary receive paths, even if reordered
            // from a newer publication. A new channel may be a legacy peer.
            if offer.channel == highest.channel
                && highest.separate_auxiliary()
                && !offer.separate_auxiliary()
            {
                return;
            }
            if generation == current && offer != *highest {
                // A lost full offer can arrive after its compatibility copy.
                // Only adding addresses is allowed at the same generation;
                // changing any already accepted address still requires a revision.
                let extension = offer.routes.len() > highest.routes.len()
                    && highest.routes.iter().all(|old| offer.routes.contains(old));
                if !extension {
                    return;
                }
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
    local_datagram_lane: u8,
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

    async fn prepare_datagram(&self) {
        let deadline = tokio::time::Instant::now() + DATAGRAM_WARM_TIMEOUT;
        while self
            .services
            .request_local_circuit_datagram(&self.circuit, self.local_datagram_lane)
            == veil_session::LocalDatagramChannelState::Warming
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        // Teach old relays the exact return child once, before publication.
        // Wait for its echo (with bounded retry) so immediate media does not
        // collide with these padded bootstrap cells in the short source queue.
        self.probe_echo.store(false, Ordering::Release);
        self.probe_datagram();
        let mut next_probe = tokio::time::Instant::now() + Duration::from_millis(250);
        while !self.probe_echo.load(Ordering::Acquire) && tokio::time::Instant::now() < deadline {
            if tokio::time::Instant::now() >= next_probe {
                self.probe_datagram();
                next_probe += Duration::from_millis(250);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn probe(&self) {
        // Steady-state keepalive is call control, not a media datagram. Reliable
        // cells preserve the learned return carrier without occupying the
        // audio/video/screen child or labelling any role on a relay's wire.
        let mut body = self.cookie.to_vec();
        body.extend_from_slice(veil_anonymity::circuit_data::CIRCUIT_PROBE_MAGIC);
        let _ = self.services.send_circuit_cell_on_local_lane_detailed(
            &self.circuit,
            &body,
            veil_session::LOCAL_SIGNALING_LANE,
        );
    }

    fn probe_datagram(&self) {
        let _ = self
            .services
            .request_local_circuit_datagram(&self.circuit, self.local_datagram_lane);
        let mut body = self.cookie.to_vec();
        body.extend_from_slice(veil_anonymity::circuit_data::CIRCUIT_PROBE_MAGIC);
        let _ = self.services.send_circuit_datagram_on_local_lane_detailed(
            &self.circuit,
            &body,
            self.local_datagram_lane,
        );
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
        .open_stream_circuit_to_rendezvous_relay_in_group(
            relay,
            &registration.keypair,
            &registration.epoch,
            CIRCUIT_HOPS,
            Some(&core.path_group),
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
        local_datagram_lane: core.local_datagram_lane,
    };
    if !confirm_circuit_with_probe(&core.services, &owned.circuit, &owned.cookie).await {
        return None;
    }
    owned.prepare_datagram().await;
    owned.is_live().then_some(owned)
}

/// The fallback pools are used only while a peer is older or a private route
/// is not yet ready. Dedicated send/receive handles belong to this call.
pub(crate) struct MediaRoutes {
    peer: [u8; 32],
    channel: u64,
    cores: [CircuitCells; 4],
    cipher: Arc<crate::media::MediaCipher>,
    outgoing: [tokio::sync::Mutex<Option<(ReceiveAddress, PinnedRoute, u64)>>; 4],
    repair_generation: [AtomicU64; 4],
    offers: Mutex<OfferInbox>,
    closed: AtomicBool,
    screen_active: AtomicBool,
    control_active: AtomicBool,
    incoming: Mutex<([Option<ReceiveAddress>; 4], u64)>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    #[cfg(test)]
    legacy_peer: AtomicBool,
}

impl MediaRoutes {
    pub(super) fn new(
        peer: [u8; 32],
        channel: u64,
        cores: [CircuitCells; 4],
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
            screen_active: AtomicBool::new(false),
            control_active: AtomicBool::new(false),
            incoming: Mutex::new((std::array::from_fn(|_| None), 0)),
            tasks: Mutex::new(Vec::new()),
            #[cfg(test)]
            legacy_peer: AtomicBool::new(false),
        })
    }

    pub(crate) fn start(self: &Arc<Self>, runtime: &tokio::runtime::Handle) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|p| p.into_inner());
        if !tasks.is_empty() || self.closed.load(Ordering::Acquire) {
            return;
        }
        let receive_planes = self.receive_plane_count();
        for plane in 0..receive_planes {
            let routes = Arc::clone(self);
            tasks.push(runtime.spawn(routes.run_plane(plane)));
        }
        for plane in receive_planes..4 {
            let routes = Arc::clone(self);
            tasks.push(runtime.spawn(routes.run_auxiliary_sender(plane)));
        }
        let routes = Arc::clone(self);
        tasks.push(runtime.spawn(routes.advertise()));
    }

    fn receive_plane_count(&self) -> usize {
        #[cfg(test)]
        if self.legacy_peer.load(Ordering::Acquire) {
            return 2;
        }
        4
    }

    fn outgoing_active(&self, i: usize) -> bool {
        match i {
            0 | 1 => true,
            2 => self.screen_active.load(Ordering::Acquire),
            3 => self.control_active.load(Ordering::Acquire),
            _ => unreachable!("unknown local producer"),
        }
    }

    fn advertisement_offers(&self, offer: Offer) -> Vec<Offer> {
        if self.receive_plane_count() == 2 {
            return vec![offer.legacy()];
        }
        let peer_extended = self
            .offers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .highest
            .as_ref()
            .is_some_and(Offer::separate_auxiliary);
        if offer.separate_auxiliary() && !peer_extended {
            // Existing peers reject extra route IDs but swallow VMR1 control
            // before media decoding. The companion has their exact old shape.
            let legacy = offer.legacy();
            vec![offer, legacy]
        } else {
            vec![offer]
        }
    }

    pub(crate) fn accept_control(&self, body: &[u8]) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let Some(offer) = Offer::decode(body) else {
            return;
        };
        #[cfg(test)]
        if self.legacy_peer.load(Ordering::Acquire) && offer.separate_auxiliary() {
            return;
        }
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
        if i == 2 {
            self.screen_active.store(true, Ordering::Release);
        } else if i == 3 {
            self.control_active.store(true, Ordering::Release);
        }
        self.cores[i]
            .ensure_outbound_opening(self.peer, RouteClass::Bulk)
            .await;
    }

    pub(crate) fn repair(&self) {
        for i in 0..self.cores.len() {
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
            let result = match sealed.local_deadline() {
                Some(deadline) => core.services.send_circuit_datagram_on_local_lane_before(
                    &route.circuit,
                    &env,
                    core.local_datagram_lane,
                    deadline.into_std(),
                ),
                None => core.services.send_circuit_datagram_on_local_lane_detailed(
                    &route.circuit,
                    &env,
                    core.local_datagram_lane,
                ),
            };
            match result {
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

    async fn refresh_outgoing(self: &Arc<Self>, i: usize) {
        let core = &self.cores[i];
        let offer = self
            .offers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .highest
            .clone();
        if let Some(offer) = offer
            && let Some(address) = offer.receive_address(i)
        {
            let repair_generation = self.repair_generation[i].load(Ordering::Acquire);
            let ready =
                self.outgoing[i]
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|(old, route, generation)| {
                        old == address && route.is_live() && *generation == repair_generation
                    });
            if ready && let Some((_, route, _)) = self.outgoing[i].lock().await.as_ref() {
                route.probe();
            }
            if !ready && let Some(route) = open_private_route(core, address.relay, self).await {
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
    }

    async fn run_auxiliary_sender(self: Arc<Self>, i: usize) {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            let active = if i == 2 {
                &self.screen_active
            } else {
                &self.control_active
            };
            if active.load(Ordering::Acquire) {
                self.refresh_outgoing(i).await;
            }
        }
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
            if self.outgoing_active(i) {
                self.refresh_outgoing(i).await;
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
        self.warm(LocalMediaPlane::Control).await;
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
            for offer in self.advertisement_offers(offer) {
                if let Some(sealed) = self
                    .cipher
                    .seal_on_plane(LocalMediaPlane::Control, &offer.encode())
                {
                    let sealed = sealed.with_local_deadline(
                        tokio::time::Instant::now() + veil_proto::ipc::LOCAL_SHORT_DATAGRAM_MAX_AGE,
                    );
                    let _ = self.send(LocalMediaPlane::Control, &sealed).await;
                }
            }
        }
    }
}

fn plane_index(plane: LocalMediaPlane) -> usize {
    match plane {
        LocalMediaPlane::Primary => 0,
        LocalMediaPlane::Secondary => 1,
        LocalMediaPlane::Screen => 2,
        LocalMediaPlane::Control => 3,
    }
}

// Compatibility with peers publishing only the original two opaque receive
// addresses. Upgraded peers use the exact source's private address instead.
// Every address/plane remains inside the call AEAD, never a public role marker.
fn receive_plane_index(source: usize) -> usize {
    match source {
        0 | 3 => 0,
        1 | 2 => 1,
        _ => unreachable!("unknown local producer"),
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
    let routes = MediaRoutes::new(
        peer,
        channel,
        [
            core.isolated_producer(LocalMediaPlane::Primary),
            core.isolated_producer(LocalMediaPlane::Secondary),
            core.isolated_producer(LocalMediaPlane::Screen),
            core.isolated_producer(LocalMediaPlane::Control),
        ],
        cipher,
    );
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
    pub first_hop: [u8; 32],
    pub destination_cookie: [u8; 16],
    pub return_cookie: [u8; 16],
}

#[cfg(all(test, feature = "test-low-difficulty"))]
impl MediaRoutes {
    pub(crate) fn emulate_legacy_peer_for_test(&self) {
        assert!(self.tasks.lock().unwrap().is_empty());
        self.legacy_peer.store(true, Ordering::Release);
    }

    pub(crate) fn on_node_for_test(
        me: [u8; 32],
        peer: [u8; 32],
        channel: u64,
        cipher: Arc<crate::media::MediaCipher>,
    ) -> (Arc<Self>, super::CircuitStreamMuxForTest) {
        let (tx, rx) = mpsc::channel(256);
        let core = super::try_open_circuit(me, tx, CircuitMode::PublishedRendezvous).unwrap();
        let cores = [
            core.isolated_producer(LocalMediaPlane::Primary),
            core.isolated_producer(LocalMediaPlane::Secondary),
            core.isolated_producer(LocalMediaPlane::Screen),
            core.isolated_producer(LocalMediaPlane::Control),
        ];
        // Match AnonStreamHub: one base registration/feed owns file streams;
        // its isolated producers own this call's media circuits. A second base
        // core would race this one for the node's published receive cookie.
        let aliases = Arc::clone(&core.peer_aliases);
        let cells = HubCells::Circuit(Box::new(core));
        let mss = circuit_mss_for(veil_anonymity::circuit_origin::choose_cell_bytes());
        let cfg = stream_config(me, &cells, mss);
        let mux = super::CircuitStreamMuxForTest(StreamMux::new_with_aliases(
            me,
            Arc::new(cells),
            rx,
            cfg,
            aliases,
        ));
        (Self::new(peer, channel, cores, cipher), mux)
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
        for i in 0..self.cores.len() {
            if let Some((address, route, _)) = self.outgoing[i].lock().await.as_ref() {
                routes.push(RouteSnapshot {
                    plane: i as u8,
                    origin: route.circuit.origin_circuit_id(),
                    first_hop: route.circuit.first_hop(),
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

    #[tokio::test]
    async fn blocked_control_route_cannot_hold_audio_or_retarget_its_receive_address() {
        let cipher =
            Arc::new(crate::media::cipher_for_test(&[0xc1; 32], &[1; 32], &[2; 32]).unwrap());
        let (_dir, mut runtime, routes) = fixture([0xc1; 32], 1, Arc::clone(&cipher)).await;
        assert_eq!(receive_plane_index(3), 0);
        assert_eq!(
            routes.cores[3].local_datagram_lane,
            veil_session::LOCAL_SIGNALING_LANE
        );
        let held_route = routes.outgoing[3].lock().await;
        let held_pool = routes.cores[3].outbound_circuits.lock().await;
        let held_opening = routes.cores[3].outbound_opening.lock().await;
        let cell = cipher
            .seal(b"audio")
            .unwrap()
            .with_local_deadline(tokio::time::Instant::now() + Duration::from_millis(200));
        let result = tokio::time::timeout(Duration::from_millis(100), async {
            routes.warm(LocalMediaPlane::Primary).await;
            routes.send(LocalMediaPlane::Primary, &cell).await
        })
        .await;
        drop((held_route, held_pool, held_opening));
        routes.stop();
        runtime.stop().await.unwrap();
        assert!(!result.expect("audio must not await any control-route lock"));
    }

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

    fn extended_offer(channel: u64, revision: u64) -> Offer {
        let mut result = offer(channel, revision);
        for plane in 2..4 {
            let mut route = result.routes[0].clone();
            route.plane = plane;
            route.cookie = [plane + 1; 16];
            result.routes.push(route);
        }
        result
    }

    #[test]
    fn extended_offers_bind_four_distinct_receive_planes_and_keep_legacy_bytes() {
        let full = extended_offer(1, 1);
        assert_eq!(full.encode().len(), 345);
        assert_eq!(Offer::decode(&full.encode()), Some(full.clone()));
        assert_eq!(full.legacy().encode(), offer(1, 1).encode());
        for i in 0..4 {
            assert_eq!(full.receive_address(i).unwrap().plane as usize, i);
        }
        assert_eq!(full.legacy().receive_address(3).unwrap().plane, 0);
        assert_eq!(full.legacy().receive_address(2).unwrap().plane, 1);
        let mut partial = full.clone();
        partial.routes.remove(2); // screen address is not ready yet
        assert_eq!(Offer::decode(&partial.encode()), Some(partial.clone()));
        assert!(partial.receive_address(2).is_none());
        assert_eq!(partial.receive_address(3).unwrap().plane, 3);
        let mut invalid = full.clone();
        invalid.routes[3].plane = 4;
        assert!(Offer::decode(&invalid.encode()).is_none());
        invalid.routes[3].plane = 2;
        assert!(Offer::decode(&invalid.encode()).is_none());
        let mut primary_missing = full;
        primary_missing.routes.remove(0);
        assert!(Offer::decode(&primary_missing.encode()).is_none());
    }

    #[test]
    fn compatibility_reordering_cannot_collapse_extended_routes_or_change_addresses() {
        let mut inbox = OfferInbox::default();
        let full = extended_offer(1, 1);
        inbox.accept(full.legacy());
        inbox.accept(full.clone());
        assert!(inbox.is_current(&full));
        inbox.accept(full.legacy());
        inbox.accept(offer(1, 100)); // compatibility does not undo negotiated isolation
        assert!(inbox.is_current(&full));
        let next = extended_offer(1, 2);
        inbox.accept(next.clone());
        inbox.accept(full);
        assert!(inbox.is_current(&next));
        let mut conflict = next.clone();
        conflict.routes[3].cookie = [99; 16];
        inbox.accept(conflict);
        assert!(inbox.is_current(&next));
        let legacy_restart = offer(2, 1);
        inbox.accept(legacy_restart.clone());
        assert!(inbox.is_current(&legacy_restart));
        let mut conflict_extension = extended_offer(2, 1);
        conflict_extension.routes[0].cookie = [99; 16];
        inbox.accept(conflict_extension);
        assert!(inbox.is_current(&legacy_restart));
    }

    #[tokio::test]
    async fn compatibility_advertisement_stops_after_peer_proves_extended_decoder() {
        let peer = [0xc1; 32];
        let cipher = Arc::new(crate::media::cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap());
        let (_dir, mut runtime, routes) = fixture(peer, 1, cipher).await;
        let full = extended_offer(1, 1);
        assert_eq!(
            routes.advertisement_offers(full.clone()),
            vec![full.clone(), full.legacy()]
        );
        routes.accept_control(&full.encode());
        assert_eq!(routes.advertisement_offers(full.clone()), vec![full]);
        routes.stop();
        runtime.stop().await.unwrap();
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
        assert_eq!(aborts.len(), 5);
        assert!(!routes.screen_active.load(Ordering::Acquire));
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
