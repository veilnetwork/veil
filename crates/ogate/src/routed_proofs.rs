//! Prove that a configured gateway can be reached over Veil's app path.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context as _, ensure};
use tokio::io::AsyncReadExt as _;
use tokio::sync::{broadcast, watch};
use tokio::time::{Instant, MissedTickBehavior, interval, sleep, timeout};
use veil_proto::budget::MAX_MEMBERSHIP_CERT_SIZE;
use veil_proto::event_kind;
use veil_util::unix_secs_now_u64;
use veilclient::{AppSender, IncomingMessage, PnetAuthority, SenderProvenance, VeilClient};

use crate::app_id::derive_app_id;
use crate::config::OgateConfig;
use crate::routing::NodeId;

type AppId = [u8; 32];
type Nonce = [u8; 32];

const VERSION: u8 = 1;
const HEADER_SIZE: usize = 2 + 32 * 3;
const ENDPOINT: u32 = 1;
const PROBE_SPACING: Duration = Duration::from_millis(300);
const RENEWAL_BURST: u8 = 3;
const CHALLENGE_SPACING: Duration = Duration::from_millis(200);
const PEER_ANSWER_SPACING: Duration = Duration::from_secs(1);
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(10);
const RENEW_AFTER: Duration = Duration::from_secs(12);
const ROUTE_LIFETIME: Duration = Duration::from_secs(18);
const RENEW_RETRANSMIT_AFTER: Duration = Duration::from_secs(2);
const RECOVERY_WINDOW: Duration = Duration::from_secs(36);
const LOCAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const RETRY_AFTER: Duration = Duration::from_secs(5);

type Assignment = Arc<AtomicBool>;

/// Only the route task publishes eligible peers, after resolving the address
/// policy. Each assignment remains valid across continuous, unchanged grants.
#[derive(Default)]
pub(crate) struct ProbeRoster {
    peers: BTreeMap<NodeId, Assignment>,
    policy_window: Option<(u64, u64)>,
}

fn policy_current(window: Option<(u64, u64)>, unix: u64) -> bool {
    unix != 0 && window.is_none_or(|(from, until)| unix >= from && unix < until)
}

impl ProbeRoster {
    pub(crate) fn updated(
        &self,
        peers: impl Iterator<Item = NodeId>,
        policy_window: Option<(u64, u64)>,
        same_addresses: impl Fn(&NodeId) -> bool,
    ) -> Self {
        let unix = unix_secs_now_u64();
        let preserve =
            policy_current(self.policy_window, unix) && policy_current(policy_window, unix);
        let mut assignments = BTreeMap::new();
        for peer in peers {
            let previous = self
                .peers
                .get(&peer)
                .filter(|_| preserve && same_addresses(&peer));
            let assignment = previous
                .cloned()
                .unwrap_or_else(|| Arc::new(AtomicBool::new(true)));
            assignments.insert(peer, assignment);
        }
        for (peer, previous) in &self.peers {
            if !assignments
                .get(peer)
                .is_some_and(|current| Arc::ptr_eq(current, previous))
            {
                previous.store(false, Ordering::Release);
            }
        }
        Self {
            peers: assignments,
            policy_window,
        }
    }

    pub(crate) fn matches(&self, peer: &NodeId, proof: &RouteProof) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|assignment| Arc::ptr_eq(assignment, &proof.assignment))
    }
}

/// An old route snapshot cannot outlive withdrawal of its proof.
#[derive(Clone)]
pub(crate) struct RouteProof {
    valid: Arc<AtomicBool>,
    lease_until: Instant,
    cert_until: u64,
    assignment: Assignment,
    policy_window: Option<(u64, u64)>,
}

impl RouteProof {
    pub(crate) fn allows_at(&self, now: Instant, unix: u64) -> bool {
        self.valid.load(Ordering::Acquire)
            && self.assignment.load(Ordering::Acquire)
            && now < self.lease_until
            && policy_current(self.policy_window, unix)
            && (self.cert_until == 0 || unix < self.cert_until)
    }

    fn revoke(&self) {
        self.valid.store(false, Ordering::Release);
    }
}

pub(crate) type RouteProofs = HashMap<NodeId, RouteProof>;

struct RouteLeases<'a> {
    active: RouteProofs,
    report: Option<&'a watch::Sender<Arc<RouteProofs>>>,
}

impl RouteLeases<'_> {
    fn publish(&self) {
        if let Some(report) = self.report {
            report.send_replace(Arc::new(self.active.clone()));
        }
    }

    fn renew(
        &mut self,
        peer: NodeId,
        cert_until: u64,
        assignment: &Assignment,
        policy_window: Option<(u64, u64)>,
    ) {
        if self.report.is_none() {
            return;
        }
        let now = Instant::now();
        let unix = unix_secs_now_u64();
        let valid = self.active.get(&peer).and_then(|previous| {
            if previous.allows_at(now, unix) && Arc::ptr_eq(&previous.assignment, assignment) {
                Some(Arc::clone(&previous.valid))
            } else {
                previous.revoke();
                None
            }
        });
        self.active.insert(
            peer,
            RouteProof {
                valid: valid.unwrap_or_else(|| Arc::new(AtomicBool::new(true))),
                lease_until: now + ROUTE_LIFETIME,
                cert_until,
                assignment: Arc::clone(assignment),
                policy_window,
            },
        );
        self.publish();
    }

    fn retain(&mut self, mut keep: impl FnMut(&NodeId, &RouteProof) -> bool) {
        let old_count = self.active.len();
        self.active.retain(|peer, proof| {
            if keep(peer, proof) {
                return true;
            }
            proof.revoke();
            false
        });
        if self.active.len() != old_count {
            self.publish();
        }
    }

    fn revoke(&mut self, peer: &NodeId) {
        if let Some(proof) = self.active.remove(peer) {
            proof.revoke();
            self.publish();
        }
    }
}

impl Drop for RouteLeases<'_> {
    fn drop(&mut self) {
        self.retain(|_, _| false);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Challenge = 1,
    Answer = 2,
}

struct Proof<'a> {
    kind: Kind,
    sender: AppId,
    recipient: AppId,
    nonce: Nonce,
    certificate: &'a [u8],
}

impl<'a> Proof<'a> {
    fn decode(data: &'a [u8]) -> Option<Self> {
        let (header, certificate) = data.split_first_chunk::<HEADER_SIZE>()?;
        if certificate.is_empty() || certificate.len() > MAX_MEMBERSHIP_CERT_SIZE {
            return None;
        }
        let kind = match *header {
            [VERSION, 1, ..] => Kind::Challenge,
            [VERSION, 2, ..] => Kind::Answer,
            _ => return None,
        };
        Some(Self {
            kind,
            sender: header[2..34].try_into().ok()?,
            recipient: header[34..66].try_into().ok()?,
            nonce: header[66..].try_into().ok()?,
            certificate,
        })
    }

    fn from_message(message: &'a IncomingMessage, sender: AppId, recipient: AppId) -> Option<Self> {
        if !matches!(
            message.provenance,
            SenderProvenance::Signed | SenderProvenance::SessionPeer
        ) || message.src_app_id != sender
        {
            return None;
        }
        // The pair also belongs inside the authenticated application payload.
        let proof = Self::decode(&message.data)?;
        (proof.sender == sender && proof.recipient == recipient).then_some(proof)
    }

    fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(HEADER_SIZE + self.certificate.len());
        data.extend_from_slice(&[VERSION, self.kind as u8]);
        data.extend_from_slice(&self.sender);
        data.extend_from_slice(&self.recipient);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(self.certificate);
        data
    }
}

struct Challenge {
    nonce: Nonce,
    deadline: Instant,
    retransmitted: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProbeKind {
    Renewal,
    Hint,
    Discovery,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ScheduledProbe {
    at: Instant,
    kind: ProbeKind,
}

#[derive(Default)]
struct ProbeSchedule {
    renewals: BTreeSet<(Instant, NodeId)>,
    hints: BTreeSet<(Instant, NodeId)>,
    discovery: BTreeSet<(Instant, NodeId)>,
    renewal_run: u8,
    last_background_was_hint: bool,
}

impl ProbeSchedule {
    fn queue(&mut self, kind: ProbeKind) -> &mut BTreeSet<(Instant, NodeId)> {
        match kind {
            ProbeKind::Renewal => &mut self.renewals,
            ProbeKind::Hint => &mut self.hints,
            ProbeKind::Discovery => &mut self.discovery,
        }
    }

    fn rebuild(&mut self, peers: &BTreeMap<NodeId, Peer>) {
        self.renewals.clear();
        self.hints.clear();
        self.discovery.clear();
        for (&node, peer) in peers {
            self.queue(peer.probe.kind).insert((peer.probe.at, node));
        }
    }

    fn update(&mut self, node: NodeId, before: ScheduledProbe, after: ScheduledProbe) {
        if before != after {
            self.queue(before.kind).remove(&(before.at, node));
            self.queue(after.kind).insert((after.at, node));
        }
    }

    fn next(&mut self, now: Instant) -> Option<NodeId> {
        fn due(queue: &BTreeSet<(Instant, NodeId)>, now: Instant) -> Option<NodeId> {
            let &(at, node) = queue.first()?;
            (at <= now).then_some(node)
        }

        let discovery = due(&self.discovery, now);
        let hint = due(&self.hints, now);
        if (self.renewal_run < RENEWAL_BURST || discovery.is_none() && hint.is_none())
            && let Some(node) = due(&self.renewals, now)
        {
            self.renewal_run = (self.renewal_run + 1).min(RENEWAL_BURST);
            return Some(node);
        }
        // Reserve a slot for background work. A stream of authenticated hints
        // must also leave a turn for peers that have never exchanged traffic.
        self.renewal_run = 0;
        let next = if self.last_background_was_hint {
            discovery.or(hint)
        } else {
            hint.or(discovery)
        };
        if let Some(node) = next {
            self.last_background_was_hint = hint == Some(node);
        }
        next
    }
}

struct Peer {
    app_id: AppId,
    assignment: Assignment,
    pending: Option<Challenge>,
    last_confirmed: Option<Instant>,
    probe: ScheduledProbe,
    answer_after: Instant,
}

impl Peer {
    fn new(app_id: AppId, assignment: Assignment, now: Instant) -> Self {
        Self {
            app_id,
            assignment,
            pending: None,
            last_confirmed: None,
            probe: ScheduledProbe {
                at: now,
                kind: ProbeKind::Discovery,
            },
            answer_after: now,
        }
    }

    fn expects(&self, nonce: &Nonce, now: Instant) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|challenge| challenge.deadline > now && &challenge.nonce == nonce)
    }

    fn accept_answer(&mut self, nonce: &Nonce, now: Instant) -> bool {
        if !self.expects(nonce, now) {
            return false;
        }
        self.pending = None;
        self.last_confirmed = Some(now);
        self.probe = ScheduledProbe {
            at: now + RENEW_AFTER,
            kind: ProbeKind::Renewal,
        };
        true
    }

    fn discover_at(&mut self, at: Instant) {
        self.probe = ScheduledProbe {
            at,
            kind: ProbeKind::Discovery,
        };
    }

    fn defer_probe(&mut self) {
        self.pending = None;
        self.retry_at(Instant::now() + RETRY_AFTER);
    }

    fn recently_confirmed(&self, now: Instant) -> bool {
        self.last_confirmed
            .is_some_and(|at| now.saturating_duration_since(at) < RECOVERY_WINDOW)
    }

    fn retry_at(&mut self, at: Instant) {
        if self.recently_confirmed(at) {
            self.probe = ScheduledProbe {
                at,
                kind: ProbeKind::Hint,
            };
        } else {
            self.discover_at(at);
        }
    }

    fn hint(&mut self, now: Instant) {
        if self.probe.kind != ProbeKind::Renewal
            && self
                .pending
                .as_ref()
                .is_none_or(|probe| probe.deadline <= now || !probe.retransmitted)
        {
            self.probe = ScheduledProbe {
                at: now,
                kind: ProbeKind::Hint,
            };
        }
    }

    fn outgoing_nonce(&mut self, now: Instant) -> anyhow::Result<Nonce> {
        if self.probe.kind == ProbeKind::Hint
            && let Some(challenge) = self.pending.as_mut()
            && challenge.deadline > now
            && !challenge.retransmitted
        {
            challenge.retransmitted = true;
            let (nonce, deadline) = (challenge.nonce, challenge.deadline);
            self.retry_at(deadline);
            return Ok(nonce);
        }
        let mut nonce = Nonce::default();
        getrandom::fill(&mut nonce)
            .map_err(|error| anyhow::anyhow!("generate routed challenge: {error}"))?;
        let deadline = now + CHALLENGE_LIFETIME;
        self.pending = Some(Challenge {
            nonce,
            deadline,
            retransmitted: false,
        });
        if self.recently_confirmed(now) {
            self.retry_at(now + RENEW_RETRANSMIT_AFTER);
        } else {
            self.discover_at(deadline);
        }
        Ok(nonce)
    }
}

struct Gateway {
    node: NodeId,
    namespace: String,
    name: String,
    socket: PathBuf,
    authority: PnetAuthority,
}

impl Gateway {
    fn new(cfg: &OgateConfig, node: NodeId, authority: PnetAuthority) -> Self {
        let namespace = format!(
            "ogate.route.v1.{}",
            hex::encode(authority.root.owner_fingerprint)
        );
        let domain = derive_app_id(&authority.root.network_id, &cfg.network, &cfg.app);
        let name = format!("{:08x}.{}", cfg.endpoint_id, hex::encode(domain));
        Self {
            node,
            namespace,
            name,
            socket: cfg.socket_path.clone(),
            authority,
        }
    }

    fn app_id(&self, peer: &NodeId) -> AppId {
        veil_app::address::app_id(peer, &self.namespace, &self.name)
    }

    fn reconcile(&self, roster: &ProbeRoster, peers: &mut BTreeMap<NodeId, Peer>) {
        let mut updated = BTreeMap::new();
        let now = Instant::now();
        for (&node, assignment) in &roster.peers {
            if node != self.node {
                let peer = peers
                    .remove(&node)
                    .filter(|peer| Arc::ptr_eq(&peer.assignment, assignment));
                updated.insert(
                    node,
                    peer.unwrap_or_else(|| {
                        Peer::new(self.app_id(&node), Arc::clone(assignment), now)
                    }),
                );
            }
        }
        *peers = updated;
    }
}

pub(crate) async fn run(
    gateway_config: OgateConfig,
    mut roster: watch::Receiver<Arc<ProbeRoster>>,
    certificate_path: PathBuf,
    node: NodeId,
    authority: PnetAuthority,
    report: Option<watch::Sender<Arc<RouteProofs>>>,
) {
    let gateway = Gateway::new(&gateway_config, node, authority);
    let mut first_failure = true;
    while authority.is_current(unix_secs_now_u64()) && roster.has_changed().is_ok() {
        match serve(&gateway, &certificate_path, &mut roster, report.as_ref()).await {
            Ok(()) => return,
            Err(error) if first_failure => {
                tracing::warn!(%error, "routed P-Net checks unavailable");
                first_failure = false;
            }
            Err(error) => tracing::debug!(%error, "routed P-Net check retry failed"),
        }
        sleep(RETRY_AFTER).await;
    }
}

async fn read_certificate(path: &Path) -> anyhow::Result<Vec<u8>> {
    ensure!(
        tokio::fs::metadata(path).await?.is_file(),
        "routed membership certificate must be a regular file"
    );
    let mut bytes = Vec::new();
    tokio::fs::File::open(path)
        .await?
        .take((MAX_MEMBERSHIP_CERT_SIZE + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_MEMBERSHIP_CERT_SIZE,
        "invalid routed membership certificate size"
    );
    Ok(bytes)
}

fn current(expiry: u64) -> bool {
    let now = unix_secs_now_u64();
    now != 0 && (expiry == 0 || now < expiry)
}

async fn verified_expiry(
    client: &VeilClient,
    member: &NodeId,
    certificate: &[u8],
) -> anyhow::Result<Option<u64>> {
    Ok(timeout(
        LOCAL_REQUEST_TIMEOUT,
        client.verify_pnet_member(member, certificate),
    )
    .await??
    .filter(|&expiry| current(expiry)))
}

async fn serve(
    gateway: &Gateway,
    certificate_path: &Path,
    roster: &mut watch::Receiver<Arc<ProbeRoster>>,
    report: Option<&watch::Sender<Arc<RouteProofs>>>,
) -> anyhow::Result<()> {
    let certificate = read_certificate(certificate_path)
        .await
        .context("read the local routed membership certificate")?;
    let client = VeilClient::connect_for_pnet_status(&gateway.socket, true).await?;
    ensure!(
        client.pnet_authority() == Some(gateway.authority)
            && gateway.authority.is_current(unix_secs_now_u64())
            && client.supports_pnet_member_verification(),
        "routed check IPC has a different or expired P-Net authority"
    );
    ensure!(
        timeout(LOCAL_REQUEST_TIMEOUT, client.node_identity())
            .await??
            .node_id
            == gateway.node,
        "routed check IPC has a different daemon identity"
    );
    let mut events = client.events_with_lag().await;
    let local_expiry = verified_expiry(&client, &gateway.node, &certificate)
        .await?
        .context("daemon rejected the local routed membership certificate")?;
    let handle = client
        .bind_named(&gateway.namespace, &gateway.name, ENDPOINT)
        .await?;
    let local_app = gateway.app_id(&gateway.node);
    ensure!(
        *handle.app_id() == local_app,
        "routed check app ID mismatch"
    );
    let (sender, mut receiver) = handle.into_split();
    let disconnected = client
        .pnet_status_disconnected()
        .context("routed check IPC has no liveness notification")?;
    tokio::pin!(disconnected);
    let mut exchange = Exchange {
        client: &client,
        sender: &sender,
        certificate: &certificate,
        local_app,
        local_expiry,
        challenge_after: Instant::now(),
        leases: RouteLeases {
            active: RouteProofs::new(),
            report,
        },
    };
    let mut peers = BTreeMap::new();
    let mut policy_window = {
        let configured = roster.borrow_and_update();
        gateway.reconcile(&configured, &mut peers);
        configured.policy_window
    };
    let mut schedule = ProbeSchedule::default();
    schedule.rebuild(&peers);
    let mut pace = interval(PROBE_SPACING);
    pace.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tracing::info!("checking authenticated P-Net reachability");
    loop {
        ensure!(current(local_expiry), "local routed membership expired");
        tokio::select! {
            _ = &mut disconnected => anyhow::bail!("routed check IPC disconnected"),
            event = events.recv(), if report.is_some() => {
                match event {
                    Ok(event) if event.kind == event_kind::PNET_MEMBER_REVOKED => {
                        if let Ok(node) = NodeId::try_from(event.payload.as_slice()) {
                            ensure!(node != gateway.node, "local routed membership revoked");
                            exchange.leases.revoke(&node);
                            if let Some(peer) = peers.get_mut(&node) {
                                let before = peer.probe;
                                peer.defer_probe();
                                schedule.update(node, before, peer.probe);
                            }
                        }
                    }
                    Ok(event) if event.kind == event_kind::EVENTS_LAGGED => {
                        anyhow::bail!("daemon missed routed admission events");
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        anyhow::bail!("routed admission events lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => anyhow::bail!("routed event stream closed"),
                    Ok(_) => {}
                }
            }
            changed = roster.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                let configured = Arc::clone(&roster.borrow_and_update());
                gateway.reconcile(&configured, &mut peers);
                exchange.leases.retain(|node, proof| configured.matches(node, proof));
                if configured.policy_window != policy_window {
                    policy_window = configured.policy_window;
                    // Give carried routes a chance to renew before the earlier
                    // policy's deadline. Keep challenges already in flight.
                    let now = Instant::now();
                    for (node, peer) in &mut peers {
                        if peer.pending.is_none() && exchange.leases.active.contains_key(node) {
                            peer.probe = ScheduledProbe { at: now, kind: ProbeKind::Renewal };
                        }
                    }
                }
                schedule.rebuild(&peers);
            }
            _ = pace.tick(), if !peers.is_empty() => {
                if !exchange.leases.active.is_empty() {
                    let now = Instant::now();
                    let unix = unix_secs_now_u64();
                    exchange.leases.retain(|_, proof| proof.allows_at(now, unix));
                }
                if let Some(node) = schedule.next(Instant::now()) {
                    let peer = peers.get_mut(&node).expect("selected configured peer");
                    if current_roster(roster, &node, peer).is_some() {
                        let before = peer.probe;
                        exchange.probe(node, peer).await?;
                        schedule.update(node, before, peer.probe);
                    }
                }
            }
            message = receiver.recv() => {
                let message = message?.context("routed check endpoint closed")?;
                let node = message.src_node_id;
                if let Some(peer) = peers.get_mut(&node) {
                    let before = peer.probe;
                    exchange.receive(&message, peer, roster).await?;
                    schedule.update(node, before, peer.probe);
                }
            }
        }
    }
}

fn current_roster(
    roster: &watch::Receiver<Arc<ProbeRoster>>,
    node: &NodeId,
    peer: &Peer,
) -> Option<Arc<ProbeRoster>> {
    let roster = roster.borrow();
    (roster
        .peers
        .get(node)
        .is_some_and(|assignment| Arc::ptr_eq(assignment, &peer.assignment))
        && peer.assignment.load(Ordering::Acquire)
        && policy_current(roster.policy_window, unix_secs_now_u64()))
    .then(|| Arc::clone(&roster))
}

struct Exchange<'a> {
    client: &'a VeilClient,
    sender: &'a AppSender,
    certificate: &'a [u8],
    local_app: AppId,
    local_expiry: u64,
    challenge_after: Instant,
    leases: RouteLeases<'a>,
}

impl Exchange<'_> {
    async fn send(
        &self,
        node: NodeId,
        recipient: AppId,
        kind: Kind,
        nonce: Nonce,
    ) -> anyhow::Result<()> {
        let data = Proof {
            kind,
            sender: self.local_app,
            recipient,
            nonce,
            certificate: self.certificate,
        }
        .encode();
        timeout(
            LOCAL_REQUEST_TIMEOUT,
            self.sender.send_owned(node, recipient, ENDPOINT, data),
        )
        .await??;
        Ok(())
    }

    async fn probe(&self, node: NodeId, peer: &mut Peer) -> anyhow::Result<()> {
        let now = Instant::now();
        if peer.probe.at > now || !current(self.local_expiry) {
            return Ok(());
        }
        let nonce = peer.outgoing_nonce(now)?;
        self.send(node, peer.app_id, Kind::Challenge, nonce).await
    }

    async fn receive(
        &mut self,
        message: &IncomingMessage,
        peer: &mut Peer,
        roster: &watch::Receiver<Arc<ProbeRoster>>,
    ) -> anyhow::Result<()> {
        let Some(proof) = Proof::from_message(message, peer.app_id, self.local_app) else {
            return Ok(());
        };
        let node = message.src_node_id;
        if current_roster(roster, &node, peer).is_none() || !current(self.local_expiry) {
            return Ok(());
        }
        let now = Instant::now();
        match proof.kind {
            Kind::Challenge => {
                if now < self.challenge_after || now < peer.answer_after {
                    return Ok(());
                }
                self.challenge_after = now + CHALLENGE_SPACING;
                peer.answer_after = now + PEER_ANSWER_SPACING;
            }
            Kind::Answer if !peer.expects(&proof.nonce, now) => return Ok(()),
            Kind::Answer => {}
        }
        let expiry = match verified_expiry(self.client, &node, proof.certificate).await {
            Ok(Some(expiry)) => expiry,
            Ok(None) => {
                self.leases.revoke(&node);
                peer.defer_probe();
                return Ok(());
            }
            Err(error) => {
                self.leases.revoke(&node);
                peer.defer_probe();
                tracing::debug!(%error, "could not verify routed P-Net certificate");
                return Ok(());
            }
        };
        let Some(configured) = current_roster(roster, &node, peer) else {
            return Ok(());
        };
        if !current(self.local_expiry) || !current(expiry) {
            return Ok(());
        }
        match proof.kind {
            Kind::Challenge => {
                self.send(node, peer.app_id, Kind::Answer, proof.nonce)
                    .await?;
                // An authenticated peer is ready to receive a challenge. Its
                // request can order our queue but cannot admit an IP route.
                peer.hint(Instant::now());
            }
            Kind::Answer if peer.accept_answer(&proof.nonce, Instant::now()) => {
                let cert_until = match (self.local_expiry, expiry) {
                    (0, until) | (until, 0) => until,
                    (local, remote) => local.min(remote),
                };
                self.leases
                    .renew(node, cert_until, &peer.assignment, configured.policy_window);
                tracing::debug!(
                    peer = %hex::encode(node),
                    provenance = ?message.provenance,
                    "verified routed P-Net reachability"
                );
            }
            Kind::Answer => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answer_is_bound_to_the_authenticated_endpoints() {
        let mut message = IncomingMessage {
            src_node_id: [8; 32],
            provenance: SenderProvenance::Signed,
            src_app_id: [1; 32],
            data: Proof {
                kind: Kind::Answer,
                sender: [1; 32],
                recipient: [2; 32],
                nonce: [3; 32],
                certificate: &[4],
            }
            .encode(),
            reply_id: 0,
            src_device: None,
        };
        assert!(Proof::from_message(&message, [1; 32], [2; 32]).is_some());
        assert!(Proof::from_message(&message, [1; 32], [3; 32]).is_none());
        message.src_app_id = [5; 32];
        assert!(Proof::from_message(&message, [5; 32], [2; 32]).is_none());
        message.src_app_id = [1; 32];
        for provenance in [SenderProvenance::Claimed, SenderProvenance::LocalIpc] {
            message.provenance = provenance;
            assert!(Proof::from_message(&message, [1; 32], [2; 32]).is_none());
        }
        let mut malformed = message.data;
        malformed.resize(HEADER_SIZE + MAX_MEMBERSHIP_CERT_SIZE + 1, 0);
        assert!(Proof::decode(&malformed).is_none());
        assert!(Proof::decode(&malformed[..HEADER_SIZE]).is_none());
    }

    #[test]
    fn answer_consumes_only_a_matching_unexpired_challenge() {
        let now = Instant::now();
        let mut peer = Peer::new([1; 32], Arc::new(AtomicBool::new(true)), now);
        let nonce = [2; 32];
        let deadline = now + CHALLENGE_LIFETIME;
        peer.pending = Some(Challenge {
            nonce,
            deadline,
            retransmitted: false,
        });
        assert!(!peer.accept_answer(&[3; 32], now));
        assert!(!peer.accept_answer(&nonce, deadline));
        assert!(peer.accept_answer(&nonce, now));
        assert!(!peer.accept_answer(&nonce, now));
    }

    #[test]
    fn renewals_bypass_a_large_roster_with_turns_for_hints_and_discovery() {
        let now = Instant::now();
        let assignment = Arc::new(AtomicBool::new(true));
        let mut peers = BTreeMap::new();
        for index in 0u16..4_096 {
            let mut node = [0; 32];
            node[..2].copy_from_slice(&index.to_be_bytes());
            peers.insert(node, Peer::new(node, Arc::clone(&assignment), now));
        }
        let late = [0xda; 32];
        let mut peer = Peer::new(late, Arc::clone(&assignment), now);
        peer.hint(now);
        peers.insert(late, peer);
        for byte in 0xf1..=0xf7 {
            let node = [byte; 32];
            let mut peer = Peer::new(node, Arc::clone(&assignment), now);
            peer.probe.kind = ProbeKind::Renewal;
            peers.insert(node, peer);
        }

        let mut schedule = ProbeSchedule::default();
        schedule.rebuild(&peers);
        for node in [
            [0xf1; 32], [0xf2; 32], [0xf3; 32], late, [0xf4; 32], [0xf5; 32], [0xf6; 32], [0; 32],
            [0xf7; 32],
        ] {
            assert_eq!(schedule.next(now), Some(node));
            let peer = peers.get_mut(&node).unwrap();
            let previous = peer.probe;
            peer.discover_at(now + CHALLENGE_LIFETIME);
            schedule.update(node, previous, peer.probe);
        }
    }

    #[test]
    fn authenticated_hint_retries_an_unanswered_nonce_once_without_extending_its_life() {
        let now = Instant::now();
        let mut peer = Peer::new([1; 32], Arc::new(AtomicBool::new(true)), now);
        let nonce = peer.outgoing_nonce(now).unwrap();
        let deadline = now + CHALLENGE_LIFETIME;
        let heard_at = now + Duration::from_secs(1);
        peer.hint(heard_at);
        assert_eq!(peer.probe.at, heard_at);
        assert_eq!(peer.outgoing_nonce(heard_at).unwrap(), nonce);
        assert_eq!(peer.probe.at, deadline);
        peer.hint(heard_at + Duration::from_secs(1));
        assert_eq!(peer.probe.at, deadline);
        assert!(!peer.accept_answer(&nonce, deadline));
    }

    #[test]
    fn unanswered_renewal_gets_one_early_retransmit_and_bounded_recovery() {
        let now = Instant::now();
        let mut peer = Peer::new([1; 32], Arc::new(AtomicBool::new(true)), now);
        let initial = peer.outgoing_nonce(now).unwrap();
        assert!(peer.accept_answer(&initial, now));
        let renew_at = now + RENEW_AFTER;
        let renewal = peer.outgoing_nonce(renew_at).unwrap();
        assert_eq!(peer.probe.at, renew_at + RENEW_RETRANSMIT_AFTER);
        assert_eq!(peer.outgoing_nonce(peer.probe.at).unwrap(), renewal);
        assert_eq!(peer.probe.at, renew_at + CHALLENGE_LIFETIME);
        let recovery = peer.outgoing_nonce(peer.probe.at).unwrap();
        assert_ne!(renewal, recovery);
        peer.retry_at(now + RECOVERY_WINDOW);
        assert!(peer.probe.kind == ProbeKind::Discovery);
    }

    #[test]
    fn renewal_shares_revocation_with_already_published_routes() {
        let (report, snapshot) = watch::channel(Arc::new(RouteProofs::new()));
        let mut leases = RouteLeases {
            active: RouteProofs::new(),
            report: Some(&report),
        };
        let member = [7; 32];
        let assignment = Arc::new(AtomicBool::new(true));
        leases.renew(member, 0, &assignment, None);
        let first = snapshot.borrow()[&member].clone();
        let now = Instant::now();
        let unix = unix_secs_now_u64();
        assert!(first.allows_at(now, unix));
        assert!(!first.allows_at(first.lease_until, unix));

        leases.renew(member, unix + 5, &assignment, None);
        let second = snapshot.borrow()[&member].clone();
        assert!(!second.allows_at(now, unix + 5));
        leases.revoke(&member);
        assert!(!first.allows_at(now, unix));
        assert!(!second.allows_at(now, unix));

        leases.renew(member, 0, &assignment, None);
        let third = snapshot.borrow()[&member].clone();
        assert!(third.allows_at(now, unix));
        drop(leases);
        assert!(!third.allows_at(now, unix));
    }

    #[test]
    fn policy_replacement_carries_only_continuous_address_assignments() {
        let unix = unix_secs_now_u64();
        let old_window = Some((unix - 1, unix + 10));
        let renewed_window = Some((unix - 1, unix + 60));
        let unchanged = [1; 32];
        let reassigned = [2; 32];
        let deleted = [3; 32];
        let original = ProbeRoster::default().updated(
            [unchanged, reassigned, deleted].into_iter(),
            old_window,
            |_| false,
        );
        let (report, snapshot) = watch::channel(Arc::new(RouteProofs::new()));
        let mut leases = RouteLeases {
            active: RouteProofs::new(),
            report: Some(&report),
        };
        for (&node, assignment) in &original.peers {
            leases.renew(node, 0, assignment, old_window);
        }
        let issued = Arc::clone(&snapshot.borrow());
        let replacement = original.updated(
            [unchanged, reassigned].into_iter(),
            renewed_window,
            |node| *node == unchanged,
        );
        let now = Instant::now();
        assert!(replacement.matches(&unchanged, &issued[&unchanged]));
        assert!(issued[&unchanged].allows_at(now, unix));
        assert!(!issued[&unchanged].allows_at(now, unix + 10));
        for node in [reassigned, deleted] {
            assert!(!replacement.matches(&node, &issued[&node]));
            assert!(!issued[&node].allows_at(now, unix));
        }
        let restored = replacement.updated(
            [unchanged, reassigned, deleted].into_iter(),
            renewed_window,
            |_| true,
        );
        assert!(!restored.matches(&deleted, &issued[&deleted]));
    }
}
