//! Prove that a configured gateway can be reached over Veil's app path.

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, ensure};
use tokio::io::AsyncReadExt as _;
use tokio::sync::watch;
use tokio::time::{Instant, MissedTickBehavior, interval, sleep, timeout};
use veil_proto::budget::MAX_MEMBERSHIP_CERT_SIZE;
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
const CHALLENGE_SPACING: Duration = Duration::from_millis(200);
const PEER_ANSWER_SPACING: Duration = Duration::from_secs(1);
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(10);
const RENEW_AFTER: Duration = Duration::from_secs(12);
const LOCAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const RETRY_AFTER: Duration = Duration::from_secs(5);

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
}

struct Peer {
    app_id: AppId,
    pending: Option<Challenge>,
    probe_after: Instant,
    answer_after: Instant,
}

impl Peer {
    fn new(app_id: AppId, now: Instant) -> Self {
        Self {
            app_id,
            pending: None,
            probe_after: now,
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
        self.probe_after = now + RENEW_AFTER;
        true
    }
}

struct Gateway {
    node: NodeId,
    namespace: String,
    name: String,
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
            authority,
        }
    }

    fn app_id(&self, peer: &NodeId) -> AppId {
        veil_app::address::app_id(peer, &self.namespace, &self.name)
    }

    fn reconcile(&self, cfg: &OgateConfig, peers: &mut BTreeMap<NodeId, Peer>) {
        let mut updated = BTreeMap::new();
        let now = Instant::now();
        for entry in &cfg.peers {
            let mut node = NodeId::default();
            if hex::decode_to_slice(&entry.node_id, &mut node).is_ok() && node != self.node {
                updated.entry(node).or_insert_with(|| {
                    peers
                        .remove(&node)
                        .unwrap_or_else(|| Peer::new(self.app_id(&node), now))
                });
            }
        }
        *peers = updated;
    }
}

pub(crate) async fn run(
    mut config: watch::Receiver<OgateConfig>,
    certificate_path: PathBuf,
    node: NodeId,
    authority: PnetAuthority,
) {
    let gateway = Gateway::new(&config.borrow(), node, authority);
    let mut first_failure = true;
    while authority.is_current(unix_secs_now_u64()) && config.has_changed().is_ok() {
        match serve(&gateway, &certificate_path, &mut config).await {
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
    config: &mut watch::Receiver<OgateConfig>,
) -> anyhow::Result<()> {
    let socket = config.borrow().socket_path.clone();
    let certificate = read_certificate(certificate_path)
        .await
        .context("read the local routed membership certificate")?;
    let client = VeilClient::connect_for_pnet_status(socket, true).await?;
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
    };
    let mut peers = BTreeMap::new();
    gateway.reconcile(&config.borrow_and_update(), &mut peers);
    let mut cursor = None;
    let mut pace = interval(PROBE_SPACING);
    pace.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tracing::info!("checking authenticated P-Net reachability");
    loop {
        ensure!(current(local_expiry), "local routed membership expired");
        tokio::select! {
            _ = &mut disconnected => anyhow::bail!("routed check IPC disconnected"),
            changed = config.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                gateway.reconcile(&config.borrow_and_update(), &mut peers);
            }
            _ = pace.tick() => {
                let next = cursor
                    .and_then(|node| peers.range((Excluded(node), Unbounded)).next())
                    .map(|(&node, _)| node)
                    .or_else(|| peers.first_key_value().map(|(&node, _)| node));
                if let Some(node) = next {
                    cursor = Some(node);
                    let peer = peers.get_mut(&node).expect("selected configured peer");
                    if !config.has_changed().unwrap_or(true) {
                        exchange.probe(node, peer).await?;
                    }
                }
            }
            message = receiver.recv() => {
                let message = message?.context("routed check endpoint closed")?;
                if let Some(peer) = peers.get_mut(&message.src_node_id) {
                    exchange.receive(&message, peer, config).await?;
                }
            }
        }
    }
}

struct Exchange<'a> {
    client: &'a VeilClient,
    sender: &'a AppSender,
    certificate: &'a [u8],
    local_app: AppId,
    local_expiry: u64,
    challenge_after: Instant,
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
        if peer.probe_after > now || !current(self.local_expiry) {
            return Ok(());
        }
        let mut nonce = Nonce::default();
        getrandom::fill(&mut nonce)
            .map_err(|error| anyhow::anyhow!("generate routed challenge: {error}"))?;
        let deadline = now + CHALLENGE_LIFETIME;
        peer.pending = Some(Challenge { nonce, deadline });
        peer.probe_after = deadline;
        self.send(node, peer.app_id, Kind::Challenge, nonce).await
    }

    async fn receive(
        &mut self,
        message: &IncomingMessage,
        peer: &mut Peer,
        config: &watch::Receiver<OgateConfig>,
    ) -> anyhow::Result<()> {
        let Some(proof) = Proof::from_message(message, peer.app_id, self.local_app) else {
            return Ok(());
        };
        if config.has_changed().unwrap_or(true) || !current(self.local_expiry) {
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
        let node = message.src_node_id;
        let expiry = match verified_expiry(self.client, &node, proof.certificate).await {
            Ok(Some(expiry)) => expiry,
            Ok(None) => return Ok(()),
            Err(error) => {
                tracing::debug!(%error, "could not verify routed P-Net certificate");
                return Ok(());
            }
        };
        if config.has_changed().unwrap_or(true) || !current(self.local_expiry) || !current(expiry) {
            return Ok(());
        }
        match proof.kind {
            Kind::Challenge => {
                self.send(node, peer.app_id, Kind::Answer, proof.nonce)
                    .await?
            }
            Kind::Answer if peer.accept_answer(&proof.nonce, Instant::now()) => {
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
        let mut peer = Peer::new([1; 32], now);
        let nonce = [2; 32];
        let deadline = now + CHALLENGE_LIFETIME;
        peer.pending = Some(Challenge { nonce, deadline });
        assert!(!peer.accept_answer(&[3; 32], now));
        assert!(!peer.accept_answer(&nonce, deadline));
        assert!(peer.accept_answer(&nonce, now));
        assert!(!peer.accept_answer(&nonce, now));
    }
}
