//! Pull owner-signed policy snapshots over authenticated Veil application streams.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, ensure};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, interval, sleep_until, timeout};
use veil_identity::network_policy::{
    MAX_SIGNED_ROUTE_POLICY_BYTES, VerifiedRoutePolicy, VerifiedRoutePolicyOffer,
};
use veil_proto::event_kind::SESSION_ADMITTED;
use veil_util::unix_secs_now_u64;
use veilclient::{
    AppHandle, PNET_ADMISSION_BATCH_MAX_PEERS, PnetAdmission, PnetAuthority, SenderProvenance,
    VeilClient, VeilStream,
};

use crate::routing::NodeId;
use crate::signed_policy::SignedRoutes;

const REQUEST_MAGIC: [u8; 4] = *b"PNP1";
const SERVICE: &str = "route-policy-v1";
const ENDPOINT: u32 = 1;
const POLL_INTERVAL: Duration = Duration::from_secs(15);
const RECOVERY_POLL_MIN_MS: u64 = 4_000;
const RECOVERY_POLL_JITTER_MS: u64 = 2_000;
const SESSION_POLL_DELAY_MS: u64 = 500;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(12);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_SERVING: usize = PNET_ADMISSION_BATCH_MAX_PEERS;
// Leave headroom in the daemon's per-connection query budget.
const ADMISSION_SPACING: Duration = Duration::from_millis(150);

pub(crate) async fn run(
    policy: Arc<SignedRoutes>,
    socket: &Path,
    node: NodeId,
    authority: PnetAuthority,
) {
    let namespace = format!("pnet.{}", hex::encode(authority.root.network_id));
    let connection = Distribution {
        socket,
        node,
        authority,
        namespace,
    };
    tokio::join!(
        publish(&policy, &connection),
        subscribe(&policy, &connection)
    );
}

struct Distribution<'a> {
    socket: &'a Path,
    node: NodeId,
    authority: PnetAuthority,
    namespace: String,
}

impl Distribution<'_> {
    async fn connect(&self) -> anyhow::Result<VeilClient> {
        let client = VeilClient::connect_with_pnet_authority(self.socket).await?;
        ensure!(
            client.pnet_authority() == Some(self.authority)
                && self.authority.is_current(unix_secs_now_u64()),
            "policy distribution IPC has a different or expired daemon authority"
        );
        ensure!(
            client.node_identity().await?.node_id == self.node,
            "policy distribution IPC has a different daemon identity"
        );
        ensure!(
            client.supports_pnet_admission_batch(),
            "policy distribution IPC requires P-Net admission batches"
        );
        Ok(client)
    }
}

async fn publish(policy: &Arc<SignedRoutes>, distribution: &Distribution<'_>) {
    if !policy.publish {
        return;
    }
    while distribution.authority.is_current(unix_secs_now_u64()) {
        if let Err(error) = serve_mirror(policy, distribution).await {
            tracing::debug!(%error, "P-Net policy mirror unavailable");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn serve_mirror(
    policy: &Arc<SignedRoutes>,
    distribution: &Distribution<'_>,
) -> anyhow::Result<()> {
    let client = Arc::new(distribution.connect().await?);
    let mut app = client
        .bind_device_scoped(&distribution.namespace, SERVICE, ENDPOINT)
        .await?;
    let mut requests = JoinSet::new();
    let mut in_flight = Vec::with_capacity(MAX_SERVING);
    let mut health = interval(Duration::from_secs(1));
    let authority = distribution.authority;
    let (ready, waiting) = mpsc::channel(MAX_SERVING);
    let mut dispatcher = std::pin::pin!(dispatch_requests(&client, policy, authority, waiting));
    tracing::info!("serving owner-signed P-Net route policies");
    loop {
        tokio::select! {
            _ = &mut dispatcher => return Ok(()),
            _ = health.tick() => {
                if client.is_disconnected() || !authority.is_current(unix_secs_now_u64()) {
                    return Ok(());
                }
            }
            Some(result) = requests.join_next_with_id() => {
                let finished = match result {
                    Ok((id, ())) => id,
                    Err(error) => error.id(),
                };
                in_flight.retain(|&(id, _)| id != finished);
            }
            incoming = app.accept_stream() => {
                let Some(incoming) = incoming else { return Ok(()); };
                let source = incoming.src_node_id;
                if in_flight.len() >= MAX_SERVING
                    || source == distribution.node
                    || incoming.provenance != SenderProvenance::SessionPeer
                    || in_flight.iter().any(|&(_, peer)| peer == source)
                {
                    continue;
                }
                let client = Arc::clone(&client);
                let ready = ready.clone();
                let task = requests.spawn(async move {
                    let _ = timeout(
                        TRANSFER_TIMEOUT,
                        reply_to_member(&client, authority, &ready, source, incoming.stream),
                    ).await;
                });
                in_flight.push((task.id(), source));
            }
        }
    }
}

struct WaitingRequest {
    source: NodeId,
    reply: oneshot::Sender<AuthorizedSnapshot>,
}

struct PublishedSnapshot {
    policy: Arc<VerifiedRoutePolicy>,
    bytes: Arc<[u8]>,
}

struct AuthorizedSnapshot {
    admission: PnetAdmission,
    snapshot: Arc<PublishedSnapshot>,
}

async fn dispatch_requests(
    client: &VeilClient,
    policy: &Arc<SignedRoutes>,
    authority: PnetAuthority,
    mut waiting: mpsc::Receiver<WaitingRequest>,
) {
    let mut pace = interval(ADMISSION_SPACING);
    pace.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut batch = Vec::with_capacity(MAX_SERVING);
    while let Some(first) = waiting.recv().await {
        pace.tick().await;
        batch.push(first);
        while batch.len() < MAX_SERVING
            && let Ok(request) = waiting.try_recv()
        {
            batch.push(request);
        }
        batch.retain(|request| !request.reply.is_closed());
        if let Err(error) = authorize_batch(client, policy, authority, &mut batch).await {
            tracing::debug!(%error, "P-Net policy mirror request batch failed");
        }
        batch.clear();
    }
}

async fn authorize_batch(
    client: &VeilClient,
    policy: &Arc<SignedRoutes>,
    authority: PnetAuthority,
    batch: &mut Vec<WaitingRequest>,
) -> anyhow::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let peers: Vec<_> = batch.iter().map(|request| request.source).collect();
    let admissions = client.peer_pnet_admissions(&peers).await?;
    let now = unix_secs_now_u64();
    let admitted: Vec<_> = batch
        .drain(..)
        .zip(admissions)
        .filter(|(request, admission)| {
            authorized(authority, *admission, now) && !request.reply.is_closed()
        })
        .collect();
    if admitted.is_empty() {
        return Ok(());
    }

    // Read the protected store once for the group. Each requester gets the
    // same verified bytes and still checks its own membership before writing.
    let policy = Arc::clone(policy);
    let (policy, bytes) = tokio::task::spawn_blocking(move || policy.installed_bytes()).await??;
    let snapshot = Arc::new(PublishedSnapshot { policy, bytes });
    tracing::trace!(
        requests = peers.len(),
        admitted = admitted.len(),
        "loaded P-Net policy for mirror requests"
    );
    for (request, admission) in admitted {
        let _ = request.reply.send(AuthorizedSnapshot {
            admission,
            snapshot: Arc::clone(&snapshot),
        });
    }
    Ok(())
}

async fn reply_to_member(
    client: &VeilClient,
    authority: PnetAuthority,
    ready: &mpsc::Sender<WaitingRequest>,
    source: NodeId,
    mut stream: VeilStream,
) -> anyhow::Result<()> {
    let mut request = [0; 12];
    timeout(REQUEST_TIMEOUT, stream.read_exact(&mut request)).await??;
    ensure!(
        request[..4] == REQUEST_MAGIC,
        "invalid P-Net policy request"
    );
    let revision = u64::from_be_bytes(request[4..].try_into()?);

    let (reply, authorization) = oneshot::channel();
    ready
        .try_send(WaitingRequest { source, reply })
        .map_err(|_| anyhow::anyhow!("P-Net policy mirror request queue unavailable"))?;
    let AuthorizedSnapshot {
        admission,
        snapshot,
    } = authorization.await?;
    let now = unix_secs_now_u64();
    ensure!(
        !client.is_disconnected() && authorized(authority, admission, now),
        "requester's P-Net admission expired during snapshot lookup"
    );
    if snapshot.policy.revision > revision && snapshot.policy.check_current(now).is_ok() {
        stream.write_u32(snapshot.bytes.len().try_into()?).await?;
        stream.write_all(&snapshot.bytes).await?;
    } else {
        stream.write_u32(0).await?;
    }
    stream.shutdown().await?;
    Ok(())
}

async fn subscribe(policy: &Arc<SignedRoutes>, distribution: &Distribution<'_>) {
    let mirrors: Vec<_> = policy
        .mirrors
        .iter()
        .copied()
        .filter(|peer| peer != &distribution.node)
        .collect();
    if mirrors.is_empty() {
        return;
    }

    let expiry = policy.updates();
    let phase = u64::from(u16::from_be_bytes([
        distribution.node[0],
        distribution.node[1],
    ]));
    let window = poll_interval(*expiry.borrow(), unix_secs_now_u64(), phase);
    let jitter = Duration::from_millis(phase % window.as_millis() as u64);
    let recovery = recovery_interval(phase);
    let event_delay = Duration::from_millis(SESSION_POLL_DELAY_MS + phase % SESSION_POLL_DELAY_MS);
    let mut earliest = Instant::now();
    let mut next = earliest + jitter;
    let mut reconnecting = false;
    while distribution.authority.is_current(unix_secs_now_u64()) {
        // Watch on the same connection that will run the poll. Discard it
        // after the round along with any unfinished mirror streams.
        let mut client = match distribution.connect().await {
            Ok(client) => client,
            Err(error) => {
                tracing::debug!(%error, "P-Net policy subscriber IPC unavailable");
                reconnecting = true;
                tokio::time::sleep(recovery).await;
                continue;
            }
        };
        let periodic = match wait_for_policy_poll(
            &mut client,
            next,
            earliest,
            recovery,
            event_delay,
            reconnecting,
        )
        .await
        {
            PollWake::Periodic => true,
            PollWake::Expedited => false,
            PollWake::Disconnected => {
                reconnecting = true;
                tokio::time::sleep(recovery).await;
                continue;
            }
        };
        let started = Instant::now();
        if !distribution.authority.is_current(unix_secs_now_u64()) {
            return;
        }
        if !periodic {
            if reconnecting {
                tracing::debug!("P-Net subscriber IPC recovery expedited mirror polling");
            } else {
                tracing::debug!("P-Net session admission expedited mirror polling");
            }
        }
        earliest = started + recovery;
        let client = Arc::new(client);
        if let Err(error) = poll_mirrors(policy, distribution, &mirrors, &client).await {
            tracing::debug!(%error, "P-Net policy refresh failed");
        }
        reconnecting = client.is_disconnected();
        if periodic {
            let delay = poll_interval(*expiry.borrow(), unix_secs_now_u64(), phase);
            let now = Instant::now();
            next = started + delay;
            if next <= now {
                next = now + delay;
            }
        }
    }
}

enum PollWake {
    Periodic,
    Expedited,
    Disconnected,
}

async fn wait_for_policy_poll(
    client: &mut VeilClient,
    next: Instant,
    earliest: Instant,
    recovery: Duration,
    event_delay: Duration,
    reconnecting: bool,
) -> PollWake {
    let mut events = client.events().await;
    let periodic = next.max(earliest);
    let mut due = periodic;
    // A mirror may have been admitted before the reconnected subscriber
    // could listen. Treat IPC recovery like an admission wake hint.
    if reconnecting
        && let Some(early) =
            expedited_poll(Instant::now() + event_delay, earliest, periodic, recovery)
    {
        due = early;
    }
    let mut listen = true;
    loop {
        tokio::select! {
            _ = client.wait_disconnected() => return PollWake::Disconnected,
            _ = sleep_until(due) => return if due == periodic {
                PollWake::Periodic
            } else {
                PollWake::Expedited
            },
            event = events.recv(), if listen => match event {
                Some(event) if event.kind == SESSION_ADMITTED => {
                    if let Some(early) = expedited_poll(Instant::now() + event_delay, earliest, periodic, recovery) {
                        due = due.min(early);
                    }
                }
                Some(_) => {},
                None => listen = false,
            },
        }
    }
}

fn expedited_poll(
    requested: Instant,
    earliest: Instant,
    periodic: Instant,
    recovery: Duration,
) -> Option<Instant> {
    let early = requested.max(earliest);
    // Leave room for the ordinary timer even if the mirror has a session
    // but has not started serving policies yet.
    (early + recovery <= periodic).then_some(early)
}

fn recovery_interval(phase: u64) -> Duration {
    Duration::from_millis(RECOVERY_POLL_MIN_MS + phase % RECOVERY_POLL_JITTER_MS)
}

fn poll_interval(valid_until: u64, now: u64, phase: u64) -> Duration {
    if now == 0 {
        return POLL_INTERVAL;
    }
    let remaining = Duration::from_secs(valid_until.saturating_sub(now));
    // Start the recovery cadence near expiry and spread the load across nodes.
    POLL_INTERVAL.min(remaining.saturating_add(recovery_interval(phase)))
}

struct Offer {
    source: NodeId,
    verified: VerifiedRoutePolicyOffer,
}

#[derive(Default)]
struct Selection {
    best: Option<Offer>,
    conflict: bool,
}

impl Selection {
    fn consider(&mut self, offer: Offer) {
        if let Some(best) = self.best.as_ref() {
            let incoming = offer.verified.policy();
            let current = best.verified.policy();
            if incoming.revision < current.revision {
                return;
            }
            if incoming.revision == current.revision {
                self.conflict |= incoming != current;
                return;
            }
        }
        self.best = Some(offer);
        self.conflict = false;
    }
}

async fn poll_mirrors(
    policy: &Arc<SignedRoutes>,
    distribution: &Distribution<'_>,
    mirrors: &[NodeId],
    client: &Arc<VeilClient>,
) -> anyhow::Result<()> {
    let revision = {
        let policy = Arc::clone(policy);
        tokio::task::spawn_blocking(move || policy.refresh())
            .await??
            .revision
    };
    let admissions = client.peer_pnet_admissions(mirrors).await?;
    let now = unix_secs_now_u64();
    let active: Vec<_> = admissions
        .into_iter()
        .filter(|entry| authorized(distribution.authority, *entry, now))
        .map(|entry| entry.peer_node_id)
        .collect();
    if active.is_empty() {
        return Ok(());
    }
    let app = Arc::new(
        client
            .bind(&distribution.namespace, "route-policy-fetch", ENDPOINT)
            .await?,
    );
    let mut pending = JoinSet::new();
    for source in active {
        let app = Arc::clone(&app);
        let policy = Arc::clone(policy);
        let remote = veil_app::address::app_id(&source, &distribution.namespace, SERVICE);
        pending.spawn(async move {
            match fetch_offer(&app, policy, source, remote, revision).await {
                Ok(offer) => offer,
                Err(error) => {
                    tracing::debug!(%error, "P-Net policy mirror offer rejected");
                    None
                }
            }
        });
    }

    // Recheck all sources in one query, after transfers and signature validation.
    let mut offers = Vec::new();
    while let Some(result) = pending.join_next().await {
        if let Some(offer) = result? {
            offers.push(offer);
        }
    }
    if offers.is_empty() {
        return Ok(());
    }
    let sources: Vec<_> = offers.iter().map(|offer| offer.source).collect();
    let admissions = client.peer_pnet_admissions(&sources).await?;
    let now = unix_secs_now_u64();
    let mut selection = Selection::default();
    for (offer, admission) in offers.into_iter().zip(admissions.iter().copied()) {
        if authorized(distribution.authority, admission, now) {
            selection.consider(offer);
        }
    }
    if selection.conflict {
        tracing::warn!(
            "P-Net mirrors supplied conflicting owner-signed policies at the same revision"
        );
        return Ok(());
    }
    if let Some(offer) = selection.best {
        let policy = Arc::clone(policy);
        let authority = distribution.authority;
        let admission = admissions
            .into_iter()
            .find(|entry| entry.peer_node_id == offer.source)
            .context("selected mirror's P-Net admission is missing")?;
        let client = Arc::clone(client);
        let revision = tokio::task::spawn_blocking(move || {
            ensure!(
                !client.is_disconnected() && authorized(authority, admission, unix_secs_now_u64()),
                "mirror's P-Net admission expired before installation"
            );
            policy.install_offer(offer.verified)
        })
        .await??;
        tracing::info!(revision, "installed P-Net route policy from mirror");
    }
    Ok(())
}

async fn fetch_offer(
    app: &AppHandle,
    policy: Arc<SignedRoutes>,
    source: NodeId,
    remote: [u8; 32],
    revision: u64,
) -> anyhow::Result<Option<Offer>> {
    let bytes = timeout(TRANSFER_TIMEOUT, async {
        let mut stream = app
            .open_stream(
                source,
                remote,
                ENDPOINT,
                (MAX_SIGNED_ROUTE_POLICY_BYTES + 4) as u32,
            )
            .await?;
        let mut request = [0; 12];
        request[..4].copy_from_slice(&REQUEST_MAGIC);
        request[4..].copy_from_slice(&revision.to_be_bytes());
        stream.write_all(&request).await?;
        read_snapshot(&mut stream).await
    })
    .await
    .context("P-Net policy mirror transfer timed out")??;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    // Keep verification scoped to this round even when a blocking worker
    // is busy. The transfer timer cannot leave a detached verifier behind.
    let verified = tokio::task::spawn_blocking(move || policy.verify_offer(bytes)).await??;
    ensure!(
        verified.policy().revision > revision,
        "mirror did not supply a newer P-Net policy revision"
    );
    Ok(Some(Offer { source, verified }))
}

async fn read_snapshot(mut stream: impl AsyncRead + Unpin) -> anyhow::Result<Option<Vec<u8>>> {
    let size = stream.read_u32().await? as usize;
    if size == 0 {
        return Ok(None);
    }
    ensure!(
        size <= MAX_SIGNED_ROUTE_POLICY_BYTES,
        "P-Net policy response exceeds size limit"
    );
    let mut bytes = vec![0; size];
    stream
        .read_exact(&mut bytes)
        .await
        .context("incomplete P-Net policy response")?;
    Ok(Some(bytes))
}

fn authorized(authority: PnetAuthority, admission: PnetAdmission, now: u64) -> bool {
    authority.is_current(now)
        && admission
            .valid_until_unix
            .is_some_and(|expiry| expiry == 0 || now < expiry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_polling_is_staggered_and_bounded() {
        assert_eq!(poll_interval(90, 0, 0), POLL_INTERVAL);
        assert_eq!(poll_interval(120, 100, 0), POLL_INTERVAL);
        assert_eq!(poll_interval(102, 100, 0), Duration::from_secs(6));
        assert_eq!(poll_interval(100, 100, 0), Duration::from_secs(4));
        assert_eq!(poll_interval(90, 100, 1_999), Duration::from_millis(5_999));
    }

    #[test]
    fn admitted_sessions_advance_polls_with_room_for_the_periodic_retry() {
        let now = Instant::now();
        let recovery = recovery_interval(0);
        let earliest = now + recovery;
        let periodic = now + POLL_INTERVAL;
        assert_eq!(
            expedited_poll(now + Duration::from_secs(2), earliest, periodic, recovery),
            Some(earliest)
        );
        assert_eq!(
            expedited_poll(periodic - recovery, earliest, periodic, recovery),
            Some(periodic - recovery)
        );
        assert_eq!(
            expedited_poll(
                periodic - Duration::from_secs(2),
                earliest,
                periodic,
                recovery
            ),
            None
        );
    }

    #[test]
    fn distribution_requires_both_memberships_to_be_current() {
        let local = PnetAuthority {
            root: veilclient::PnetTrustRoot::from_owner(
                [1; 32],
                veil_types::SignatureAlgorithm::Ed25519,
                &[2; 32],
            ),
            local_valid_until_unix: 20,
        };
        let peer = |valid_until_unix| PnetAdmission {
            peer_node_id: [3; 32],
            valid_until_unix,
        };
        assert!(authorized(local, peer(Some(0)), 10));
        assert!(authorized(local, peer(Some(11)), 10));
        assert!(!authorized(local, peer(Some(10)), 10));
        assert!(!authorized(local, peer(None), 10));
        assert!(!authorized(local, peer(Some(0)), 20));
        assert!(!authorized(local, peer(Some(0)), 0));
    }

    #[tokio::test]
    async fn policy_response_is_bounded_and_complete() {
        assert_eq!(
            read_snapshot(0u32.to_be_bytes().as_slice()).await.unwrap(),
            None
        );
        assert!(
            read_snapshot(u32::MAX.to_be_bytes().as_slice())
                .await
                .is_err()
        );
        assert!(read_snapshot(&[0, 0, 0, 3, 7, 8][..]).await.is_err());
        assert_eq!(
            read_snapshot(&[0, 0, 0, 3, 7, 8, 9][..]).await.unwrap(),
            Some(vec![7, 8, 9])
        );
    }
}
