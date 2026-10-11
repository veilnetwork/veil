//! End-to-end delivery observations for live direct/relay handovers.
//! The host pins both reply destinations before enabling this control. A
//! packet's claimed source is never used as an echo destination. Anonymous
//! channels cannot enable it. All control remains inside the media AEAD.
use super::*;
use crate::media_path_probe::{CONTROL_BYTES, ProbeControl, ProbeRoute, ProbeStatus, RouteProbe};
use std::sync::Weak;
use std::time::{Duration, Instant};

/// Trusted host configuration, never read from a network envelope.
#[repr(C)]
pub struct VeilMediaProbePath {
    pub app: *mut VeilApp,
    pub peer_node_id: [u8; 32],
    pub peer_app_id: [u8; 32],
    pub peer_endpoint_id: u32,
}

struct ReplyPath {
    app: Arc<VeilApp>,
    peer: [u8; 32],
    peer_app: [u8; 32],
    endpoint: u32,
}

pub(super) struct PathProbeContext {
    cipher: Arc<media::MediaCipher>,
    ingress: Weak<MediaIngress>,
    route: ProbeRoute,
    replies: [ReplyPath; 2],
    attempt: StdMutex<Option<RouteProbe>>,
    last_echo: StdMutex<Option<Instant>>,
    echo_slot: Arc<tokio::sync::Semaphore>,
}

impl PathProbeContext {
    /// Both addresses are pinned by trusted host call state, never learned
    /// from an incoming packet. The peer's sending route is independent of
    /// this endpoint's outgoing candidate qualification.
    pub(super) fn receive_peers(&self) -> [[u8; 32]; 2] {
        [self.replies[0].peer, self.replies[1].peer]
    }

    fn live(&self) -> bool {
        self.ingress
            .upgrade()
            .is_some_and(|ingress| !ingress.closed.load(std::sync::atomic::Ordering::Acquire))
    }

    pub(super) fn cancel(&self) {
        if let Some(attempt) = self
            .attempt
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
        {
            attempt.cancel();
        }
    }

    fn observe(&self, control: ProbeControl) {
        if !self.live() {
            return;
        }
        if let Some(attempt) = self
            .attempt
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
        {
            attempt.observe(control, Instant::now());
        }
    }

    fn echo(self: &Arc<Self>, control: ProbeControl) -> bool {
        let Some(reply) = control.reply() else {
            return false;
        };
        if !self.live() {
            return false;
        }
        let Ok(permit) = Arc::clone(&self.echo_slot).try_acquire_owned() else {
            return true;
        };
        let now = Instant::now();
        {
            let mut last = self.last_echo.lock().unwrap_or_else(|p| p.into_inner());
            if last.is_some_and(|last| now.duration_since(last) < Duration::from_millis(200)) {
                return true;
            }
            *last = Some(now);
        }
        let context = Arc::clone(self);
        let index = reply.route.index();
        self.replies[index].app.bundle.runtime.spawn(async move {
            let _permit = permit;
            if !context.live() {
                return;
            }
            let Some(sealed) = context
                .cipher
                .seal_on_plane(media::LocalMediaPlane::Primary, &reply.encode())
            else {
                return;
            };
            let deadline = tokio::time::Instant::now() + MEDIA_LOCAL_QUEUE_AGE;
            let sealed = sealed.with_local_deadline(deadline);
            let path = &context.replies[index];
            let Some(guard) = sealed.lock_while_fresh(&path.app.sender).await else {
                return;
            };
            if !context.live() {
                return;
            }
            let Some(sender) = guard.as_ref() else {
                return;
            };
            // Force the requested candidate path in BOTH directions. Echoing
            // over the current sender would certify an untested reverse path.
            match reply.route {
                ProbeRoute::Direct => {
                    let _ = sender
                        .send_rt_data_on_local_lane_before(
                            veil_proto::priority::REALTIME,
                            path.peer,
                            path.peer_app,
                            path.endpoint,
                            path.app
                                .rt_seq
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                            0,
                            0,
                            0,
                            sealed.as_bytes(),
                            deadline,
                        )
                        .await;
                }
                ProbeRoute::Relay => {
                    let _ = sender
                        .send_relay_media_sealed_on_local_lane_before_tracked_owned(
                            veil_proto::priority::REALTIME,
                            path.peer,
                            path.peer_app,
                            path.endpoint,
                            sealed.into_vec(),
                            deadline,
                            None,
                        )
                        .await;
                }
            }
        });
        true
    }
}

/// Enable delivery probes only on a non-anonymous channel. Reply paths must
/// be pinned from the authenticated call, with the identity app for direct
/// traffic and the physical-device app for relay traffic. Apps must remain
/// open until the channel closes. Returns 0, or -1 without changing a channel.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_channel_configure_path_probes(
    chan: u64,
    direct: *const VeilMediaProbePath,
    relay: *const VeilMediaProbePath,
) -> c_int {
    if direct.is_null() || relay.is_null() {
        return -1;
    }
    let read = |value: &VeilMediaProbePath| -> Option<ReplyPath> {
        let app = HandleTable::get(app_table(), value.app as usize)?;
        if value.peer_node_id == [0; 32]
            || value.peer_app_id == [0; 32]
            || value.peer_endpoint_id == 0
        {
            return None;
        }
        Some(ReplyPath {
            app,
            peer: value.peer_node_id,
            peer_app: value.peer_app_id,
            endpoint: value.peer_endpoint_id,
        })
    };
    let Some(direct) = read(unsafe { &*direct }) else {
        return -1;
    };
    let Some(relay) = read(unsafe { &*relay }) else {
        return -1;
    };
    let mut map = MEDIA_CHANNELS.write().unwrap_or_else(|p| p.into_inner());
    let Some(channel) = map.get_mut(&chan) else {
        return -1;
    };
    if channel.routes.is_some()
        || channel.sender_app_id.is_none()
        || ![Some(direct.app.app_id), Some(relay.app.app_id)].contains(&channel.sender_app_id)
        || ![direct.peer, relay.peer].contains(&channel.peer)
        || channel
            .ingress
            .closed
            .load(std::sync::atomic::Ordering::Acquire)
    {
        return -1;
    }
    if let Some(existing) = &channel.path_probe {
        let same = |old: &ReplyPath, new: &ReplyPath| {
            Arc::ptr_eq(&old.app, &new.app)
                && old.peer == new.peer
                && old.peer_app == new.peer_app
                && old.endpoint == new.endpoint
        };
        return if same(&existing.replies[0], &direct) && same(&existing.replies[1], &relay) {
            0
        } else {
            -1
        };
    }
    // The alias lookup below is deliberately bounded. Refuse excess control
    // contexts instead of letting HashMap order hide an accepted candidate.
    if map
        .values()
        .filter(|channel| channel.path_probe.is_some())
        .count()
        >= 16
    {
        return -1;
    }
    let channel = map
        .get_mut(&chan)
        .expect("channel checked while holding registry");
    channel.path_probe = Some(Arc::new(PathProbeContext {
        cipher: Arc::clone(&channel.cipher),
        ingress: Arc::downgrade(&channel.ingress),
        route: if channel.relay_stats.is_some() {
            ProbeRoute::Relay
        } else {
            ProbeRoute::Direct
        },
        replies: [direct, relay],
        attempt: StdMutex::new(None),
        last_echo: StdMutex::new(None),
        echo_slot: Arc::new(tokio::sync::Semaphore::new(1)),
    }));
    0
}

/// Start one candidate observation through its existing primary producer.
/// No recv callback is replaced and no old sender is stopped. Budget must be
/// 100..=1000 ms. Returns 0 queued, 1 busy/full, or -1 unsupported/closed.
#[unsafe(no_mangle)]
pub extern "C" fn veil_media_channel_begin_path_probe(chan: u64, budget_ms: u32) -> c_int {
    if !(100..=1000).contains(&budget_ms) {
        return -1;
    }
    let context = {
        let map = match MEDIA_CHANNELS.try_read() {
            Ok(map) => map,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return 1,
        };
        let Some(context) = map
            .get(&chan)
            .and_then(|channel| channel.path_probe.as_ref())
        else {
            return -1;
        };
        Arc::clone(context)
    };
    let Some(ingress) = context.ingress.upgrade() else {
        return -1;
    };
    if !context.live() {
        return -1;
    }
    let now = Instant::now();
    let mut attempt = context.attempt.lock().unwrap_or_else(|p| p.into_inner());
    if attempt
        .as_mut()
        .is_some_and(|attempt| attempt.status(now) == ProbeStatus::Pending)
    {
        return 1;
    }
    let next = RouteProbe::begin(
        context.route,
        now,
        Duration::from_millis(u64::from(budget_ms)),
    );
    let result = ingress.enqueue(QueuedMediaPacket::from(next.request_payload()));
    if result == 0 {
        *attempt = Some(next);
    }
    result
}

/// Poll a candidate without waiting for a network or changing RTP counters.
/// 0=pending/busy, 1=qualified and fresh, 2=expired, -1=closed/cancelled.
#[unsafe(no_mangle)]
pub extern "C" fn veil_media_channel_poll_path_probe(chan: u64) -> c_int {
    let map = match MEDIA_CHANNELS.try_read() {
        Ok(map) => map,
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return 0,
    };
    let Some(context) = map
        .get(&chan)
        .and_then(|channel| channel.path_probe.as_ref())
    else {
        return -1;
    };
    if !context.live() {
        return -1;
    }
    let mut attempt = context.attempt.lock().unwrap_or_else(|p| p.into_inner());
    match attempt
        .as_mut()
        .map(|attempt| attempt.status(Instant::now()))
    {
        Some(ProbeStatus::Pending) => 0,
        Some(ProbeStatus::Qualified(_)) => 1,
        Some(ProbeStatus::Expired) => 2,
        _ => -1,
    }
}

fn contexts() -> Vec<Arc<PathProbeContext>> {
    MEDIA_CHANNELS
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .values()
        .filter_map(|channel| channel.path_probe.as_ref())
        .take(16)
        .cloned()
        .collect()
}

/// Called only after the existing seal opened. Controls never reach the
/// WebRTC callback or activity metrics. Their plaintext/nonce is never logged.
pub(crate) fn dispatch_control(cipher: &media::MediaCipher, plaintext: &[u8]) -> bool {
    if !plaintext.starts_with(crate::media_path_probe::MAGIC) {
        return false;
    }
    let Some(control) = ProbeControl::decode(plaintext) else {
        return true;
    };
    let matching = contexts()
        .into_iter()
        .filter(|context| context.live() && context.cipher.same_receive_key(cipher));
    if control.reply().is_some() {
        for context in matching {
            if context.echo(control) {
                break;
            }
        }
    } else {
        for context in matching {
            context.observe(control);
        }
    }
    true
}

/// Candidate replies may name a different authenticated identity/device alias
/// from the old RTP receiver. Only exact-size sealed controls get this bounded
/// alternate-key lookup; ordinary RTP is opened once by its existing lease.
pub(crate) fn dispatch_without_lease(payload: &[u8]) {
    if payload.len() != CONTROL_BYTES + media::MEDIA_SEAL_OVERHEAD {
        return;
    }
    for context in contexts().into_iter().filter(|context| context.live()) {
        if let Some(plaintext) = context.cipher.open(payload) {
            // The candidate may arrive through the other device/identity alias
            // before it owns an RTP receive lease. Keep the same authenticated
            // endpoint trace boundary on this path, using the host-pinned peer.
            // Never log a header that failed AEAD or a malformed control.
            if let Some(control) = ProbeControl::decode(&plaintext) {
                media::trace_sealed_cell(
                    "received",
                    &context.replies[control.route.index()].peer,
                    payload,
                );
            }
            dispatch_control(&context.cipher, &plaintext);
            return;
        }
    }
}

#[cfg(all(test, unix))]
#[path = "path_probe_tests.rs"]
mod tests;
