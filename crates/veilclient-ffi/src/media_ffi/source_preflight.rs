//! Prepare the actual opaque forwarding path, before the host starts capture.
//! Controls extend the existing encrypted VMP1 namespace: old readers consume
//! the reserved subtype without handing it to RTP or echoing it.
use super::*;
use crate::media_path_probe::{CONTROL_BYTES, ProbeControl, ProbeRoute, ProbeStatus, RouteProbe};
use std::sync::Weak;
use std::time::{Duration, Instant};

const PLANES: usize = 3;
const MAX_CONTEXTS: usize = 64;
const BUDGET: Duration = Duration::from_secs(1);

fn encode(plane: usize, mut payload: Vec<u8>) -> Vec<u8> {
    debug_assert_eq!(payload.len(), CONTROL_BYTES);
    payload[6] = 1;
    payload[7] = plane as u8;
    payload
}

fn is_preparation(body: &[u8]) -> bool {
    body.starts_with(crate::media_path_probe::MAGIC) && body.get(6) == Some(&1)
}

fn decode(body: &[u8]) -> Option<(usize, ProbeControl)> {
    if body.len() != CONTROL_BYTES || !is_preparation(body) || usize::from(body[7]) >= PLANES {
        return None;
    }
    let plane = usize::from(body[7]);
    let mut control = [0; CONTROL_BYTES];
    control.copy_from_slice(body);
    control[6..8].fill(0);
    Some((plane, ProbeControl::decode(&control)?))
}

struct Attempt {
    probes: [RouteProbe; PLANES],
}

impl Attempt {
    fn new(route: ProbeRoute, now: Instant) -> Self {
        Self {
            probes: std::array::from_fn(|_| RouteProbe::begin(route, now, BUDGET)),
        }
    }

    fn initial(&self) -> Vec<(usize, Vec<u8>)> {
        self.probes
            .iter()
            .enumerate()
            .map(|(plane, probe)| (plane, encode(plane, probe.request_payload())))
            .collect()
    }

    fn retries(&mut self, now: Instant) -> Vec<(usize, Vec<u8>)> {
        self.probes
            .iter_mut()
            .enumerate()
            .filter_map(|(plane, probe)| {
                probe
                    .retry_payload(now)
                    .map(|payload| (plane, encode(plane, payload)))
            })
            .collect()
    }

    fn ready(&mut self, now: Instant) -> bool {
        self.probes
            .iter_mut()
            .all(|p| matches!(p.status(now), ProbeStatus::Qualified(_)))
    }

    fn observe(&mut self, plane: usize, control: ProbeControl, now: Instant) {
        self.probes[plane].observe(control, now);
    }

    fn cancel(&mut self) {
        for probe in &mut self.probes {
            probe.cancel();
        }
    }
}

pub(super) struct Context {
    app: Arc<VeilApp>,
    cipher: Arc<media::MediaCipher>,
    ingress: Weak<MediaIngress>,
    peer: [u8; 32],
    peer_app: [u8; 32],
    endpoint: u32,
    seq: Arc<std::sync::atomic::AtomicU32>,
    route: ProbeRoute,
    attempt: StdMutex<Option<Attempt>>,
    changed: tokio::sync::Notify,
    last_echo: StdMutex<[Option<Instant>; PLANES]>,
    echoes: Arc<tokio::sync::Semaphore>,
}

impl Context {
    fn live(&self) -> bool {
        self.ingress
            .upgrade()
            .is_some_and(|i| !i.closed.load(std::sync::atomic::Ordering::Acquire))
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
        self.changed.notify_one();
    }

    async fn send(&self, plane: usize, body: Vec<u8>, deadline: tokio::time::Instant) {
        self.send_on_reply_path(plane, body, deadline, None).await;
    }

    async fn send_on_reply_path(
        &self,
        plane: usize,
        body: Vec<u8>,
        deadline: tokio::time::Instant,
        reply_route: Option<ProbeRoute>,
    ) {
        if !self.live() || deadline <= tokio::time::Instant::now() {
            return;
        }
        let pinned = reply_route.and_then(|route| {
            super::path_probe_ffi::preparation_reply_path(&self.cipher, &self.ingress, route)
        });
        let app = pinned.as_ref().map_or(&self.app, |path| &path.app);
        let peer = pinned.as_ref().map_or(self.peer, |path| path.peer);
        let peer_app = pinned.as_ref().map_or(self.peer_app, |path| path.peer_app);
        let endpoint = pinned.as_ref().map_or(self.endpoint, |path| path.endpoint);
        let route = reply_route
            .filter(|_| pinned.is_some())
            .unwrap_or(self.route);
        let (local_plane, lane) = match plane {
            0 => (
                media::LocalMediaPlane::Primary,
                veil_proto::priority::REALTIME,
            ),
            1 => (
                media::LocalMediaPlane::Secondary,
                veil_proto::priority::BULK,
            ),
            2 => (
                media::LocalMediaPlane::Screen,
                veil_proto::priority::BACKGROUND,
            ),
            _ => return,
        };
        let Some(sealed) = self.cipher.seal_on_plane(local_plane, &body) else {
            return;
        };
        let deadline = deadline.min(tokio::time::Instant::now() + MEDIA_LOCAL_QUEUE_AGE);
        let sealed = sealed.with_local_deadline(deadline);
        let Some(guard) = sealed.lock_while_fresh(&app.sender).await else {
            return;
        };
        if !self.live() {
            return;
        }
        let Some(sender) = guard.as_ref() else {
            return;
        };
        if route == ProbeRoute::Relay {
            let _ = sender
                .send_relay_media_sealed_on_local_lane_before_tracked_owned(
                    lane,
                    peer,
                    peer_app,
                    endpoint,
                    sealed.into_vec(),
                    deadline,
                    None,
                )
                .await;
        } else {
            let _ = sender
                .send_rt_data_on_local_lane_before(
                    lane,
                    peer,
                    peer_app,
                    endpoint,
                    (if pinned.is_some() {
                        &app.rt_seq
                    } else {
                        self.seq.as_ref()
                    })
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                    0,
                    0,
                    0,
                    sealed.as_bytes(),
                    deadline,
                )
                .await;
        }
    }

    pub(super) async fn run(&self) -> bool {
        if !self.live() {
            return false;
        }
        let attempt = Attempt::new(self.route, Instant::now());
        let deadline = tokio::time::Instant::from_std(attempt.probes[0].deadline());
        let initial = attempt.initial();
        *self.attempt.lock().unwrap_or_else(|p| p.into_inner()) = Some(attempt);
        tokio::time::timeout_at(deadline, async {
            for (plane, body) in initial {
                self.send(plane, body, deadline).await;
            }
            loop {
                if !self.live() {
                    return false;
                }
                let retries = {
                    let mut state = self.attempt.lock().unwrap_or_else(|p| p.into_inner());
                    let Some(attempt) = state.as_mut() else {
                        return false;
                    };
                    if attempt.ready(Instant::now()) {
                        return true;
                    }
                    attempt.retries(Instant::now())
                };
                for (plane, body) in retries {
                    self.send(plane, body, deadline).await;
                }
                tokio::select! {
                    _ = self.changed.notified() => {},
                    _ = tokio::time::sleep(Duration::from_millis(25)) => {},
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    fn receive(self: &Arc<Self>, plane: usize, control: ProbeControl) {
        if !self.live() {
            return;
        }
        let Some(reply) = control.reply() else {
            if let Some(attempt) = self
                .attempt
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_mut()
            {
                attempt.observe(plane, control, Instant::now());
            }
            self.changed.notify_one();
            return;
        };
        let Ok(permit) = Arc::clone(&self.echoes).try_acquire_owned() else {
            return;
        };
        {
            let now = Instant::now();
            let mut last = self.last_echo.lock().unwrap_or_else(|p| p.into_inner());
            if last[plane].is_some_and(|t| now.duration_since(t) < Duration::from_millis(200)) {
                return;
            }
            last[plane] = Some(now);
        }
        // Warm the reverse candidate too when the host has already authorized
        // and pinned that route. Echoing a relay preparation on the current
        // direct sender leaves reverse relay setup to the short qualification
        // window. Without a pinned alternate, retain the current posture.
        let context = Arc::clone(self);
        self.app.bundle.runtime.spawn(async move {
            let _permit = permit;
            context
                .send_on_reply_path(
                    plane,
                    encode(plane, reply.encode()),
                    tokio::time::Instant::now() + MEDIA_LOCAL_QUEUE_AGE,
                    Some(control.route),
                )
                .await;
        });
    }
}

pub(super) fn install(chan: u64, app: Arc<VeilApp>) -> Option<Arc<Context>> {
    let context = {
        let mut map = MEDIA_CHANNELS.write().unwrap_or_else(|p| p.into_inner());
        if map
            .values()
            .filter(|c| c.source_preflight.is_some())
            .count()
            >= MAX_CONTEXTS
        {
            return None;
        }
        let channel = map.get_mut(&chan)?;
        if channel.routes.is_some() || channel.sender_app_id != Some(app.app_id) {
            return None;
        }
        let (peer_app, endpoint) = channel.control_destination?;
        let context = Arc::new(Context {
            app: Arc::clone(&app),
            cipher: Arc::clone(&channel.cipher),
            ingress: Arc::downgrade(&channel.ingress),
            peer: channel.peer,
            peer_app,
            endpoint,
            seq: channel
                .direct_seq
                .clone()
                .unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicU32::new(0))),
            route: if channel.relay_stats.is_some() {
                ProbeRoute::Relay
            } else {
                ProbeRoute::Direct
            },
            attempt: StdMutex::new(None),
            changed: tokio::sync::Notify::new(),
            last_echo: StdMutex::new([None; PLANES]),
            echoes: Arc::new(tokio::sync::Semaphore::new(PLANES)),
        });
        channel.source_preflight = Some(Arc::clone(&context));
        context
    };
    Some(context)
}

pub(super) fn install_and_prepare(chan: u64, app: Arc<VeilApp>) {
    let Some(context) = install(chan, Arc::clone(&app)) else {
        return;
    };
    // Existing direct/relay open is a blocking FFI operation on the SDK worker.
    // A legacy peer can consume the unknown subtype; its silence only expires
    // this best-effort bounded observation, never fails the established open.
    let ready = app.bundle.runtime.block_on(context.run());
    media::diag(format_args!("forwarding preparation ready={ready}"));
}

pub(crate) fn dispatch_control(chan: u64, cipher: &media::MediaCipher, body: &[u8]) -> bool {
    if !is_preparation(body) {
        return false;
    }
    let Some((plane, control)) = decode(body) else {
        return true;
    };
    let mut matching: Vec<_> = contexts()
        .into_iter()
        .filter(|(_, c)| c.cipher.same_receive_key(cipher))
        .collect();
    if control.reply().is_some() {
        // Prefer the current callback's channel for an echo. During handover,
        // all alternate destinations still come from authenticated host state.
        matching.sort_by_key(|(id, _)| *id != chan);
        if let Some((_, context)) = matching.first() {
            context.receive(plane, control);
        }
    } else {
        // Old and candidate channels can share keys. Only the owner of this
        // random challenge can qualify; a receive lease is not its owner.
        for (_, context) in matching {
            context.receive(plane, control);
        }
    }
    true
}

fn contexts() -> Vec<(u64, Arc<Context>)> {
    MEDIA_CHANNELS
        .try_read()
        .ok()
        .map(|map| {
            map.iter()
                .filter_map(|(id, c)| c.source_preflight.as_ref().map(|context| (*id, context)))
                .filter(|(_, c)| c.live())
                .map(|(id, c)| (id, Arc::clone(c)))
                .collect()
        })
        .unwrap_or_default()
}

/// An open can wait before the engine has installed its RTP callback. Restrict
/// alternate decryption to the exact existing control length and a bounded
/// number of live contexts. Consume successful controls just once: reopening
/// the same cell in another handler would fail the cipher's replay window.
pub(crate) fn dispatch_without_lease(payload: &[u8]) -> bool {
    if payload.len() != CONTROL_BYTES + media::MEDIA_SEAL_OVERHEAD {
        return false;
    }
    for (chan, context) in contexts() {
        let Some(plaintext) = context.cipher.open(payload) else {
            continue;
        };
        if is_preparation(&plaintext) {
            if decode(&plaintext).is_some() {
                media::trace_sealed_cell("received", &context.peer, payload);
                dispatch_control(chan, &context.cipher, &plaintext);
            }
            return true;
        }
        if super::path_probe_ffi::dispatch_control(&context.cipher, &plaintext) {
            return true;
        }
        return false;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_decoder_consumes_extension_as_unknown_not_rtp() {
        let attempt = Attempt::new(ProbeRoute::Relay, Instant::now());
        for (plane, payload) in attempt.initial() {
            assert!(payload.starts_with(crate::media_path_probe::MAGIC));
            assert!(ProbeControl::decode(&payload).is_none());
            assert_eq!(decode(&payload).unwrap().0, plane);
            for len in 0..payload.len() {
                assert!(decode(&payload[..len]).is_none());
            }
            let mut bad = payload.clone();
            bad[7] = 3;
            assert!(decode(&bad).is_none());
            let mut bad = payload.clone();
            bad.push(0);
            assert!(decode(&bad).is_none());
        }
    }

    #[test]
    fn all_three_distinct_challenges_are_required_and_cross_plane_replies_do_not_qualify() {
        let now = Instant::now();
        let mut attempt = Attempt::new(ProbeRoute::Relay, now);
        let requests = attempt.initial();
        let (_, first) = decode(&requests[0].1).unwrap();
        attempt.observe(1, first.reply().unwrap(), now);
        assert!(!attempt.ready(now));
        for (plane, request) in requests {
            let (_, control) = decode(&request).unwrap();
            attempt.observe(
                plane,
                control.reply().unwrap(),
                now + Duration::from_millis(10),
            );
            assert_eq!(attempt.ready(now + Duration::from_millis(10)), plane == 2);
        }
        attempt.cancel();
        assert!(!attempt.ready(now + Duration::from_millis(20)));
    }

    #[test]
    fn retries_are_bounded_and_late_replies_cannot_revive_preparation() {
        let now = Instant::now();
        let mut attempt = Attempt::new(ProbeRoute::Direct, now);
        let initial = attempt.initial();
        assert!(attempt.retries(now + Duration::from_millis(249)).is_empty());
        assert_eq!(attempt.retries(now + Duration::from_millis(250)), initial);
        assert_eq!(attempt.retries(now + Duration::from_millis(500)), initial);
        assert!(attempt.retries(now + Duration::from_millis(750)).is_empty());
        for (plane, request) in initial {
            let (_, control) = decode(&request).unwrap();
            attempt.observe(
                plane,
                control.reply().unwrap(),
                now + BUDGET + Duration::from_millis(1),
            );
        }
        assert!(!attempt.ready(now + BUDGET + Duration::from_millis(1)));
    }
}
