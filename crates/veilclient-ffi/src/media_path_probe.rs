//! Candidate-route control, carried inside the existing directional media seal.
//! No timestamp, media role, scheduling class or route instruction is added to
//! the relay envelope. An authenticated echo is a delivery observation; local
//! queue admission alone never qualifies a candidate.
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

pub(crate) const MAGIC: &[u8; 4] = b"VMP1";
pub(crate) const CONTROL_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeRoute {
    Direct,
    Relay,
}

impl ProbeRoute {
    pub(crate) fn index(self) -> usize {
        self.wire() as usize
    }
    fn wire(self) -> u8 {
        match self {
            Self::Direct => 0,
            Self::Relay => 1,
        }
    }

    fn decode(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Direct),
            1 => Some(Self::Relay),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Request = 1,
    Reply = 2,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProbeControl {
    kind: Kind,
    pub(crate) route: ProbeRoute,
    token: [u8; 16],
}

impl ProbeControl {
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut body = Vec::with_capacity(CONTROL_BYTES);
        body.extend_from_slice(MAGIC);
        body.push(self.kind as u8);
        body.push(self.route.wire());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&self.token);
        body
    }

    /// Parse only plaintext returned by the call's AEAD. This parser does not
    /// authenticate bytes or authorize an outbound route by itself.
    pub(crate) fn decode(body: &[u8]) -> Option<Self> {
        if body.len() != CONTROL_BYTES || !body.starts_with(MAGIC) || body[6..8] != [0, 0] {
            return None;
        }
        let kind = match body[4] {
            1 => Kind::Request,
            2 => Kind::Reply,
            _ => return None,
        };
        let route = ProbeRoute::decode(body[5])?;
        let token = body[8..].try_into().ok()?;
        (token != [0; 16]).then_some(Self { kind, route, token })
    }

    /// The receiver must send this reply on `route`, after applying its local
    /// call/posture authorization, rather than echoing on its current route.
    pub(crate) fn reply(self) -> Option<Self> {
        (self.kind == Kind::Request).then_some(Self {
            kind: Kind::Reply,
            ..self
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeStatus {
    Pending,
    Qualified(Duration),
    Expired,
    Cancelled,
}

/// One bounded attempt owned by one candidate. The caller retains the old
/// sender until this observation qualifies and rechecks call ownership before
/// committing. Replies must pass the candidate's receive key before entering
/// `observe`; possession of a token without a valid seal is insufficient.
pub(crate) struct RouteProbe {
    request: ProbeControl,
    sent_at: Instant,
    max_round_trip: Duration,
    status: ProbeStatus,
}

impl RouteProbe {
    pub(crate) fn begin(route: ProbeRoute, sent_at: Instant, max_round_trip: Duration) -> Self {
        let mut token = [0; 16];
        while token == [0; 16] {
            OsRng.fill_bytes(&mut token);
        }
        Self {
            request: ProbeControl {
                kind: Kind::Request,
                route,
                token,
            },
            sent_at,
            max_round_trip,
            status: ProbeStatus::Pending,
        }
    }

    pub(crate) fn request_payload(&self) -> Vec<u8> {
        self.request.encode()
    }

    pub(crate) fn status(&mut self, now: Instant) -> ProbeStatus {
        if matches!(
            self.status,
            ProbeStatus::Pending | ProbeStatus::Qualified(_)
        ) && now
            .checked_duration_since(self.sent_at)
            .is_some_and(|age| age > self.max_round_trip)
        {
            self.status = ProbeStatus::Expired;
        }
        self.status
    }

    pub(crate) fn observe(&mut self, reply: ProbeControl, now: Instant) -> ProbeStatus {
        if self.status(now) != ProbeStatus::Pending {
            return self.status;
        }
        if reply.kind != Kind::Reply
            || reply.route != self.request.route
            || reply.token != self.request.token
        {
            return self.status;
        }
        if let Some(age) = now.checked_duration_since(self.sent_at) {
            self.status = ProbeStatus::Qualified(age);
        }
        self.status
    }

    pub(crate) fn cancel(&mut self) {
        // Cancellation revokes even a successful observation. A hangup must
        // not leave a certificate that can commit a later call's candidate.
        self.status = ProbeStatus::Cancelled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media;

    #[test]
    fn only_a_matching_timely_reply_qualifies() {
        let now = Instant::now();
        let mut probe = RouteProbe::begin(ProbeRoute::Relay, now, Duration::from_millis(400));
        let request = ProbeControl::decode(&probe.request_payload()).unwrap();
        assert_eq!(probe.observe(request, now), ProbeStatus::Pending);
        let mut reply = request.reply().unwrap();
        reply.route = ProbeRoute::Direct;
        assert_eq!(probe.observe(reply, now), ProbeStatus::Pending);
        reply.route = ProbeRoute::Relay;
        reply.token[0] ^= 1;
        assert_eq!(probe.observe(reply, now), ProbeStatus::Pending);
        assert_eq!(
            probe.observe(request.reply().unwrap(), now + Duration::from_millis(90)),
            ProbeStatus::Qualified(Duration::from_millis(90))
        );
    }

    #[test]
    fn an_old_attempt_cannot_qualify_its_replacement() {
        let now = Instant::now();
        let old = RouteProbe::begin(ProbeRoute::Relay, now, Duration::from_millis(400));
        let mut current = RouteProbe::begin(ProbeRoute::Relay, now, Duration::from_millis(400));
        let old_reply = ProbeControl::decode(&old.request_payload())
            .unwrap()
            .reply()
            .unwrap();
        assert_ne!(old_reply.token, current.request.token);
        assert_eq!(
            current.observe(old_reply, now + Duration::from_millis(20)),
            ProbeStatus::Pending
        );
    }

    #[test]
    fn late_replayed_and_cancelled_replies_do_not_revive_a_candidate() {
        let now = Instant::now();
        let mut probe = RouteProbe::begin(ProbeRoute::Relay, now, Duration::from_millis(400));
        let reply = ProbeControl::decode(&probe.request_payload())
            .unwrap()
            .reply()
            .unwrap();
        assert_eq!(
            probe.observe(reply, now + Duration::from_millis(401)),
            ProbeStatus::Expired
        );
        assert_eq!(
            probe.observe(reply, now + Duration::from_millis(402)),
            ProbeStatus::Expired
        );
        probe.cancel();
        assert_eq!(
            probe.observe(reply, now + Duration::from_millis(403)),
            ProbeStatus::Cancelled
        );
        let mut live = RouteProbe::begin(ProbeRoute::Direct, now, Duration::from_millis(400));
        let reply = ProbeControl::decode(&live.request_payload())
            .unwrap()
            .reply()
            .unwrap();
        assert_eq!(
            live.observe(reply, now),
            ProbeStatus::Qualified(Duration::ZERO)
        );
        live.cancel();
        assert_eq!(live.status(now), ProbeStatus::Cancelled);
    }

    #[test]
    fn malformed_control_and_ordinary_rtp_are_not_probe_evidence() {
        let request = RouteProbe::begin(
            ProbeRoute::Relay,
            Instant::now(),
            Duration::from_millis(400),
        )
        .request_payload();
        for len in 0..request.len() {
            assert!(ProbeControl::decode(&request[..len]).is_none());
        }
        let mut longer = request.clone();
        longer.push(0);
        assert!(ProbeControl::decode(&longer).is_none());
        for (at, value) in [(0, 0x80), (4, 0), (5, 2), (6, 1), (7, 1)] {
            let mut bad = request.clone();
            bad[at] = value;
            assert!(ProbeControl::decode(&bad).is_none());
        }
        let mut zero = request;
        zero[8..].fill(0);
        assert!(ProbeControl::decode(&zero).is_none());
        assert!(ProbeControl::decode(&[0x80, 111, 0, 1]).is_none());
    }

    #[test]
    fn request_and_reply_use_the_existing_seal_and_replay_gate() {
        let peer = [0xa7; 32];
        let tx = [0x53; 32];
        let rx = [0x84; 32];
        let ours = media::cipher_for_test(&peer, &tx, &rx).unwrap();
        let theirs = media::cipher_for_test(&peer, &rx, &tx).unwrap();
        let wrong = media::cipher_for_test(&peer, &[0x36; 32], &[0x47; 32]).unwrap();
        let now = Instant::now();
        let mut probe = RouteProbe::begin(ProbeRoute::Relay, now, Duration::from_millis(400));
        let wire = ours.seal(&probe.request_payload()).unwrap().into_vec();
        assert!(wire.starts_with(&media::MEDIA_SEALED_MAGIC));
        assert_eq!(wire.len(), CONTROL_BYTES + media::MEDIA_SEAL_OVERHEAD);
        assert!(wrong.open(&wire).is_none());
        let request = ProbeControl::decode(&theirs.open(&wire).unwrap()).unwrap();
        assert!(theirs.open(&wire).is_none());
        let reply_wire = theirs
            .seal(&request.reply().unwrap().encode())
            .unwrap()
            .into_vec();
        let mut tampered = reply_wire.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(ours.open(&tampered).is_none());
        assert_eq!(probe.status(now), ProbeStatus::Pending);
        let reply = ProbeControl::decode(&ours.open(&reply_wire).unwrap()).unwrap();
        assert_eq!(
            probe.observe(reply, now + Duration::from_millis(100)),
            ProbeStatus::Qualified(Duration::from_millis(100))
        );
        assert!(ours.open(&reply_wire).is_none());
        // Neither the control parser nor the ledger asks the transport for an
        // unsealed fallback. Verify that plain control is refused by the seal.
        assert!(ours.open(&request.encode()).is_none());
    }
}
