//! Short-lived return paths for a single admitted discovery exchange.
//!
//! Claims here never authorize an identity, key, data route, or endpoint. They
//! only return control replies along the request/challenge that caused them.
//! First arrival wins; duplicates cannot renew leases or replace another peer.
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use veil_types::NodeIdBytes;

const MAX_REQUESTS: usize = 1024;
const MAX_LOCAL_REQUESTS: usize = 128;
const MAX_PER_PEER: usize = 64;
const MAX_CHALLENGES: usize = 256;
const TTL: Duration = Duration::from_secs(veil_proto::budget::POW_CHALLENGE_TTL_SECS);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestKey {
    pub requester: NodeIdBytes,
    pub target: NodeIdBytes,
    pub id: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyTo {
    Local,
    Peer(NodeIdBytes),
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChallengeKey {
    pub requester: NodeIdBytes,
    pub acceptor: NodeIdBytes,
    pub nonce: [u8; 32],
}
#[derive(Clone, Copy)]
struct RequestPath {
    reply: ReplyTo,
    at: Instant,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengePath {
    pub reply: ReplyTo,
    pub issuer_hop: NodeIdBytes,
}
struct PendingChallenge {
    path: ChallengePath,
    at: Instant,
}

#[derive(Default)]
pub struct DiscoveryPaths {
    requests: HashMap<RequestKey, RequestPath>,
    challenges: HashMap<ChallengeKey, PendingChallenge>,
}
impl DiscoveryPaths {
    pub fn remember_request(&mut self, key: RequestKey, reply: ReplyTo, now: Instant) -> bool {
        self.requests
            .retain(|_, p| now.saturating_duration_since(p.at) < TTL);
        if let Some(held) = self.requests.get(&key) {
            return held.reply == reply;
        }
        let count = self.requests.values().filter(|p| p.reply == reply).count();
        let cap = if reply == ReplyTo::Local {
            MAX_LOCAL_REQUESTS
        } else {
            MAX_PER_PEER
        };
        // Transit peers, including many distinct peers, cannot spend the
        // local request budget. Never evict a live return-path witness: it
        // binds replies to the originally admitted ingress.
        let local_count = self
            .requests
            .values()
            .filter(|p| p.reply == ReplyTo::Local)
            .count();
        let limit = if reply == ReplyTo::Local {
            MAX_REQUESTS
        } else {
            MAX_REQUESTS - MAX_LOCAL_REQUESTS + local_count
        };
        if self.requests.len() >= limit || count >= cap {
            return false;
        }
        self.requests.insert(key, RequestPath { reply, at: now });
        true
    }
    pub fn request_path(&mut self, key: RequestKey, now: Instant) -> Option<ReplyTo> {
        let held = *self.requests.get(&key)?;
        if now.saturating_duration_since(held.at) >= TTL {
            self.requests.remove(&key);
            return None;
        }
        Some(held.reply)
    }
    pub fn remember_challenge(
        &mut self,
        key: ChallengeKey,
        request: RequestKey,
        issuer_hop: NodeIdBytes,
        now: Instant,
    ) -> Option<ChallengePath> {
        if key.requester != request.requester || key.acceptor != request.target {
            return None;
        }
        let reply = self.request_path(request, now)?;
        let request_started = self.requests.get(&request)?.at;
        if reply == ReplyTo::Peer(issuer_hop) {
            return None;
        }
        self.challenges
            .retain(|_, p| now.saturating_duration_since(p.at) < TTL);
        let path = ChallengePath { reply, issuer_hop };
        if let Some(held) = self.challenges.get(&key) {
            return (held.path == path).then_some(path);
        }
        if self.challenges.len() >= MAX_CHALLENGES
            || self
                .challenges
                .values()
                .filter(|p| p.path.issuer_hop == issuer_hop)
                .count()
                >= MAX_PER_PEER
        {
            return None;
        }
        self.challenges.insert(
            key,
            PendingChallenge {
                path,
                at: request_started,
            },
        );
        Some(path)
    }
    pub fn challenge_path(&mut self, key: ChallengeKey, now: Instant) -> Option<ChallengePath> {
        let held = self.challenges.get(&key)?;
        if now.saturating_duration_since(held.at) >= TTL {
            self.challenges.remove(&key);
            return None;
        }
        Some(held.path)
    }
    pub fn accept_path(
        &mut self,
        requester: NodeIdBytes,
        nonce: [u8; 32],
        now: Instant,
    ) -> Option<ChallengePath> {
        self.challenges
            .retain(|_, p| now.saturating_duration_since(p.at) < TTL);
        let mut found = self
            .challenges
            .iter()
            .filter(|(key, _)| key.requester == requester && key.nonce == nonce);
        let first = found.next()?.1.path;
        found.next().is_none().then_some(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(id: u32) -> RequestKey {
        RequestKey {
            requester: [1; 32],
            target: [2; 32],
            id,
        }
    }
    fn challenge() -> ChallengeKey {
        ChallengeKey {
            requester: [1; 32],
            acceptor: [2; 32],
            nonce: [3; 32],
        }
    }
    #[test]
    fn request_first_ingress_wins_and_replay_does_not_extend_lease() {
        let now = Instant::now();
        let mut paths = DiscoveryPaths::default();
        assert!(paths.remember_request(request(1), ReplyTo::Peer([4; 32]), now));
        assert!(!paths.remember_request(request(1), ReplyTo::Peer([5; 32]), now));
        assert!(paths.remember_request(request(1), ReplyTo::Peer([4; 32]), now + TTL / 2));
        assert_eq!(paths.request_path(request(1), now + TTL), None);
    }
    #[test]
    fn local_witness_cannot_be_created_or_replaced_by_a_relay() {
        let now = Instant::now();
        let mut paths = DiscoveryPaths::default();
        assert!(paths.remember_request(request(1), ReplyTo::Local, now));
        assert!(!paths.remember_request(request(1), ReplyTo::Peer([4; 32]), now));
        assert_eq!(paths.request_path(request(1), now), Some(ReplyTo::Local));
        assert_eq!(paths.request_path(request(2), now), None);
    }
    #[test]
    fn per_peer_pressure_preserves_other_peers_and_local_requests() {
        let now = Instant::now();
        let mut paths = DiscoveryPaths::default();
        for i in 0..MAX_PER_PEER {
            assert!(paths.remember_request(request(i as u32), ReplyTo::Peer([4; 32]), now));
        }
        assert!(!paths.remember_request(request(999), ReplyTo::Peer([4; 32]), now));
        assert!(paths.remember_request(request(1000), ReplyTo::Peer([5; 32]), now));
        assert!(paths.remember_request(request(1001), ReplyTo::Local, now));
        assert_eq!(
            paths.request_path(request(0), now),
            Some(ReplyTo::Peer([4; 32]))
        );
    }
    #[test]
    fn global_capacity_refuses_new_entries_without_eviction() {
        let now = Instant::now();
        let mut paths = DiscoveryPaths::default();
        for i in 0..MAX_REQUESTS - MAX_LOCAL_REQUESTS {
            let mut peer = [0; 32];
            peer[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(paths.remember_request(request(i as u32), ReplyTo::Peer(peer), now));
        }
        for i in 0..MAX_LOCAL_REQUESTS {
            assert!(paths.remember_request(request(8000 + i as u32), ReplyTo::Local, now));
        }
        assert_eq!(paths.requests.len(), MAX_REQUESTS);
        assert!(!paths.remember_request(request(9999), ReplyTo::Local, now));
        assert!(!paths.remember_request(request(9999), ReplyTo::Peer([9; 32]), now));
        assert!(paths.request_path(request(0), now).is_some());
        assert!(paths.remember_request(request(9999), ReplyTo::Local, now + TTL));
        assert_eq!(paths.requests.len(), 1);
    }
    #[test]
    fn sybil_request_pressure_keeps_a_bounded_local_reserve() {
        let now = Instant::now();
        let mut paths = DiscoveryPaths::default();
        for i in 0..MAX_REQUESTS - MAX_LOCAL_REQUESTS {
            let mut peer = [0; 32];
            peer[..8].copy_from_slice(&((i / MAX_PER_PEER) as u64).to_be_bytes());
            assert!(paths.remember_request(request(i as u32), ReplyTo::Peer(peer), now));
        }
        assert!(!paths.remember_request(request(8000), ReplyTo::Peer([9; 32]), now));
        for i in 0..MAX_LOCAL_REQUESTS {
            assert!(paths.remember_request(request(9000 + i as u32), ReplyTo::Local, now));
        }
        assert_eq!(paths.requests.len(), MAX_REQUESTS);
        assert!(!paths.remember_request(request(9999), ReplyTo::Local, now));
        assert!(paths.request_path(request(0), now).is_some());
        // Replays cannot replace another request or renew the reserve lease.
        assert!(paths.remember_request(request(9000), ReplyTo::Local, now + TTL / 2));
        assert_eq!(paths.request_path(request(9000), now + TTL), None);
        assert!(paths.remember_request(request(9999), ReplyTo::Local, now + TTL));
        assert_eq!(paths.requests.len(), 1);
    }
    #[test]
    fn nonce_paths_require_a_matching_live_request_and_keep_both_legs() {
        let now = Instant::now();
        let mut paths = DiscoveryPaths::default();
        assert_eq!(
            paths.remember_challenge(challenge(), request(1), [5; 32], now),
            None
        );
        paths.remember_request(request(1), ReplyTo::Peer([4; 32]), now);
        assert_eq!(
            paths.remember_challenge(challenge(), request(1), [4; 32], now),
            None
        );
        let path = ChallengePath {
            reply: ReplyTo::Peer([4; 32]),
            issuer_hop: [5; 32],
        };
        assert_eq!(
            paths.remember_challenge(challenge(), request(1), [5; 32], now),
            Some(path)
        );
        assert_eq!(
            paths.remember_challenge(challenge(), request(1), [6; 32], now),
            None
        );
        assert_eq!(
            paths.remember_challenge(challenge(), request(1), [5; 32], now + TTL / 2),
            Some(path)
        );
        assert_eq!(paths.challenge_path(challenge(), now + TTL), None);
    }
    #[test]
    fn challenge_ids_cannot_cross_requester_or_target() {
        let now = Instant::now();
        let mut paths = DiscoveryPaths::default();
        paths.remember_request(request(1), ReplyTo::Peer([4; 32]), now);
        let mut key = challenge();
        key.acceptor = [9; 32];
        assert_eq!(
            paths.remember_challenge(key, request(1), [5; 32], now),
            None
        );
        key = challenge();
        key.requester = [9; 32];
        assert_eq!(
            paths.remember_challenge(key, request(1), [5; 32], now),
            None
        );
    }
    #[test]
    fn challenge_capacity_and_nonce_ambiguity_are_bounded() {
        let now = Instant::now();
        let mut paths = DiscoveryPaths::default();
        paths.remember_request(request(1), ReplyTo::Peer([4; 32]), now);
        for i in 0..MAX_CHALLENGES {
            let mut key = challenge();
            key.nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let mut issuer = [5; 32];
            issuer[0] = (i / MAX_PER_PEER) as u8;
            assert!(
                paths
                    .remember_challenge(key, request(1), issuer, now)
                    .is_some()
            );
        }
        assert_eq!(
            paths.remember_challenge(challenge(), request(1), [8; 32], now),
            None
        );
        assert_eq!(paths.challenges.len(), MAX_CHALLENGES);
        let mut second = request(2);
        second.target = [9; 32];
        let mut clean = DiscoveryPaths::default();
        clean.remember_request(request(1), ReplyTo::Peer([4; 32]), now);
        clean.remember_request(second, ReplyTo::Peer([4; 32]), now);
        clean.remember_challenge(challenge(), request(1), [5; 32], now);
        assert!(clean.accept_path([1; 32], [3; 32], now).is_some());
        let mut key = challenge();
        key.acceptor = [9; 32];
        clean.remember_challenge(key, second, [6; 32], now);
        assert_eq!(clean.accept_path([1; 32], [3; 32], now), None);
    }
}
