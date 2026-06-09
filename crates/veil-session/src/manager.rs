//! Post-handshake session registry — keyed by the 32-byte `SessionId`
//! derived from `SESSION_CONFIRM`, it stores the sovereign-identity
//! outputs of the OVL1 handshake (identity proof, capabilities, role).
//! Complementary to `NodeRuntime.live_sessions`, which holds link-level
//! transport metadata keyed by `LinkId` (assigned at connection accept
//! well before `SESSION_CONFIRM`).

use std::collections::{HashMap, HashSet};

use veil_cfg::NodeId;
use veil_identity::verify::ValidatedIdentity;
use veil_proto::recipient::{InstanceTag, Recipient};
use veil_proto::session::{AttachPayload, CapabilitiesPayload, IdentityPayload};
use veil_types::NodeIdBytes;

/// Stable identifier for an OVL1 session (derived from SESSION_CONFIRM).
pub type SessionId = [u8; 32];

/// The role the remote node declared during ATTACH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteRole {
    Leaf,
    Core,
    Unknown(u8),
}

impl From<u8> for RemoteRole {
    fn from(v: u8) -> Self {
        match v {
            0 => RemoteRole::Leaf,
            1..=3 => RemoteRole::Core,
            other => RemoteRole::Unknown(other),
        }
    }
}

/// Information collected about a fully-established OVL1 session.
#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub session_id: SessionId,
    pub remote_node_id: [u8; 32],
    pub remote_identity: IdentityPayload,
    pub remote_capabilities: CapabilitiesPayload,
    pub remote_attach: AttachPayload,
    pub remote_role: RemoteRole,
    /// verified sovereign identity of the peer when the
    /// OVL1 handshake exchanged a `SessionMsg::IdentityProof` frame and
    /// verification passed. `None` for legacy (non-sovereign) peers
    /// and for fast-path resumptions (ticket certifies the identity
    /// from the original handshake).
    pub validated_sovereign_identity: Option<ValidatedIdentity>,
}

/// Registry that stores active OVL1 sessions, keyed by `session_id`.
///
/// Complementary to `NodeRuntime.live_sessions`: that map holds
/// link-level transport metadata (listener handle, transport URI
/// remote addr) keyed by the early-assigned `LinkId`; this registry
/// holds the post-handshake sovereign-identity data keyed by the
/// `SESSION_CONFIRM`-derived `SessionId`. Kept separate because the
/// two identifiers have different lifetimes (LinkId exists for the
/// whole connection; SessionId only after SESSION_CONFIRM).
#[derive(Debug, Default)]
pub struct SessionRegistry {
    sessions: HashMap<SessionId, SessionEntry>,
    /// Secondary index: `remote_node_id → session_id` for O(1) peer lookups.
    by_peer: HashMap<NodeIdBytes, SessionId>,
    /// 462.17 secondary index: `(node_id, instance_id)
    /// → session_id` so delivery/mailbox code can resolve sovereign
    /// addressees without re-fetching the IdentityDocument. Keyed by
    /// the composite `(node_id, instance_id)` so multiple live
    /// instances of the same identity (laptop + phone both connected)
    /// each get their own entry and can be fanned-out to individually
    /// via `InstanceTag::Specific` or collectively via
    /// `InstanceTag::All`. Populated only for sessions whose
    /// handshake produced a [`ValidatedIdentity`].
    by_identity_instance: HashMap<([u8; 32], [u8; 16]), SessionId>,
    /// Tertiary index: `node_id → {instance_id}` — the set of instances present
    /// in `by_identity_instance` for each identity. Lets `InstanceTag::Any`/
    /// `All` resolution (which only knows the node_id) enumerate an identity's
    /// instances in O(instances) instead of an O(total-sessions) scan of
    /// `by_identity_instance`. Maintained in lockstep: an instance is added on
    /// insert and removed only when its `by_identity_instance` entry is actually
    /// removed (same reconnect-race guard). (audit cycle-3 perf.)
    by_identity: HashMap<[u8; 32], HashSet<[u8; 16]>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a newly-established session.
    pub fn insert(&mut self, entry: SessionEntry) {
        self.by_peer.insert(entry.remote_node_id, entry.session_id);
        if let Some(ref v) = entry.validated_sovereign_identity {
            self.by_identity_instance
                .insert((v.node_id, v.active_instance_id), entry.session_id);
            self.by_identity
                .entry(v.node_id)
                .or_default()
                .insert(v.active_instance_id);
        }
        self.sessions.insert(entry.session_id, entry);
    }

    /// Look up a session by its id.
    pub fn get(&self, id: &SessionId) -> Option<&SessionEntry> {
        self.sessions.get(id)
    }

    /// Remove a session (e.g. on DETACH or connection drop).
    pub fn remove(&mut self, id: &SessionId) -> Option<SessionEntry> {
        if let Some(entry) = self.sessions.remove(id) {
            // Audit L-3: only clear the by_peer index if it still points at THIS
            // session. `remote_node_id` is the peer's stable id (BLAKE3 of its
            // long-term key), identical across reconnects, and `insert`
            // overwrites `by_peer[remote_node_id]`. On a reconnect-before-old-
            // close race the new session has already taken the index slot; an
            // unconditional remove here would delete the entry pointing at the
            // LIVE new session, breaking peer→session routing (get_by_peer_id /
            // node_id_for_peer return None for a peer that has a live session).
            // Mirrors the by_identity_instance guard below.
            if self.by_peer.get(&entry.remote_node_id) == Some(&entry.session_id) {
                self.by_peer.remove(&entry.remote_node_id);
            }
            if let Some(ref v) = entry.validated_sovereign_identity {
                let key = (v.node_id, v.active_instance_id);
                // Only clear the index if it still points at this
                // session — a newer session with the same composite
                // key could have overwritten it.
                if self.by_identity_instance.get(&key) == Some(&entry.session_id) {
                    self.by_identity_instance.remove(&key);
                    // Keep the node_id→instances index in lockstep: only drop
                    // the instance here (under the same guard), and prune the
                    // node_id key once its last instance is gone.
                    if let Some(set) = self.by_identity.get_mut(&v.node_id) {
                        set.remove(&v.active_instance_id);
                        if set.is_empty() {
                            self.by_identity.remove(&v.node_id);
                        }
                    }
                }
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Look up a session by the remote node's `node_id` (peer_id) — O(1).
    ///
    /// In practice only one session exists per peer so the result is deterministic.
    pub fn get_by_peer_id(&self, peer_id: &NodeId) -> Option<&SessionEntry> {
        self.by_peer
            .get(peer_id.as_bytes())
            .and_then(|id| self.sessions.get(id))
    }

    /// resolve a session-layer `peer_id` to the
    /// peer's sovereign `node_id` if the handshake produced
    /// a `ValidatedIdentity`. Returns `None` for legacy
    /// (node_id-keyed) peers without a sovereign identity —
    /// callers are expected to fall back to `peer_id` as a
    /// degenerate identifier in that case. Used by reputation
    /// per-identity quotas, and other accounting paths that need
    /// to survive key rotation / device churn under a stable
    /// identity.
    pub fn node_id_for_peer(&self, peer_id: &NodeId) -> Option<[u8; 32]> {
        self.get_by_peer_id(peer_id)
            .and_then(|e| e.validated_sovereign_identity.as_ref())
            .map(|v| v.node_id)
    }

    /// convenience: look up *any one* live session for an
    /// identity (picks the first entry encountered — unspecified
    /// order across builds). Callers that need a specific instance
    /// MUST use [`Self::get_by_identity_instance`]; callers that need
    /// to fan out to every live instance MUST use
    /// [`Self::peer_ids_for_identity`].
    pub fn get_by_node_id(&self, node_id: &NodeId) -> Option<&SessionEntry> {
        let node_id_bytes = node_id.as_bytes();
        self.by_identity
            .get(node_id_bytes)?
            .iter()
            .find_map(|inst| {
                self.by_identity_instance
                    .get(&(*node_id_bytes, *inst))
                    .and_then(|sid| self.sessions.get(sid))
            })
    }

    /// look up a session by the peer's `(node_id
    /// instance_id)` composite — O(1). This is the
    /// `InstanceTag::Specific` routing entry point.
    pub fn get_by_identity_instance(
        &self,
        node_id: &NodeId,
        instance_id: &[u8; 16],
    ) -> Option<&SessionEntry> {
        self.by_identity_instance
            .get(&(*node_id.as_bytes(), *instance_id))
            .and_then(|sid| self.sessions.get(sid))
    }

    /// routing: peer_id of the session for the specific
    /// `(node_id, instance_id)` pair, if a live session exists.
    /// This is the `InstanceTag::Specific` dispatch helper.
    pub fn peer_id_for_identity_instance(
        &self,
        node_id: &NodeId,
        instance_id: &[u8; 16],
    ) -> Option<[u8; 32]> {
        self.get_by_identity_instance(node_id, instance_id)
            .map(|e| e.remote_node_id)
    }

    /// routing: all live sessions for an identity across
    /// every currently-connected instance. Empty when the peer is
    /// offline from this node's perspective or hasn't advertised
    /// sovereign support. This is the `InstanceTag::All` fan-out
    /// entry point — each `(instance_id, peer_id)` is a distinct
    /// delivery target.
    pub fn peer_ids_for_identity(&self, node_id: &NodeId) -> Vec<([u8; 16], [u8; 32])> {
        let node_id_bytes = node_id.as_bytes();
        self.by_identity
            .get(node_id_bytes)
            .into_iter()
            .flatten()
            .filter_map(|inst| {
                self.by_identity_instance
                    .get(&(*node_id_bytes, *inst))
                    .and_then(|sid| self.sessions.get(sid))
                    .map(|e| (*inst, e.remote_node_id))
            })
            .collect()
    }

    /// (test-only): raw snapshot of the
    /// `by_identity_instance` table so sim scenarios can debug
    /// multi-instance fan-out issues. Returns every
    /// `(node_id, instance_id)` composite key that resolves
    /// to a live session, regardless of sovereign-identity
    /// namespace — useful for diagnosing why `Recipient::All`
    /// returned fewer peers than expected.
    /// test-only — sole caller is `NodeRuntime::debug_session_identity_instances`
    /// in `runtime/debug.rs`, which is itself `#[cfg(test)]`-gated.
    pub fn debug_identity_instance_keys(&self) -> Vec<([u8; 32], [u8; 16])> {
        self.by_identity_instance.keys().copied().collect()
    }

    /// routing: pick *any one* live session for an
    /// identity — used by `InstanceTag::Any` when the sender doesn't
    /// care which device receives the message. Returns `None` when
    /// no instance is currently connected.
    ///
    /// Selection order is deterministic for a given registry state
    /// but unspecified across builds — callers MUST NOT rely on a
    /// particular instance being picked. (Future work: weight by
    /// recency / RTT / battery — scoring.)
    /// pick a single peer for
    /// `InstanceTag::Any` weighted by a caller-provided scorer.
    /// The scorer receives `(peer_id, instance_id)` for each
    /// candidate and returns an `f64` weight; the highest-scoring
    /// entry wins, with a deterministic tie-break on
    /// `(instance_id, peer_id)` byte order so two builds with the
    /// same scoring inputs always pick the same instance.
    ///
    /// Production callers pass a scorer that consults
    /// reputation, RTT, battery, or a composite — anything that
    /// makes "Any" route to the BEST live device of a sovereign
    /// identity. Returns `None` when no live session for
    /// `node_id` is registered.
    ///
    /// currently only consumed by `runtime::debug`
    /// (cfg(test)-gated) and this file's own tests — gated
    /// accordingly. Drop the gate when a production scorer gets
    /// wired in.
    pub fn peer_id_for_identity_scored<F>(&self, node_id: &NodeId, scorer: F) -> Option<[u8; 32]>
    where
        F: Fn([u8; 32], [u8; 16]) -> f64,
    {
        let node_id_bytes = node_id.as_bytes();
        let candidates: Vec<([u8; 16], [u8; 32], f64)> = self
            .by_identity
            .get(node_id_bytes)
            .into_iter()
            .flatten()
            .filter_map(|inst| {
                self.by_identity_instance
                    .get(&(*node_id_bytes, *inst))
                    .and_then(|sid| self.sessions.get(sid))
                    .map(|e| {
                        let peer = e.remote_node_id;
                        let score = scorer(peer, *inst);
                        (*inst, peer, score)
                    })
            })
            .collect();
        // Highest score wins; deterministic tie-break by (instance, peer).
        // `total_cmp` handles NaN sanely (NaN sorts as the largest f64
        // which we explicitly demote by treating as `f64::NEG_INFINITY`).
        candidates
            .into_iter()
            .max_by(|(ai, ap, as_), (bi, bp, bs)| {
                let a = if as_.is_nan() {
                    f64::NEG_INFINITY
                } else {
                    *as_
                };
                let b = if bs.is_nan() { f64::NEG_INFINITY } else { *bs };
                match a.total_cmp(&b) {
                    std::cmp::Ordering::Equal => (ai, ap).cmp(&(bi, bp)),
                    other => other,
                }
            })
            .map(|(_, peer, _)| peer)
    }

    pub fn peer_id_for_identity(&self, node_id: &NodeId) -> Option<[u8; 32]> {
        let node_id_bytes = node_id.as_bytes();
        self.by_identity
            .get(node_id_bytes)?
            .iter()
            .find_map(|inst| {
                self.by_identity_instance
                    .get(&(*node_id_bytes, *inst))
                    .and_then(|sid| self.sessions.get(sid))
                    .map(|e| e.remote_node_id)
            })
    }

    /// unified routing: resolve a sovereign [`Recipient`]
    /// into the transport-level peer_ids the dispatcher should
    /// forward to.
    ///
    /// Return-value semantics:
    /// `InstanceTag::Any` — `Vec` of length 0 or 1 (no live
    /// session, or a single instance picked — see
    /// [`Self::peer_id_for_identity`]).
    /// `InstanceTag::Specific(inst)` — `Vec` of length 0 or 1
    /// (the peer_id of that specific instance if live).
    /// `InstanceTag::All` — every currently-connected instance of
    /// the identity, empty if none.
    ///
    /// The dispatcher layer fans out to each returned peer_id.
    /// Empty return means "no live session" — the caller falls back
    /// to the mailbox / DHT path.
    pub fn resolve_recipient(&self, recipient: &Recipient) -> Vec<[u8; 32]> {
        let recipient_node_id = NodeId::from(recipient.node_id);
        match recipient.instance_tag {
            InstanceTag::Any => self
                .peer_id_for_identity(&recipient_node_id)
                .into_iter()
                .collect(),
            InstanceTag::Specific(inst) => self
                .peer_id_for_identity_instance(&recipient_node_id, &inst)
                .into_iter()
                .collect(),
            InstanceTag::All => self
                .peer_ids_for_identity(&recipient_node_id)
                .into_iter()
                .map(|(_inst, peer)| peer)
                .collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::session::{
        AttachPayload, CapabilitiesPayload, IdentityPayload, cap_flags, role_bits,
    };

    fn make_entry(seed: u8) -> SessionEntry {
        SessionEntry {
            session_id: [seed; 32],
            remote_node_id: [seed + 1; 32],
            remote_identity: IdentityPayload {
                algo: 1,
                public_key: vec![seed; 32],
                nonce: b"nonce".to_vec(),
                node_id: [seed + 1; 32],
                mlkem_pubkey: None,
            },
            remote_capabilities: CapabilitiesPayload {
                roles_supported: role_bits::CORE,
                flags: cap_flags::CAN_RELAY,
                discovery_mode: 0,
            },
            remote_attach: AttachPayload {
                role: 3,
                realm_id: 0,
                attach_epoch: 1,
                mailbox_preference_count: 0,
                gateway_preference_count: 0,
                flags: 0,
            },
            remote_role: RemoteRole::Core,
            validated_sovereign_identity: None,
        }
    }

    fn make_sovereign_entry(seed: u8, node_id: [u8; 32]) -> SessionEntry {
        let mut e = make_entry(seed);
        e.validated_sovereign_identity = Some(ValidatedIdentity {
            node_id,
            master_algo: 0,
            master_pubkey: vec![0xEE; 32],
            active_identity_pubkey: vec![0xFF; 32],
            active_identity_algo: 0,
            active_key_idx: 0,
            active_device_id: [0xDD; 32],
            active_instance_id: [0xCC; 16],
        });
        e
    }

    /// Audit L-3: a reconnect that reuses the SAME stable `remote_node_id` must
    /// keep peer→session routing pointing at the LIVE new session after the old
    /// session's close. (The existing reconnect test uses a distinct node_id, so
    /// it does not cover the unconditional `by_peer.remove` bug.)
    #[test]
    fn remove_keeps_by_peer_for_newer_session_same_node_id_l3() {
        let mut reg = SessionRegistry::new();
        let peer = [0x99u8; 32];

        let mut s1 = make_entry(0x10);
        s1.remote_node_id = peer;
        let s1_id = s1.session_id;
        reg.insert(s1);

        // Reconnect: a new session for the SAME peer overwrites by_peer[peer].
        let mut s2 = make_entry(0x20);
        s2.remote_node_id = peer;
        let s2_id = s2.session_id;
        reg.insert(s2);
        assert_eq!(
            reg.get_by_peer_id(&NodeId::from(peer))
                .map(|e| e.session_id),
            Some(s2_id)
        );

        // Closing the OLD session must NOT evict the index for the live new one.
        reg.remove(&s1_id);
        assert_eq!(
            reg.get_by_peer_id(&NodeId::from(peer))
                .map(|e| e.session_id),
            Some(s2_id),
            "by_peer must still resolve to the live newer session after old close"
        );
    }

    #[test]
    fn insert_get_remove() {
        let mut reg = SessionRegistry::new();
        assert!(reg.is_empty());

        let entry = make_entry(0xAA);
        let id = entry.session_id;
        reg.insert(entry);
        assert_eq!(reg.len(), 1);

        let found = reg.get(&id).unwrap();
        assert_eq!(found.session_id, id);

        reg.remove(&id);
        assert!(reg.is_empty());
    }

    #[test]
    fn get_missing_returns_none() {
        let reg = SessionRegistry::new();
        assert!(reg.get(&[0u8; 32]).is_none());
    }

    // ── node_id secondary index ──────────────────────────

    #[test]
    fn sovereign_entry_is_indexed_by_node_id() {
        let mut reg = SessionRegistry::new();
        let node_id = [0x77; 32];
        let entry = make_sovereign_entry(0xAA, node_id);
        let peer_id = entry.remote_node_id;
        reg.insert(entry);

        // Look up by node_id returns the same session.
        let by_id = reg.get_by_node_id(&NodeId::from(node_id)).unwrap();
        assert_eq!(
            by_id.validated_sovereign_identity.as_ref().unwrap().node_id,
            node_id
        );
        // Convenience helper returns the peer_id for this session.
        assert_eq!(
            reg.peer_id_for_identity(&NodeId::from(node_id)),
            Some(peer_id)
        );
    }

    #[test]
    fn non_sovereign_entry_is_not_indexed_by_identity() {
        let mut reg = SessionRegistry::new();
        let entry = make_entry(0xBB);
        reg.insert(entry);
        // No node_id was attached — lookups MUST miss.
        assert!(reg.get_by_node_id(&NodeId::from([0u8; 32])).is_none());
        assert_eq!(reg.peer_id_for_identity(&NodeId::from([0u8; 32])), None);
    }

    #[test]
    fn identity_index_is_cleared_on_remove() {
        let mut reg = SessionRegistry::new();
        let node_id = [0x99; 32];
        let entry = make_sovereign_entry(0xCC, node_id);
        let sid = entry.session_id;
        reg.insert(entry);
        assert!(reg.get_by_node_id(&NodeId::from(node_id)).is_some());

        reg.remove(&sid);
        assert!(reg.get_by_node_id(&NodeId::from(node_id)).is_none());
        assert_eq!(reg.peer_id_for_identity(&NodeId::from(node_id)), None);
    }

    // ── 462.20: (node_id, instance_id) composite index ──

    #[test]
    fn by_identity_index_survives_reconnect_race_and_removal() {
        // audit cycle-3: the node_id->instances index must stay in lockstep with
        // by_identity_instance through a reconnect race (a new session takes the
        // same (node_id, instance) slot before the old session is removed).
        let mut reg = SessionRegistry::new();
        let node_id = [0xCD; 32];
        let inst = [0x07; 16];

        let mut a = make_sovereign_entry(0x30, node_id);
        a.session_id = [0x30; 32];
        a.remote_node_id = [0x31; 32];
        a.validated_sovereign_identity
            .as_mut()
            .unwrap()
            .active_instance_id = inst;
        reg.insert(a);

        // Reconnect: B takes the same (node_id, instance) slot.
        let mut b = make_sovereign_entry(0x40, node_id);
        b.session_id = [0x40; 32];
        b.remote_node_id = [0x41; 32];
        b.validated_sovereign_identity
            .as_mut()
            .unwrap()
            .active_instance_id = inst;
        reg.insert(b);

        // Removing the OLD session must NOT evict the live (B) index entry.
        reg.remove(&[0x30; 32]);
        assert_eq!(
            reg.peer_id_for_identity(&NodeId::from(node_id)),
            Some([0x41; 32])
        );
        assert_eq!(
            reg.peer_ids_for_identity(&NodeId::from(node_id)),
            vec![(inst, [0x41; 32])]
        );

        // Removing the live session clears the index entirely.
        reg.remove(&[0x40; 32]);
        assert_eq!(reg.peer_id_for_identity(&NodeId::from(node_id)), None);
        assert!(reg.peer_ids_for_identity(&NodeId::from(node_id)).is_empty());
    }

    #[test]
    fn two_instances_of_same_identity_coexist() {
        // Bob has a laptop and a phone both connected to our node —
        // distinct instance_ids under the same node_id. Both
        // must be individually reachable via the composite index.
        let mut reg = SessionRegistry::new();
        let node_id = [0xAB; 32];

        let mut laptop = make_sovereign_entry(0x10, node_id);
        laptop.session_id = [0x10; 32];
        laptop.remote_node_id = [0x11; 32];
        laptop
            .validated_sovereign_identity
            .as_mut()
            .unwrap()
            .active_instance_id = [0x01; 16];
        reg.insert(laptop);

        let mut phone = make_sovereign_entry(0x20, node_id);
        phone.session_id = [0x20; 32];
        phone.remote_node_id = [0x21; 32];
        phone
            .validated_sovereign_identity
            .as_mut()
            .unwrap()
            .active_instance_id = [0x02; 16];
        reg.insert(phone);

        // Specific routing hits each distinctly.
        assert_eq!(
            reg.peer_id_for_identity_instance(&NodeId::from(node_id), &[0x01; 16]),
            Some([0x11; 32])
        );
        assert_eq!(
            reg.peer_id_for_identity_instance(&NodeId::from(node_id), &[0x02; 16]),
            Some([0x21; 32])
        );

        // All-fanout sees both.
        let mut all = reg.peer_ids_for_identity(&NodeId::from(node_id));
        all.sort();
        assert_eq!(
            all,
            vec![([0x01; 16], [0x11; 32]), ([0x02; 16], [0x21; 32])]
        );

        // Any-picks-one still works — returns one of the two.
        let any = reg.peer_id_for_identity(&NodeId::from(node_id)).unwrap();
        assert!(any == [0x11; 32] || any == [0x21; 32]);
    }

    #[test]
    fn specific_instance_missing_returns_none() {
        let mut reg = SessionRegistry::new();
        let node_id = [0xCD; 32];
        let mut laptop = make_sovereign_entry(0x30, node_id);
        laptop
            .validated_sovereign_identity
            .as_mut()
            .unwrap()
            .active_instance_id = [0x01; 16];
        reg.insert(laptop);

        // Phone not connected.
        assert_eq!(
            reg.peer_id_for_identity_instance(&NodeId::from(node_id), &[0x99; 16]),
            None
        );
        // But the laptop is reachable.
        assert!(
            reg.peer_id_for_identity_instance(&NodeId::from(node_id), &[0x01; 16])
                .is_some()
        );
    }

    #[test]
    fn fan_out_is_empty_for_unknown_identity() {
        let reg = SessionRegistry::new();
        assert!(
            reg.peer_ids_for_identity(&NodeId::from([0u8; 32]))
                .is_empty()
        );
    }

    // ── resolve_recipient(Recipient) → Vec<peer_id> ──────────

    fn seed_two_instances(reg: &mut SessionRegistry, node_id: [u8; 32]) {
        let mut laptop = make_sovereign_entry(0x10, node_id);
        laptop.session_id = [0x10; 32];
        laptop.remote_node_id = [0x11; 32];
        laptop
            .validated_sovereign_identity
            .as_mut()
            .unwrap()
            .active_instance_id = [0x01; 16];
        reg.insert(laptop);

        let mut phone = make_sovereign_entry(0x20, node_id);
        phone.session_id = [0x20; 32];
        phone.remote_node_id = [0x21; 32];
        phone
            .validated_sovereign_identity
            .as_mut()
            .unwrap()
            .active_instance_id = [0x02; 16];
        reg.insert(phone);
    }

    #[test]
    fn resolve_recipient_any_returns_one() {
        let mut reg = SessionRegistry::new();
        let node_id = [0xAB; 32];
        seed_two_instances(&mut reg, node_id);

        let got = reg.resolve_recipient(&Recipient::any(node_id));
        assert_eq!(got.len(), 1, "Any → single peer");
        assert!(got[0] == [0x11; 32] || got[0] == [0x21; 32]);
    }

    // ── score-based Any ─────────────────────────

    #[test]
    fn peer_id_for_identity_scored_picks_highest() {
        let mut reg = SessionRegistry::new();
        let node_id = [0x11; 32];
        seed_two_instances(&mut reg, node_id);
        // Laptop's instance_id is [0x01; 16] → peer_id [0x11; 32].
        // Phone's instance_id is [0x02; 16] → peer_id [0x21; 32].
        // Score the phone higher.
        let picked = reg.peer_id_for_identity_scored(&NodeId::from(node_id), |_peer, inst| {
            if inst == [0x02; 16] { 100.0 } else { 1.0 }
        });
        assert_eq!(picked, Some([0x21; 32]), "phone scored higher → phone wins");

        // Flip the scorer; laptop wins.
        let picked = reg.peer_id_for_identity_scored(&NodeId::from(node_id), |_peer, inst| {
            if inst == [0x01; 16] { 100.0 } else { 1.0 }
        });
        assert_eq!(
            picked,
            Some([0x11; 32]),
            "laptop scored higher → laptop wins"
        );
    }

    #[test]
    fn peer_id_for_identity_scored_tie_break_deterministic() {
        let mut reg = SessionRegistry::new();
        let node_id = [0x22; 32];
        seed_two_instances(&mut reg, node_id);
        // Equal scores — tie-break sorts by `(instance_id, peer_id)` →
        // [0x01;16] < [0x02;16] so laptop wins both runs.
        let p1 = reg.peer_id_for_identity_scored(&NodeId::from(node_id), |_, _| 5.0);
        let p2 = reg.peer_id_for_identity_scored(&NodeId::from(node_id), |_, _| 5.0);
        assert_eq!(p1, p2, "tie-break must be deterministic across calls");
        assert_eq!(
            p1,
            Some([0x21; 32]),
            "max_by picks the LAST element on tie when ordering equal — \
             with (instance, peer) cmp the larger key wins, i.e. phone"
        );
    }

    #[test]
    fn peer_id_for_identity_scored_returns_none_for_unknown_identity() {
        let reg = SessionRegistry::new();
        let picked = reg.peer_id_for_identity_scored(&NodeId::from([0x99; 32]), |_, _| 1.0);
        assert_eq!(picked, None);
    }

    #[test]
    fn peer_id_for_identity_scored_treats_nan_as_lowest_priority() {
        // NaN scores must NOT win — the helper demotes NaN to
        // ∞ so a real score always beats it.
        let mut reg = SessionRegistry::new();
        let node_id = [0x33; 32];
        seed_two_instances(&mut reg, node_id);
        let picked = reg.peer_id_for_identity_scored(&NodeId::from(node_id), |_, inst| {
            if inst == [0x01; 16] { f64::NAN } else { -50.0 }
        });
        assert_eq!(
            picked,
            Some([0x21; 32]),
            "NaN-score instance must lose to any finite-score one"
        );
    }

    #[test]
    fn resolve_recipient_all_returns_every_instance() {
        let mut reg = SessionRegistry::new();
        let node_id = [0xCD; 32];
        seed_two_instances(&mut reg, node_id);

        let mut got = reg.resolve_recipient(&Recipient::all(node_id));
        got.sort();
        assert_eq!(got, vec![[0x11; 32], [0x21; 32]]);
    }

    #[test]
    fn resolve_recipient_specific_hits_one_instance() {
        let mut reg = SessionRegistry::new();
        let node_id = [0xEF; 32];
        seed_two_instances(&mut reg, node_id);

        let got = reg.resolve_recipient(&Recipient {
            node_id,
            instance_tag: InstanceTag::Specific([0x01; 16]),
        });
        assert_eq!(got, vec![[0x11; 32]]);

        let got = reg.resolve_recipient(&Recipient {
            node_id,
            instance_tag: InstanceTag::Specific([0x02; 16]),
        });
        assert_eq!(got, vec![[0x21; 32]]);

        let got = reg.resolve_recipient(&Recipient {
            node_id,
            instance_tag: InstanceTag::Specific([0xFF; 16]),
        });
        assert!(got.is_empty(), "unknown instance → empty");
    }

    #[test]
    fn resolve_recipient_empty_when_identity_offline() {
        // No live session for this identity at all — every tag
        // variant returns an empty vec so the dispatcher falls
        // through to mailbox / DHT paths.
        let reg = SessionRegistry::new();
        let unknown = [0xBA; 32];
        assert!(reg.resolve_recipient(&Recipient::any(unknown)).is_empty());
        assert!(reg.resolve_recipient(&Recipient::all(unknown)).is_empty());
        assert!(
            reg.resolve_recipient(&Recipient {
                node_id: unknown,
                instance_tag: InstanceTag::Specific([0x01; 16]),
            })
            .is_empty()
        );
    }

    #[test]
    fn resolve_recipient_ignores_legacy_peers_with_no_sovereign_identity() {
        // A peer that connected without sovereign-identity support
        // is in the `by_peer` map but NOT in `by_identity_instance`
        // so resolve_recipient (which keys off node_id) returns
        // empty. Legacy routing must go through `get_by_peer_id`.
        let mut reg = SessionRegistry::new();
        let legacy = make_entry(0x55);
        let some_node_id = [0x66; 32];
        reg.insert(legacy);

        // The node_id isn't indexed at all.
        assert!(
            reg.resolve_recipient(&Recipient::any(some_node_id))
                .is_empty()
        );
        assert!(
            reg.resolve_recipient(&Recipient::all(some_node_id))
                .is_empty()
        );
    }

    #[test]
    fn removing_one_instance_leaves_others_reachable() {
        // Bob's laptop drops; phone stays connected. The by-identity
        // fan-out must still see the phone.
        let mut reg = SessionRegistry::new();
        let node_id = [0xEF; 32];

        let mut laptop = make_sovereign_entry(0x40, node_id);
        laptop.session_id = [0x40; 32];
        laptop
            .validated_sovereign_identity
            .as_mut()
            .unwrap()
            .active_instance_id = [0x01; 16];
        let laptop_sid = laptop.session_id;
        reg.insert(laptop);

        let mut phone = make_sovereign_entry(0x50, node_id);
        phone.session_id = [0x50; 32];
        phone.remote_node_id = [0x51; 32];
        phone
            .validated_sovereign_identity
            .as_mut()
            .unwrap()
            .active_instance_id = [0x02; 16];
        reg.insert(phone);

        reg.remove(&laptop_sid);

        assert_eq!(
            reg.peer_id_for_identity_instance(&NodeId::from(node_id), &[0x01; 16]),
            None
        );
        assert_eq!(
            reg.peer_id_for_identity_instance(&NodeId::from(node_id), &[0x02; 16]),
            Some([0x51; 32])
        );
        assert_eq!(reg.peer_ids_for_identity(&NodeId::from(node_id)).len(), 1);
    }

    #[test]
    fn identity_reconnect_does_not_evict_newer_session_on_old_close() {
        // Same node_id reconnects on a fresh session_id (runtime
        // replaced the old session). When the OLD session's close
        // event finally fires, it must NOT evict the identity index
        // entry now pointing at the NEW session.
        let mut reg = SessionRegistry::new();
        let node_id = [0xAB; 32];
        let old = make_sovereign_entry(0x01, node_id);
        let old_sid = old.session_id;
        reg.insert(old);

        let mut new = make_sovereign_entry(0x02, node_id);
        new.session_id = [0x02; 32]; // distinct session_id
        new.remote_node_id = [0x03; 32]; // distinct peer_id
        let new_sid = new.session_id;
        let new_peer = new.remote_node_id;
        reg.insert(new);

        // After the newer insert, the identity index points at the new session.
        assert_eq!(
            reg.peer_id_for_identity(&NodeId::from(node_id)),
            Some(new_peer)
        );

        // Removing the OLD session must leave the identity index intact.
        reg.remove(&old_sid);
        assert_eq!(
            reg.peer_id_for_identity(&NodeId::from(node_id)),
            Some(new_peer)
        );

        // Now removing the NEW session does clear the identity index.
        reg.remove(&new_sid);
        assert_eq!(reg.peer_id_for_identity(&NodeId::from(node_id)), None);
    }
}
