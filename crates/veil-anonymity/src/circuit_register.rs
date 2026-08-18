//! Onion registration AT the rendezvous (onion-registration epic b4a). See
//! `docs/internal/PLAN_ANON_SERVICE_ONION_REGISTRATION.md` §3.B.
//!
//! A receiver that wants a LOCATION-anonymous service builds a circuit whose
//! terminus is the rendezvous relay R (b2) and piggy-backs a
//! [`CircuitRegisterPayload`] as the setup's terminus payload. R records
//! `cookie → circuit` here, keyed by COOKIE ALONE — it never learns the
//! receiver's node_id (the whole point), so the session-keyed namespacing the
//! plain rendezvous registry uses is unavailable.
//!
//! ## Anti-squat without an identity
//! Cookie-only keying invites hijack (cookies are public in the ad). Defence:
//! the ad commits to a per-service **registration key** `reg_pk`; the
//! registration is SIGNED by `reg_sk` over `(domain ‖ cookie ‖ reg_pk)`, and the
//! registry is **first-registration-wins per cookie** — a later party trying to
//! claim the same cookie with a DIFFERENT `reg_pk` is rejected. The legitimate
//! service registers (fresh random cookie) BEFORE publishing its ad, so it wins
//! the race. A squatter who guesses the cookie can at worst DROP sealed
//! introduces (a DoS) — never read them (they are sealed to the service's
//! x25519 key), and never re-bind the cookie once the service holds it.
//!
//! b4a is the payload + registry only; the dispatcher wires R's terminus to
//! `register` + `handle_final_introduce` to forward down the circuit in b4b.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use veil_types::SignatureAlgorithm;

use crate::circuit_table::CircuitState;

/// Domain separation for the registration signature.
const REGISTER_DOMAIN: &[u8] = b"veil.circuit.register.v1\0";
/// Cookie length (matches the rendezvous `auth_cookie`).
pub const COOKIE_LEN: usize = 16;
/// Ed25519 public-key length.
pub const REG_PK_LEN: usize = 32;
/// Max signature bytes accepted on the wire.
const MAX_SIG_LEN: usize = 128;

/// Domain separation for [`cookie_for_reg_pk`].
const COOKIE_BINDING_CONTEXT: &str = "veil.circuit.register.v1 cookie from reg_pk";

/// The one cookie a given registration key may claim.
///
/// ## Why the cookie is not free-form
///
/// First-registration-wins is only a defence while the legitimate service holds
/// the entry. It does not survive the service losing it — R restarts, or the
/// 600-second TTL reaps a subscription during an outage — and the cookie is
/// public: it rides in the DHT ad so senders can find the service. Whoever
/// registers first after that moment owns the cookie, and the real service is
/// then rejected as the squatter (`CookieClaimed`) on its own name.
///
/// R cannot tell the two apart from anything it holds. It never learns the
/// receiver's node_id — that is the property the whole design exists for — so
/// it has no identity to check the claim against, and it never sees the ad, so
/// it cannot look up which key the service published. Everything R knows is in
/// the registration payload.
///
/// Deriving the cookie from the registration key puts the answer there. R
/// recomputes it from `reg_pk` and rejects any pairing that does not match, so
/// claiming a cookie now requires the key that hashes to it — a preimage
/// problem — rather than merely being early. R still learns nothing about who
/// the service is.
///
/// This costs nothing in key lifetime: for a sovereign service both the cookie
/// and `reg_pk` were already derived from `(identity_seed, period, slot)` and
/// so already rotated together. This makes that pairing checkable instead of
/// merely conventional.
#[must_use]
pub fn cookie_for_reg_pk(reg_pk: &[u8; REG_PK_LEN]) -> [u8; COOKIE_LEN] {
    let full = blake3::derive_key(COOKIE_BINDING_CONTEXT, reg_pk);
    let mut cookie = [0u8; COOKIE_LEN];
    cookie.copy_from_slice(&full[..COOKIE_LEN]);
    cookie
}

/// Default cap on circuit-backed subscriptions at one relay (mirrors the
/// rendezvous registry's `MAX_REGISTRATIONS`).
pub const MAX_CIRCUIT_SUBSCRIPTIONS: usize = 10_000;
/// Default subscription TTL — refreshed on re-register.
pub const DEFAULT_SUBSCRIPTION_TTL_SECS: u64 = 600;
/// Cap on subscriptions whose circuit arrived over ONE neighbour link.
///
/// The circuit table caps a neighbour at
/// [`MAX_CIRCUITS_PER_LINK`](crate::circuit_table::MAX_CIRCUITS_PER_LINK) = 64
/// concurrent circuits, and that number was the relay's whole answer to "how
/// much state can one neighbour make me hold". It stopped being the answer
/// when install-pressure reclaim landed: reclaim frees the TABLE slot but
/// deliberately leaves the cookie bound, because return-forwarding does not
/// consult the table and dropping the binding would cut the late slices of a
/// sliced reply. The subscription therefore outlives its slot, holding an
/// `Arc<CircuitState>` for up to [`DEFAULT_SUBSCRIPTION_TTL_SECS`].
///
/// A binding is reclaimable 30 s after it last served
/// ([`SERVED_LINGER_SECS`](crate::circuit_table::SERVED_LINGER_SECS)), so a
/// neighbour that keeps serving its own circuits can cycle its 64 slots about
/// twenty times inside one 600 s TTL: ≈1280 live states against a quota of 64,
/// and ~13% of the global cap from a single peer.
///
/// 256 is deliberately 4× the table's per-link quota rather than equal to it:
/// the reply circuits this bounds are minted one per send and one per mailbox
/// poll, so a cap AT the table quota would refuse a busy honest client — the
/// exact starvation the reclaim work was undoing. See
/// [`CircuitRendezvousRegistry::register`] for why hitting it evicts instead
/// of refusing.
pub const MAX_SUBSCRIPTIONS_PER_LINK: usize = 256;

/// Signed registration a receiver delivers as the circuit-setup terminus
/// payload. `reg_pk` is an Ed25519 public key (raw bytes); `signature` covers
/// `(domain ‖ cookie ‖ reg_pk ‖ epoch)`.
///
/// `epoch` (diff-audit M2) is a monotonic freshness counter (the receiver uses
/// its unix-seconds clock; rebuilds are minutes apart so it strictly increases).
/// R only accepts a re-registration whose epoch is STRICTLY GREATER than the one
/// it last recorded for the cookie. Without it the signature was static and
/// replayable: a party that captured a registration off the circuit path could
/// replay it on its OWN circuit to re-bind `cookie → attacker circuit` and
/// black-hole introduces. A replayed payload carries an old (≤ stored) epoch and
/// is now rejected; only the holder of `reg_sk` can mint a fresher one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitRegisterPayload {
    pub cookie: [u8; COOKIE_LEN],
    pub reg_pk: [u8; REG_PK_LEN],
    pub epoch: u64,
    pub signature: Vec<u8>,
}

impl CircuitRegisterPayload {
    /// Bytes the `reg_sk` signs over.
    pub fn signing_bytes(
        cookie: &[u8; COOKIE_LEN],
        reg_pk: &[u8; REG_PK_LEN],
        epoch: u64,
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(REGISTER_DOMAIN.len() + COOKIE_LEN + REG_PK_LEN + 8);
        m.extend_from_slice(REGISTER_DOMAIN);
        m.extend_from_slice(cookie);
        m.extend_from_slice(reg_pk);
        m.extend_from_slice(&epoch.to_be_bytes());
        m
    }

    /// Verify the registration self-signature (proves possession of `reg_sk`).
    pub fn verify(&self) -> bool {
        let msg = Self::signing_bytes(&self.cookie, &self.reg_pk, self.epoch);
        let pk_b64 = STANDARD.encode(self.reg_pk);
        veil_crypto::verify_message(SignatureAlgorithm::Ed25519, &pk_b64, &msg, &self.signature)
            .is_ok()
    }

    /// Wire: `[cookie(16)][reg_pk(32)][epoch(8) BE][sig_len u16 BE][sig]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(COOKIE_LEN + REG_PK_LEN + 8 + 2 + self.signature.len());
        b.extend_from_slice(&self.cookie);
        b.extend_from_slice(&self.reg_pk);
        b.extend_from_slice(&self.epoch.to_be_bytes());
        b.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        b.extend_from_slice(&self.signature);
        b
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        let fixed = COOKIE_LEN + REG_PK_LEN + 8 + 2;
        if buf.len() < fixed {
            return None;
        }
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(&buf[..COOKIE_LEN]);
        let mut reg_pk = [0u8; REG_PK_LEN];
        reg_pk.copy_from_slice(&buf[COOKIE_LEN..COOKIE_LEN + REG_PK_LEN]);
        let epoch_off = COOKIE_LEN + REG_PK_LEN;
        let epoch = u64::from_be_bytes(buf[epoch_off..epoch_off + 8].try_into().ok()?);
        let sig_len_off = epoch_off + 8;
        let sig_len = u16::from_be_bytes([buf[sig_len_off], buf[sig_len_off + 1]]) as usize;
        // Exact length: reject trailing garbage as well as truncation. The
        // registration is delivered as the exact innermost circuit-setup
        // payload (no padding through the onion layers), so a legitimate
        // payload is precisely `fixed + sig_len`; accepting trailing bytes is
        // wire malleability with no legitimate producer.
        if sig_len > MAX_SIG_LEN || buf.len() != fixed + sig_len {
            return None;
        }
        Some(Self {
            cookie,
            reg_pk,
            epoch,
            signature: buf[fixed..fixed + sig_len].to_vec(),
        })
    }
}

/// Why a circuit-registration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// Registration self-signature did not verify.
    BadSignature,
    /// Cookie already held by a DIFFERENT `reg_pk` (squat attempt).
    CookieClaimed,
    /// Global subscription cap reached.
    Full,
    /// Re-registration epoch is not strictly greater than the recorded one
    /// (diff-audit M2) — a replayed/stale registration. The legitimate holder
    /// always mints a fresher epoch on each rebuild.
    StaleEpoch,
    /// The cookie is not the one this `reg_pk` may claim
    /// ([`cookie_for_reg_pk`]) — a squat attempt on a public cookie, or a
    /// producer that minted the two independently.
    CookieNotBoundToKey,
}

struct Subscription {
    reg_pk: [u8; REG_PK_LEN],
    circuit: Arc<CircuitState>,
    registered_unix: u64,
    /// Last accepted registration epoch (M2 replay guard).
    epoch: u64,
}

/// Subscriptions plus the per-link index that makes the ceiling cheap.
///
/// The index is not an optimisation of a scan that would otherwise be fine.
/// `register` runs on every circuit build a relay accepts, and the registry
/// holds up to `MAX_CIRCUIT_SUBSCRIPTIONS` = 10 000 entries — asking "how many
/// does this neighbour hold" by filtering the whole map would put a
/// 10 000-element walk on that path. Cookies, not a bare count, because the
/// eviction has to pick a victim among one link's entries; bounded by
/// `per_link_cap`, so the linear scans inside a bucket stay trivial. Same
/// shape and the same reason as `circuit_table::Inner::per_link`.
#[derive(Default)]
struct Inner {
    subs: HashMap<[u8; COOKIE_LEN], Subscription>,
    per_link: HashMap<[u8; 32], Vec<[u8; COOKIE_LEN]>>,
}

impl Inner {
    fn insert(&mut self, cookie: [u8; COOKIE_LEN], sub: Subscription) {
        let link = sub.circuit.prev_link;
        match self.subs.insert(cookie, sub) {
            // A refresh keeping the same neighbour: the bucket already has it.
            Some(prev) if prev.circuit.prev_link == link => {}
            // A refresh that arrived over a DIFFERENT neighbour, which is the
            // ordinary case rather than the exotic one: a service rebuilds its
            // circuit every 150 s down a freshly chosen path and re-registers
            // the same cookie, since the cookie follows the reg_pk and not the
            // route. Leaving it in the old bucket would charge one link for
            // state another link holds — the count the ceiling is measured on
            // would stop meaning anything for both.
            Some(prev) => {
                self.unbucket(&prev.circuit.prev_link, &cookie);
                self.per_link.entry(link).or_default().push(cookie);
            }
            None => self.per_link.entry(link).or_default().push(cookie),
        }
    }

    /// The single removal path — teardown, TTL gc and the per-link ceiling all
    /// go through it, so the two indices cannot drift apart.
    fn remove(&mut self, cookie: &[u8; COOKIE_LEN]) -> Option<Subscription> {
        let sub = self.subs.remove(cookie)?;
        self.unbucket(&sub.circuit.prev_link, cookie);
        Some(sub)
    }

    fn unbucket(&mut self, prev_link: &[u8; 32], cookie: &[u8; COOKIE_LEN]) {
        let Some(cookies) = self.per_link.get_mut(prev_link) else {
            return;
        };
        if let Some(pos) = cookies.iter().position(|c| c == cookie) {
            cookies.swap_remove(pos);
        }
        if cookies.is_empty() {
            self.per_link.remove(prev_link);
        }
    }

    fn bucket_len(&self, prev_link: &[u8; 32]) -> usize {
        self.per_link.get(prev_link).map_or(0, Vec::len)
    }
}

/// Bounded, cookie-keyed registry of circuit-backed rendezvous subscriptions.
/// First-registration-wins per cookie; refresh allowed for the same `reg_pk`.
pub struct CircuitRendezvousRegistry {
    inner: Mutex<Inner>,
    cap: usize,
    per_link_cap: usize,
    ttl_secs: u64,
    /// Bindings dropped by the per-link ceiling since the last read. Counted
    /// because an evicted binding is what later surfaces as an
    /// `introduce.cookie_unknown` at this relay, and the periodic GC already
    /// reports its own evictions for exactly that reason — a ceiling that
    /// fired silently would be the one eviction nothing could account for.
    over_link_cap_evictions: AtomicU64,
}

impl CircuitRendezvousRegistry {
    pub fn new() -> Self {
        Self::with_params(MAX_CIRCUIT_SUBSCRIPTIONS, DEFAULT_SUBSCRIPTION_TTL_SECS)
    }

    pub fn with_params(cap: usize, ttl_secs: u64) -> Self {
        Self::with_link_cap(cap, MAX_SUBSCRIPTIONS_PER_LINK, ttl_secs)
    }

    pub fn with_link_cap(cap: usize, per_link_cap: usize, ttl_secs: u64) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            cap: cap.max(1),
            per_link_cap: per_link_cap.max(1),
            ttl_secs,
            over_link_cap_evictions: AtomicU64::new(0),
        }
    }

    /// Subscriptions currently held whose circuit arrived over `prev_link`.
    pub fn link_occupancy(&self, prev_link: &[u8; 32]) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .bucket_len(prev_link)
    }

    /// Verify + record a registration, binding `payload.cookie` to `circuit`.
    /// First-wins: a different `reg_pk` on an existing cookie is rejected.
    pub fn register(
        &self,
        payload: &CircuitRegisterPayload,
        circuit: Arc<CircuitState>,
        now_unix: u64,
    ) -> Result<(), RegisterError> {
        if !payload.verify() {
            return Err(RegisterError::BadSignature);
        }
        // The signature proves possession of `reg_sk`; it says nothing about
        // whether this key is entitled to THIS cookie. Without the binding a
        // squatter signs its own key over any public cookie and wins the race
        // the moment the real service loses its entry. See `cookie_for_reg_pk`.
        if payload.cookie != cookie_for_reg_pk(&payload.reg_pk) {
            return Err(RegisterError::CookieNotBoundToKey);
        }
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let fresh_cookie = match g.subs.get(&payload.cookie) {
            Some(existing) if existing.reg_pk != payload.reg_pk => {
                return Err(RegisterError::CookieClaimed);
            }
            // Same reg_pk → refresh, but ONLY with a strictly-fresher epoch (M2).
            // A replayed payload carries epoch ≤ the recorded one and is rejected
            // before it can re-bind the cookie to a different circuit.
            Some(existing) if payload.epoch <= existing.epoch => {
                return Err(RegisterError::StaleEpoch);
            }
            Some(_) => false,
            None => {
                if g.subs.len() >= self.cap {
                    return Err(RegisterError::Full);
                }
                true
            }
        };
        // Per-link ceiling (see `MAX_SUBSCRIPTIONS_PER_LINK`). Only a NEW
        // cookie can grow this link's share; a refresh replaces an entry the
        // link already holds.
        if fresh_cookie && Self::make_room_for_link(&mut g, &circuit.prev_link, self.per_link_cap)
        {
            self.over_link_cap_evictions.fetch_add(1, Ordering::Relaxed);
        }
        // Record the cookie ON the circuit so its teardown can evict this sub.
        circuit.set_registered_cookie(payload.cookie);
        g.insert(
            payload.cookie,
            Subscription {
                reg_pk: payload.reg_pk,
                circuit,
                registered_unix: now_unix,
                epoch: payload.epoch,
            },
        );
        Ok(())
    }

    /// Make one slot for `prev_link` when it is already at its ceiling.
    ///
    /// Evicting instead of refusing is the deliberate half. A refusal would
    /// leave the originator without its `CircuitBuilt` ACK while its peer
    /// introduces at a cookie no relay bound — the exact starvation the
    /// install-pressure reclaim exists to end — and the client most likely to
    /// reach a per-link ceiling is an honest one bursting sends, since one
    /// reply circuit is minted per send and per mailbox poll.
    ///
    /// The victim is the binding that has ALREADY forwarded a reply and did so
    /// longest ago: `last_served_unix` is re-armed on every forward, so the
    /// minimum over served entries is the one whose reply finished furthest in
    /// the past and therefore the least likely to still owe a slice. Only if
    /// this link has served nothing at all does the oldest registration go —
    /// a link holding 256 never-served bindings is not a caller with a reply
    /// in flight.
    ///
    /// Returns whether a binding was dropped.
    fn make_room_for_link(g: &mut Inner, prev_link: &[u8; 32], per_link_cap: usize) -> bool {
        if g.bucket_len(prev_link) < per_link_cap {
            return false;
        }
        let Some(bucket) = g.per_link.get(prev_link) else {
            return false;
        };
        let served_first = |c: &&[u8; COOKIE_LEN]| {
            g.subs
                .get(*c)
                .is_some_and(|s| s.circuit.last_served_unix() != 0)
        };
        let victim = bucket
            .iter()
            .filter(served_first)
            .min_by_key(|c| g.subs.get(*c).map_or(0, |s| s.circuit.last_served_unix()))
            .or_else(|| {
                bucket
                    .iter()
                    .min_by_key(|c| g.subs.get(*c).map_or(0, |s| s.registered_unix))
            })
            .copied();
        match victim {
            Some(cookie) => g.remove(&cookie).is_some(),
            None => false,
        }
    }

    /// Read and reset the per-link-ceiling eviction counter — the same shape
    /// [`Self::gc`] reports its evictions in, so both land in one log line.
    pub fn take_over_link_cap_evictions(&self) -> u64 {
        self.over_link_cap_evictions.swap(0, Ordering::Relaxed)
    }

    /// Resolve a cookie to its circuit (for forwarding an introduce down it).
    pub fn lookup(&self, cookie: &[u8; COOKIE_LEN]) -> Option<Arc<CircuitState>> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.subs.get(cookie).map(|s| Arc::clone(&s.circuit))
    }

    /// Drop a cookie's subscription (e.g. on circuit teardown).
    pub fn remove(&self, cookie: &[u8; COOKIE_LEN]) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(cookie);
    }

    /// Evict subscriptions older than the TTL. Returns the count removed.
    pub fn gc(&self, now_unix: u64) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let ttl = self.ttl_secs;
        let expired: Vec<[u8; COOKIE_LEN]> = g
            .subs
            .iter()
            .filter(|(_, s)| now_unix.saturating_sub(s.registered_unix) >= ttl)
            .map(|(c, _)| *c)
            .collect();
        // Through `Inner::remove` rather than `retain`, so the per-link index
        // is emptied with the map instead of holding cookies that no longer
        // resolve — a stale bucket would keep counting against the ceiling.
        for cookie in &expired {
            g.remove(cookie);
        }
        expired.len()
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .subs
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CircuitRendezvousRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_setup::CircuitInstall;
    use crate::circuit_table::CircuitTable;
    use veil_crypto::{generate_keypair, sign_message};

    /// Make a signed registration under a fresh Ed25519 key at `epoch`.
    /// The cookie is the one that key may claim, so every fresh key yields a
    /// distinct cookie. Returns (payload, reg_pk_bytes).
    fn signed_at(epoch: u64) -> (CircuitRegisterPayload, [u8; REG_PK_LEN]) {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        signed_with(epoch, &kp)
    }

    /// Sign at `epoch` under a SPECIFIC keypair (so a refresh can reuse the
    /// same reg_pk with a fresher epoch, as the real service does). The cookie
    /// follows the key.
    fn signed_with(
        epoch: u64,
        kp: &veil_crypto::GeneratedKeyPair,
    ) -> (CircuitRegisterPayload, [u8; REG_PK_LEN]) {
        let reg_pk_bytes: [u8; REG_PK_LEN] =
            STANDARD.decode(&kp.public_key).unwrap().try_into().unwrap();
        let cookie = cookie_for_reg_pk(&reg_pk_bytes);
        signed_pairing(cookie, epoch, kp)
    }

    /// Sign an ARBITRARY (cookie, key) pairing — used only to build the
    /// mispaired claims the binding is there to refuse.
    fn signed_pairing(
        cookie: [u8; COOKIE_LEN],
        epoch: u64,
        kp: &veil_crypto::GeneratedKeyPair,
    ) -> (CircuitRegisterPayload, [u8; REG_PK_LEN]) {
        let reg_pk_bytes: [u8; REG_PK_LEN] =
            STANDARD.decode(&kp.public_key).unwrap().try_into().unwrap();
        let msg = CircuitRegisterPayload::signing_bytes(&cookie, &reg_pk_bytes, epoch);
        let sig = sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &msg,
        )
        .unwrap();
        (
            CircuitRegisterPayload {
                cookie,
                reg_pk: reg_pk_bytes,
                epoch,
                signature: sig,
            },
            reg_pk_bytes,
        )
    }

    /// Shim for tests that don't care about epoch: epoch = 1, fresh key.
    fn signed() -> (CircuitRegisterPayload, [u8; REG_PK_LEN]) {
        signed_at(1)
    }

    fn a_circuit() -> Arc<CircuitState> {
        circuit_from(&CircuitTable::new(), [0xEE; 32], 1)
    }

    /// A terminus circuit installed on `prev_link` under `cid`. The table is
    /// passed in so several circuits can share one (ids must not collide).
    fn circuit_from(t: &CircuitTable, prev_link: [u8; 32], cid: u32) -> Arc<CircuitState> {
        t.install(
            &CircuitInstall {
                circuit_id_in: cid,
                circuit_id_out: 0,
                circuit_key: [9u8; 32],
            },
            prev_link,
            None,
            0,
        )
        .unwrap()
    }

    #[test]
    fn payload_roundtrip_and_verify() {
        let (p, _) = signed();
        assert!(p.verify());
        let d = CircuitRegisterPayload::decode(&p.encode()).unwrap();
        assert_eq!(d, p);
        assert!(d.verify());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // Exact-length: the registration is the exact innermost circuit-setup
        // payload (unpadded), so trailing bytes after the signature are wire
        // malleability with no legitimate producer and must be rejected.
        let (p, _) = signed();
        let mut enc = p.encode();
        assert!(CircuitRegisterPayload::decode(&enc).is_some());
        enc.push(0x00); // trailing garbage
        assert!(
            CircuitRegisterPayload::decode(&enc).is_none(),
            "trailing bytes after the signature must be rejected"
        );
    }

    #[test]
    fn tampered_signature_or_cookie_fails_verify() {
        let (mut p, _) = signed();
        p.cookie[0] ^= 0xFF; // signature no longer covers this cookie
        assert!(!p.verify());
    }

    #[test]
    fn register_then_lookup() {
        let reg = CircuitRendezvousRegistry::new();
        let (p, _) = signed();
        let cookie = p.cookie;
        reg.register(&p, a_circuit(), 1000).unwrap();
        assert!(reg.lookup(&cookie).is_some());
        assert!(reg.lookup(&[0x00; COOKIE_LEN]).is_none());
    }

    #[test]
    fn rejects_bad_signature() {
        let reg = CircuitRendezvousRegistry::new();
        let (mut p, _) = signed();
        p.signature[0] ^= 0xFF;
        assert_eq!(
            reg.register(&p, a_circuit(), 0),
            Err(RegisterError::BadSignature)
        );
        assert!(reg.is_empty());
    }

    #[test]
    fn first_wins_blocks_squatter_but_allows_refresh() {
        let reg = CircuitRendezvousRegistry::new();
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let cookie =
            cookie_for_reg_pk(&STANDARD.decode(&kp.public_key).unwrap().try_into().unwrap());
        let (legit, _) = signed_with(10, &kp);
        reg.register(&legit, a_circuit(), 0).unwrap();

        // Squatter: same cookie, DIFFERENT reg_pk. It is now refused one step
        // EARLIER than first-wins — the claim is malformed on its face, so the
        // squatter loses even against an empty registry (the restart / TTL-reap
        // window that first-wins never covered).
        let (squat, _) =
            signed_pairing(cookie, 999, &generate_keypair(SignatureAlgorithm::Ed25519));
        assert_eq!(
            reg.register(&squat, a_circuit(), 0),
            Err(RegisterError::CookieNotBoundToKey)
        );
        let empty = CircuitRendezvousRegistry::new();
        assert_eq!(
            empty.register(&squat, a_circuit(), 0),
            Err(RegisterError::CookieNotBoundToKey),
            "an unheld cookie must not be claimable by a foreign key either",
        );

        // Legit owner refreshes (same reg_pk, FRESHER epoch) → ok.
        let (refresh, _) = signed_with(11, &kp);
        reg.register(&refresh, a_circuit(), 100).unwrap();
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn replayed_registration_is_rejected_m2() {
        // diff-audit M2: a captured registration cannot be replayed to re-bind
        // the cookie to a different circuit — its epoch is not strictly fresher.
        let reg = CircuitRendezvousRegistry::new();
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let (first, _) = signed_with(100, &kp);
        reg.register(&first, a_circuit(), 0).unwrap();

        // Replay of the SAME payload (same epoch) → rejected.
        assert_eq!(
            reg.register(&first, a_circuit(), 1),
            Err(RegisterError::StaleEpoch)
        );
        // An OLDER epoch (same key) → rejected.
        let (older, _) = signed_with(50, &kp);
        assert_eq!(
            reg.register(&older, a_circuit(), 1),
            Err(RegisterError::StaleEpoch)
        );
        // A strictly-fresher epoch from the legitimate holder → accepted.
        let (fresher, _) = signed_with(101, &kp);
        reg.register(&fresher, a_circuit(), 2).unwrap();
    }

    /// One neighbour must not out-hold its quota by cycling table slots.
    ///
    /// Reclaim frees the table slot and deliberately keeps the cookie bound,
    /// so the state survives in this registry for the full TTL. Without a
    /// ceiling here, a link that serves its own circuits recycles its 64 table
    /// slots every 30 s and holds ~1280 states against a quota of 64. The
    /// ceiling has to be measured on the ORIGINATING LINK — the registry is
    /// cookie-keyed and never learns who the receiver is — and `prev_link` is
    /// the one thing it does know, being this relay's immediate neighbour.
    #[test]
    fn one_link_cannot_hold_more_than_its_ceiling() {
        const CAP: usize = 4;
        let reg = CircuitRendezvousRegistry::with_link_cap(1000, CAP, 600);
        let table = CircuitTable::new();
        let link = [0xA1u8; 32];

        // Every registration is a fresh key (hence a fresh cookie) on the same
        // neighbour — a peer minting reply circuits as fast as it likes.
        for i in 0..(CAP as u32 * 5) {
            let (p, _) = signed_at(1);
            reg.register(&p, circuit_from(&table, link, i + 1), i as u64)
                .expect("a new cookie is admitted, never refused");
        }
        assert_eq!(
            reg.link_occupancy(&link),
            CAP,
            "the neighbour's share is bounded no matter how many it mints"
        );
        assert_eq!(reg.len(), CAP, "and nothing leaked into the global count");
    }

    /// The ceiling is per neighbour, not a global one wearing a disguise: a
    /// second link's bindings must be untouched by the first filling up.
    #[test]
    fn the_ceiling_does_not_reach_across_links() {
        const CAP: usize = 3;
        let reg = CircuitRendezvousRegistry::with_link_cap(1000, CAP, 600);
        let table = CircuitTable::new();
        let quiet = [0xB2u8; 32];
        let noisy = [0xC3u8; 32];

        let (p, _) = signed_at(1);
        let quiet_cookie = p.cookie;
        reg.register(&p, circuit_from(&table, quiet, 1), 0).unwrap();

        for i in 0..(CAP as u32 * 3) {
            let (p, _) = signed_at(1);
            reg.register(&p, circuit_from(&table, noisy, 100 + i), i as u64)
                .unwrap();
        }

        assert!(
            reg.lookup(&quiet_cookie).is_some(),
            "a busy neighbour must not evict a quiet one's binding"
        );
        assert_eq!(reg.link_occupancy(&noisy), CAP);
        assert_eq!(reg.link_occupancy(&quiet), 1);
    }

    /// Which binding goes matters: the one whose reply finished longest ago,
    /// not whichever the hash map happened to hand over. A binding that has
    /// never served — a hosted service waiting for its first introduce — is
    /// the last thing to drop while any served one remains.
    #[test]
    fn eviction_takes_the_reply_that_finished_longest_ago() {
        const CAP: usize = 3;
        let reg = CircuitRendezvousRegistry::with_link_cap(1000, CAP, 600);
        let table = CircuitTable::new();
        let link = [0xD4u8; 32];

        // Three bindings: one never served (a hosted service), two served —
        // one long ago, one just now.
        let (unserved, _) = signed_at(1);
        reg.register(&unserved, circuit_from(&table, link, 1), 0)
            .unwrap();

        let (stale, _) = signed_at(1);
        let stale_circuit = circuit_from(&table, link, 2);
        stale_circuit.mark_served(100);
        reg.register(&stale, stale_circuit, 0).unwrap();

        let (recent, _) = signed_at(1);
        let recent_circuit = circuit_from(&table, link, 3);
        recent_circuit.mark_served(900);
        reg.register(&recent, recent_circuit, 0).unwrap();

        // A fourth arrives at the ceiling.
        let (fourth, _) = signed_at(1);
        reg.register(&fourth, circuit_from(&table, link, 4), 1000)
            .unwrap();

        assert!(
            reg.lookup(&stale.cookie).is_none(),
            "the reply that finished longest ago is the one that goes"
        );
        assert!(
            reg.lookup(&recent.cookie).is_some(),
            "a reply that just went out may still owe a slice"
        );
        assert!(
            reg.lookup(&unserved.cookie).is_some(),
            "a binding that never served has no finished reply to judge it by"
        );
        assert!(reg.lookup(&fourth.cookie).is_some());
    }

    /// The per-link index has to empty with the map. A bucket still holding
    /// cookies that no longer resolve would count phantoms against the
    /// ceiling, and the link would be evicting live bindings to make room for
    /// entries that are already gone. Both removal paths are checked because
    /// each is a separate chance to drift.
    #[test]
    fn removing_a_binding_empties_its_place_in_the_link_index() {
        let reg = CircuitRendezvousRegistry::with_link_cap(1000, 8, 300);
        let table = CircuitTable::new();
        let link = [0xE5u8; 32];

        let (torn_down, _) = signed_at(1);
        reg.register(&torn_down, circuit_from(&table, link, 1), 0)
            .unwrap();
        let (expires, _) = signed_at(1);
        reg.register(&expires, circuit_from(&table, link, 2), 0)
            .unwrap();
        assert_eq!(reg.link_occupancy(&link), 2);

        reg.remove(&torn_down.cookie); // teardown path
        assert_eq!(reg.link_occupancy(&link), 1);

        assert_eq!(reg.gc(300), 1); // TTL path
        assert_eq!(
            reg.link_occupancy(&link),
            0,
            "the link's bucket must go with its last binding"
        );
        assert_eq!(reg.len(), 0);
    }

    /// A service rebuilds its circuit down a fresh path every 150 s and
    /// re-registers the SAME cookie, because the cookie follows `reg_pk` and
    /// not the route — so a refresh routinely arrives over a different
    /// neighbour. The link index has to follow it. Left behind, one link would
    /// be charged for state another link holds, and both counts would stop
    /// describing anything.
    #[test]
    fn a_refresh_over_a_new_path_moves_the_binding_between_links() {
        let reg = CircuitRendezvousRegistry::with_link_cap(1000, 8, 600);
        let table = CircuitTable::new();
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];

        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let (initial, _) = signed_with(10, &kp);
        reg.register(&initial, circuit_from(&table, first, 1), 0)
            .unwrap();
        assert_eq!(reg.link_occupancy(&first), 1);

        // Same key, same cookie, fresher epoch, new neighbour.
        let (rebuilt, _) = signed_with(11, &kp);
        reg.register(&rebuilt, circuit_from(&table, second, 2), 150)
            .unwrap();

        assert_eq!(reg.len(), 1, "a refresh replaces, it does not add");
        assert_eq!(
            reg.link_occupancy(&first),
            0,
            "the old neighbour must stop being charged for it"
        );
        assert_eq!(reg.link_occupancy(&second), 1);
    }

    #[test]
    fn cap_and_gc() {
        let reg = CircuitRendezvousRegistry::with_params(1, 300);
        let (p1, _) = signed();
        reg.register(&p1, a_circuit(), 0).unwrap();
        let (p2, _) = signed();
        assert_eq!(reg.register(&p2, a_circuit(), 0), Err(RegisterError::Full));
        // GC frees the first after TTL, making room.
        assert_eq!(reg.gc(300), 1);
        reg.register(&p2, a_circuit(), 300).unwrap();
        assert_eq!(reg.len(), 1);
    }
}
