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

/// Default cap on circuit-backed subscriptions at one relay (mirrors the
/// rendezvous registry's `MAX_REGISTRATIONS`).
pub const MAX_CIRCUIT_SUBSCRIPTIONS: usize = 10_000;
/// Default subscription TTL — refreshed on re-register.
pub const DEFAULT_SUBSCRIPTION_TTL_SECS: u64 = 600;

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
}

struct Subscription {
    reg_pk: [u8; REG_PK_LEN],
    circuit: Arc<CircuitState>,
    registered_unix: u64,
    /// Last accepted registration epoch (M2 replay guard).
    epoch: u64,
}

/// Bounded, cookie-keyed registry of circuit-backed rendezvous subscriptions.
/// First-registration-wins per cookie; refresh allowed for the same `reg_pk`.
pub struct CircuitRendezvousRegistry {
    inner: Mutex<HashMap<[u8; COOKIE_LEN], Subscription>>,
    cap: usize,
    ttl_secs: u64,
}

impl CircuitRendezvousRegistry {
    pub fn new() -> Self {
        Self::with_params(MAX_CIRCUIT_SUBSCRIPTIONS, DEFAULT_SUBSCRIPTION_TTL_SECS)
    }

    pub fn with_params(cap: usize, ttl_secs: u64) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            cap: cap.max(1),
            ttl_secs,
        }
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
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match g.get(&payload.cookie) {
            Some(existing) if existing.reg_pk != payload.reg_pk => {
                return Err(RegisterError::CookieClaimed);
            }
            // Same reg_pk → refresh, but ONLY with a strictly-fresher epoch (M2).
            // A replayed payload carries epoch ≤ the recorded one and is rejected
            // before it can re-bind the cookie to a different circuit.
            Some(existing) if payload.epoch <= existing.epoch => {
                return Err(RegisterError::StaleEpoch);
            }
            Some(_) => {}
            None => {
                if g.len() >= self.cap {
                    return Err(RegisterError::Full);
                }
            }
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

    /// Resolve a cookie to its circuit (for forwarding an introduce down it).
    pub fn lookup(&self, cookie: &[u8; COOKIE_LEN]) -> Option<Arc<CircuitState>> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.get(cookie).map(|s| Arc::clone(&s.circuit))
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
        let before = g.len();
        g.retain(|_, s| now_unix.saturating_sub(s.registered_unix) < ttl);
        before - g.len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
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

    /// Make a signed registration for `cookie` under a fresh Ed25519 key at
    /// `epoch`; return (payload, reg_pk_bytes).
    fn signed_at(
        cookie: [u8; COOKIE_LEN],
        epoch: u64,
    ) -> (CircuitRegisterPayload, [u8; REG_PK_LEN]) {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        signed_with(cookie, epoch, &kp)
    }

    /// Sign for `cookie`/`epoch` under a SPECIFIC keypair (so a refresh can reuse
    /// the same reg_pk with a fresher epoch, as the real service does).
    fn signed_with(
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

    /// Back-compat shim for tests that don't care about epoch: epoch = 1.
    fn signed(cookie: [u8; COOKIE_LEN]) -> (CircuitRegisterPayload, [u8; REG_PK_LEN]) {
        signed_at(cookie, 1)
    }

    fn a_circuit() -> Arc<CircuitState> {
        let t = CircuitTable::new();
        t.install(
            &CircuitInstall {
                circuit_id_in: 1,
                circuit_id_out: 0,
                circuit_key: [9u8; 32],
            },
            [0xEE; 32],
            None,
            0,
        )
        .unwrap()
    }

    #[test]
    fn payload_roundtrip_and_verify() {
        let (p, _) = signed([0xC1; COOKIE_LEN]);
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
        let (p, _) = signed([0xC2; COOKIE_LEN]);
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
        let (mut p, _) = signed([0x01; COOKIE_LEN]);
        p.cookie[0] ^= 0xFF; // signature no longer covers this cookie
        assert!(!p.verify());
    }

    #[test]
    fn register_then_lookup() {
        let reg = CircuitRendezvousRegistry::new();
        let (p, _) = signed([0xAB; COOKIE_LEN]);
        reg.register(&p, a_circuit(), 1000).unwrap();
        assert!(reg.lookup(&[0xAB; COOKIE_LEN]).is_some());
        assert!(reg.lookup(&[0x00; COOKIE_LEN]).is_none());
    }

    #[test]
    fn rejects_bad_signature() {
        let reg = CircuitRendezvousRegistry::new();
        let (mut p, _) = signed([0x02; COOKIE_LEN]);
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
        let cookie = [0x07; COOKIE_LEN];
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let (legit, _) = signed_with(cookie, 10, &kp);
        reg.register(&legit, a_circuit(), 0).unwrap();

        // Squatter: same cookie, DIFFERENT reg_pk → rejected.
        let (squat, _) = signed_at(cookie, 999);
        assert_eq!(
            reg.register(&squat, a_circuit(), 0),
            Err(RegisterError::CookieClaimed)
        );

        // Legit owner refreshes (same reg_pk, FRESHER epoch) → ok.
        let (refresh, _) = signed_with(cookie, 11, &kp);
        reg.register(&refresh, a_circuit(), 100).unwrap();
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn replayed_registration_is_rejected_m2() {
        // diff-audit M2: a captured registration cannot be replayed to re-bind
        // the cookie to a different circuit — its epoch is not strictly fresher.
        let reg = CircuitRendezvousRegistry::new();
        let cookie = [0x55; COOKIE_LEN];
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let (first, _) = signed_with(cookie, 100, &kp);
        reg.register(&first, a_circuit(), 0).unwrap();

        // Replay of the SAME payload (same epoch) → rejected.
        assert_eq!(
            reg.register(&first, a_circuit(), 1),
            Err(RegisterError::StaleEpoch)
        );
        // An OLDER epoch (same key) → rejected.
        let (older, _) = signed_with(cookie, 50, &kp);
        assert_eq!(
            reg.register(&older, a_circuit(), 1),
            Err(RegisterError::StaleEpoch)
        );
        // A strictly-fresher epoch from the legitimate holder → accepted.
        let (fresher, _) = signed_with(cookie, 101, &kp);
        reg.register(&fresher, a_circuit(), 2).unwrap();
    }

    #[test]
    fn cap_and_gc() {
        let reg = CircuitRendezvousRegistry::with_params(1, 300);
        let (p1, _) = signed([0x10; COOKIE_LEN]);
        reg.register(&p1, a_circuit(), 0).unwrap();
        let (p2, _) = signed([0x11; COOKIE_LEN]);
        assert_eq!(reg.register(&p2, a_circuit(), 0), Err(RegisterError::Full));
        // GC frees the first after TTL, making room.
        assert_eq!(reg.gc(300), 1);
        reg.register(&p2, a_circuit(), 300).unwrap();
        assert_eq!(reg.len(), 1);
    }
}
