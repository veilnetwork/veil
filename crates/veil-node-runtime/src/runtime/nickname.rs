//! Nickname claim / resolve on the running node — brick 3b of the
//! nicknames epic (design: xVeil `doc/NICKNAMES-DESIGN.md`).
//!
//! A nickname is a `NicknameRecord` ("NK") DHT record owned by the SOVEREIGN
//! identity; ownership is contestable by cumulative PoW weight (the
//! dispatcher STORE gate — `nickname_store_gate` — enforces
//! replace-on-heavier at every holder). This module is the node-side glue:
//!
//! * [`NodeServices::nickname_resolve`] — replicated fetch by
//!   `nickname_dht_key(name)`, verify every replica, return the HEAVIEST
//!   valid record (displacement semantics, not majority quorum), and
//!   mirror-repair the local shard through the same replace-on-heavier
//!   decision the STORE gate applies.
//! * [`NodeServices::nickname_claim`] — sign an already-mined seed set with
//!   the sovereign MASTER ed25519 key (same owner-binding rule as anycast
//!   owner records: `blake3(owner_pk) == node_id`, standalone only), run an
//!   availability pre-check against the current network owner, then
//!   store_local + fan out to the K-closest via the recursive STORE plane
//!   (`replicate_dht_value` — the same plane the sovereign identity
//!   publisher uses).
//!
//! Mining itself never happens here — the host mines in bounded chunks off
//! the UI isolate (`veil_nickname_mine` FFI) and hands the finished seed set
//! to [`NodeServices::nickname_claim`]. Anonymous identities must never call
//! claim/resolve-publish paths (a public name is a linkability signal); the
//! app enforces that above the FFI, and relays simply treat records by their
//! own validity.
//!
//! Auto-renewal: nickname records are re-fanned by the periodic
//! `dht_republish` task (the "NK" arm of `is_self_authenticating_dht_value`),
//! so a claimed name stays alive at the K-closest while the node runs.
//! Weight top-up is app-driven: mine more seeds, call claim again (the
//! heavier record displaces the owner's own lighter one everywhere).

use std::time::Duration;

use veil_crypto::nickname::{
    NicknameRecord, StoreDecision, nickname_dht_key, nickname_store_decision, normalize_name,
};

use super::NodeServices;

/// Replicas requested on a resolve — mirrors the identity resolver's
/// `resolver_max_replicas` default. Displacement picks the heaviest valid
/// record among them (NOT a byte-equality quorum: any single heavier valid
/// record wins by design).
const RESOLVE_REPLICAS: usize = 5;

impl NodeServices {
    /// Resolve the current owner record for `name` (leading `@` accepted).
    ///
    /// Fetches up to [`RESOLVE_REPLICAS`] replicas (recursive FIND_VALUE
    /// quorum; a validated local mirror counts as ONE replica and never
    /// short-circuits the walk — contested fetch), verifies each
    /// (`NicknameRecord::verify`: owner binding + signature + recomputed
    /// cumulative PoW + length floor + name match), and returns the record
    /// that displaces all others — or `None` when the name is free.
    ///
    /// The winner is mirrored into the local DHT shard through the same
    /// replace-on-heavier decision the STORE gate applies, so a poisoned or
    /// stale local copy self-repairs on resolve (cf. the identity resolver's
    /// post-quorum `store_local`).
    pub async fn nickname_resolve(
        &self,
        name: &str,
        timeout: Duration,
    ) -> Result<Option<NicknameRecord>, String> {
        let norm = normalize_name(name.trim_start_matches('@'))
            .ok_or_else(|| "not a valid nickname (3..=32 chars of [a-z0-9_])".to_string())?;
        let key = nickname_dht_key(&norm).expect("normalized name always derives a key");
        let is_valid = |bytes: &[u8]| -> bool {
            NicknameRecord::from_bytes(bytes).is_some_and(|r| r.name == norm && r.verify().is_ok())
        };
        // Contested fetch: a valid LOCAL mirror must not short-circuit the
        // remote quorum — a stale lighter record still verifies, and the
        // whole point of re-resolving is spotting a heavier displacement.
        let replicas = self
            .dht_get_replicated_contested(key, RESOLVE_REPLICAS, timeout, is_valid)
            .await;
        let mut best: Option<NicknameRecord> = None;
        for bytes in &replicas {
            let Some(rec) = NicknameRecord::from_bytes(bytes) else {
                continue;
            };
            if rec.name != norm || rec.verify().is_err() {
                continue;
            }
            best = Some(match best.take() {
                None => rec,
                Some(cur) if rec.displaces(&cur) => rec,
                Some(cur) => cur,
            });
        }
        if let Some(rec) = &best {
            let bytes = rec.to_bytes();
            if matches!(
                nickname_store_decision(self.dht.get_local(&key).as_deref(), &bytes),
                StoreDecision::Accept
            ) {
                self.dht.store_local(key, bytes);
            }
        }
        Ok(best)
    }

    /// Sign a mined seed set with the sovereign MASTER key and publish the
    /// nickname record to the DHT. Returns the record that now represents
    /// this node's claim (the freshly published one, or the already-heavier
    /// record this owner published earlier — idempotent republish).
    ///
    /// Errors (all pre-publish, so a failed claim never emits network
    /// traffic beyond the resolve pre-check):
    /// * name not normalizable / seed set invalid / weight under the
    ///   per-length floor (`UnderLengthFloor` — mine more first);
    /// * no sovereign identity, multi-device subkey (master required for the
    ///   `blake3(owner_pk) == node_id` owner binding — same rule as anycast
    ///   owner records), or a non-ed25519 sovereign;
    /// * the name is owned by a FOREIGN record this seed set cannot
    ///   displace — the error carries the weight to beat.
    pub async fn nickname_claim(
        &self,
        name: &str,
        seeds: Vec<[u8; 32]>,
        timeout: Duration,
    ) -> Result<NicknameRecord, String> {
        let norm = normalize_name(name.trim_start_matches('@'))
            .ok_or_else(|| "not a valid nickname (3..=32 chars of [a-z0-9_])".to_string())?;
        let sov = self
            .identity
            .sovereign_identity
            .get()
            .ok_or("node has no sovereign identity — nicknames require one")?;
        if !sov.is_standalone() {
            return Err(
                "nickname claims require the sovereign MASTER key; this device holds a \
                 multi-device subkey"
                    .to_string(),
            );
        }
        let sk = sov
            .ed25519_signing_key()
            .ok_or("sovereign identity is not ed25519 — nickname v1 cannot sign")?;
        let owner: [u8; 32] = *blake3::hash(&sk.verifying_key().to_bytes()).as_bytes();
        if owner != self.local_node_id {
            // Owner binding sanity: the published record must resolve to the
            // node id contacts actually use for this identity.
            return Err(
                "sovereign key does not hash to this node id — refusing to claim".to_string(),
            );
        }
        let issued_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let rec = NicknameRecord::sign(&norm, sk, owner, seeds, issued_at_unix)
            .ok_or("seed set invalid (duplicates or oversized)")?;
        rec.verify()
            .map_err(|e| format!("record not publishable: {e:?}"))?;

        // Availability pre-check: if a FOREIGN record this one cannot
        // displace already owns the name, every honest holder would reject
        // the STORE — surface the weight to beat instead of publishing.
        if let Some(current) = self.nickname_resolve(&norm, timeout).await?
            && !rec.displaces(&current)
        {
            if current.owner_node_id == owner {
                // Already ours with at least as much weight — idempotent.
                return Ok(current);
            }
            return Err(format!(
                "name is taken with cumulative weight {}; this seed set proves only {} — \
                 mine strictly more",
                current.weight, rec.weight,
            ));
        }

        let key = nickname_dht_key(&norm).expect("normalized name always derives a key");
        let bytes = rec.to_bytes();
        // Local shard first, through the same replace-on-heavier decision the
        // STORE gate applies (never clobber a heavier record we hold).
        if matches!(
            nickname_store_decision(self.dht.get_local(&key).as_deref(), &bytes),
            StoreDecision::Accept
        ) {
            self.dht.store_local(key, bytes.clone());
        }
        // Fan out to the K-closest over the recursive STORE plane — the same
        // plane the sovereign identity publisher uses; receivers re-verify
        // and re-apply displacement in `nickname_store_gate`. Periodic
        // re-publish (auto-renewal) is the dht_republish "NK" arm.
        crate::identity_local::publisher_dht::replicate_dht_value(
            &self.dht,
            &self.session_tx_registry,
            self.local_node_id,
            key,
            bytes,
        );
        Ok(rec)
    }
}
