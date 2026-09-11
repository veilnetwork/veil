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
//!   the IDENTITY's master key, whatever its algorithm (owner binding:
//!   `blake3(master_pubkey) == node_id`, which is the identity's address on
//!   every device it has), run an
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
use veil_types::SignatureAlgorithm;

use super::NodeServices;

/// The identity's MASTER key, offered by the caller for the moment of a claim.
///
/// It is a parameter and not something the node holds because on every device
/// but a standalone one the master secret is not in this process: it lives in
/// the host's encrypted credential (the recovery certificate / sovereign
/// bundle), which the host opens for the claim and closes again.
///
/// The secret itself never crosses this boundary — only the public key and a
/// closure that signs. So the node cannot log, persist or leak a master key it
/// was never given, and a caller whose key lives behind a handle (or one day a
/// hardware token) satisfies this without ever materialising bytes.
pub struct NicknameMasterKey {
    pub algo: SignatureAlgorithm,
    /// The master PUBLIC key — the one the identity's `node_id` derives from.
    pub public_key: Vec<u8>,
    /// Signs the record's canonical bytes with the matching master secret.
    pub sign: NicknameMasterSignFn,
}

/// Produces the master's signature over the bytes it is handed, or `None` when
/// the key it speaks for cannot sign them.
///
/// `FnOnce` because a claim asks exactly once: the caller is free to close the
/// credential the moment it returns.
pub type NicknameMasterSignFn = Box<dyn FnOnce(&[u8]) -> Option<Vec<u8>> + Send>;

/// Replicas requested on a resolve — mirrors the identity resolver's
/// `resolver_max_replicas` default. Displacement picks the heaviest valid
/// record among them (NOT a byte-equality quorum: any single heavier valid
/// record wins by design).
const RESOLVE_REPLICAS: usize = 5;

impl NodeServices {
    /// The identity this node answers for, as a node id — the owner a
    /// nickname belongs to.
    ///
    /// `None` when the node has no sovereign identity, which is also when it
    /// cannot own a name. Distinct from `local_node_id`, which names the
    /// DEVICE and differs on every device but a standalone one.
    pub fn sovereign_node_id(&self) -> Option<[u8; 32]> {
        self.identity
            .sovereign_identity
            .get()
            .map(|sov| *sov.node_id())
    }

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

    /// Sign a mined seed set with the IDENTITY's master key and publish the
    /// nickname record to the DHT. Returns the record that now represents
    /// this identity's claim (the freshly published one, or the
    /// already-heavier record this owner published earlier — idempotent
    /// republish).
    ///
    /// The name belongs to the identity, not to the device that publishes it:
    /// the record's owner is `document.master_pubkey`, and the identity's
    /// address is `blake3` of exactly that key. So any device of the identity
    /// can publish, refresh or top up the same name, and losing a device
    /// loses nothing.
    ///
    /// `master` carries that key. It is a parameter because on every device
    /// but a standalone one the master secret is not in this process — the
    /// host unlocks its encrypted credential for the moment of the claim.
    /// `None` means "the node already holds it", which is true exactly when
    /// the identity is standalone (master == this device's key); asking for it
    /// anyway is allowed and is checked the same way.
    ///
    /// Errors (all pre-publish, so a failed claim never emits network
    /// traffic beyond the resolve pre-check):
    /// * name not normalizable / seed set invalid / weight under the
    ///   per-length floor (`UnderLengthFloor` — mine more first);
    /// * no sovereign identity, or a master key that is not this identity's
    ///   (`blake3(master_pubkey) != node_id`), or no master supplied on a
    ///   device that does not hold one;
    /// * the name is owned by a FOREIGN record this seed set cannot
    ///   displace — the error carries the weight to beat.
    pub async fn nickname_claim(
        &self,
        name: &str,
        seeds: Vec<[u8; 32]>,
        timeout: Duration,
        master: Option<NicknameMasterKey>,
    ) -> Result<NicknameRecord, String> {
        let norm = normalize_name(name.trim_start_matches('@'))
            .ok_or_else(|| "not a valid nickname (3..=32 chars of [a-z0-9_])".to_string())?;
        let sov = self
            .identity
            .sovereign_identity
            .get()
            .ok_or("node has no sovereign identity — nicknames require one")?;
        // The identity's address — the same value on every device it has.
        // NOT `self.local_node_id`, which is this device's transport id and
        // differs on every device but a standalone one.
        let owner: [u8; 32] = *sov.node_id();
        let issued_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let rec = match master {
            Some(master) => {
                // Refuse a key that is not THIS identity's master before it
                // signs anything: a record under someone else's address is
                // unpublishable, and building one would waste the claim.
                if *blake3::hash(&master.public_key).as_bytes() != owner {
                    return Err(
                        "the supplied master key is not this identity's — its hash is not the \
                         identity's node id"
                            .to_string(),
                    );
                }
                NicknameRecord::sign_with_master(
                    &norm,
                    master.algo,
                    master.public_key,
                    owner,
                    seeds,
                    issued_at_unix,
                    master.sign,
                )
                .ok_or("seed set invalid (duplicates or oversized), or the master could not sign")?
            }
            None => {
                // No master supplied: the only identity whose master is
                // already in this process is a standalone one, where the
                // device key IS the master. Say which of the two is missing
                // rather than the old message, which blamed "multi-device"
                // for what is really "the master lives elsewhere".
                let sk = sov.ed25519_signing_key().ok_or(
                    "no master key supplied, and this identity's master is not a bare ed25519 \
                     key this node can use — unlock the identity's credential and pass it",
                )?;
                if *blake3::hash(&sk.verifying_key().to_bytes()).as_bytes() != owner {
                    return Err(
                        "no master key supplied: this device holds a subkey, not the identity's \
                         master — unlock the identity's credential and pass it"
                            .to_string(),
                    );
                }
                NicknameRecord::sign(&norm, sk, owner, seeds, issued_at_unix)
                    .ok_or("seed set invalid (duplicates or oversized)")?
            }
        };
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

#[cfg(test)]
mod tests {
    //! What the claim decides, checked where it is decided.
    //!
    //! The defect these guard was not in the record format but in the choice
    //! of owner: the claim used the DEVICE's id and refused anything that was
    //! not standalone. Both facts below are the ones that made the whole
    //! feature unreachable, so both are asserted directly rather than through
    //! a live node.

    use std::time::{SystemTime, UNIX_EPOCH};

    use veil_identity::sovereign::SovereignIdentity;
    use veil_identity::sovereign_flow::{
        CreateIdentityOptions, create_identity, save_standalone_identity_to_dir,
    };
    use veil_types::SignatureAlgorithm;
    use veil_util::sensitive_bytes::SensitiveBytesN;

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// An identity made through the master ceremony is NEVER standalone.
    ///
    /// `create_identity` mints the device subkey from `OsRng` and has the
    /// master certify it — for every algorithm, on the FIRST device, before
    /// any second device exists. A claim gated on `is_standalone()` therefore
    /// refused every such identity everywhere, which is the bug; and its
    /// device key is not what the name may be published under, which is why
    /// the owner has to come from the document.
    #[test]
    fn a_ceremony_identity_is_never_standalone_so_the_device_is_not_the_owner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir.path().to_path_buf(),
            save_encrypted_with_password: None,
            // The cheapest KDF the API allows: this fixture is about which
            // key the document names, not about Argon2.
            argon2_params_override: Some((8, 1, 1)),
            extra_entropy: None,
            instance_label: "test".to_string(),
            pow_difficulty: 0,
            issued_at_unix: now(),
            valid_until_unix: now() + 7 * 24 * 3600,
            algo: SignatureAlgorithm::Ed25519,
        })
        .expect("create_identity");

        let sov = SovereignIdentity::load_from_dir(dir.path()).expect("load");
        assert!(
            !sov.is_standalone(),
            "the ceremony mints a per-device subkey; if this is ever standalone \
             the fixture stopped exercising the case the claim was broken for"
        );

        // The owner a name belongs to is the identity's id, and it is NOT the
        // hash of the key this device signs with.
        let owner = *sov.node_id();
        assert_eq!(owner, out.document.node_id);
        let device_pk = &sov.document.identity_keys[sov.sig_key_idx as usize].pubkey;
        assert_ne!(
            *blake3::hash(device_pk).as_bytes(),
            owner,
            "device key hashes to the owner id — then this fixture cannot tell \
             the two apart and proves nothing"
        );
    }

    /// The claim must not reach for this DEVICE's id.
    ///
    /// A live claim needs a running node, so the decision itself is guarded
    /// structurally: `local_node_id` is the device, and using it as the owner
    /// is precisely the defect — it made the published name a device's, and
    /// made the pre-check refuse every identity whose master lives elsewhere.
    /// A future edit that reintroduces it reddens here.
    #[test]
    fn the_claim_never_takes_the_owner_from_this_device() {
        let src = include_str!("nickname.rs");
        let start = src
            .find("pub async fn nickname_claim(")
            .expect("nickname_claim is still here");
        // Up to the test module, so this reads the function and its callees
        // in the impl block, not the fixtures below.
        let end = src.find("#[cfg(test)]").unwrap_or(src.len());
        let body = &src[start..end];
        // `local_node_id` legitimately appears once more, as the ORIGIN of the
        // DHT fan-out — that really is this device. What must never happen is
        // the OWNER coming from it, so the guard is on lines that speak of
        // both, with comments excluded (a comment naming the trap is not the
        // trap).
        let offenders: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//"))
            .filter(|l| l.contains("local_node_id") && l.contains("owner"))
            .collect();
        assert!(
            offenders.is_empty(),
            "the claim derives or checks the OWNER from `local_node_id`: a \
             nickname belongs to the IDENTITY, so the owner comes from the \
             sovereign document. Using the device id publishes a name only \
             that device can hold:\n{offenders:#?}"
        );
        assert!(
            body.contains("let owner: [u8; 32] = *sov.node_id();"),
            "the claim no longer takes its owner from the sovereign document \
             — then this guard is watching nothing"
        );
    }

    /// The standalone case still works, and its owner is unchanged.
    ///
    /// This is the only identity that could ever have claimed a name, so its
    /// owner id must survive the change byte-for-byte — otherwise a name
    /// already held would silently become someone else's.
    #[test]
    fn a_standalone_identity_owns_under_the_same_id_as_before() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut seed: SensitiveBytesN<32> = SensitiveBytesN::new();
        seed.as_mut_array().copy_from_slice(&[5u8; 32]);
        save_standalone_identity_to_dir(dir.path(), &seed, now(), now() + 7 * 24 * 3600)
            .expect("standalone identity");

        let sov = SovereignIdentity::load_from_dir(dir.path()).expect("load");
        assert!(sov.is_standalone());

        let device_pk = &sov.document.identity_keys[sov.sig_key_idx as usize].pubkey;
        assert_eq!(
            *blake3::hash(device_pk).as_bytes(),
            *sov.node_id(),
            "standalone means the device key IS the master, so the owner id is \
             the one this device already published under"
        );
    }
}
