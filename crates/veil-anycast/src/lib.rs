//! Anycast service-address resolution.
//!
//! `AnycastService` lets a node:
//! **Advertise** itself as a provider of a named service (e.g. gateway
//! mailbox shard, bridge) by storing an `AnycastRecord` in the DHT under
//! the well-known key `BLAKE3("anycast:v1:" ‖ service_tag)`.
//! **Resolve** a service tag to the nearest N candidate `node_id`s, ranked
//! by the node's routing score.
//!
//! # Design
//! The DHT value at the anycast key is a concatenated list of
//! `AnycastRecord` entries (44 bytes each, magic "AC"). Each advertising
//! node merges its own record into the existing list before re-storing.
//! Nodes that are no longer reachable age out naturally when their TTL
//! causes the DHT entry to expire.
//!
//! # Security considerations — secure-by-default, with an opt-down discovery mode
//!
//! `AnycastRecord.score` is **peer-controlled**: a node can sign its own record
//! claiming `score = 0` to try to win anycast traffic for a service tag. The
//! default resolve policy rejects unsigned / unbound records outright; two
//! further shipped layers harden the opt-down `BestEffort` path; one honesty
//! gap remains deferred.
//!
//! ## Owner-signing (shipped)
//!
//! Records may carry an owner-binding signature (v2 wire format, magic "AD":
//! `signature` + `owner_pubkey` + `sig_key_idx`): [`AnycastRecord::sign`]
//! produces them and `AnycastRecord::verify_signature` validates them.
//! [`AnycastResolvePolicy::SignedOnly`] filters resolution to signature-verified
//! records; [`AnycastResolvePolicy::SignedBound`] additionally requires the
//! owner binding (`BLAKE3(owner_pubkey) == node_id`, key idx 0) — closing the
//! "claim to be the canonical provider of someone else's node_id" vector.
//! **`SignedBound` is the DEFAULT** (audit cycle-6 T2): unsigned and unbound
//! records are dropped unless an operator explicitly opts DOWN to `BestEffort`
//! (`[anycast] resolve_policy = "best_effort"`) for discovery-only deployments.
//! The two layers below harden that opt-down path.
//!
//! ## Resolver-XOR tie-break (shipped)
//!
//! [`AnycastService::resolve`] mixes XOR distance from the **resolver's**
//! node_id into the sort, so under `BestEffort` a `score = 0` sybil's payoff is
//! resolver-specific (no single sybil farm uniformly eclipses all resolvers).
//!
//! ## Reputation downweight (shipped)
//!
//! Owner-signing proves WHO published a record, not that its advertised
//! `score` is HONEST — a node can still sign its OWN record with `score = 0`.
//! [`AnycastService::resolve`] therefore stacks a resolver-local reputation
//! penalty on top of the peer-claimed score: [`AnycastReputation::record_failure`]
//! (invoked when a handed-out candidate later times out or misbehaves) makes
//! that node sort below honest tiers on subsequent resolves, via
//! [`reputation::AnycastReputation::score_offset`].
//!
//! ## What remains deferred
//!
//! **Quorum vote** — declining to trust a single first-time `score = 0` claim
//! before it has actually served, by cross-checking multiple DHT replicas —
//! is the remaining deferred half of the "Anycast signed records" row in
//! TASKS.md. Re-open trigger: a production trust-sensitive anycast consumer
//! materializes.
//!
//! ## Acceptable use
//!
//! Use `AnycastService` for:
//! **Best-effort service discovery** in environments where the worst-case
//! outcome of a sybil capture is "client falls back to a direct lookup
//! on the known service identity" — i.e. anycast is a latency-saving
//! hint, not a trust anchor.
//! **Sharded internal infrastructure** where the resolver and provider are
//! under the same operator's control (sybil attacks require attacker
//! control of the resolver's local DHT view, which they don't have).
//!
//! Do **NOT** use `AnycastService` for:
//! **Routing of trust-sensitive payloads** (identity-flagged, sovereign
//! E2E records, mailbox routing of personally-identifying material) —
//! resolve via signed records ([`veil_proto::identity_document`]
//! [`veil_proto::name_claim_v2`]) instead.
//! **Bootstrap discovery** of seed peers in untrusted environments —
//! use [`veil_proto::transport_hints`] (signed-by-issuer) or the
//! bootstrap-bundle path with pinned `BUILTIN_SEEDS`.
//! **First-time service-owner authentication under `BestEffort`** — when an
//! operator has opted DOWN to `BestEffort`, a sybil might be the first record
//! returned. The default `SignedBound` rejects unsigned / unbound records; the
//! residual under any policy is that even a correctly-signed first-time record's
//! `score` is unproven until reputation accrues. Keep the default `SignedBound`,
//! or resolve via sovereign records ([`veil_proto::identity_document`]).

use std::sync::Arc;

use base64::Engine as _;
use veil_dht::KademliaService;
use veil_proto::ProtoError;
use veil_proto::anycast::{
    AnycastList, AnycastRecord, AnycastRecordSig, AnycastResultPayload, MAX_ANYCAST_CANDIDATES,
};
use veil_types::SignatureAlgorithm;

pub mod reputation;
pub use reputation::AnycastReputation;

// ── Algo-generic v3 (Falcon-512 / hybrid) verify ──────────────────────────────

/// Whether a `sig_algo` wire-byte denotes Ed25519 (the v2 algorithm). Mirrors
/// the v2/v3 split in `veil-proto`: Ed25519 records carry a 32-byte pubkey +
/// 64-byte sig and are verified by `veil-proto` directly; every other algorithm
/// is verified here through `veil-crypto`.
fn sig_algo_is_ed25519(sig_algo: u8) -> bool {
    sig_algo == 0 || sig_algo == 1
}

/// Algo-generic anycast owner-signature verification. Ed25519 records use
/// `veil-proto`'s built-in Ed25519 path; Falcon-512 / hybrid records are
/// verified here via `veil-crypto` over the record's canonical bytes. The
/// resolver-side complement to v3 signing — it lets a resolver admit records
/// published by PQ-only sovereign identities.
pub fn verify_record_signature(record: &AnycastRecord) -> Result<(), ProtoError> {
    let Some(sig) = &record.signature else {
        return Err(ProtoError::Malformed(
            "anycast record is unsigned; cannot verify".to_string(),
        ));
    };
    if sig_algo_is_ed25519(sig.sig_algo) {
        return record.verify_signature();
    }
    let algo = SignatureAlgorithm::from_wire_byte(sig.sig_algo).ok_or_else(|| {
        ProtoError::Malformed(format!("anycast record: unknown sig_algo {}", sig.sig_algo))
    })?;
    let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&sig.owner_pubkey);
    veil_crypto::verify_message(algo, &pubkey_b64, &record.canonical_bytes(), &sig.signature)
        .map_err(|e| {
            ProtoError::Malformed(format!(
                "anycast record: {algo:?} signature verify failed: {e}"
            ))
        })
}

/// Algo-generic owner-binding: the record's signature must verify (any algo) AND
/// `BLAKE3(owner_pubkey) == node_id` with `sig_key_idx == 0` (the self-signed
/// master-key case). Closes, for v3 records, the same "valid signature under an
/// attacker key claiming a victim node_id" forgery that
/// [`AnycastRecord::verify_owner_binding`] closes for v2.
pub fn verify_record_owner_binding(record: &AnycastRecord) -> Result<(), ProtoError> {
    verify_record_signature(record)?;
    let sig = record.signature.as_ref().ok_or_else(|| {
        ProtoError::Malformed("anycast record: owner-binding requires a signature".to_string())
    })?;
    if sig.sig_key_idx != 0 {
        return Err(ProtoError::Malformed(format!(
            "anycast record: owner-binding only supports sig_key_idx == 0 (got {})",
            sig.sig_key_idx,
        )));
    }
    if blake3::hash(sig.owner_pubkey.as_slice()).as_bytes() != &record.node_id {
        return Err(ProtoError::Malformed(
            "anycast record: BLAKE3(owner_pubkey) != node_id — owner-binding forged".to_string(),
        ));
    }
    Ok(())
}

/// Detached signer: maps an anycast record's canonical bytes to a raw signature
/// of the owner's algorithm. The secret key stays captured inside the closure.
pub type AnycastSignFn = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// Algo-generic owner-signer for anycast advertisements. Lets the daemon
/// own-sign v2 (Ed25519) OR v3 (Falcon-512 / hybrid) records depending on the
/// identity's algorithm.
///
/// The private key never lives here — it is held inside the `sign` closure (e.g.
/// the sovereign `IdentitySigningKey`, which deliberately hides its SK), so this
/// type stays clonable and SK-free.
#[derive(Clone)]
pub struct AnycastSigner {
    /// Signature algorithm of the owner key.
    algo: SignatureAlgorithm,
    /// Owner verifying-key bytes — embedded as the record's `owner_pubkey`. MUST
    /// be the master pubkey for owner-binding (`BLAKE3(owner_pubkey) == node_id`)
    /// to hold under `SignedBound`.
    owner_pubkey: Vec<u8>,
    /// Subkey index (`0` = master). Owner-binding requires `0`.
    sig_key_idx: u8,
    /// Detached signer over the record's canonical bytes; returns the algo's raw
    /// signature. The SK stays encapsulated here.
    sign: AnycastSignFn,
}

impl AnycastSigner {
    /// Construct from a detached signer. `owner_pubkey` must be the master
    /// verifying key (so the BLAKE3 owner-binding holds); `sign(canonical)` must
    /// return a raw `algo` signature over the bytes it is given.
    pub fn new(
        algo: SignatureAlgorithm,
        owner_pubkey: Vec<u8>,
        sig_key_idx: u8,
        sign: AnycastSignFn,
    ) -> Self {
        Self {
            algo,
            owner_pubkey,
            sig_key_idx,
            sign,
        }
    }

    /// Build + sign an anycast record. Ed25519 serializes to the v2 wire,
    /// Falcon-512 / hybrid to v3 (chosen by `AnycastRecord::encode`).
    fn sign_record(
        &self,
        service_tag: [u8; 4],
        node_id: [u8; 32],
        score: u16,
        ttl: u32,
    ) -> Option<AnycastRecord> {
        let mut rec = AnycastRecord {
            service_tag,
            node_id,
            score,
            ttl,
            signature: Some(AnycastRecordSig {
                sig_algo: self.algo.wire_byte(),
                owner_pubkey: self.owner_pubkey.clone(),
                sig_key_idx: self.sig_key_idx,
                // placeholder; canonical_bytes() excludes the signature itself.
                signature: Vec::new(),
            }),
        };
        let canonical = rec.canonical_bytes();
        rec.signature.as_mut()?.signature = (self.sign)(&canonical);
        Some(rec)
    }
}

// ── Policy ────────────────────────────────────────────────────────────────────

/// Resolution policy applied to [`AnycastService::resolve`].
///
/// The IPC anycast handler routes through `resolve`, so this controls the
/// daemon-wide trust posture for anycast lookups regardless of any
/// service tags they target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnycastResolvePolicy {
    /// Accept ANY record (signed or unsigned).  A Sybil publishing an unsigned
    /// record with `score = 0` wins resolution if they're XOR-close to the
    /// resolver (mitigation: their identity remains a sybil cost).  Use this for
    /// legacy / discovery-only deployments.
    ///
    /// audit cycle-6 (T2): no longer the default — secure-by-default is now the
    /// strictest [`AnycastResolvePolicy::SignedBound`] (the network has no legacy unsigned-anycast
    /// deployments to preserve). Opt down to `BestEffort` explicitly for
    /// discovery-only use.
    BestEffort,
    /// Return ONLY candidates with a valid owner-signed Ed25519 record
    /// ([`AnycastRecord::verify_signature`]).  Unsigned (v1) records are
    /// silently dropped.  Use this for trust-sensitive routing (mailbox,
    /// payment, service-discovery in production).  Operators publishing
    /// service records MUST call [`AnycastService::advertise_signed`].
    ///
    /// **Caveat**: this policy verifies signature INTEGRITY only — a
    /// sybil can mint a valid signature under their own key while claiming
    /// another node's `node_id`, and `SignedOnly` will accept it.  For
    /// closing that gap use [`AnycastResolvePolicy::SignedBound`].
    SignedOnly,
    /// Return ONLY candidates with a valid signature AND a provable
    /// owner-binding (`BLAKE3(owner_pubkey) == node_id`, see.
    /// [`AnycastRecord::verify_owner_binding`]).  Records whose signature
    /// is valid but whose embedded pubkey does NOT hash to the claimed
    /// `node_id` are dropped — this closes the "forge the binding while
    /// signing with your own key" sybil vector that `SignedOnly` cannot
    /// detect.  Records using sovereign-identity subkeys
    /// (`sig_key_idx > 0`) are also dropped because verifying them
    /// requires an async DHT identity-document lookup, which doesn't fit
    /// the synchronous `resolve` API; callers that need subkey support
    /// should use `SignedOnly` + perform the identity-doc check themselves.
    ///
    /// Use this for trust-sensitive routing where the cost of accepting a
    /// spoofed-binding record is high (e.g. mailbox-routing of PII,
    /// payment-channel endpoint discovery, sovereign identity-bound
    /// service-discovery). audit cycle-6 (T2): this is now the DEFAULT.
    #[default]
    SignedBound,
}

// ── AnycastService ────────────────────────────────────────────────────────────

/// Anycast service-address resolution engine.
///
/// Clone-cheap: wraps an `Arc<KademliaService>` and an `Arc<AnycastReputation>`.
#[derive(Clone)]
pub struct AnycastService {
    dht: Arc<KademliaService>,
    local_node_id: [u8; 32],
    reputation: Arc<AnycastReputation>,
    policy: AnycastResolvePolicy,
    /// Audit batch 2026-05-25 phase O: optional sovereign signing key for
    /// auto-signing IPC-initiated advertisements.  When `Some`, [`Self::
    /// advertise`] writes a v2 signed record (with the supplied
    /// `sig_key_idx`); when `None`, advertise stays on the legacy
    /// unsigned v1 path for backwards-compatibility with peers that
    /// don't have sovereign identity wired.  Set via [`Self::with_
    /// signing_key`] at daemon startup once the sovereign master
    /// signing key is loaded.
    signing_key: Option<(Arc<ed25519_dalek::SigningKey>, u8)>,
    /// Algo-generic owner-signer (v2 Ed25519 / v3 Falcon-512 / hybrid). When
    /// `Some`, it takes precedence over `signing_key` so a PQ-only sovereign
    /// identity can own-sign its advertisements. Set via [`Self::with_signer`].
    generic_signer: Option<AnycastSigner>,
}

impl AnycastService {
    pub fn new(dht: Arc<KademliaService>, local_node_id: [u8; 32]) -> Self {
        Self {
            dht,
            local_node_id,
            reputation: Arc::new(AnycastReputation::new()),
            policy: AnycastResolvePolicy::default(),
            signing_key: None,
            generic_signer: None,
        }
    }

    /// Construct with a pre-existing reputation slice. Use when the caller
    /// wants to share one ledger across multiple `AnycastService` instances
    /// (e.g. testing, or a node that splits resolution between several
    /// service-tag families but wants unified penalty accounting).
    pub fn with_reputation(
        dht: Arc<KademliaService>,
        local_node_id: [u8; 32],
        reputation: Arc<AnycastReputation>,
    ) -> Self {
        Self {
            dht,
            local_node_id,
            reputation,
            policy: AnycastResolvePolicy::default(),
            signing_key: None,
            generic_signer: None,
        }
    }

    /// Replace the runtime resolution policy.  Builder-style; returns
    /// `Self` so callers can chain after `new` / `with_reputation`.
    /// Daemons construct AnycastService from config and chain this
    /// to match the operator's trust posture.
    #[must_use]
    pub fn with_policy(mut self, policy: AnycastResolvePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Audit batch 2026-05-25 phase O (cross-audit #3 closure): wire
    /// in the daemon's sovereign signing key so all subsequent
    /// `advertise()` calls — including those initiated through the
    /// IPC `AnycastAdvertise` opcode — publish v2 signed records.
    /// Closes the cross-audit gap where IPC apps published unsigned v1
    /// records that were silently dropped by resolvers running
    /// `SignedOnly` / `SignedBound` policy.
    ///
    /// `sig_key_idx = 0` is the master signing key per the
    /// `IdentityDocument` convention.  Caller must ensure
    /// `BLAKE3(signing_key.verifying_key.to_bytes()) ==
    /// local_node_id` for [`AnycastResolvePolicy::SignedBound`] to
    /// admit our own records.
    #[must_use]
    pub fn with_signing_key(
        mut self,
        signing_key: Arc<ed25519_dalek::SigningKey>,
        sig_key_idx: u8,
    ) -> Self {
        self.signing_key = Some((signing_key, sig_key_idx));
        self
    }

    /// Wire in an ALGO-GENERIC sovereign owner-signer so `advertise()` publishes
    /// owner-signed records regardless of the identity's algorithm — v2 for
    /// Ed25519, v3 for Falcon-512 / hybrid. Takes precedence over
    /// [`Self::with_signing_key`]. This is the path a PQ-only sovereign identity
    /// uses; without it such a node previously fell through to UNSIGNED v1
    /// records that `SignedBound` resolvers drop. Caller must ensure
    /// `BLAKE3(signer.public_key) == local_node_id` (sig_key_idx 0) for
    /// `SignedBound` to admit our own records.
    #[must_use]
    pub fn with_signer(mut self, signer: AnycastSigner) -> Self {
        self.generic_signer = Some(signer);
        self
    }

    /// Current resolve policy.  Surfaced for diagnostic /
    /// admin-debug commands.
    pub fn policy(&self) -> AnycastResolvePolicy {
        self.policy
    }

    /// Access the underlying reputation ledger. Callers that observe a
    /// failed resolve (timeout, conn-refused, wrong response) should
    /// invoke [`AnycastReputation::record_failure`] so that the offending
    /// node gets penalized on the next sort.
    pub fn reputation(&self) -> &Arc<AnycastReputation> {
        &self.reputation
    }

    /// Advertise this node as a provider of `service_tag` with the given
    /// routing `score` (lower = better, 0 = no information) and `ttl_secs`.
    ///
    /// Merges the local record into the existing DHT list and re-stores it.
    /// Call periodically (every `ttl_secs / 2`) to keep the entry fresh.
    pub fn advertise(&self, service_tag: [u8; 4], score: u16, ttl_secs: u32) {
        // Algo-generic owner-signer takes precedence (covers Ed25519 AND
        // Falcon-512 / hybrid) so a PQ-only sovereign identity own-signs its
        // records too (A1 audit fix). Falls back to the Ed25519-only signing
        // key, then to legacy unsigned v1.
        if let Some(signer) = &self.generic_signer {
            self.advertise_with_signer(service_tag, score, ttl_secs, signer);
            return;
        }
        // Audit batch 2026-05-25 phase O: auto-sign if the daemon
        // wired a signing key through `with_signing_key`.  IPC apps
        // calling `AnycastAdvertise` keep their existing wire format
        // (unsigned IPC payload), but the daemon-side advertise now
        // produces a signed v2 DHT record so that resolvers running
        // `SignedOnly` / `SignedBound` admit it.  Cross-audit #3.
        if let Some((sk, idx)) = &self.signing_key {
            self.advertise_signed(service_tag, score, ttl_secs, *idx, sk);
            return;
        }
        let key = AnycastRecord::dht_key(service_tag);
        // Load existing list or start fresh.
        let mut list = self
            .dht
            .get_local(&key)
            .map(|b| AnycastList::decode(&b))
            .unwrap_or_default();
        list.upsert(AnycastRecord {
            service_tag,
            node_id: self.local_node_id,
            score,
            ttl: ttl_secs,
            // Legacy v1 advertise — see `advertise_signed` for v2 owner-signed records.
            signature: None,
        });
        self.dht.store_local(key, list.encode());
    }

    /// **v2 owner-signed** advertise. Publishes a record signed with the
    /// supplied Ed25519 key; resolvers with trust-sensitive policy can
    /// reject unsigned (v1) records or records with signatures that don't
    /// verify. Recommended for service-discovery in production.
    ///
    /// Caller is responsible for making sure `signing_key`'s pubkey is
    /// bound to `self.local_node_id` (typically through a sovereign
    /// identity document). Without that binding the signature is only
    /// integrity-attestation, not ownership-attestation.
    pub fn advertise_signed(
        &self,
        service_tag: [u8; 4],
        score: u16,
        ttl_secs: u32,
        sig_key_idx: u8,
        signing_key: &ed25519_dalek::SigningKey,
    ) {
        let key = AnycastRecord::dht_key(service_tag);
        let mut list = self
            .dht
            .get_local(&key)
            .map(|b| AnycastList::decode(&b))
            .unwrap_or_default();
        let signed_record = AnycastRecord::sign(
            service_tag,
            self.local_node_id,
            score,
            ttl_secs,
            sig_key_idx,
            signing_key,
        );
        list.upsert(signed_record);
        self.dht.store_local(key, list.encode());
    }

    /// Algo-generic owner-signed advertise (v2 Ed25519 / v3 Falcon-512 /
    /// hybrid). Signs the record with the wired [`AnycastSigner`]. On malformed
    /// signer key material the advertise is SKIPPED (we never downgrade to an
    /// unsigned record), and the existing list is left untouched.
    fn advertise_with_signer(
        &self,
        service_tag: [u8; 4],
        score: u16,
        ttl_secs: u32,
        signer: &AnycastSigner,
    ) {
        let Some(record) = signer.sign_record(service_tag, self.local_node_id, score, ttl_secs)
        else {
            return;
        };
        let key = AnycastRecord::dht_key(service_tag);
        let mut list = self
            .dht
            .get_local(&key)
            .map(|b| AnycastList::decode(&b))
            .unwrap_or_default();
        list.upsert(record);
        self.dht.store_local(key, list.encode());
    }

    /// Withdraw this node's advertisement for `service_tag`.
    ///
    /// Removes the local entry from the DHT list and re-stores the result.
    /// When the list becomes empty we still write the empty blob so that
    /// subsequent `resolve` calls return no candidates immediately —
    /// otherwise the previous (stale) blob would survive until natural TTL
    /// expiry.
    pub fn withdraw(&self, service_tag: [u8; 4]) {
        let key = AnycastRecord::dht_key(service_tag);
        if let Some(blob) = self.dht.get_local(&key) {
            let mut list = AnycastList::decode(&blob);
            list.0.retain(|r| r.node_id != self.local_node_id);
            self.dht.store_local(key, list.encode());
        }
    }

    /// Resolve `service_tag` to the nearest `max_results` candidate node_ids.
    ///
    /// Candidates are ranked by `AnycastRecord.score` ascending (lower =
    /// better). Returns an `AnycastResultPayload` ready to send over IPC.
    ///
    /// A7: under the opt-down `BestEffort` policy `score` is peer-controlled —
    /// any node publishing an AnycastRecord can claim `score = 0` to win all
    /// traffic for the service tag. (The DEFAULT `SignedBound` policy already
    /// rejects unsigned / unbound records outright.) Under `BestEffort`, two
    /// shipped layers bound this WITHOUT requiring signatures: (1) a
    /// resolver-local **reputation penalty** is
    /// added to the claimed score (see `resolve_internal`), demoting nodes that
    /// failed to serve on prior resolves; and (2) ties — including a fabricated
    /// `0` — fall back to **XOR distance from this resolver**, so a sybil must be
    /// both `score = 0` *and* XOR-close to each target resolver, a constraint it
    /// cannot satisfy uniformly (different resolvers rank the same Sybil farm
    /// differently, breaking the universal eclipse). Callers that want to reject
    /// unsigned or unowned records outright use [`Self::resolve_signed_only`] /
    /// [`Self::resolve_signed_bound`] (policies `SignedOnly` / `SignedBound`).
    pub fn resolve(&self, service_tag: [u8; 4], max_results: u8) -> AnycastResultPayload {
        let (require_signed, require_binding) = match self.policy {
            AnycastResolvePolicy::BestEffort => (false, false),
            AnycastResolvePolicy::SignedOnly => (true, false),
            AnycastResolvePolicy::SignedBound => (true, true),
        };
        self.resolve_internal(service_tag, max_results, require_signed, require_binding)
    }

    /// **Signed-only** variant. Returns ONLY candidates whose record carries
    /// a valid Ed25519 owner-signature ([`AnycastRecord::verify_signature`]).
    /// Use for trust-sensitive routing where accepting unsigned (v1) records
    /// would re-open the score=0 sybil vector. Sigs are verified per-record
    /// inline; failure-to-verify silently drops the record (no error
    /// surfaced — same FIFO semantics as malformed records).
    ///
    /// Caller is responsible separately for checking that the embedded
    /// `owner_pubkey` corresponds to the claimed `node_id` (identity binding);
    /// this method only validates signature integrity, not ownership.
    /// Use [`Self::resolve_signed_bound`] when the daemon should also
    /// enforce the `BLAKE3(owner_pubkey) == node_id` binding.
    pub fn resolve_signed_only(
        &self,
        service_tag: [u8; 4],
        max_results: u8,
    ) -> AnycastResultPayload {
        self.resolve_internal(
            service_tag,
            max_results,
            /*require_signed=*/ true,
            /*require_binding=*/ false,
        )
    }

    /// **Signed + owner-bound** variant.  Returns ONLY candidates whose
    /// record carries a valid Ed25519 signature AND whose embedded
    /// `owner_pubkey` provably corresponds to the claimed `node_id` via
    /// [`AnycastRecord::verify_owner_binding`] (`BLAKE3(owner_pubkey) ==
    /// node_id`, `sig_key_idx == 0`).  Use for trust-sensitive routing
    /// where a sybil with their own valid Ed25519 key MUST NOT be able to
    /// claim someone else's `node_id`.
    pub fn resolve_signed_bound(
        &self,
        service_tag: [u8; 4],
        max_results: u8,
    ) -> AnycastResultPayload {
        self.resolve_internal(
            service_tag,
            max_results,
            /*require_signed=*/ true,
            /*require_binding=*/ true,
        )
    }

    fn resolve_internal(
        &self,
        service_tag: [u8; 4],
        max_results: u8,
        require_signed: bool,
        require_binding: bool,
    ) -> AnycastResultPayload {
        let key = AnycastRecord::dht_key(service_tag);
        // Audit batch 2026-05-25 phase N: per-record TTL enforcement.
        // Pre-fix, `AnycastRecord::ttl` was declared in the wire format
        // but not consulted on resolve — stale records survived in the
        // store until the DHT-wide TTL evicted them (potentially
        // hours).  Resolves were returning routes to long-departed
        // publishers, producing blackholes at destinations that had
        // long since stopped advertising.  Now we fetch the entry's
        // hot-tier `inserted_at` via `get_local_with_meta`, compute
        // age, and drop records where `age >= record.ttl`.  No wire
        // change — the `ttl` field always existed in the record.
        let entry = self.dht.get_local_with_meta(&key);
        let now = std::time::Instant::now();
        // (node_id, effective_score) — effective_score = peer-claimed score
        // PLUS resolver-local reputation penalty. u32 not u16 because
        // saturating-add of repeated failures can overflow the u16 score
        // domain — we don't need the original score back, only a stable
        // sort key, so widening is safe.
        let mut candidates: Vec<([u8; 32], u32)> = entry
            .map(|(b, inserted_at)| {
                let age = now.duration_since(inserted_at);
                AnycastList::decode(&b)
                    .0
                    .into_iter()
                    .filter(|r| {
                        // Per-record TTL: drop expired.  TTL=0 in the
                        // wire format means "no TTL", treated as
                        // "always fresh" for backwards compatibility
                        // with pre-fix records.
                        if r.ttl > 0 && age.as_secs() >= r.ttl as u64 {
                            return false;
                        }
                        if require_binding {
                            // Strictest gate: drop unless signature is valid
                            // AND owner-binding holds. The algo-generic path
                            // admits v3 (Falcon-512 / hybrid) records too, not
                            // just Ed25519 v2. `verify_record_owner_binding`
                            // calls `verify_record_signature` internally.
                            return verify_record_owner_binding(r).is_ok();
                        }
                        if !require_signed {
                            return true;
                        }
                        // Trust-policy gate: drop unsigned records and records
                        // whose embedded sig doesn't verify under owner_pubkey
                        // (any supported algorithm).
                        verify_record_signature(r).is_ok()
                    })
                    .map(|r| {
                        let penalty = self.reputation.score_offset(r.node_id, service_tag);
                        let eff = (r.score as u32).saturating_add(penalty);
                        (r.node_id, eff)
                    })
                    .collect()
            })
            .unwrap_or_default();

        // A7: primary key = peer-claimed score + reputation-penalty,
        // secondary key = XOR distance to local_node_id. Score still wins
        // so legitimate operators advertising honest scores keep their
        // priority; but tied scores (incl. attacker-fabricated `0`) fall
        // back to the resolver-specific XOR ordering, which Sybil can't
        // game uniformly. Reputation penalty stacks on top of score
        // so misbehaving peers drop below honest tiers after a handful of
        // observed failures (see `reputation::FAILURE_PENALTY_PER`).
        // Final tiebreak by node_id keeps determinism for true ties.
        let local = self.local_node_id;
        candidates.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| {
                    let mut da = [0u8; 32];
                    let mut db = [0u8; 32];
                    for i in 0..32 {
                        da[i] = a.0[i] ^ local[i];
                        db[i] = b.0[i] ^ local[i];
                    }
                    da.cmp(&db)
                })
                .then(a.0.cmp(&b.0))
        });
        candidates.dedup_by_key(|(id, _)| *id);

        let limit = (max_results as usize).min(MAX_ANYCAST_CANDIDATES);
        let node_ids: Vec<[u8; 32]> = candidates
            .into_iter()
            .map(|(id, _)| id)
            .take(limit)
            .collect();

        // Bind future app-reported failures to this real resolve: only the
        // candidates we actually hand out may later be reported as failed
        // (see `AnycastReputation::record_failure_if_issued`), so a local IPC
        // app cannot penalize an honest node it was never offered.
        for id in &node_ids {
            self.reputation.note_issued(*id, service_tag);
        }

        AnycastResultPayload {
            service_tag,
            node_ids,
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use veil_dht::KademliaService;
    use veil_proto::anycast::{ANYCAST_MAGIC_V3, ANYCAST_RECORD_SIZE, ANYCAST_RECORD_V2_SIZE};

    /// Falcon-512 (v3) owner-signing round-trips through the wire and verifies —
    /// the core of the A1 fix: a PQ-only identity can own-sign anycast records,
    /// and a resolver admits them under the strictest (binding) policy.
    #[test]
    fn falcon_v3_sign_verify_and_binding_roundtrip() {
        let kp = veil_crypto::generate_keypair(SignatureAlgorithm::Falcon512);
        let pubkey_bytes = base64::engine::general_purpose::STANDARD
            .decode(&kp.public_key)
            .unwrap();
        let node_id: [u8; 32] = blake3::hash(&pubkey_bytes).into();
        let signer = AnycastSigner::new(SignatureAlgorithm::Falcon512, pubkey_bytes.clone(), 0, {
            let pk = kp.public_key.clone();
            let sk = kp.private_key.clone();
            Arc::new(move |msg: &[u8]| {
                veil_crypto::sign_message(SignatureAlgorithm::Falcon512, &pk, &sk, msg).unwrap()
            })
        });
        let rec = signer
            .sign_record(*b"mbox", node_id, 5, 3600)
            .expect("falcon sign");

        // Serializes as v3 and round-trips exactly through the wire.
        let enc = rec.encode();
        assert_eq!(&enc[0..2], &ANYCAST_MAGIC_V3, "Falcon record is v3");
        let dec = AnycastRecord::decode(&enc).unwrap();
        assert_eq!(dec, rec);

        // Generic verify + owner-binding accept it.
        assert!(verify_record_signature(&dec).is_ok());
        assert!(verify_record_owner_binding(&dec).is_ok());

        // Tampered signature → verify fails.
        let mut bad = dec.clone();
        if let Some(s) = bad.signature.as_mut() {
            s.signature[0] ^= 0xFF;
        }
        assert!(verify_record_signature(&bad).is_err());

        // Forged binding (sig still valid, but node_id changed) → binding fails.
        let mut forged = dec.clone();
        forged.node_id[0] ^= 0xFF;
        assert!(
            verify_record_owner_binding(&forged).is_err(),
            "BLAKE3(owner_pubkey) != node_id must be rejected",
        );
    }

    /// The strictest resolve policy (`SignedBound`) admits a Falcon-signed v3
    /// record whose owner-binding holds — proving the resolver-side generic
    /// verify is wired into the policy.
    #[test]
    fn signed_bound_policy_admits_falcon_record() {
        let kp = veil_crypto::generate_keypair(SignatureAlgorithm::Falcon512);
        let pubkey_bytes = base64::engine::general_purpose::STANDARD
            .decode(&kp.public_key)
            .unwrap();
        let node_id: [u8; 32] = blake3::hash(&pubkey_bytes).into();
        let dht = Arc::new(KademliaService::new([0x9; 32]));
        let svc = AnycastService::with_reputation(
            Arc::clone(&dht),
            node_id,
            Arc::new(AnycastReputation::new()),
        )
        .with_policy(AnycastResolvePolicy::SignedBound)
        .with_signer(AnycastSigner::new(
            SignatureAlgorithm::Falcon512,
            pubkey_bytes.clone(),
            0,
            {
                let pk = kp.public_key.clone();
                let sk = kp.private_key.clone();
                Arc::new(move |msg: &[u8]| {
                    veil_crypto::sign_message(SignatureAlgorithm::Falcon512, &pk, &sk, msg).unwrap()
                })
            },
        ));
        svc.advertise(*b"mbox", 1, 3600);
        let got = svc.resolve(*b"mbox", 8);
        assert!(
            got.node_ids.contains(&node_id),
            "SignedBound must admit our own Falcon-signed v3 record",
        );
    }

    fn make_service(seed: u8) -> AnycastService {
        let dht = Arc::new(KademliaService::new([seed; 32]));
        // audit cycle-6 (T2): the default policy is now `SignedBound`, which
        // drops unsigned records. These mechanics tests (TTL / withdraw / score
        // / dedup) exercise resolution with UNSIGNED records, so pin
        // `BestEffort` explicitly — the policy-specific behaviour is covered by
        // the dedicated `resolve_with_*_policy_*` tests.
        AnycastService::new(dht, [seed; 32]).with_policy(AnycastResolvePolicy::BestEffort)
    }

    fn make_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn v2_record_roundtrip_verifies() {
        let key = make_signing_key(0x42);
        let node_id = [0xAA; 32];
        let r = AnycastRecord::sign(*b"mbox", node_id, 5, 3600, 0, &key);
        // Signature integrity holds round-trip.
        assert!(r.verify_signature().is_ok());
        // Encoded length matches v2 wire size.
        let blob = r.encode();
        assert_eq!(blob.len(), ANYCAST_RECORD_V2_SIZE);
        // Decode preserves all fields.
        let decoded = AnycastRecord::decode(&blob).unwrap();
        assert_eq!(decoded, r);
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn v2_tampered_field_breaks_signature() {
        let key = make_signing_key(0x42);
        let r = AnycastRecord::sign(*b"mbox", [0xAA; 32], 5, 3600, 0, &key);
        let mut blob = r.encode();
        // Flip a byte in score field (offset 38 = bytes 38..40 score).
        blob[38] ^= 0x01;
        let tampered = AnycastRecord::decode(&blob).unwrap();
        // Sig must reject the tampered record.
        assert!(tampered.verify_signature().is_err());
    }

    #[test]
    fn v2_wrong_key_rejected() {
        let key_a = make_signing_key(0xAA);
        let key_b = make_signing_key(0xBB);
        // Sign with key_a but overwrite owner_pubkey with key_b's.
        let mut r = AnycastRecord::sign(*b"mbox", [0xAA; 32], 5, 3600, 0, &key_a);
        if let Some(s) = r.signature.as_mut() {
            s.owner_pubkey = key_b.verifying_key().to_bytes().to_vec();
        }
        // Signature was produced by key_a but claims key_b → mismatch.
        assert!(r.verify_signature().is_err());
    }

    #[test]
    fn v1_record_unsigned_returns_err_on_verify() {
        let r = AnycastRecord {
            service_tag: *b"mbox",
            node_id: [0xAA; 32],
            score: 5,
            ttl: 3600,
            signature: None,
        };
        // v1 is unsigned by construction; verify_signature MUST error.
        assert!(r.verify_signature().is_err());
        let blob = r.encode();
        assert_eq!(blob.len(), ANYCAST_RECORD_SIZE);
    }

    #[test]
    fn mixed_list_decodes_v1_and_v2() {
        let key = make_signing_key(0x42);
        let v1 = AnycastRecord {
            service_tag: *b"mbox",
            node_id: [0xA1; 32],
            score: 10,
            ttl: 3600,
            signature: None,
        };
        let v2 = AnycastRecord::sign(*b"mbox", [0xB2; 32], 5, 3600, 0, &key);
        let mut blob = Vec::new();
        blob.extend_from_slice(&v1.encode());
        blob.extend_from_slice(&v2.encode());
        let list = AnycastList::decode(&blob);
        assert_eq!(list.0.len(), 2);
        assert!(list.0[0].signature.is_none());
        assert!(list.0[1].signature.is_some());
        // v1 wire size + v2 wire size matches encoded length.
        assert_eq!(blob.len(), ANYCAST_RECORD_SIZE + ANYCAST_RECORD_V2_SIZE);
    }

    #[test]
    fn resolve_signed_only_filters_v1_records() {
        let svc = make_service(0xCC);
        let key = make_signing_key(0xCC);
        // Advertise one unsigned (legacy) + one signed.
        svc.advertise(*b"mbox", 10, 3600);
        // Add a second signed entry under a different node_id manually.
        let dht_key = AnycastRecord::dht_key(*b"mbox");
        let mut list = AnycastList::decode(&svc.dht.get_local(&dht_key).unwrap_or_default());
        list.upsert(AnycastRecord::sign(*b"mbox", [0xDD; 32], 5, 3600, 0, &key));
        svc.dht.store_local(dht_key, list.encode());
        // Default resolve returns BOTH records.
        let r_all = svc.resolve(*b"mbox", 32);
        assert_eq!(r_all.node_ids.len(), 2, "default resolve includes both");
        // resolve_signed_only returns ONLY the signed one.
        let r_signed = svc.resolve_signed_only(*b"mbox", 32);
        assert_eq!(r_signed.node_ids.len(), 1, "signed-only filters out v1");
        assert_eq!(r_signed.node_ids[0], [0xDD; 32]);
    }

    /// `with_policy(SignedOnly)` makes `resolve()` behave as
    /// `resolve_signed_only` without needing a separate IPC opcode.  Closes
    /// the audit-flagged gap "anycast hardening partially implemented but
    /// IPC/runtime uses the ordinary resolve" (Phase C11, 2026-05-22).
    #[test]
    fn resolve_with_signed_only_policy_filters_v1() {
        let svc = make_service(0xCC).with_policy(AnycastResolvePolicy::SignedOnly);
        assert_eq!(svc.policy(), AnycastResolvePolicy::SignedOnly);
        let key = make_signing_key(0xCC);
        svc.advertise(*b"mbox", 10, 3600);
        let dht_key = AnycastRecord::dht_key(*b"mbox");
        let mut list = AnycastList::decode(&svc.dht.get_local(&dht_key).unwrap_or_default());
        list.upsert(AnycastRecord::sign(*b"mbox", [0xDD; 32], 5, 3600, 0, &key));
        svc.dht.store_local(dht_key, list.encode());
        let r = svc.resolve(*b"mbox", 32);
        assert_eq!(r.node_ids.len(), 1, "policy SignedOnly drops v1 records");
        assert_eq!(r.node_ids[0], [0xDD; 32]);
    }

    /// `with_policy(BestEffort)` retains default behaviour — both
    /// signed and unsigned records returned.
    #[test]
    fn resolve_with_best_effort_policy_returns_all() {
        let svc = make_service(0xCC).with_policy(AnycastResolvePolicy::BestEffort);
        assert_eq!(svc.policy(), AnycastResolvePolicy::BestEffort);
        let key = make_signing_key(0xCC);
        svc.advertise(*b"mbox", 10, 3600);
        let dht_key = AnycastRecord::dht_key(*b"mbox");
        let mut list = AnycastList::decode(&svc.dht.get_local(&dht_key).unwrap_or_default());
        list.upsert(AnycastRecord::sign(*b"mbox", [0xDD; 32], 5, 3600, 0, &key));
        svc.dht.store_local(dht_key, list.encode());
        let r = svc.resolve(*b"mbox", 32);
        assert_eq!(r.node_ids.len(), 2, "BestEffort accepts both v1 and signed");
    }

    #[test]
    fn advertise_then_resolve_finds_self() {
        let svc = make_service(0xAA);
        let tag = *b"mbox";
        svc.advertise(tag, 100, 3600);
        let result = svc.resolve(tag, 8);
        assert_eq!(result.service_tag, tag);
        assert_eq!(result.node_ids, vec![[0xAAu8; 32]]);
    }

    #[test]
    fn resolve_unknown_tag_returns_empty() {
        let svc = make_service(0xBB);
        let result = svc.resolve(*b"unkn", 8);
        assert!(result.node_ids.is_empty());
    }

    #[test]
    fn multiple_advertisers_sorted_by_score() {
        let dht = Arc::new(KademliaService::new([0xA0; 32]));
        let svc_a = AnycastService::new(Arc::clone(&dht), [0xA0; 32])
            .with_policy(AnycastResolvePolicy::BestEffort);
        let svc_b = AnycastService::new(Arc::clone(&dht), [0xB0; 32]);
        let svc_c = AnycastService::new(Arc::clone(&dht), [0xC0; 32]);

        let tag = *b"gate";
        svc_a.advertise(tag, 300, 3600); // worst score
        svc_b.advertise(tag, 100, 3600); // best score
        svc_c.advertise(tag, 200, 3600); // middle

        let result = svc_a.resolve(tag, 8);
        assert_eq!(result.node_ids.len(), 3);
        assert_eq!(result.node_ids[0], [0xB0; 32]); // best score first
        assert_eq!(result.node_ids[1], [0xC0; 32]);
        assert_eq!(result.node_ids[2], [0xA0; 32]);
    }

    #[test]
    fn withdraw_removes_own_entry() {
        let dht = Arc::new(KademliaService::new([0xA0; 32]));
        let svc_a = AnycastService::new(Arc::clone(&dht), [0xA0; 32]);
        let svc_b = AnycastService::new(Arc::clone(&dht), [0xB0; 32])
            .with_policy(AnycastResolvePolicy::BestEffort);

        let tag = *b"brg\0";
        svc_a.advertise(tag, 50, 3600);
        svc_b.advertise(tag, 60, 3600);
        svc_a.withdraw(tag);

        let result = svc_b.resolve(tag, 8);
        assert_eq!(result.node_ids, vec![[0xB0u8; 32]]);
    }

    #[test]
    fn max_results_clamped() {
        let svc = make_service(0xCC);
        svc.advertise(*b"svc1", 10, 3600);
        let result = svc.resolve(*b"svc1", 255); // ask for 255, capped at MAX
        assert!(result.node_ids.len() <= MAX_ANYCAST_CANDIDATES);
    }

    /// Audit batch 2026-05-25 phase N: per-record TTL must filter
    /// stale records on resolve.  Pre-fix the `ttl` field in the
    /// wire record was advisory only — resolve returned expired
    /// records until the DHT-wide TTL evicted them (potentially
    /// hours).  Now resolve drops records whose `age >= ttl`.
    ///
    /// Uses a 1-second TTL + 1.2-second sleep to keep the test fast
    /// while still crossing the boundary with some margin for CI
    /// scheduler jitter.
    #[test]
    fn resolve_drops_records_past_their_ttl() {
        let svc = make_service(0xE1);
        svc.advertise(*b"ttl0", 7, 1); // 1 s record TTL
        // Immediate resolve sees the record.
        let immediate = svc.resolve(*b"ttl0", 8);
        assert_eq!(immediate.node_ids.len(), 1, "fresh record must be returned");
        // Cross the TTL boundary with margin for slow CI runners.
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let expired = svc.resolve(*b"ttl0", 8);
        assert_eq!(
            expired.node_ids.len(),
            0,
            "expired record must be filtered out"
        );
    }

    /// TTL=0 means "no per-record expiry"; resolve preserves
    /// pre-phase-N behaviour where records lived until DHT eviction.
    /// Backwards-compat for records published by pre-fix peers that did not
    /// set a meaningful ttl.
    #[test]
    fn resolve_keeps_ttl_zero_records_indefinitely() {
        let svc = make_service(0xE2);
        svc.advertise(*b"ttl0", 7, 0); // ttl_secs = 0 ⇒ no expiry
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let r = svc.resolve(*b"ttl0", 8);
        assert_eq!(r.node_ids.len(), 1, "ttl=0 means persistent");
    }

    /// Audit batch 2026-05-25 phase O: `with_signing_key` makes
    /// `advertise()` auto-publish a v2 signed record so `SignedOnly`
    /// / `SignedBound` resolvers admit it.  Without the signing key
    /// (default state) advertise stays on the legacy v1 path.
    #[test]
    fn advertise_auto_signs_when_signing_key_configured() {
        let key = make_signing_key(0x77);
        // node_id MUST equal BLAKE3(verifying_key) for SignedBound,
        // but for SignedOnly we only need signature integrity.
        let local_node_id = [0x77; 32];
        let dht = Arc::new(KademliaService::new(local_node_id));
        let svc = AnycastService::new(Arc::clone(&dht), local_node_id)
            .with_policy(AnycastResolvePolicy::SignedOnly)
            .with_signing_key(Arc::new(key.clone()), 0);

        svc.advertise(*b"sig1", 11, 3600);
        // Inspect what we wrote in DHT — must be a v2 signed record.
        let dht_key = AnycastRecord::dht_key(*b"sig1");
        let blob = dht.get_local(&dht_key).expect("DHT entry present");
        let list = AnycastList::decode(&blob);
        assert_eq!(list.0.len(), 1, "exactly one local record");
        assert!(
            list.0[0].signature.is_some(),
            "with_signing_key must produce a v2 signed record"
        );
        assert!(
            list.0[0].verify_signature().is_ok(),
            "signature must verify under embedded owner_pubkey"
        );

        // SignedOnly resolve should admit our own record.
        let r = svc.resolve(*b"sig1", 8);
        assert_eq!(r.node_ids.len(), 1, "SignedOnly admits signed record");
    }

    #[test]
    fn advertise_falls_back_to_unsigned_without_signing_key() {
        let svc = make_service(0x88);
        svc.advertise(*b"sig2", 11, 3600);
        let dht_key = AnycastRecord::dht_key(*b"sig2");
        let blob = svc.dht.get_local(&dht_key).expect("DHT entry");
        let list = AnycastList::decode(&blob);
        assert_eq!(list.0.len(), 1);
        assert!(
            list.0[0].signature.is_none(),
            "no signing key → legacy v1 unsigned record"
        );
    }

    #[test]
    fn reputation_penalty_demotes_misbehaver() {
        // Sybil-style scenario: attacker advertises score=0 (best),
        // honest node advertises score=300. By default sybil wins.
        // After a few recorded failures against the sybil, honest
        // node should sort above it.
        let dht = Arc::new(KademliaService::new([0xA0; 32]));
        let resolver = AnycastService::new(Arc::clone(&dht), [0xA0; 32])
            .with_policy(AnycastResolvePolicy::BestEffort);
        let sybil = AnycastService::with_reputation(
            Arc::clone(&dht),
            [0xFF; 32],
            Arc::clone(resolver.reputation()),
        );
        let honest = AnycastService::with_reputation(
            Arc::clone(&dht),
            [0x11; 32],
            Arc::clone(resolver.reputation()),
        );

        let tag = *b"mbox";
        sybil.advertise(tag, 0, 3600); // claims best score
        honest.advertise(tag, 300, 3600); // honest moderate score

        // Initial resolve: sybil wins because score=0 < 300.
        let before = resolver.resolve(tag, 8);
        assert_eq!(
            before.node_ids[0], [0xFF; 32],
            "sybil initially wins by score=0"
        );
        assert_eq!(before.node_ids[1], [0x11; 32]);

        // Record a failure against sybil. Single failure = +500 penalty,
        // so effective score 0 + 500 = 500 > honest 300 → honest wins.
        resolver.reputation().record_failure([0xFF; 32], tag);

        let after = resolver.resolve(tag, 8);
        assert_eq!(
            after.node_ids[0], [0x11; 32],
            "honest promoted over penalized sybil"
        );
        assert_eq!(after.node_ids[1], [0xFF; 32]);
    }

    #[test]
    fn reputation_per_tag_isolation() {
        // Failure on tag "mbox" must NOT affect ranking under tag "gate".
        let dht = Arc::new(KademliaService::new([0xA0; 32]));
        let resolver = AnycastService::new(Arc::clone(&dht), [0xA0; 32])
            .with_policy(AnycastResolvePolicy::BestEffort);
        let candidate = AnycastService::with_reputation(
            Arc::clone(&dht),
            [0xFF; 32],
            Arc::clone(resolver.reputation()),
        );
        let competitor = AnycastService::with_reputation(
            Arc::clone(&dht),
            [0x11; 32],
            Arc::clone(resolver.reputation()),
        );

        candidate.advertise(*b"mbox", 0, 3600);
        candidate.advertise(*b"gate", 0, 3600);
        competitor.advertise(*b"mbox", 300, 3600);
        competitor.advertise(*b"gate", 300, 3600);

        // Penalize candidate under "mbox" only.
        resolver.reputation().record_failure([0xFF; 32], *b"mbox");

        // "mbox" → competitor wins (penalty applies).
        let mbox = resolver.resolve(*b"mbox", 8);
        assert_eq!(mbox.node_ids[0], [0x11; 32]);

        // "gate" → candidate still wins (no penalty there).
        let gate = resolver.resolve(*b"gate", 8);
        assert_eq!(gate.node_ids[0], [0xFF; 32]);
    }

    // ── SignedBound policy (audit batch 2026-05-23) ────────────────

    /// Derive a node_id from an Ed25519 signing-key the same way the
    /// production sovereign-identity layer does (`BLAKE3(pubkey)`).
    fn bound_node_id_for(key: &SigningKey) -> [u8; 32] {
        *blake3::hash(&key.verifying_key().to_bytes()).as_bytes()
    }

    #[test]
    fn resolve_signed_bound_filters_unbound_records() {
        // Build a DHT containing three records under one service tag:
        //   1. Signed + BOUND   (BLAKE3(pubkey) == node_id) — kept
        //   2. Signed + UNBOUND (claims a foreign node_id)   — dropped
        //   3. Unsigned v1                                    — dropped
        let key_bound = make_signing_key(0x11);
        let bound_node_id = bound_node_id_for(&key_bound);
        let key_unbound = make_signing_key(0x22);
        // node_id is a foreign value, NOT derived from key_unbound.
        let unbound_node_id = [0xEE; 32];

        // svc uses a fresh DHT; we'll write all 3 records directly.
        let dht = Arc::new(KademliaService::new([0xA0; 32]));
        let svc = AnycastService::new(Arc::clone(&dht), [0xA0; 32]);
        let dht_key = AnycastRecord::dht_key(*b"mbox");

        let mut list = AnycastList::default();
        list.upsert(AnycastRecord::sign(
            *b"mbox",
            bound_node_id,
            5,
            3600,
            0,
            &key_bound,
        ));
        list.upsert(AnycastRecord::sign(
            *b"mbox",
            unbound_node_id,
            3,
            3600,
            0,
            &key_unbound,
        ));
        // Add unsigned v1 record for good measure.
        list.upsert(AnycastRecord {
            service_tag: *b"mbox",
            node_id: [0x33; 32],
            score: 1,
            ttl: 3600,
            signature: None,
        });
        dht.store_local(dht_key, list.encode());

        // SignedOnly accepts both signed records, regardless of binding.
        let signed_only = svc.resolve_signed_only(*b"mbox", 32);
        assert!(
            signed_only.node_ids.contains(&bound_node_id),
            "SignedOnly keeps the bound record"
        );
        assert!(
            signed_only.node_ids.contains(&unbound_node_id),
            "SignedOnly does NOT detect forged binding — sybil leaks through"
        );
        assert_eq!(
            signed_only.node_ids.len(),
            2,
            "SignedOnly drops only the v1 record"
        );

        // SignedBound drops the unbound record AND v1, leaving only the
        // bound entry.  This is the regression bar.
        let bound = svc.resolve_signed_bound(*b"mbox", 32);
        assert_eq!(
            bound.node_ids,
            vec![bound_node_id],
            "SignedBound must keep ONLY records where BLAKE3(pubkey) == node_id"
        );
    }

    #[test]
    fn resolve_with_signed_bound_policy_via_cfg_works() {
        // Same scenario as the explicit `resolve_signed_bound` test, but
        // driven through the `with_policy` builder so cfg-side wiring
        // is exercised end-to-end.
        let key_bound = make_signing_key(0x44);
        let bound_node_id = bound_node_id_for(&key_bound);
        let key_unbound = make_signing_key(0x55);
        let unbound_node_id = [0xCC; 32];

        let dht = Arc::new(KademliaService::new([0xA0; 32]));
        let svc = AnycastService::new(Arc::clone(&dht), [0xA0; 32])
            .with_policy(AnycastResolvePolicy::SignedBound);
        assert_eq!(svc.policy(), AnycastResolvePolicy::SignedBound);

        let dht_key = AnycastRecord::dht_key(*b"svc1");
        let mut list = AnycastList::default();
        list.upsert(AnycastRecord::sign(
            *b"svc1",
            bound_node_id,
            5,
            3600,
            0,
            &key_bound,
        ));
        list.upsert(AnycastRecord::sign(
            *b"svc1",
            unbound_node_id,
            5,
            3600,
            0,
            &key_unbound,
        ));
        dht.store_local(dht_key, list.encode());

        let result = svc.resolve(*b"svc1", 32);
        assert_eq!(
            result.node_ids,
            vec![bound_node_id],
            "SignedBound policy via with_policy() drops unbound records"
        );
    }

    #[test]
    fn resolve_signed_bound_drops_subkey_records() {
        // Even with a valid BLAKE3 binding, sig_key_idx > 0 must be
        // dropped under SignedBound (async identity-doc lookup
        // required, not in-scope for the sync resolve path).
        let key = make_signing_key(0x66);
        let derived_id = bound_node_id_for(&key);

        let dht = Arc::new(KademliaService::new([0xA0; 32]));
        let svc = AnycastService::new(Arc::clone(&dht), [0xA0; 32]);
        let dht_key = AnycastRecord::dht_key(*b"sub1");
        let mut list = AnycastList::default();
        // sig_key_idx = 3 (subkey flow) even with a matching node_id.
        list.upsert(AnycastRecord::sign(*b"sub1", derived_id, 5, 3600, 3, &key));
        dht.store_local(dht_key, list.encode());

        // SignedOnly keeps it (signature integrity holds).
        assert_eq!(svc.resolve_signed_only(*b"sub1", 32).node_ids.len(), 1);
        // SignedBound drops it (sig_key_idx > 0 unsupported synchronously).
        assert!(
            svc.resolve_signed_bound(*b"sub1", 32).node_ids.is_empty(),
            "SignedBound must drop sig_key_idx > 0 records"
        );
    }

    #[test]
    fn reputation_does_not_affect_signed_filter() {
        // Signed-only filter is a binary trust gate (drop unsigned).
        // Reputation must apply on top of the filter — penalize within
        // the signed set, but not promote unsigned records.
        let svc = make_service(0xCC);
        let key = make_signing_key(0xCC);
        let dht_key = AnycastRecord::dht_key(*b"mbox");

        // Insert one unsigned + two signed records.
        svc.advertise(*b"mbox", 0, 3600); // unsigned, score=0 (would win sans filter)
        let mut list = AnycastList::decode(&svc.dht.get_local(&dht_key).unwrap_or_default());
        list.upsert(AnycastRecord::sign(
            *b"mbox", [0xAA; 32], 100, 3600, 0, &key,
        ));
        list.upsert(AnycastRecord::sign(
            *b"mbox", [0xBB; 32], 200, 3600, 0, &key,
        ));
        svc.dht.store_local(dht_key, list.encode());

        // Without penalties: signed-only returns [0xAA, 0xBB] (sorted by score).
        let before = svc.resolve_signed_only(*b"mbox", 8);
        assert_eq!(before.node_ids, vec![[0xAAu8; 32], [0xBB; 32]]);

        // Penalize the previously-best signed candidate (0xAA, +500).
        // Effective: 0xAA = 100 + 500 = 600; 0xBB = 200 → 0xBB now wins.
        svc.reputation().record_failure([0xAA; 32], *b"mbox");
        let after = svc.resolve_signed_only(*b"mbox", 8);
        assert_eq!(after.node_ids, vec![[0xBBu8; 32], [0xAA; 32]]);

        // Unsigned record still excluded (filter independent of reputation).
        assert!(!after.node_ids.contains(&[0xCC; 32]));
    }
}
