//! Runtime-facing sovereign-identity provider.
//!
//! The library-layer helpers ([`sign_identity_proof`]
//! [`verify_identity_proof_frame`]) are stateless — they take the
//! material they need as parameters. The runtime session layer
//! doesn't want to thread 5 arguments through every call site; it
//! wants a single handle that says "here is my sovereign identity
//! use it".
//!
//! [`SovereignIdentity`] is that handle. It bundles:
//!
//! the signed [`IdentityDocument`] (cert chain + revocations)
//! the active instance's `identity_sk` (for signing [`IdentityProof`]s)
//! the `sig_key_idx` pointing at the active subkey in the document.
//!
//! The node loads one of these at startup (from the disk layout
//! written by `cfg/sovereign_flow`) and hands a reference to the
//! handshake. The handshake calls [`SovereignIdentity::sign_proof`]
//! each time it needs to emit an `IdentityProof` frame bound to a
//! fresh X25519 ephemeral pk.
//!
//! ## Invariants
//!
//! Constructed `SovereignIdentity` values always satisfy:
//!
//! 1. `sig_key_idx` is a valid in-document subkey index.
//! 2. The SK's derived pubkey matches that subkey's `pubkey`.
//!
//! The document's OWN signature / master cert chain is NOT
//! re-verified here — that's the job of
//! [`verify_identity_document`] which the caller typically runs
//! before constructing a [`SovereignIdentity`]. This module trusts
//! the passed-in document and only cross-checks the SK↔subkey
//! binding.
//!
//! [`sign_identity_proof`]: super::publish::sign_identity_proof
//! [`verify_identity_proof_frame`]: super::verify::verify_identity_proof_frame
//! [`verify_identity_document`]: super::verify::verify_identity_document

use std::path::Path;

use crate::signing_key::{IdentitySigningKey, IdentitySigningKeyError};
use crate::sovereign_flow::{DEVICE_IDENTITY_SK_FILE, load_device_sig_key_idx};
use veil_proto::ProtoError;
use veil_proto::identity_document::IdentityDocument;
use veil_proto::identity_proof::IdentityProof;

use super::publish::{PublishError, sign_identity_proof};

// ── Constants ────────────────────────────────────────────────────────────────

/// Filename where the signed [`IdentityDocument`] is persisted.
/// Mirrors [`cfg::sovereign_flow::IDENTITY_DOCUMENT_FILE`] but re-exported
/// here so the loader's contract is self-contained.
pub const IDENTITY_DOCUMENT_FILE: &str = "identity_document.bin";

/// Subdirectory under `veil_dir` where persisted
/// [`NameClaim`](veil_proto::name_claim_v2::NameClaim) files live.
/// Each claim lives at `<veil_dir>/name_claims/<normalized-name>.bin`
/// so `load_persisted_name_claims` can enumerate them with a single
/// directory read.
pub const NAME_CLAIMS_DIR: &str = "name_claims";

// ── Types ────────────────────────────────────────────────────────────────────

/// Runtime handle bundling the signed document + active subkey SK.
///
/// See module docs for invariants and construction contract.
pub struct SovereignIdentity {
    /// The full signed identity document (cert chain, revocations
    /// document sig). Kept in-memory so the handshake can embed
    /// subkey fields into outbound [`IdentityProof`]s without
    /// re-reading the file.
    pub document: IdentityDocument,
    /// Index into `document.identity_keys` of the subkey this handle
    /// signs with. Validated by the constructor.
    pub sig_key_idx: u16,
    /// (Falcon producer): the active
    /// subkey's secret, dispatched by algo. `Ed25519SigningKey`
    /// implements `ZeroizeOnDrop`; Falcon-512 SK lives in
    /// `pqcrypto-falcon`'s structure (no built-in zeroize, but the
    /// SK material is heap-bound and dropped when the handle is).
    identity_sk: IdentitySigningKey,
}

/// Errors emitted by [`SovereignIdentity::reissue_self_delegation`]
///
#[derive(Debug, thiserror::Error)]
pub enum ReissueError {
    #[error(
        "reissue: not standalone — master_pubkey != active_subkey.pubkey, \
         re-issue requires the master_sk which lives on a different device"
    )]
    NotStandalone,
    #[error(
        "reissue: freshness window {secs}s out of range \
         (must be > 0 and ≤ MAX_FRESHNESS_WINDOW_SECS)"
    )]
    FreshnessWindowTooLong { secs: u64 },
    #[error(
        "reissue: new valid_until_unix {proposed} is not strictly later than \
         the current document's {current} — refusing to write a non-progressing \
         delegation"
    )]
    NewValidityNotForward { current: u64, proposed: u64 },
}

#[derive(Debug, thiserror::Error)]
pub enum SovereignIdentityError {
    #[error("sovereign_identity: sig_key_idx {idx} out of bounds ({n_keys} keys)")]
    SigKeyIdxOutOfBounds { idx: u16, n_keys: usize },
    #[error(
        "sovereign_identity: identity_sk derived pubkey does not match document.identity_keys[{idx}].pubkey — \
         wrong SK for the indexed subkey"
    )]
    SkSubkeyMismatch { idx: u16 },
    #[error(
        "sovereign_identity: subkey algo {algo} is not supported (Ed25519 = 1, Falcon-512 = 2)"
    )]
    UnsupportedAlgo { algo: u8 },
    #[error("sovereign_identity: signing-key dispatch error: {0}")]
    SigningKey(#[from] IdentitySigningKeyError),
    #[error("sovereign_identity: i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sovereign_identity: document decode failed: {0}")]
    DocumentDecode(#[from] ProtoError),
    #[error(
        "sovereign_identity: required file `{file}` missing from `{dir}` \
         (has the node been provisioned with `identity create`?)"
    )]
    FileMissing { file: &'static str, dir: String },
}

impl SovereignIdentity {
    /// Construct from already-in-memory material, validating the
    /// SK↔subkey binding and the "active subkey is not revoked"
    /// invariant.
    ///
    /// Caller typically obtains `sig_key_idx` from
    /// `document.sig_key_idx` — see [`Self::from_parts_active`] for
    /// that convenience.
    pub fn from_parts(
        document: IdentityDocument,
        identity_sk_seed: &veil_util::sensitive_bytes::SensitiveBytesN<32>,
        sig_key_idx: u16,
    ) -> Result<Self, SovereignIdentityError> {
        let n_keys = document.identity_keys.len();
        let idx = sig_key_idx as usize;
        let subkey = document.identity_keys.get(idx).ok_or(
            SovereignIdentityError::SigKeyIdxOutOfBounds {
                idx: sig_key_idx,
                n_keys,
            },
        )?;

        // (Falcon producer):
        // * Ed25519 subkeys: 32-byte seed → wrap in `IdentitySigningKey`.
        // * Falcon-512 subkeys: see `from_parts_with_signer` for the
        // SK-bytes path — this constructor is reserved for the
        // 32-byte Ed25519 seed shape. Backward-compatible: existing
        // callers loading a 32-byte seed file continue to work.
        if subkey.algo != veil_proto::identity_document::ALGO_ED25519 {
            return Err(SovereignIdentityError::UnsupportedAlgo { algo: subkey.algo });
        }

        // SK↔subkey cross-check: derive the pubkey from the seed and
        // compare bytes via the dispatcher's challenge-response check.
        let identity_sk = IdentitySigningKey::from_ed25519_seed(*identity_sk_seed.as_array());
        identity_sk
            .verify_skpk_match(&subkey.pubkey)
            .map_err(|_| SovereignIdentityError::SkSubkeyMismatch { idx: sig_key_idx })?;

        Ok(Self {
            document,
            sig_key_idx,
            identity_sk,
        })
    }

    /// (Falcon producer): construct from a
    /// pre-built [`IdentitySigningKey`]. Supports both Ed25519 and
    /// Falcon-512 subkeys. Caller is responsible for safely loading
    /// the SK material from disk (encrypted file, hardware token, etc.)
    /// and constructing the appropriate variant.
    pub fn from_parts_with_signer(
        document: IdentityDocument,
        identity_sk: IdentitySigningKey,
        sig_key_idx: u16,
    ) -> Result<Self, SovereignIdentityError> {
        let n_keys = document.identity_keys.len();
        let idx = sig_key_idx as usize;
        let subkey = document.identity_keys.get(idx).ok_or(
            SovereignIdentityError::SigKeyIdxOutOfBounds {
                idx: sig_key_idx,
                n_keys,
            },
        )?;
        if subkey.algo != identity_sk.algo() {
            return Err(SovereignIdentityError::UnsupportedAlgo { algo: subkey.algo });
        }
        identity_sk
            .verify_skpk_match(&subkey.pubkey)
            .map_err(|_| SovereignIdentityError::SkSubkeyMismatch { idx: sig_key_idx })?;
        Ok(Self {
            document,
            sig_key_idx,
            identity_sk,
        })
    }

    /// Test-only accessor for the embedded `IdentitySigningKey`. Used
    /// by integration tests that need to drive the producer functions
    /// directly; production code calls the dedicated `sign_*` methods
    /// on this handle which forward to `&self.identity_sk` internally.
    #[cfg(test)]
    pub fn identity_signing_key_for_test(&self) -> &crate::signing_key::IdentitySigningKey {
        &self.identity_sk
    }

    /// Audit batch 2026-05-25 phase O: borrow the embedded Ed25519
    /// signing key for service layers that need it directly (currently
    /// only [`veil_anycast::AnycastService::with_signing_key`]
    /// to auto-sign IPC-initiated advertisements).  Returns `None`
    /// for PQ-only identities (Falcon-512 sovereign), wherein the
    /// service should fall back to unsigned advertise.
    ///
    /// Caller pattern:
    ///   let sk_arc = sovereign.ed25519_signing_key()
    ///       .map(|sk| Arc::new(sk.clone()));
    pub fn ed25519_signing_key(&self) -> Option<&ed25519_dalek::SigningKey> {
        self.identity_sk.as_ed25519()
    }

    /// Convenience: use `document.sig_key_idx` as the active index.
    pub fn from_parts_active(
        document: IdentityDocument,
        identity_sk_seed: &veil_util::sensitive_bytes::SensitiveBytesN<32>,
    ) -> Result<Self, SovereignIdentityError> {
        let idx = document.sig_key_idx;
        Self::from_parts(document, identity_sk_seed, idx)
    }

    /// Load from the canonical on-disk layout written by
    /// `cfg::sovereign_flow::create_identity`:
    ///
    /// `<veil_dir>/identity_document.bin` — encoded document
    /// **One of**:
    /// * `<veil_dir>/device_identity_sk.bin` — 32-byte Ed25519 seed
    /// * `<veil_dir>/device_identity_sk_falcon.bin` +
    ///   `<veil_dir>/device_identity_pk_falcon.bin` —
    ///   Falcon-512 keypair
    ///   `<veil_dir>/device_sig_key_idx.bin` — *optional* 2-byte
    ///   override. Present on
    ///   target-side devices whose `identity_sk` signs as a
    ///   subkey whose index isn't `document.sig_key_idx`; absent
    ///   on source-side devices where the doc's `sig_key_idx`
    ///   already matches.
    ///
    /// Returns a validated [`SovereignIdentity`] handle.
    pub fn load_from_dir(veil_dir: &Path) -> Result<Self, SovereignIdentityError> {
        let doc_path = veil_dir.join(IDENTITY_DOCUMENT_FILE);
        if !doc_path.exists() {
            return Err(SovereignIdentityError::FileMissing {
                file: IDENTITY_DOCUMENT_FILE,
                dir: veil_dir.display().to_string(),
            });
        }
        let doc_bytes = std::fs::read(&doc_path)?;
        let document = IdentityDocument::decode(&doc_bytes)?;

        // follow-up: dispatch via the unified loader so
        // both Ed25519 (`device_identity_sk.bin`) and Falcon-512
        // (`device_identity_sk_falcon.bin` + sidecar pk) layouts work
        // transparently. The loader returns `NotFound` when neither
        // file is present — re-mapped to `FileMissing` here for the
        // caller's existing error-handling shape.
        let identity_sk = match crate::sovereign_flow::load_identity_signing_key(veil_dir) {
            Ok(sk) => sk,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SovereignIdentityError::FileMissing {
                    file: DEVICE_IDENTITY_SK_FILE,
                    dir: veil_dir.display().to_string(),
                });
            }
            Err(e) => return Err(SovereignIdentityError::Io(e)),
        };

        let sig_key_idx = match load_device_sig_key_idx(veil_dir)? {
            Some(idx) => idx,
            None => document.sig_key_idx,
        };
        Self::from_parts_with_signer(document, identity_sk, sig_key_idx)
    }

    /// Stable `node_id` (BLAKE3 over master_pubkey). This is
    /// the value runtime code keys its peer-identity cache by.
    pub fn node_id(&self) -> &[u8; 32] {
        &self.document.node_id
    }

    /// Instance_id of the active subkey. : derived from the
    /// deterministic `device_id` (= BLAKE3(active_pubkey)) by truncation
    /// — a compatibility shim for runtime code that still keys on
    /// `[u8; 16]` instance ids. New code should prefer
    /// [`Self::active_device_id`].
    pub fn active_instance_id(&self) -> [u8; 16] {
        let dev = self.active_device_id();
        let mut out = [0u8; 16];
        out.copy_from_slice(&dev[..16]);
        out
    }

    /// Deterministic device address of the active subkey
    /// (`BLAKE3(active_pubkey)`).
    pub fn active_device_id(&self) -> [u8; 32] {
        self.document.identity_keys[self.sig_key_idx as usize].device_id
    }

    /// Produce an [`IdentityProof`] binding this identity to the
    /// handshake's freshly-generated X25519 ephemeral pk. This is
    /// the one-call emitter the runtime handshake invokes at frame
    /// send time.
    pub fn sign_proof(
        &self,
        ephemeral_x25519_pk: [u8; 32],
        proof_valid_until_unix: u64,
        freshness_hour: u32,
    ) -> Result<IdentityProof, PublishError> {
        sign_identity_proof(
            &self.document,
            self.sig_key_idx,
            &self.identity_sk,
            ephemeral_x25519_pk,
            proof_valid_until_unix,
            freshness_hour,
        )
    }

    /// helper: returns `true` iff this handle's active
    /// subkey IS the master key — i.e. the document was built in
    /// standalone mode (or is functionally equivalent: single subkey
    /// whose pubkey equals `master_pubkey`).
    ///
    /// In standalone mode the device's `identity_sk` IS the
    /// `master_sk`, so the runtime can re-issue its own delegation
    /// without an external master ceremony. See
    /// [`Self::reissue_self_delegation`].
    pub fn is_standalone(&self) -> bool {
        let active = &self.document.identity_keys[self.sig_key_idx as usize];
        active.pubkey == self.document.master_pubkey
    }

    /// re-sign the active subkey's delegation with a
    /// fresh `valid_until_unix`. Standalone-mode only — the runtime
    /// holds the master_sk as part of the device's `identity_sk`
    /// (since master_pk == device_pk).
    ///
    /// Multi-device delegations cannot be re-issued by the runtime:
    /// the master keypair lives on a different device. Operators
    /// must run `veil-cli identity delegate-device --validity 7d`
    /// from the master before the existing delegation expires; the
    /// re-signed document is transported back to this device + dropped
    /// into `<veil_dir>/identity_document.bin` (the on-change
    /// reload poll in `runtime/sovereign_republish.rs` picks it up
    /// within 60 s).
    ///
    /// On success, returns the new `IdentityDocument` (with bumped
    /// `valid_until_unix` on both the document AND the active
    /// `IdentityKey`, plus a fresh document signature). Errors
    /// indicate either non-standalone mode or a freshness-window
    /// violation.
    pub fn reissue_self_delegation(
        &self,
        now_unix: u64,
        new_valid_until_unix: u64,
    ) -> Result<IdentityDocument, ReissueError> {
        use veil_crypto::identity::certify_message as build_certify;
        use veil_proto::identity_document::{
            ALGO_ED25519, DOC_SIG_CONTEXT, MAX_FRESHNESS_WINDOW_SECS,
        };

        if !self.is_standalone() {
            return Err(ReissueError::NotStandalone);
        }
        let window = new_valid_until_unix.saturating_sub(now_unix);
        if window == 0 || window > MAX_FRESHNESS_WINDOW_SECS {
            return Err(ReissueError::FreshnessWindowTooLong { secs: window });
        }
        if new_valid_until_unix <= self.document.valid_until_unix {
            return Err(ReissueError::NewValidityNotForward {
                current: self.document.valid_until_unix,
                proposed: new_valid_until_unix,
            });
        }

        let mut new_doc = self.document.clone();
        let active_idx = self.sig_key_idx as usize;
        let active_pubkey = new_doc.identity_keys[active_idx].pubkey.clone();
        let active_device_id = new_doc.identity_keys[active_idx].device_id;
        let valid_from = new_doc.identity_keys[active_idx].valid_from_unix;

        // Standalone re-issue: master_sk == identity_sk, so the
        // self.identity_sk produces both the cert sig and the doc sig.
        let cert_msg = build_certify(
            &new_doc.node_id,
            ALGO_ED25519,
            &active_pubkey,
            &active_device_id,
            valid_from,
            new_valid_until_unix,
        );
        let cert_sig = self.identity_sk.sign(&cert_msg);

        new_doc.identity_keys[active_idx].valid_until_unix = new_valid_until_unix;
        new_doc.identity_keys[active_idx].master_sig = cert_sig;
        new_doc.issued_at_unix = now_unix;
        new_doc.valid_until_unix = new_valid_until_unix;

        // Re-sign the document with (unchanged) identity_sk.
        let mut doc_msg = Vec::with_capacity(DOC_SIG_CONTEXT.len() + 512);
        doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
        doc_msg.extend_from_slice(&new_doc.canonical_signing_bytes());
        new_doc.document_sig = self.identity_sk.sign(&doc_msg);

        Ok(new_doc)
    }

    /// source-side: sign a pairing invite binding this
    /// identity to a fresh `pair_secret_hash`. The caller owns the
    /// raw `pair_secret` (never persisted) and must render it into
    /// a `PairingUri` / QR separately — only its hash is signed
    /// here, so a scanned URI can be checked against the published
    /// invite.
    pub fn sign_pair_invite(
        &self,
        pair_secret_hash: [u8; 32],
        issued_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<veil_proto::pairing_invite::PairingInvite, PublishError> {
        crate::publish::sign_pairing_invite(
            self.document.node_id,
            pair_secret_hash,
            self.active_instance_id(),
            issued_at_unix,
            expires_at_unix,
            self.sig_key_idx,
            &self.identity_sk,
            &self.document,
        )
    }

    /// runtime: mine + sign a fresh
    /// [`NameClaim`](veil_proto::name_claim_v2::NameClaim) binding
    /// `name` to this identity. The input name is normalized (via
    /// `name_claim_v2::normalize_name`) and rarity-proportional PoW is
    /// mined inside `sign_name_claim`.
    ///
    /// Production callers (CLI `identity claim-name`) run this on a
    /// worker thread and persist the result to disk via
    /// [`save_name_claim`]. Runtime startup scans the persisted
    /// claims and DHT-publishes each one.
    pub fn sign_name_claim(
        &self,
        name: &str,
        claimed_at_unix: u64,
    ) -> Result<veil_proto::name_claim_v2::NameClaim, PublishError> {
        use crate::publish::{build_name_claim, sign_name_claim};
        use veil_proto::name_claim_v2;

        let normalized =
            name_claim_v2::normalize_name(name).map_err(PublishError::NameNormalization)?;
        let draft = build_name_claim(
            normalized,
            self.document.node_id,
            claimed_at_unix,
            self.sig_key_idx,
        );
        sign_name_claim(draft, &self.identity_sk)
    }

    /// runtime: sign a per-instance
    /// [`MlKemKeyCert`](veil_proto::mlkem_cert::MlKemKeyCert) binding
    /// this node's ML-KEM-768 encapsulation key to the active subkey
    /// of the identity document.
    ///
    /// Runtime callers (`NodeRuntime::start`) use this to certify
    /// their own `mlkem_ek` at startup — peers can then E2E-encrypt
    /// payloads toward this node without a separate key-exchange
    /// round-trip. The cert is DHT-published at the canonical
    /// `(node_id, instance_id)` slot and replaces
    /// on each rotation.
    ///
    /// `cert_version` is monotonic across key rotations; `valid_from` /
    /// `valid_until` are usually `now` and `now + 30 days` per the
    /// spec — callers set them to pin clock expectations.
    pub fn sign_mlkem_cert(
        &self,
        mlkem_pubkey: Vec<u8>,
        valid_from_unix: u64,
        valid_until_unix: u64,
        cert_version: u64,
    ) -> Result<veil_proto::mlkem_cert::MlKemKeyCert, PublishError> {
        crate::publish::sign_mlkem_cert(
            self.document.node_id,
            self.active_instance_id(),
            mlkem_pubkey,
            valid_from_unix,
            valid_until_unix,
            cert_version,
            self.sig_key_idx,
            &self.identity_sk,
            &self.document,
        )
    }

    /// runtime: build + sign a fresh
    /// [`InstanceRegistry`](veil_proto::instance_registry::InstanceRegistry)
    /// that advertises this node's `instances`.
    ///
    /// The runtime calls this at startup to produce the registry
    /// shipped to the DHT alongside the identity document. For
    /// single-device identities `instances` is a single-entry vec
    /// carrying this node's `InstanceEntry`; multi-device identities
    /// (future pairing / sync) extend the list.
    ///
    /// `reg_version` is monotonic — callers either persist the
    /// previous value and bump, or (for now) stamp `1` on every
    /// fresh startup; peers tie-break on `(reg_version, sig)` so
    /// publishing the same version repeatedly is benign.
    pub fn build_and_sign_registry(
        &self,
        reg_version: u64,
        instances: Vec<veil_proto::instance_registry::InstanceEntry>,
    ) -> veil_proto::instance_registry::InstanceRegistry {
        use crate::publish::{build_instance_registry, sign_instance_registry};
        let draft = build_instance_registry(
            self.document.node_id,
            reg_version,
            self.sig_key_idx,
            instances,
        );
        sign_instance_registry(draft, &self.identity_sk)
    }
}

// ── NameClaim disk persistence ───────────────────

/// Persist `claim` to `<veil_dir>/name_claims/<name>.bin` with an
/// atomic tmp-then-rename so a partial write never leaves a
/// half-signed claim on disk. Overwrites if the file already exists
/// (re-claiming a name after rotation produces a newer signature with
/// the same name).
pub fn save_name_claim(
    veil_dir: &std::path::Path,
    claim: &veil_proto::name_claim_v2::NameClaim,
) -> std::io::Result<std::path::PathBuf> {
    use std::fs;
    use std::io::Write as _;

    let dir = veil_dir.join(NAME_CLAIMS_DIR);
    veil_util::create_dir_all_with_eacces_retry(&dir)?;
    // `claim.name` is already normalized at sign time — safe to use as a filename.
    let path = dir.join(format!("{}.bin", claim.name));
    let tmp = path.with_extension("tmp");
    veil_util::with_eacces_retry(|| {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&claim.encode())?;
        f.sync_all()?;
        Ok(())
    })?;
    match fs::rename(&tmp, &path) {
        Ok(()) => Ok(path),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Load all persisted [`NameClaim`](veil_proto::name_claim_v2::NameClaim)
/// files from `<veil_dir>/name_claims/*.bin`. Files that fail to
/// decode (partial writes mid-update, corrupt content) are silently
/// skipped — a single bad claim must not block startup publish of
/// the remaining good ones.
///
/// Returns an empty `Vec` when the directory does not exist (the
/// common case for a freshly-provisioned node with no names claimed).
pub fn load_persisted_name_claims(
    veil_dir: &std::path::Path,
) -> std::io::Result<Vec<veil_proto::name_claim_v2::NameClaim>> {
    let dir = veil_dir.join(NAME_CLAIMS_DIR);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("bin") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if let Ok(claim) = veil_proto::name_claim_v2::NameClaim::decode(&bytes) {
            out.push(claim);
        }
    }
    // Deterministic order for runtime observability (log lines list claims
    // in the same order run-over-run).
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

impl std::fmt::Debug for SovereignIdentity {
    /// Avoid Debug-leaking the identity_sk. The derived
    /// `SigningKey::Debug` is safe (it zeroes), but handlers that
    /// log the whole `SovereignIdentity` would still expose the SK
    /// representation. Hide it explicitly.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SovereignIdentity")
            .field("node_id", &self.document.node_id)
            .field("sig_key_idx", &self.sig_key_idx)
            .field("document.valid_until_unix", &self.document.valid_until_unix)
            .field("identity_sk", &"<redacted>")
            .finish()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use crate::sovereign_flow::{CreateIdentityOptions, create_identity};
    use crate::verify::{verify_identity_document, verify_identity_proof_frame};

    use std::path::PathBuf;

    /// Test PoW difficulty kept low so create_identity completes in
    /// milliseconds during tests.
    const TEST_POW_DIFFICULTY: u32 = 8;

    fn tempdir() -> PathBuf {
        crate::test_support::scratch_dir("veil-sovereign-tests")
    }

    fn fresh_dir_with_identity() -> (PathBuf, crate::sovereign_flow::CreateIdentityOutput) {
        let dir = tempdir();
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "test".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();
        (dir, out)
    }

    #[test]
    fn load_from_dir_happy_path() {
        let (dir, out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).expect("load ok");
        assert_eq!(sov.node_id(), &out.node_id);
        // `active_instance_id` is derived deterministically
        // from the active subkey's device_id (truncated), not from the
        // legacy on-disk `LocalInstance.instance_id`.
        assert_eq!(
            sov.active_device_id(),
            out.document.identity_keys[out.document.sig_key_idx as usize].device_id
        );
        assert_eq!(sov.sig_key_idx, out.document.sig_key_idx);
    }

    #[test]
    fn load_from_dir_honours_sig_key_idx_override() {
        // Simulate a paired target: doc has `sig_key_idx = 0` but
        // this device's identity_sk corresponds to a later subkey.
        // Persist the override file and assert `load_from_dir`
        // uses it (via `from_parts`, not `from_parts_active`).
        use crate::sovereign_flow::{save_device_sig_key_idx, save_identity_sk};
        use ed25519_dalek::SigningKey as EdSk;
        use veil_proto::identity_document::IdentityKey;

        let (dir, out) = fresh_dir_with_identity();

        // Append a second IdentityKey for a fake "target device" —
        // we only need the binding `SK seed → subkey.pubkey` to be
        // consistent for `from_parts` to accept it.
        let mut doc = out.document.clone();
        let tgt_seed: veil_util::sensitive_bytes::SensitiveBytesN<32> =
            veil_util::sensitive_bytes::SensitiveBytesN::from_bytes([0x33u8; 32]);
        let tgt_sk = EdSk::from_bytes(tgt_seed.as_array());
        let tgt_pk = tgt_sk.verifying_key();
        doc.identity_keys.push(IdentityKey {
            algo: veil_proto::identity_document::ALGO_ED25519,
            pubkey: tgt_pk.as_bytes().to_vec(),
            device_id: veil_crypto::identity::compute_node_id(tgt_pk.as_bytes()),
            valid_from_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            master_sig: vec![0u8; 64], // signature not verified by
                                       // `SovereignIdentity` at load time
        });
        let new_idx = (doc.identity_keys.len() - 1) as u16;

        // Overwrite disk with the mutated doc + target's SK seed +
        // override pointer.
        std::fs::write(dir.join(IDENTITY_DOCUMENT_FILE), doc.encode()).unwrap();
        save_identity_sk(&dir, &tgt_seed).unwrap();
        save_device_sig_key_idx(&dir, new_idx).unwrap();

        let sov = SovereignIdentity::load_from_dir(&dir).expect("load ok");
        assert_eq!(sov.sig_key_idx, new_idx);
        // `from_parts_active` would have rejected with `SkSubkeyMismatch`
        // since doc.sig_key_idx still points at slot 0 and its
        // SK is the source's, not the target's.
    }

    #[test]
    fn load_from_dir_without_override_falls_back_to_document_sig_key_idx() {
        // Backward-compat guard: the override file is optional;
        // `load_from_dir` must still work for single-device layouts.
        let (dir, out) = fresh_dir_with_identity();
        assert!(
            !dir.join(crate::sovereign_flow::DEVICE_SIG_KEY_IDX_FILE)
                .exists()
        );

        let sov = SovereignIdentity::load_from_dir(&dir).expect("load ok");
        assert_eq!(sov.sig_key_idx, out.document.sig_key_idx);
    }

    #[test]
    fn load_rejects_missing_document() {
        let dir = tempdir();
        // No files written — loader must report the expected filename.
        let err = SovereignIdentity::load_from_dir(&dir).unwrap_err();
        match err {
            SovereignIdentityError::FileMissing { file, .. } => {
                assert_eq!(file, IDENTITY_DOCUMENT_FILE);
            }
            other => panic!("expected FileMissing, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_missing_identity_sk() {
        let (dir, _out) = fresh_dir_with_identity();
        std::fs::remove_file(dir.join(DEVICE_IDENTITY_SK_FILE)).unwrap();
        let err = SovereignIdentity::load_from_dir(&dir).unwrap_err();
        match err {
            SovereignIdentityError::FileMissing { file, .. } => {
                assert_eq!(file, DEVICE_IDENTITY_SK_FILE);
            }
            other => panic!("expected FileMissing, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_corrupted_document() {
        let (dir, _out) = fresh_dir_with_identity();
        std::fs::write(dir.join(IDENTITY_DOCUMENT_FILE), b"garbage").unwrap();
        let err = SovereignIdentity::load_from_dir(&dir).unwrap_err();
        assert!(
            matches!(err, SovereignIdentityError::DocumentDecode(_)),
            "{err:?}"
        );
    }

    #[test]
    fn load_rejects_wrong_sk_seed() {
        // Overwrite the SK file with random bytes so the derived
        // pubkey no longer matches the document's active subkey.
        let (dir, _out) = fresh_dir_with_identity();
        std::fs::write(dir.join(DEVICE_IDENTITY_SK_FILE), [0xFFu8; 32]).unwrap();
        let err = SovereignIdentity::load_from_dir(&dir).unwrap_err();
        assert!(
            matches!(err, SovereignIdentityError::SkSubkeyMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn from_parts_rejects_out_of_bounds_idx() {
        let (_, out) = fresh_dir_with_identity();
        let err = SovereignIdentity::from_parts(out.document.clone(), &out.identity_sk_seed, 99)
            .unwrap_err();
        assert!(
            matches!(err, SovereignIdentityError::SigKeyIdxOutOfBounds { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn sign_proof_round_trips_through_frame_consumer() {
        // End-to-end plausibility: a `SovereignIdentity` produces a
        // proof that the runtime-facing frame consumer accepts
        // against the same ephemeral_pk. This is the exact loop
        // `node/session/handshake.rs` will run.
        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();

        let now = 1_700_000_000u64;
        let eph_pk = veil_crypto::kex::generate_ephemeral().public_key;
        let proof = sov
            .sign_proof(eph_pk, now + 300, (now / 3600) as u32)
            .unwrap();
        let body = proof.encode();

        let validated = verify_identity_proof_frame(&body, &eph_pk, now).unwrap();
        assert_eq!(validated.node_id, *sov.node_id());
        assert_eq!(validated.active_instance_id, sov.active_instance_id());
    }

    #[test]
    fn sign_name_claim_produces_valid_claim() {
        // Helper signs a name claim; the resulting bytes decode back
        // to the same struct and the embedded node_id/sig_key_idx
        // match self.
        use veil_proto::name_claim_v2::NameClaim;

        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        let now = 1_700_000_000u64;

        let claim = sov.sign_name_claim("alice", now).unwrap();
        assert_eq!(claim.name, "alice");
        assert_eq!(claim.node_id, *sov.node_id());
        assert_eq!(claim.signing_identity_key_idx, sov.sig_key_idx);
        assert!(!claim.sig.is_empty());

        // Wire round-trip.
        let bytes = claim.encode();
        let decoded = NameClaim::decode(&bytes).unwrap();
        assert_eq!(decoded, claim);
    }

    #[test]
    fn sign_name_claim_rejects_non_normalizable_name() {
        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        // Unicode homoglyph — normalize_name rejects.
        let err = sov.sign_name_claim("alíce", 1_700_000_000).unwrap_err();
        assert!(matches!(err, PublishError::NameNormalization(_)), "{err:?}");
    }

    #[test]
    fn save_and_load_name_claim_roundtrips() {
        // Sign + save a claim, then scan the directory — the loader
        // must return exactly what was saved.
        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        let claim = sov.sign_name_claim("bob", 1_700_000_000).unwrap();

        let saved_path = save_name_claim(&dir, &claim).unwrap();
        assert!(saved_path.exists());
        assert_eq!(
            saved_path.file_name().and_then(|s| s.to_str()),
            Some("bob.bin"),
        );

        let loaded = load_persisted_name_claims(&dir).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], claim);
    }

    #[test]
    fn load_persisted_name_claims_handles_missing_dir() {
        // Fresh veil_dir with no `name_claims/` subdirectory returns
        // empty — not an error.
        let dir = tempdir();
        assert!(load_persisted_name_claims(&dir).unwrap().is_empty());
    }

    #[test]
    fn load_persisted_name_claims_skips_corrupt_files() {
        // A partial/garbage.bin file must not block scanning the rest
        // of the valid claims.
        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();

        // Write a good claim.
        let good = sov.sign_name_claim("carol", 1_700_000_000).unwrap();
        save_name_claim(&dir, &good).unwrap();

        // Write a bad.bin file alongside it.
        let bad_path = dir.join(NAME_CLAIMS_DIR).join("garbage.bin");
        std::fs::write(&bad_path, b"not a valid NameClaim").unwrap();

        let loaded = load_persisted_name_claims(&dir).unwrap();
        assert_eq!(loaded.len(), 1, "only the good claim loads");
        assert_eq!(loaded[0], good);
    }

    #[test]
    fn sign_mlkem_cert_verifies_against_document() {
        // Helper signs an ML-KEM cert for an ephemeral keypair; the
        // cert must verify through the `verify_mlkem_cert` consumer
        // path (same function runtime peers call to validate).
        use crate::mlkem_fanout::verify_mlkem_cert;
        use veil_crypto::x3dh::generate_prekey;

        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        let now = 1_700_000_000u64;

        let (ek, _dk_seed) = generate_prekey();
        let cert = sov
            .sign_mlkem_cert(ek, now - 60, now + 30 * 86_400, 1)
            .unwrap();

        assert_eq!(cert.node_id, *sov.node_id());
        assert_eq!(cert.instance_id, sov.active_instance_id());
        assert_eq!(cert.cert_version, 1);

        // Full verify through the consumer API — cert chain + window
        // + subkey-in-doc checks all pass.
        let verified = verify_mlkem_cert(&cert, &sov.document, now).unwrap();
        assert_eq!(verified.node_id, *sov.node_id());
        assert_eq!(verified.instance_id, sov.active_instance_id());
    }

    #[test]
    fn build_and_sign_registry_verifies_against_document() {
        // Build a single-entry registry for this node's instance
        // sign it, and confirm:
        // (a) the sig verifies with the active identity subkey
        // (b) the encoded bytes round-trip cleanly through decode
        // (c) the embedded node_id + sig_key_idx match `self`.
        use crate::publish::build_instance_entry;
        use ed25519_dalek::Verifier as _;
        use veil_proto::instance_registry::{INSTANCE_REGISTRY_SIG_CONTEXT, InstanceRegistry};

        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();

        let entry = build_instance_entry(
            sov.active_instance_id(),
            sov.sig_key_idx,
            "laptop".into(),
            0,
        );
        let reg = sov.build_and_sign_registry(1, vec![entry]);

        // Wire round-trip.
        let bytes = reg.encode();
        let decoded = InstanceRegistry::decode(&bytes).unwrap();
        assert_eq!(decoded, reg);

        // Correct node_id + sig_key_idx.
        assert_eq!(decoded.node_id, *sov.node_id());
        assert_eq!(decoded.signing_identity_key_idx, sov.sig_key_idx);
        assert_eq!(decoded.reg_version, 1);
        assert_eq!(decoded.instances.len(), 1);

        // Signature verifies against the active subkey's pubkey.
        let active_pk = &sov.document.identity_keys[sov.sig_key_idx as usize].pubkey;
        let pk_arr: &[u8; 32] = active_pk.as_slice().try_into().unwrap();
        let pk = ed25519_dalek::VerifyingKey::from_bytes(pk_arr).unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(INSTANCE_REGISTRY_SIG_CONTEXT);
        msg.extend_from_slice(&decoded.canonical_signing_bytes());
        let sig = ed25519_dalek::Signature::from_slice(&decoded.sig).unwrap();
        pk.verify(&msg, &sig).expect("registry sig verifies");
    }

    #[test]
    fn loaded_document_passes_full_verifier() {
        // Sanity: what we loaded is also what the document verifier
        // signs off on. If this ever regresses, the loader and
        // verifier have drifted apart.
        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        verify_identity_document(&sov.document, 1_700_000_000).expect("loaded document verifies");
    }

    #[test]
    fn debug_impl_redacts_identity_sk() {
        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        let s = format!("{sov:?}");
        assert!(s.contains("<redacted>"), "Debug must redact SK: {s}");
        assert!(
            !s.contains("SigningKey"),
            "Debug must not leak inner type: {s}"
        );
    }

    // ── standalone re-issue ────────────────────────────────────

    fn fresh_standalone_dir() -> (PathBuf, veil_proto::identity_document::IdentityDocument) {
        use crate::sovereign_flow::save_standalone_identity_to_dir;
        use veil_proto::identity_document::DELEGATION_VALIDITY_SECS;
        let dir = tempdir();
        let now = 1_700_000_000u64;
        let valid_until = now + DELEGATION_VALIDITY_SECS;
        // Deterministic seed so the test pins one identity.
        let seed: veil_util::sensitive_bytes::SensitiveBytesN<32> =
            veil_util::sensitive_bytes::SensitiveBytesN::from_bytes([0xA5u8; 32]);
        let doc = save_standalone_identity_to_dir(&dir, &seed, now, valid_until)
            .expect("standalone save");
        (dir, doc)
    }

    #[test]
    fn standalone_load_reports_is_standalone() {
        let (dir, _) = fresh_standalone_dir();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        assert!(sov.is_standalone(), "standalone flag must be true");
    }

    #[test]
    fn multi_device_load_reports_not_standalone() {
        // Normal `create_identity` produces master_pk!= device_pk
        // (master is derived from a fresh master_seed; device gets
        // its own random Ed25519 key). The flag must be false.
        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        assert!(
            !sov.is_standalone(),
            "create_identity produces master != device → not standalone",
        );
    }

    #[test]
    fn reissue_self_delegation_extends_valid_until_and_verifies() {
        use crate::verify::verify_identity_document;
        use veil_proto::identity_document::DELEGATION_VALIDITY_SECS;

        let (dir, original) = fresh_standalone_dir();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();

        let now = original.issued_at_unix + DELEGATION_VALIDITY_SECS / 2 + 100;
        let new_valid_until = now + DELEGATION_VALIDITY_SECS;
        let new_doc = sov
            .reissue_self_delegation(now, new_valid_until)
            .expect("standalone reissue");
        assert!(new_doc.valid_until_unix > original.valid_until_unix);
        assert_eq!(new_doc.valid_until_unix, new_valid_until);
        assert_eq!(
            new_doc.identity_keys[0].valid_until_unix, new_valid_until,
            "per-key valid_until must match the document-level extension",
        );
        // Same node_id, same active pubkey — only the windows + sigs change.
        assert_eq!(new_doc.node_id, original.node_id);
        assert_eq!(
            new_doc.identity_keys[0].pubkey,
            original.identity_keys[0].pubkey,
        );
        // Verifier accepts the re-issued document.
        verify_identity_document(&new_doc, now).expect("re-issued doc verifies");
    }

    #[test]
    fn reissue_rejects_non_standalone() {
        // Multi-device handle (master!= device) cannot self-reissue —
        // the runtime doesn't have access to the master_sk.
        let (dir, _out) = fresh_dir_with_identity();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        let err = sov
            .reissue_self_delegation(1_700_500_000, 1_700_500_000 + 7 * 86_400)
            .unwrap_err();
        assert!(matches!(err, ReissueError::NotStandalone), "{err:?}");
    }

    #[test]
    fn reissue_rejects_non_progressing_validity() {
        let (dir, original) = fresh_standalone_dir();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        let err = sov
            .reissue_self_delegation(
                original.issued_at_unix + 100,
                original.valid_until_unix, // not strictly later
            )
            .unwrap_err();
        assert!(
            matches!(err, ReissueError::NewValidityNotForward { .. }),
            "{err:?}",
        );
    }

    #[test]
    fn reissue_rejects_oversized_window() {
        use veil_proto::identity_document::MAX_FRESHNESS_WINDOW_SECS;
        let (dir, _) = fresh_standalone_dir();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        let now = 1_700_900_000u64;
        let err = sov
            .reissue_self_delegation(now, now + MAX_FRESHNESS_WINDOW_SECS + 1)
            .unwrap_err();
        assert!(
            matches!(err, ReissueError::FreshnessWindowTooLong { .. }),
            "{err:?}",
        );
    }

    #[test]
    fn reissue_preserves_active_device_id() {
        // device_id = BLAKE3(pubkey) is a function of the pubkey
        // and re-issue does not rotate the pubkey — so device_id
        // must be byte-identical pre/post re-issue. Peers' caches
        // keyed on (node_id, device_id) keep working unchanged.
        let (dir, original) = fresh_standalone_dir();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        let now = original.issued_at_unix + 100;
        let new_doc = sov.reissue_self_delegation(now, now + 7 * 86_400).unwrap();
        assert_eq!(
            new_doc.identity_keys[0].device_id, original.identity_keys[0].device_id,
            "re-issue MUST NOT rotate device_id (same pubkey, same hash)",
        );
    }
}
