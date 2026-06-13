//! Pairing-ceremony state machines.
//!
//! Two tiny transport-agnostic state machines that exchange the
//! three frames defined [`veil_proto::pair_session`]:
//!
//! * [`PairingSource`] holds the pre-unlocked `master_sk` + active
//!   `identity_sk` + loaded [`IdentityDocument`], waits for a Hello
//!   on the attached channel, runs the X25519 + BLAKE3-MAC checks
//!   appends a master-certified `IdentityKey` for the target, and
//!   emits the Cert. Then waits for a Confirm and returns the
//!   final state.
//! * [`PairingTarget`] holds the scanned [`PairingUri`], generates
//!   its own fresh Ed25519 identity SK + X25519 ephemeral, emits
//!   the Hello, consumes the Cert (deriving the shared session
//!   key + 6-digit OOB code), and — once the user's compared
//!   screens match — emits the Confirm.
//!
//! Transport is explicitly out of scope — the methods take `&[u8]`
//! incoming and return `Vec<u8>` outgoing; a caller wires them over
//! TCP / QUIC / the existing session framer at integration time.
//! The end-to-end test in this file drives both sides through an
//! in-memory duplex.
//!
//! # Session-key derivation
//!
//! Both sides compute
//!
//! ```text
//! shared = X25519(my_ephemeral_sk, peer_ephemeral_pk)
//! session_key = BLAKE3_keyed(pair_secret, PAIR_SESSION_CONTEXT || shared)
//! ```
//!
//! `pair_secret` is mixed in **as the BLAKE3 key**, so only parties
//! that hold the raw QR secret can reproduce the session key. The
//! OOB code comes from
//! [`derive_pair_oob_code`](veil_crypto::pair_oob::derive_pair_oob_code).
//!
//! # Scope of this slice
//!
//! What this module does **not** do yet (follow-up slices for the
//! full runtime):
//!
//! * dial a TCP endpoint (target) / listen for one (source) —
//!   transport wiring + session framer integration;
//! * prompt the user for the master-file password to unlock
//!   `master_sk` (CLI concern);
//! * persist the new document + target identity_sk seed to disk
//!   (CLI concern);
//! * republish the doc / registry to the DHT (runtime loop
//!   concern);
//! * emit `DeviceLinkedEvent` + watcher integration.
//!
//! The state machines here cover the cryptographic core: transcript
//! MAC, DH, master-cert, session-key derivation, OOB computation
//! and confirm-proof binding.

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSec};
use zeroize::Zeroizing;

use veil_crypto::identity::certify_message as build_certify;
use veil_crypto::pair_oob::derive_pair_oob_code;
use veil_proto::identity_document::{
    ALGO_ED25519, DOC_SIG_CONTEXT, IdentityDocument, IdentityKey, MAX_IDENTITY_KEYS,
};
use veil_proto::pair_session::{
    PAIR_CONFIRM_PROOF_CONTEXT, PairSessionError, PairingCert, PairingConfirm, PairingHello,
};
use veil_proto::pairing_invite::{PAIR_SECRET_LEN, PairingUri, hash_pair_secret};

// ── Constants ────────────────────────────────────────────────────────────────

/// Domain tag mixed into the session-key derivation. Distinct from
/// the OOB tag so the session key and the OOB digits can't alias.
pub const PAIR_SESSION_CONTEXT: &[u8] = b"veil.pair.session.v1";

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PairCeremonyError {
    #[error("pair ceremony: wire frame: {0}")]
    Wire(#[from] PairSessionError),
    #[error("pair ceremony: hello's pair_secret_hash does not match scanned URI")]
    PairSecretMismatch,
    #[error(
        "pair ceremony: hello MAC verification failed — target didn't hold the raw pair_secret"
    )]
    BadHelloMac,
    #[error("pair ceremony: confirm proof failed — target's session_key differed (MITM?)")]
    BadConfirmProof,
    #[error("pair ceremony: user aborted — OOB codes didn't match")]
    UserAborted,
    #[error("pair ceremony: identity document decode: {0}")]
    DocumentDecode(String),
    #[error("pair ceremony: identity document verification failed: {0}")]
    DocumentVerify(String),
    #[error("pair ceremony: document already at MAX_IDENTITY_KEYS ({MAX_IDENTITY_KEYS})")]
    IdentityKeysFull,
    #[error("pair ceremony: wrong state ({actual}) — expected {expected}")]
    WrongState {
        actual: &'static str,
        expected: &'static str,
    },
    #[error("pair ceremony: cert's appended node_id does not match scanned URI's node_id")]
    CertIdentityIdMismatch,
    #[error("pair ceremony: peer sent a non-contributory (low-order) X25519 ephemeral key")]
    NonContributoryDh,
}

// ── Session-key helpers (shared) ─────────────────────────────────────────────

fn derive_session_key(
    my_ephemeral_sk: &XSec,
    peer_ephemeral_pk: &[u8; 32],
    pair_secret: &[u8; PAIR_SECRET_LEN],
) -> Result<[u8; 32], PairCeremonyError> {
    let shared = my_ephemeral_sk.diffie_hellman(&XPub::from(*peer_ephemeral_pk));
    // Defense-in-depth: reject a low-order / degenerate peer ephemeral key that
    // forces a non-contributory (all-zero) shared secret. The session key is
    // ALREADY keyed by the OOB `pair_secret` (so a forced `shared` is not by
    // itself enough to derive it, and the OOB-code confirm catches a MITM), but
    // rejecting early forecloses the degenerate-DH foot-gun entirely at ~zero
    // cost.
    if !shared.was_contributory() {
        return Err(PairCeremonyError::NonContributoryDh);
    }
    let mut keyed = Hasher::new_keyed(pair_secret);
    keyed.update(PAIR_SESSION_CONTEXT);
    keyed.update(shared.as_bytes());
    Ok(*keyed.finalize().as_bytes())
}

fn mac_hello(pair_secret: &[u8; PAIR_SECRET_LEN], mac_input: &[u8]) -> [u8; 32] {
    let mut keyed = Hasher::new_keyed(pair_secret);
    keyed.update(mac_input);
    *keyed.finalize().as_bytes()
}

fn proof_confirm(session_key: &[u8; 32], confirmed: bool) -> [u8; 32] {
    let mut keyed = Hasher::new_keyed(session_key);
    keyed.update(PAIR_CONFIRM_PROOF_CONTEXT);
    keyed.update(&[u8::from(confirmed)]);
    *keyed.finalize().as_bytes()
}

// ── Document re-sign after appending a subkey ────────────────────────────────

fn resign_document(doc: &mut IdentityDocument, identity_sk: &SigningKey) {
    let mut msg = Vec::with_capacity(DOC_SIG_CONTEXT.len() + doc.encoded_len());
    msg.extend_from_slice(DOC_SIG_CONTEXT);
    msg.extend_from_slice(&doc.canonical_signing_bytes());
    doc.document_sig = identity_sk.sign(&msg).to_bytes().to_vec();
}

// ── PairingSource ────────────────────────────────────────────────────────────

/// State of the source-side ceremony.
#[derive(Debug, PartialEq, Eq)]
enum SourceState {
    /// Waiting for the target's Hello.
    AwaitingHello,
    /// Cert has been sent; waiting for the target's Confirm.
    AwaitingConfirm,
    /// Ceremony finished (either confirmed or aborted).
    Finished,
}

/// Source-side state machine. Construct with the already-loaded
/// identity document + active `identity_sk` + unlocked `master_sk`
/// + the raw `pair_secret` that was rendered into the QR earlier.
pub struct PairingSource {
    /// Mutable working copy of the identity document. Starts as
    /// the on-disk doc; on successful ceremony the target's
    /// `IdentityKey` has been appended and the doc re-signed.
    document: IdentityDocument,
    /// Active identity subkey SK — signs the document_sig.
    identity_sk: SigningKey,
    /// Master SK — master-certifies the target's new subkey.
    /// Expected to have been unlocked by the CLI via password prompt.
    master_sk: SigningKey,
    /// Raw 32-B pair secret from the QR we published.
    pair_secret: [u8; PAIR_SECRET_LEN],
    /// Source's ephemeral X25519 secret. Lives only for this
    /// ceremony; dropped at `Finished`.
    ek_sk: Option<XSec>,
    /// Derived session key (set once Hello is processed).
    session_key: Option<[u8; 32]>,
    /// Wall clock injected by the caller — tests pass fixed times
    /// production passes `SystemTime::now.duration_since(EPOCH)`.
    now_unix: u64,
    state: SourceState,
}

/// Outcome [`PairingSource::handle_hello`].
#[derive(Debug)]
pub struct SourceHelloOutcome {
    /// Bytes to send back to the target (the encoded Cert).
    pub cert_bytes: Vec<u8>,
    /// 6-digit code the source is about to display for the user
    /// to compare against the target's screen.
    pub oob_code: String,
    /// Echo of the target's new `identity_key` idx in `document` —
    /// useful for the CLI to log / display which slot got used.
    pub appended_identity_key_idx: u16,
}

impl PairingSource {
    pub fn new(
        document: IdentityDocument,
        identity_sk: SigningKey,
        master_sk: SigningKey,
        pair_secret: [u8; PAIR_SECRET_LEN],
        now_unix: u64,
    ) -> Self {
        Self {
            document,
            identity_sk,
            master_sk,
            pair_secret,
            ek_sk: None,
            session_key: None,
            now_unix,
            state: SourceState::AwaitingHello,
        }
    }

    /// Consume a Hello frame. Verifies the target's MAC over the
    /// pair_secret, derives the session key via X25519, master-
    /// certifies the target's `target_identity_pk`, appends the new
    /// `IdentityKey`, re-signs the document, and returns the Cert
    /// bytes + the OOB code.
    pub fn handle_hello(
        &mut self,
        hello_bytes: &[u8],
    ) -> Result<SourceHelloOutcome, PairCeremonyError> {
        if self.state != SourceState::AwaitingHello {
            return Err(PairCeremonyError::WrongState {
                actual: self.state_name(),
                expected: "awaiting_hello",
            });
        }
        let hello = PairingHello::decode(hello_bytes)?;

        // 1. Correlate pair_secret via its published hash.
        if hello.pair_secret_hash != hash_pair_secret(&self.pair_secret) {
            return Err(PairCeremonyError::PairSecretMismatch);
        }

        // 2. Verify MAC over the prior fields, keyed by pair_secret.
        // Note: the MAC input prepends PAIR_HELLO_MAC_CONTEXT
        // (checked here via `mac_input` inside the BLAKE3 keyed
        // hash).
        let mac_input = PairingHello::mac_input(
            &hello.pair_secret_hash,
            &hello.target_ephemeral_x25519_pk,
            &hello.target_identity_pk,
            &hello.target_instance_id,
        );
        let expected_mac = mac_hello(&self.pair_secret, &mac_input);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            &expected_mac[..],
            &hello.mac[..],
        )) {
            return Err(PairCeremonyError::BadHelloMac);
        }

        // 3. Session-key derivation. Source draws its ephemeral
        // X25519 secret now (not during construction) so the
        // key material lives no longer than strictly needed.
        let mut ek_seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *ek_seed);
        let ek_sk = XSec::from(*ek_seed);
        let ek_pk = XPub::from(&ek_sk);
        let session_key =
            derive_session_key(&ek_sk, &hello.target_ephemeral_x25519_pk, &self.pair_secret)?;

        // 4. Master-certify the target subkey.
        if self.document.identity_keys.len() >= MAX_IDENTITY_KEYS {
            return Err(PairCeremonyError::IdentityKeysFull);
        }
        // deterministic device_id binding + 7-day delegation.
        let target_device_id = veil_crypto::identity::compute_node_id(&hello.target_identity_pk);
        let key_valid_until =
            self.now_unix + veil_proto::identity_document::DELEGATION_VALIDITY_SECS;
        let cert_msg = build_certify(
            &self.document.node_id,
            ALGO_ED25519,
            &hello.target_identity_pk,
            &target_device_id,
            self.now_unix,
            key_valid_until,
        );
        let cert_sig = self.master_sk.sign(&cert_msg);
        self.document.identity_keys.push(IdentityKey {
            algo: ALGO_ED25519,
            pubkey: hello.target_identity_pk.to_vec(),
            device_id: target_device_id,
            valid_from_unix: self.now_unix,
            valid_until_unix: key_valid_until,
            master_sig: cert_sig.to_bytes().to_vec(),
        });
        let appended_idx = (self.document.identity_keys.len() - 1) as u16;

        // 5. Re-sign the document. Leave `sig_key_idx` on the
        // source's current active subkey — pairing adds a new
        // device, it doesn't hand active signing to the new
        // device.
        resign_document(&mut self.document, &self.identity_sk);

        // 6. Build the Cert.
        let cert = PairingCert {
            source_ephemeral_x25519_pk: *ek_pk.as_bytes(),
            signed_document: self.document.encode(),
        };
        let cert_bytes = cert.encode();

        let oob_code = derive_pair_oob_code(&session_key);

        // 7. Advance state.
        self.ek_sk = Some(ek_sk);
        self.session_key = Some(session_key);
        self.state = SourceState::AwaitingConfirm;

        Ok(SourceHelloOutcome {
            cert_bytes,
            oob_code,
            appended_identity_key_idx: appended_idx,
        })
    }

    /// Consume a Confirm frame. Verifies the target's session-key
    /// proof and returns the user's decision. On abort (codes
    /// didn't match), the caller should roll back the appended
    /// IdentityKey — the document field was mutated in-place but
    /// not yet persisted / published.
    pub fn handle_confirm(
        &mut self,
        confirm_bytes: &[u8],
    ) -> Result<SourceConfirmOutcome, PairCeremonyError> {
        if self.state != SourceState::AwaitingConfirm {
            return Err(PairCeremonyError::WrongState {
                actual: self.state_name(),
                expected: "awaiting_confirm",
            });
        }
        let confirm = PairingConfirm::decode(confirm_bytes)?;
        let session_key = self.session_key.expect("session_key set in handle_hello");

        let expected = proof_confirm(&session_key, confirm.confirmed);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            &expected[..],
            &confirm.proof[..],
        )) {
            return Err(PairCeremonyError::BadConfirmProof);
        }
        self.state = SourceState::Finished;
        if !confirm.confirmed {
            return Err(PairCeremonyError::UserAborted);
        }
        Ok(SourceConfirmOutcome {
            finalized_document: self.document.clone(),
        })
    }

    /// Working copy of the identity document. Caller reads this
    /// after `handle_confirm(true)` to persist + republish.
    pub fn document(&self) -> &IdentityDocument {
        &self.document
    }

    fn state_name(&self) -> &'static str {
        match self.state {
            SourceState::AwaitingHello => "awaiting_hello",
            SourceState::AwaitingConfirm => "awaiting_confirm",
            SourceState::Finished => "finished",
        }
    }
}

#[derive(Debug)]
pub struct SourceConfirmOutcome {
    /// Fully re-signed document ready to persist + publish.
    pub finalized_document: IdentityDocument,
}

// ── PairingTarget ────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum TargetState {
    /// Constructed, Hello not yet emitted.
    Ready,
    /// Hello emitted, waiting for Cert.
    AwaitingCert,
    /// Cert consumed, awaiting user's OOB-compare decision.
    AwaitingUserCompare,
    /// Confirm emitted, ceremony finished.
    Finished,
}

/// Target-side state machine. Construct with the scanned
/// [`PairingUri`] (already parsed by the CLI via
/// `PairingUri::from_uri`). The target generates its own fresh
/// Ed25519 SK + instance_id + X25519 ephemeral; the source only
/// ever sees the public halves.
pub struct PairingTarget {
    uri: PairingUri,
    /// Fresh Ed25519 subkey SK. Never leaves this device — on
    /// success the CLI persists the seed under the target's
    /// veil config dir.
    target_identity_sk_seed: Zeroizing<[u8; 32]>,
    /// Echo of the pub half — cached so the target can verify
    /// the Cert's document includes an IdentityKey entry for it.
    target_identity_pk: [u8; 32],
    /// Fresh random 16-B target instance_id.
    target_instance_id: [u8; 16],
    /// Target's ephemeral X25519 SK.
    ek_sk: XSec,
    /// Session key, computed once Cert arrives.
    session_key: Option<[u8; 32]>,
    /// Resolved doc, parsed out of the Cert.
    document: Option<IdentityDocument>,
    state: TargetState,
    /// Wall-clock seconds at ceremony start, used to verify the received
    /// IdentityDocument's validity windows in `handle_cert` (C-15).
    /// Production passes `SystemTime::now()`; tests pass the fixture time so
    /// the document's `issued_at`/`valid_until` windows line up.
    now_unix: u64,
}

/// Outcome [`PairingTarget::handle_cert`].
#[derive(Debug, Clone)]
pub struct TargetCertOutcome {
    /// 6-digit OOB code derived from the session key. Display
    /// this; user visually compares against the source's screen.
    pub oob_code: String,
    /// Index at which the target's `IdentityKey` was appended in
    /// the document.
    pub target_identity_key_idx: u16,
}

impl PairingTarget {
    pub fn new(uri: PairingUri, now_unix: u64) -> Self {
        // Ed25519 fresh.
        let mut sk_seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *sk_seed);
        let identity_sk = SigningKey::from_bytes(&sk_seed);
        let identity_pk = identity_sk.verifying_key();

        // Instance_id fresh.
        let mut instance = [0u8; 16];
        OsRng.fill_bytes(&mut instance);

        // X25519 ephemeral.
        let mut ek_seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *ek_seed);
        let ek_sk = XSec::from(*ek_seed);

        Self {
            uri,
            target_identity_sk_seed: sk_seed,
            target_identity_pk: *identity_pk.as_bytes(),
            target_instance_id: instance,
            ek_sk,
            session_key: None,
            document: None,
            state: TargetState::Ready,
            now_unix,
        }
    }

    /// The public half of the freshly-minted target identity SK.
    pub fn target_identity_pk(&self) -> &[u8; 32] {
        &self.target_identity_pk
    }

    /// The target's fresh per-device instance_id.
    pub fn target_instance_id(&self) -> &[u8; 16] {
        &self.target_instance_id
    }

    /// Build the Hello bytes to send to the source.
    pub fn build_hello(&mut self) -> Result<Vec<u8>, PairCeremonyError> {
        if self.state != TargetState::Ready {
            return Err(PairCeremonyError::WrongState {
                actual: self.state_name(),
                expected: "ready",
            });
        }
        let pair_secret_hash = hash_pair_secret(&self.uri.pair_secret);
        let ek_pk = XPub::from(&self.ek_sk);
        let mac_input = PairingHello::mac_input(
            &pair_secret_hash,
            ek_pk.as_bytes(),
            &self.target_identity_pk,
            &self.target_instance_id,
        );
        let mac = mac_hello(&self.uri.pair_secret, &mac_input);
        let hello = PairingHello {
            pair_secret_hash,
            target_ephemeral_x25519_pk: *ek_pk.as_bytes(),
            target_identity_pk: self.target_identity_pk,
            target_instance_id: self.target_instance_id,
            mac,
        };
        self.state = TargetState::AwaitingCert;
        Ok(hello.encode())
    }

    /// Consume a Cert frame. Derives the session key (so the OOB
    /// code can be shown), verifies the cert actually contains the
    /// target's public subkey at a valid master-certified entry
    /// and caches the parsed document.
    pub fn handle_cert(
        &mut self,
        cert_bytes: &[u8],
    ) -> Result<TargetCertOutcome, PairCeremonyError> {
        if self.state != TargetState::AwaitingCert {
            return Err(PairCeremonyError::WrongState {
                actual: self.state_name(),
                expected: "awaiting_cert",
            });
        }
        let cert = PairingCert::decode(cert_bytes)?;
        let doc = IdentityDocument::decode(&cert.signed_document)
            .map_err(|e| PairCeremonyError::DocumentDecode(e.to_string()))?;

        // Bind the cert to the identity whose QR the target scanned (the URI
        // carries node_id). This catches a MITM substituting a *different*
        // document before the (more expensive) full verify below.
        if doc.node_id != self.uri.node_id {
            return Err(PairCeremonyError::CertIdentityIdMismatch);
        }

        // SECURITY (C-15): fully verify the document before trusting or
        // persisting it. `IdentityDocument::decode` only parses structure — it
        // does NOT validate the `node_id == BLAKE3(master_pubkey)` binding nor
        // the master-cert chain over the appended subkeys; only
        // `verify_identity_document` does. Verified against the ceremony's
        // `now_unix` (the document's issued_at / valid_until windows must hold
        // at pairing time). MITM is already blocked by the OOB pair_secret; this
        // ensures the target never persists a self-inconsistent document.
        crate::verify::verify_identity_document(&doc, self.now_unix)
            .map_err(|e| PairCeremonyError::DocumentVerify(e.to_string()))?;

        // Session-key derivation + OOB.
        let session_key = derive_session_key(
            &self.ek_sk,
            &cert.source_ephemeral_x25519_pk,
            &self.uri.pair_secret,
        )?;

        // Locate the IdentityKey entry for our target_identity_pk.
        // device_id is deterministic from the pubkey, so the
        // pubkey match alone uniquely identifies the row (the prior
        // `bound_instance_id` cross-check was redundant once
        // device_id derives from pubkey).
        let idx = doc
            .identity_keys
            .iter()
            .position(|k| {
                k.algo == ALGO_ED25519 && k.pubkey.as_slice() == self.target_identity_pk.as_slice()
            })
            .ok_or(PairCeremonyError::CertIdentityIdMismatch)?;

        self.session_key = Some(session_key);
        self.document = Some(doc);
        self.state = TargetState::AwaitingUserCompare;

        Ok(TargetCertOutcome {
            oob_code: derive_pair_oob_code(&session_key),
            target_identity_key_idx: idx as u16,
        })
    }

    /// User's decision from the OOB compare. Emits the Confirm
    /// bytes the target sends back. On `false` the Confirm
    /// carries `confirmed=false`; the source side will then roll
    /// back the pending IdentityKey append.
    pub fn build_confirm(&mut self, confirmed: bool) -> Result<Vec<u8>, PairCeremonyError> {
        if self.state != TargetState::AwaitingUserCompare {
            return Err(PairCeremonyError::WrongState {
                actual: self.state_name(),
                expected: "awaiting_user_compare",
            });
        }
        let session_key = self.session_key.expect("session_key set in handle_cert");
        let proof = proof_confirm(&session_key, confirmed);
        let confirm = PairingConfirm { confirmed, proof };
        self.state = TargetState::Finished;
        Ok(confirm.encode())
    }

    /// The fully-verified IdentityDocument carrying the target's
    /// subkey. Target callers persist this to disk once the user
    /// confirmed.
    pub fn document(&self) -> Option<&IdentityDocument> {
        self.document.as_ref()
    }

    /// The target's freshly-minted identity_sk seed — caller (CLI)
    /// persists this to the target's veil dir as the target's
    /// own `identity_sk` for the paired identity. Exposed read-only;
    /// callers should `.clone_from` into their own `Zeroizing`.
    pub fn target_identity_sk_seed(&self) -> &[u8; 32] {
        &self.target_identity_sk_seed
    }

    fn state_name(&self) -> &'static str {
        match self.state {
            TargetState::Ready => "ready",
            TargetState::AwaitingCert => "awaiting_cert",
            TargetState::AwaitingUserCompare => "awaiting_user_compare",
            TargetState::Finished => "finished",
        }
    }
}

// Expose the target pubkey derived from SK so tests can assert the
// binding without reaching into private state.
impl PairingTarget {
    /// Convenience: the verifying key matching
    /// `target_identity_sk_seed`.
    pub fn target_verifying_key(&self) -> VerifyingKey {
        SigningKey::from_bytes(&self.target_identity_sk_seed).verifying_key()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sovereign::SovereignIdentity;
    use crate::sovereign_flow::{CreateIdentityOptions, create_identity, load_identity_sk};

    struct TestCtx {
        sov: SovereignIdentity,
        master_seed: Zeroizing<[u8; 32]>,
        identity_sk: SigningKey,
    }

    /// `derive_session_key` rejects a low-order / non-contributory peer key
    /// (e.g. all-zeros) rather than deriving a key from a forced shared secret.
    #[test]
    fn derive_session_key_rejects_low_order_peer_key() {
        let my_sk = XSec::from([0x11u8; 32]);
        let pair_secret = [0x22u8; PAIR_SECRET_LEN];
        // All-zeros is a canonical low-order X25519 point → non-contributory.
        let low_order = [0u8; 32];
        assert!(matches!(
            derive_session_key(&my_sk, &low_order, &pair_secret),
            Err(PairCeremonyError::NonContributoryDh)
        ));
        // A genuine peer ephemeral public key is accepted.
        let peer_pk = XPub::from(&XSec::from([0x33u8; 32]));
        assert!(derive_session_key(&my_sk, peer_pk.as_bytes(), &pair_secret).is_ok());
    }

    /// Driver: runs `create_identity` with `#[cfg(test)]` PoW
    /// difficulty (16 bits). Returns the source's
    /// `SovereignIdentity` handle + raw master seed + the
    /// active identity_sk (re-derived from disk).
    fn provision_source() -> TestCtx {
        let dir = crate::test_support::scratch_dir("veil-pair-runtime");

        let issued = 1_800_000_000u64;
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "test-laptop".into(),
            pow_difficulty: crate::identity_policy::IdentityPolicy::DEFAULT_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        let id_seed = load_identity_sk(&dir).unwrap();
        let identity_sk = SigningKey::from_bytes(id_seed.as_array());
        TestCtx {
            sov,
            master_seed: out.master_seed,
            identity_sk,
        }
    }

    fn master_sk_from_seed(seed: &[u8; 32]) -> SigningKey {
        use veil_crypto::identity::derive_master_sk_ed25519;
        let bytes = derive_master_sk_ed25519(seed);
        SigningKey::from_bytes(&bytes)
    }

    fn fresh_pair_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    /// End-to-end happy-path: target drives through all three
    /// frames via an in-memory buffer, both sides land on the
    /// same OOB, document ends up with a new IdentityKey for the
    /// target, document_sig re-verifies.
    #[test]
    fn end_to_end_happy_path() {
        let TestCtx {
            sov,
            master_seed,
            identity_sk,
        } = provision_source();
        let pair_secret = fresh_pair_secret();
        let master_sk = master_sk_from_seed(&master_seed);

        let original_n_keys = sov.document.identity_keys.len();
        let mut src = PairingSource::new(
            sov.document.clone(),
            identity_sk,
            master_sk,
            pair_secret,
            1_800_000_000,
        );

        let uri = PairingUri {
            node_id: *sov.node_id(),
            pair_secret,
            endpoint: "tcp://127.0.0.1:0".into(),
            expires_at_unix: 1_800_000_300,
        };
        let mut tgt = PairingTarget::new(uri, 1_800_000_000);

        // Hello.
        let hello_bytes = tgt.build_hello().unwrap();
        let src_outcome = src.handle_hello(&hello_bytes).unwrap();
        assert_eq!(
            src_outcome.appended_identity_key_idx as usize,
            original_n_keys,
        );

        // Cert.
        let tgt_outcome = tgt.handle_cert(&src_outcome.cert_bytes).unwrap();
        assert_eq!(src_outcome.oob_code, tgt_outcome.oob_code);
        assert_eq!(tgt_outcome.oob_code.len(), 7); // "XXX-XXX"
        assert!(tgt_outcome.oob_code.contains('-'));

        // User approves.
        let confirm_bytes = tgt.build_confirm(true).unwrap();
        let final_outcome = src.handle_confirm(&confirm_bytes).unwrap();

        // Document ends up with +1 IdentityKey.
        assert_eq!(
            final_outcome.finalized_document.identity_keys.len(),
            original_n_keys + 1,
        );

        // Target's pubkey landed in the appended slot.
        let appended = &final_outcome.finalized_document.identity_keys[original_n_keys];
        assert_eq!(appended.pubkey, tgt.target_identity_pk().to_vec());
        // device_id is deterministic from the appended subkey's
        // pubkey rather than the legacy random `bound_instance_id`.
        assert_eq!(
            appended.device_id,
            veil_crypto::identity::compute_node_id(&appended.pubkey),
        );

        // document_sig re-verifies.
        use ed25519_dalek::{Signature, Verifier};
        let active_idx = final_outcome.finalized_document.sig_key_idx as usize;
        let active_pk = VerifyingKey::from_bytes(
            final_outcome.finalized_document.identity_keys[active_idx]
                .pubkey
                .as_slice()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let sig_bytes: [u8; 64] = final_outcome
            .finalized_document
            .document_sig
            .as_slice()
            .try_into()
            .unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        let mut msg = DOC_SIG_CONTEXT.to_vec();
        msg.extend_from_slice(&final_outcome.finalized_document.canonical_signing_bytes());
        active_pk.verify(&msg, &sig).unwrap();
    }

    #[test]
    fn user_abort_cleanly_surfaces_as_error() {
        let TestCtx {
            sov,
            master_seed,
            identity_sk,
        } = provision_source();
        let pair_secret = fresh_pair_secret();
        let master_sk = master_sk_from_seed(&master_seed);

        let mut src = PairingSource::new(
            sov.document.clone(),
            identity_sk,
            master_sk,
            pair_secret,
            1_800_000_000,
        );
        let uri = PairingUri {
            node_id: *sov.node_id(),
            pair_secret,
            endpoint: "tcp://127.0.0.1:0".into(),
            expires_at_unix: 1_800_000_300,
        };
        let mut tgt = PairingTarget::new(uri, 1_800_000_000);

        let hello_bytes = tgt.build_hello().unwrap();
        let src_outcome = src.handle_hello(&hello_bytes).unwrap();
        tgt.handle_cert(&src_outcome.cert_bytes).unwrap();
        let confirm_bytes = tgt.build_confirm(false).unwrap(); // user rejects

        let err = src.handle_confirm(&confirm_bytes).unwrap_err();
        assert!(matches!(err, PairCeremonyError::UserAborted));
    }

    #[test]
    fn mitm_substituting_ephemeral_pk_causes_oob_mismatch() {
        // Classic MITM: attacker sits between target and source
        // swaps target_ek_pk with its own, forwards a Hello with
        // unchanged MAC input (bounded — attacker can't recompute
        // the MAC without pair_secret anyway, so Hello MAC would
        // fail). Here we emulate a weaker adversary who merely
        // flips target_ek_pk bits *inside* the Hello the source
        // sees — the MAC check should catch it and refuse.
        let TestCtx {
            sov,
            master_seed,
            identity_sk,
        } = provision_source();
        let pair_secret = fresh_pair_secret();
        let master_sk = master_sk_from_seed(&master_seed);

        let mut src = PairingSource::new(
            sov.document.clone(),
            identity_sk,
            master_sk,
            pair_secret,
            1_800_000_000,
        );
        let uri = PairingUri {
            node_id: *sov.node_id(),
            pair_secret,
            endpoint: "tcp://127.0.0.1:0".into(),
            expires_at_unix: 1_800_000_300,
        };
        let mut tgt = PairingTarget::new(uri, 1_800_000_000);

        let mut hello_bytes = tgt.build_hello().unwrap();
        // Flip target_ek_pk (offset 35..67 per proto::pair_session layout).
        hello_bytes[40] ^= 0xFF;
        let err = src.handle_hello(&hello_bytes).unwrap_err();
        assert!(matches!(err, PairCeremonyError::BadHelloMac));
    }

    #[test]
    fn wrong_pair_secret_in_hello_rejected() {
        let TestCtx {
            sov,
            master_seed,
            identity_sk,
        } = provision_source();
        let real_pair_secret = fresh_pair_secret();
        let master_sk = master_sk_from_seed(&master_seed);

        let mut src = PairingSource::new(
            sov.document.clone(),
            identity_sk,
            master_sk,
            real_pair_secret,
            1_800_000_000,
        );

        // Attacker runs with a *different* pair_secret — hash
        // won't match.
        let bad_uri = PairingUri {
            node_id: *sov.node_id(),
            pair_secret: fresh_pair_secret(),
            endpoint: "tcp://127.0.0.1:0".into(),
            expires_at_unix: 1_800_000_300,
        };
        let mut bad_tgt = PairingTarget::new(bad_uri, 1_800_000_000);
        let bad_hello = bad_tgt.build_hello().unwrap();
        let err = src.handle_hello(&bad_hello).unwrap_err();
        assert!(matches!(err, PairCeremonyError::PairSecretMismatch));
    }

    #[test]
    fn confirm_with_wrong_session_key_rejected() {
        let TestCtx {
            sov,
            master_seed,
            identity_sk,
        } = provision_source();
        let pair_secret = fresh_pair_secret();
        let master_sk = master_sk_from_seed(&master_seed);

        let mut src = PairingSource::new(
            sov.document.clone(),
            identity_sk,
            master_sk,
            pair_secret,
            1_800_000_000,
        );
        let uri = PairingUri {
            node_id: *sov.node_id(),
            pair_secret,
            endpoint: "tcp://127.0.0.1:0".into(),
            expires_at_unix: 1_800_000_300,
        };
        let mut tgt = PairingTarget::new(uri, 1_800_000_000);

        let hello_bytes = tgt.build_hello().unwrap();
        let src_outcome = src.handle_hello(&hello_bytes).unwrap();
        let _ = tgt.handle_cert(&src_outcome.cert_bytes).unwrap();

        // Forge a confirm with a random 32-B proof.
        let bad = PairingConfirm {
            confirmed: true,
            proof: [0xCC; 32],
        };
        let err = src.handle_confirm(&bad.encode()).unwrap_err();
        assert!(matches!(err, PairCeremonyError::BadConfirmProof));
    }

    #[test]
    fn target_rejects_cert_for_different_node_id() {
        let TestCtx {
            sov,
            master_seed,
            identity_sk,
        } = provision_source();
        let pair_secret = fresh_pair_secret();
        let master_sk = master_sk_from_seed(&master_seed);

        let mut src = PairingSource::new(
            sov.document.clone(),
            identity_sk,
            master_sk,
            pair_secret,
            1_800_000_000,
        );

        // Target's URI pins a *different* node_id than the
        // source's actual identity — so when Cert comes back
        // decoded doc.node_id won't match.
        let mut spoofed_id = *sov.node_id();
        spoofed_id[0] ^= 0xFF;
        let spoofed_uri = PairingUri {
            node_id: spoofed_id,
            pair_secret,
            endpoint: "tcp://127.0.0.1:0".into(),
            expires_at_unix: 1_800_000_300,
        };
        let mut tgt = PairingTarget::new(spoofed_uri, 1_800_000_000);

        // Hello still goes through (source matches pair_secret).
        let hello_bytes = tgt.build_hello().unwrap();
        let src_outcome = src.handle_hello(&hello_bytes).unwrap();
        // Cert handling MUST catch the node_id mismatch.
        let err = tgt.handle_cert(&src_outcome.cert_bytes).unwrap_err();
        assert!(matches!(err, PairCeremonyError::CertIdentityIdMismatch));
    }

    #[test]
    fn source_rejects_hello_in_wrong_state() {
        let TestCtx {
            sov,
            master_seed,
            identity_sk,
        } = provision_source();
        let pair_secret = fresh_pair_secret();
        let master_sk = master_sk_from_seed(&master_seed);

        let mut src = PairingSource::new(
            sov.document.clone(),
            identity_sk,
            master_sk,
            pair_secret,
            1_800_000_000,
        );
        let uri = PairingUri {
            node_id: *sov.node_id(),
            pair_secret,
            endpoint: "tcp://127.0.0.1:0".into(),
            expires_at_unix: 1_800_000_300,
        };
        let mut tgt = PairingTarget::new(uri, 1_800_000_000);
        let hello_bytes = tgt.build_hello().unwrap();
        src.handle_hello(&hello_bytes).unwrap();

        // Second Hello in AwaitingConfirm state → WrongState.
        let err = src.handle_hello(&hello_bytes).unwrap_err();
        assert!(matches!(err, PairCeremonyError::WrongState { .. }));
    }

    #[test]
    fn target_rejects_double_build_hello() {
        let TestCtx { sov, .. } = provision_source();
        let uri = PairingUri {
            node_id: *sov.node_id(),
            pair_secret: fresh_pair_secret(),
            endpoint: "tcp://127.0.0.1:0".into(),
            expires_at_unix: 1_800_000_300,
        };
        let mut tgt = PairingTarget::new(uri, 1_800_000_000);
        tgt.build_hello().unwrap();
        let err = tgt.build_hello().unwrap_err();
        assert!(matches!(err, PairCeremonyError::WrongState { .. }));
    }
}
