//! IPC → runtime adapter для multi-device pairing ceremony
//! (Epic 489.8).
//!
//! Wraps the [`veil_identity::pair_runtime::PairingSource`] /
//! `PairingTarget` state machines с one-at-a-time semantics — а
//! fresh `create_invite` / `consume_uri` drops any in-flight
//! ceremony on that side.  Source и Target ceremonies live в
//! independent `Mutex<Option<...>>` slots so а single daemon can
//! act как both sides of а pairing simultaneously (rare, но е.g.
//! testing scenarios).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use veil_ipc::{
    PairSourceCreateOutcome, PairSourceHandleConfirmOutcome, PairSourceHandleHelloOutcome,
    PairSourceSink, PairTargetBuildConfirmOutcome, PairTargetConsumeOutcome,
    PairTargetHandleCertOutcome, PairTargetSink,
};

use veil_observability::NodeLogger;

/// Pairing-invite TTL applied when create_invite is called.  Matches
/// the CLI's default (`veil-cli identity pair listen --ttl`).
pub const PAIR_INVITE_TTL_SECS: u64 = 600;

/// Placeholder endpoint string baked into the rendered PairingUri.
/// The QR-based pairing flow does not actually rely на the URI's
/// transport endpoint (the IPC layer ferrying bytes both directions
/// is application-mediated).  The endpoint field remains в the wire
/// format для CLI backward-compat и for future direct-network
/// pairing.  An empty endpoint fails URI validation, so we use а
/// sentinel scheme `app://manual` that any reader can identify как
/// "do not dial; transport is OOB".
pub const PAIR_MANUAL_ENDPOINT: &str = "app://manual";

/// Default instance label persisted на `save_paired_target_state`.
/// Operator can rename later via а dedicated CLI command; for the
/// IPC-driven flow the daemon doesn't know the user's display name
/// for this device, so we ship а neutral label.  TODO Phase 4:
/// surface instance_label as an optional ConsumeUri payload field.
pub const DEFAULT_PAIRED_INSTANCE_LABEL: &str = "paired-device";

pub struct PairingForwarder {
    logger: Arc<NodeLogger>,
    /// `<veil_dir>` где master.enc / identity_document.bin /
    /// instance.toml live — needed by `handle_confirm` (Source) и
    /// `build_confirm` (Target) к persist the updated identity files.
    veil_dir: PathBuf,
    /// Active sovereign identity handle.  `None` если the daemon
    /// runs against а legacy non-sovereign identity (pre-Epic 462) —
    /// pairing requires а sovereign identity by definition (it adds
    /// а subkey к the IdentityDocument).
    sovereign: Option<Arc<veil_identity::sovereign::SovereignIdentity>>,
    /// Source-side ceremony state — `Some` between `create_invite`
    /// and `handle_confirm` completion / abort.
    source: Mutex<Option<veil_identity::pair_runtime::PairingSource>>,
    /// Target-side ceremony state.
    target: Mutex<Option<veil_identity::pair_runtime::PairingTarget>>,
    /// Optional device label captured at `consume_uri` and applied by
    /// `build_confirm` when persisting the paired-target state (Phase 4).
    pending_instance_label: Mutex<Option<String>>,
}

impl PairingForwarder {
    pub fn new(
        logger: Arc<NodeLogger>,
        veil_dir: PathBuf,
        sovereign: Option<Arc<veil_identity::sovereign::SovereignIdentity>>,
    ) -> Self {
        Self {
            logger,
            veil_dir,
            sovereign,
            source: Mutex::new(None),
            target: Mutex::new(None),
            pending_instance_label: Mutex::new(None),
        }
    }
}

pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl PairSourceSink for PairingForwarder {
    fn create_invite(&self, master_password: Option<&str>) -> PairSourceCreateOutcome {
        use rand_core::{OsRng, RngCore};
        use veil_identity::pair_runtime::PairingSource;
        use veil_identity::sovereign_flow::load_identity_sk;
        use veil_proto::pairing_invite::{PAIR_SECRET_LEN, PairingUri};

        let Some(sov) = self.sovereign.as_ref() else {
            return PairSourceCreateOutcome::NotConfigured(
                "daemon has no sovereign identity loaded — \
                 run `veil-cli identity create` first"
                    .into(),
            );
        };

        // Load master_seed.  master.enc is the canonical at-rest form
        // (encrypted via Argon2id-derived KEK + AEAD).  Empty password
        // is rejected upstream by the IPC layer's `BadPassword` path,
        // но we double-check here defensively.
        let pw = match master_password {
            Some(p) if !p.trim().is_empty() => p,
            _ => {
                return PairSourceCreateOutcome::NotConfigured(
                    "master_password is required к decrypt master.enc \
                     для pairing-source ceremony"
                        .into(),
                );
            }
        };
        let enc_path = self.veil_dir.join("master.enc");
        let master_seed = match veil_identity::master_file::load_master_seed_encrypted(
            &enc_path,
            pw.as_bytes(),
        ) {
            Ok(s) => s,
            Err(e) => {
                return PairSourceCreateOutcome::InternalError(format!("decrypt master.enc: {e}"));
            }
        };

        // Derive master_sk via the same path the CLI uses.
        let master_sk_bytes = veil_crypto::identity::derive_master_sk_ed25519(&master_seed);
        let master_sk = SigningKey::from_bytes(&master_sk_bytes);

        // Load active identity_sk from disk.
        let id_seed = match load_identity_sk(&self.veil_dir) {
            Ok(s) => s,
            Err(e) => {
                return PairSourceCreateOutcome::InternalError(format!("load identity_sk: {e}"));
            }
        };
        let identity_sk = SigningKey::from_bytes(id_seed.as_array());

        // Fresh pair_secret + URI assembly.
        let mut pair_secret = [0u8; PAIR_SECRET_LEN];
        OsRng.fill_bytes(&mut pair_secret);
        let now = now_unix_secs();
        let expires_at = now.saturating_add(PAIR_INVITE_TTL_SECS);

        let uri_str = match (PairingUri {
            node_id: sov.document.node_id,
            pair_secret,
            endpoint: PAIR_MANUAL_ENDPOINT.into(),
            expires_at_unix: expires_at,
        })
        .to_uri()
        {
            Ok(u) => u,
            Err(e) => {
                return PairSourceCreateOutcome::InternalError(format!("render pair URI: {e}"));
            }
        };

        // Build the source state и replace any in-flight ceremony.
        let source = PairingSource::new(
            sov.document.clone(),
            identity_sk,
            master_sk,
            pair_secret,
            now,
        );
        match self.source.lock() {
            Ok(mut g) => *g = Some(source),
            Err(poisoned) => {
                *poisoned.into_inner() = Some(source);
            }
        }
        self.logger.info(
            "pair.source.create_invite",
            format!("expires_at={expires_at} ttl_secs={PAIR_INVITE_TTL_SECS}"),
        );
        PairSourceCreateOutcome::Ok { uri: uri_str }
    }

    fn handle_hello(&self, hello_bytes: &[u8]) -> PairSourceHandleHelloOutcome {
        use veil_identity::pair_runtime::PairCeremonyError;
        let mut guard = match self.source.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(source) = guard.as_mut() else {
            return PairSourceHandleHelloOutcome::WrongState(
                "no in-flight Source ceremony — call create_invite first".into(),
            );
        };
        match source.handle_hello(hello_bytes) {
            Ok(outcome) => {
                let mut oob = [0u8; 6];
                let oob_bytes = outcome.oob_code.as_bytes();
                let copy_len = oob_bytes.len().min(6);
                oob[..copy_len].copy_from_slice(&oob_bytes[..copy_len]);
                self.logger.info(
                    "pair.source.handle_hello",
                    format!("appended_idx={}", outcome.appended_identity_key_idx),
                );
                PairSourceHandleHelloOutcome::Ok {
                    cert_bytes: outcome.cert_bytes,
                    oob_code: oob,
                }
            }
            Err(PairCeremonyError::WrongState { actual, expected }) => {
                PairSourceHandleHelloOutcome::WrongState(format!(
                    "ceremony state {actual}, expected {expected}"
                ))
            }
            Err(e @ (PairCeremonyError::PairSecretMismatch | PairCeremonyError::BadHelloMac)) => {
                PairSourceHandleHelloOutcome::BadHello(e.to_string())
            }
            Err(e) => PairSourceHandleHelloOutcome::InternalError(e.to_string()),
        }
    }

    fn handle_confirm(&self, confirm_bytes: &[u8]) -> PairSourceHandleConfirmOutcome {
        use veil_identity::pair_runtime::PairCeremonyError;
        use veil_identity::sovereign_flow::IDENTITY_DOCUMENT_FILE;
        use veil_util::atomic_write;

        // Take() so а completed (or aborted) ceremony drops state
        // unconditionally — the appended IdentityKey already lives в
        // the in-memory document, so wrapping back на error doesn't
        // help anyway.
        let mut guard = match self.source.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(mut source) = guard.take() else {
            return PairSourceHandleConfirmOutcome::WrongState(
                "no in-flight Source ceremony".into(),
            );
        };
        match source.handle_confirm(confirm_bytes) {
            Ok(outcome) => {
                // Persist the finalized document.
                let doc_path = self.veil_dir.join(IDENTITY_DOCUMENT_FILE);
                if let Err(e) = atomic_write(&doc_path, &outcome.finalized_document.encode()) {
                    return PairSourceHandleConfirmOutcome::InternalError(format!(
                        "persist identity_document: {e}"
                    ));
                }
                self.logger
                    .info("pair.source.finalized", format!("path={doc_path:?}"));
                PairSourceHandleConfirmOutcome::Ok
            }
            Err(PairCeremonyError::UserAborted) => PairSourceHandleConfirmOutcome::UserAborted(
                "target reported user aborted (OOB codes did not match)".into(),
            ),
            Err(e @ PairCeremonyError::BadConfirmProof) => {
                PairSourceHandleConfirmOutcome::BadConfirm(e.to_string())
            }
            Err(PairCeremonyError::WrongState { actual, expected }) => {
                PairSourceHandleConfirmOutcome::WrongState(format!(
                    "ceremony state {actual}, expected {expected}"
                ))
            }
            Err(e) => PairSourceHandleConfirmOutcome::InternalError(e.to_string()),
        }
    }
}

impl PairTargetSink for PairingForwarder {
    fn consume_uri(&self, uri_str: &str, instance_label: Option<&str>) -> PairTargetConsumeOutcome {
        use veil_identity::pair_runtime::PairingTarget;
        use veil_proto::pairing_invite::PairingUri;

        // Validate + stash the optional device label (Phase 4). An oversized /
        // control-char / empty label is rejected -> None -> daemon default.
        // Scoped so the lock is released before we take `self.target` below.
        {
            let label = instance_label
                .map(str::trim)
                .filter(|l| {
                    !l.is_empty()
                        && l.len() <= veil_proto::instance_registry::MAX_LABEL_BYTES
                        && !l.chars().any(char::is_control)
                })
                .map(str::to_owned);
            match self.pending_instance_label.lock() {
                Ok(mut g) => *g = label,
                Err(p) => *p.into_inner() = label,
            }
        }

        let uri = match PairingUri::from_uri(uri_str.trim()) {
            Ok(u) => u,
            Err(e) => {
                return PairTargetConsumeOutcome::BadUri(format!("parse uri: {e}"));
            }
        };
        let now = now_unix_secs();
        if uri.expires_at_unix <= now {
            return PairTargetConsumeOutcome::Expired(format!(
                "pair invite expired at unix={}, now={now}",
                uri.expires_at_unix
            ));
        }
        let mut target = PairingTarget::new(uri, now);
        let hello_bytes = match target.build_hello() {
            Ok(b) => b,
            Err(e) => {
                return PairTargetConsumeOutcome::InternalError(format!("build_hello: {e}"));
            }
        };
        match self.target.lock() {
            Ok(mut g) => *g = Some(target),
            Err(p) => {
                *p.into_inner() = Some(target);
            }
        }
        self.logger.info(
            "pair.target.consume_uri",
            format!("hello_len={}", hello_bytes.len()),
        );
        PairTargetConsumeOutcome::Ok { hello_bytes }
    }

    fn handle_cert(&self, cert_bytes: &[u8]) -> PairTargetHandleCertOutcome {
        use veil_identity::pair_runtime::PairCeremonyError;
        let mut guard = match self.target.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(target) = guard.as_mut() else {
            return PairTargetHandleCertOutcome::WrongState(
                "no in-flight Target ceremony — call consume_uri first".into(),
            );
        };
        match target.handle_cert(cert_bytes) {
            Ok(outcome) => {
                let mut oob = [0u8; 6];
                let oob_bytes = outcome.oob_code.as_bytes();
                let copy_len = oob_bytes.len().min(6);
                oob[..copy_len].copy_from_slice(&oob_bytes[..copy_len]);
                self.logger.info(
                    "pair.target.handle_cert",
                    format!("target_idx={}", outcome.target_identity_key_idx),
                );
                PairTargetHandleCertOutcome::Ok { oob_code: oob }
            }
            Err(PairCeremonyError::WrongState { actual, expected }) => {
                PairTargetHandleCertOutcome::WrongState(format!(
                    "ceremony state {actual}, expected {expected}"
                ))
            }
            Err(e) => PairTargetHandleCertOutcome::BadCert(e.to_string()),
        }
    }

    fn build_confirm(&self, confirmed: bool) -> PairTargetBuildConfirmOutcome {
        use veil_identity::pair_runtime::PairCeremonyError;
        use veil_identity::sovereign_flow::save_paired_target_state;

        let mut guard = match self.target.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(mut target) = guard.take() else {
            return PairTargetBuildConfirmOutcome::WrongState(
                "no in-flight Target ceremony".into(),
            );
        };
        let confirm_bytes = match target.build_confirm(confirmed) {
            Ok(b) => b,
            Err(PairCeremonyError::WrongState { actual, expected }) => {
                return PairTargetBuildConfirmOutcome::WrongState(format!(
                    "ceremony state {actual}, expected {expected}"
                ));
            }
            Err(e) => {
                return PairTargetBuildConfirmOutcome::InternalError(e.to_string());
            }
        };
        if confirmed {
            // Persist the new identity files (4-tuple atomic write).
            let Some(doc) = target.document() else {
                return PairTargetBuildConfirmOutcome::InternalError(
                    "build_confirm returned Ok but document is missing".into(),
                );
            };
            // sig_key_idx = the index that source appended for this target.
            // After source.handle_hello and target.handle_cert this is the
            // last entry в `identity_keys`.  Compute defensively.
            if doc.identity_keys.is_empty() {
                return PairTargetBuildConfirmOutcome::InternalError(
                    "document has no identity_keys after Cert verify".into(),
                );
            }
            let sig_key_idx = (doc.identity_keys.len() - 1) as u16;
            // identity_sk seed copy — Этап 6 slice 6i: mlocked storage
            // for the brief copy between target ownership и disk persist.
            let seed_ref = target.target_identity_sk_seed();
            let mut seed_copy: veil_util::sensitive_bytes::SensitiveBytesN<32> =
                veil_util::sensitive_bytes::SensitiveBytesN::new();
            seed_copy.as_mut_slice().copy_from_slice(&seed_ref[..]);
            // Phase 4: use the label captured at consume_uri, else the default.
            let label_guard = match self.pending_instance_label.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let instance_label = label_guard
                .as_deref()
                .unwrap_or(DEFAULT_PAIRED_INSTANCE_LABEL);
            if let Err(e) = save_paired_target_state(
                &self.veil_dir,
                doc,
                &seed_copy,
                sig_key_idx,
                *target.target_instance_id(),
                instance_label,
            ) {
                return PairTargetBuildConfirmOutcome::InternalError(format!(
                    "persist paired target state: {e}"
                ));
            }
            self.logger.info(
                "pair.target.finalized",
                format!("sig_key_idx={sig_key_idx} dir={:?}", self.veil_dir),
            );
        }
        PairTargetBuildConfirmOutcome::Ok { confirm_bytes }
    }
}
