//! IPC → runtime adapter for `CreateBootstrapInvite` (Epic 489.7).
//!
//! Implements [`veil_ipc::BootstrapInviteCreateSink`] by snapshotting
//! the daemon's `[identity]` keypair + first `[[listen]]` advertise URI
//! at construction time, then assembling a canonical [`BootstrapPeer`]
//! and handing to [`veil_bootstrap::invite::encode_uri`] (plain) or
//! [`veil_bootstrap::encrypted_invite::encrypt_invite`] (password
//! variant) on every request.
//!
//! Snapshot-at-startup tradeoff: simpler than threading a live
//! `Arc<RwLock<Config>>` through the IPC dispatch, and matches the CLI
//! `bootstrap invite` command's behaviour (reads config off disk once
//! per invocation).  Config reload spawns a fresh sink instance so the
//! snapshot stays current across `kill -HUP`.

use std::sync::Arc;

use veil_bootstrap::{encrypted_invite::encrypt_invite, invite::encode_uri};
use veil_ipc::{BootstrapInviteCreateOutcome, BootstrapInviteCreateSink};

use veil_cfg::BootstrapPeer;
use veil_observability::NodeLogger;
use veil_types::SignatureAlgorithm;

/// Bridges `CreateBootstrapInvite` IPC requests to
/// `veil-bootstrap::invite::encode_uri` / `encrypt_invite`.
pub struct BootstrapInviteCreator {
    logger: Arc<NodeLogger>,
    /// Snapshot of `[identity]` algo + pubkey + nonce — needed to build
    /// a [`BootstrapPeer`].  Private key is NOT snapshotted because
    /// plain + encrypted invite paths don't sign — that's the
    /// signed-invite variant (future slice).
    algo: SignatureAlgorithm,
    public_key_b64: String,
    nonce_b64: String,
    /// First `[[listen]]` entry's advertise URI (falls back to the bind
    /// transport if no explicit advertise is set).  Pre-resolved at
    /// snapshot time — matches the CLI's address-picking logic.
    transport: String,
    /// `None` if the daemon's config has no `[identity]` or no
    /// `[[listen]]` — sink returns `NotConfigured` outcome in that case.
    /// Wraps the runtime field so single-field absent-config errors
    /// don't require ferrying multiple flags.
    snapshot_ok: bool,
    /// Human-readable reason `snapshot_ok == false` (e.g. "no [identity]"
    /// or "no [[listen]] entry").  Surfaced verbatim to the consumer as
    /// the `NotConfigured` detail.
    snapshot_err: String,
}

impl BootstrapInviteCreator {
    /// Build a fresh adapter snapshotting the relevant config fields.
    /// Pass `None` for either `identity` or `transport` to mark the
    /// daemon as not-configured-for-invite-creation — the sink will
    /// reply [`BootstrapInviteCreateOutcome::NotConfigured`] on every
    /// request with the reason string.
    pub fn new(
        logger: Arc<NodeLogger>,
        identity: Option<(SignatureAlgorithm, String, String)>,
        transport: Option<String>,
    ) -> Self {
        match (identity, transport) {
            (Some((algo, pk_b64, nonce_b64)), Some(transport)) => Self {
                logger,
                algo,
                public_key_b64: pk_b64,
                nonce_b64,
                transport,
                snapshot_ok: true,
                snapshot_err: String::new(),
            },
            (None, _) => Self {
                logger,
                algo: SignatureAlgorithm::Ed25519,
                public_key_b64: String::new(),
                nonce_b64: String::new(),
                transport: String::new(),
                snapshot_ok: false,
                snapshot_err:
                    "config has no `[identity]` — run `veil-cli identity standalone` first"
                        .to_owned(),
            },
            (Some(_), None) => Self {
                logger,
                algo: SignatureAlgorithm::Ed25519,
                public_key_b64: String::new(),
                nonce_b64: String::new(),
                transport: String::new(),
                snapshot_ok: false,
                snapshot_err:
                    "config has no `[[listen]]` entry — invite needs an address peers can dial"
                        .to_owned(),
            },
        }
    }

    /// Compose the canonical [`BootstrapPeer`] from the snapshot.
    fn as_peer(&self) -> BootstrapPeer {
        BootstrapPeer {
            transport: self.transport.clone(),
            public_key: self.public_key_b64.clone(),
            nonce: self.nonce_b64.clone(),
            algo: self.algo,
            // TLS material is not embedded — recipients use their own
            // trust store / OOB cert verification.  Matches CLI behaviour.
            tls_cert: None,
            tls_ca_cert: None,
        }
    }
}

impl BootstrapInviteCreateSink for BootstrapInviteCreator {
    fn create_invite(&self, password: Option<&str>) -> BootstrapInviteCreateOutcome {
        if !self.snapshot_ok {
            return BootstrapInviteCreateOutcome::NotConfigured(self.snapshot_err.clone());
        }
        // Validate password — empty / whitespace-only is a common
        // mistake (user pressed enter on the prompt); reject so the UI
        // can re-prompt rather than emitting an envelope encrypted
        // under a trivial key.
        if let Some(pw) = password
            && pw.trim().is_empty()
        {
            return BootstrapInviteCreateOutcome::BadPassword(
                "password is empty or whitespace-only".to_owned(),
            );
        }
        let peer = self.as_peer();
        let result = if let Some(pw) = password {
            encrypt_invite(&peer, pw).map_err(|e| format!("encrypt invite: {e}"))
        } else {
            encode_uri(&peer).map_err(|e| format!("encode uri: {e}"))
        };
        match result {
            Ok(uri) => {
                self.logger.info(
                    "ipc.bootstrap_invite.create",
                    format!("encrypted={} uri_len={}", password.is_some(), uri.len(),),
                );
                BootstrapInviteCreateOutcome::Ok { uri }
            }
            Err(e) => BootstrapInviteCreateOutcome::InternalError(e),
        }
    }
}
