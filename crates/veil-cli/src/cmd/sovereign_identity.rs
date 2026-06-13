//! Sovereign-identity CLI subcommands.
//!
//! Thin wrappers that compose the library primitives:
//! [`create_identity`](veil_cfg::sovereign_flow::create_identity)
//! for `veil-cli identity create`.
//! [`format_identity_summary`](veil_cfg::sovereign_flow::format_identity_summary)
//! for `veil-cli identity show`.
//!
//! File persistence (the `IdentityDocument` is encoded and saved to
//! `<veil_dir>/identity_document.bin` so `show` can read it back)
//! lives here rather than in the library layer — it's a UX decision
//! about where on-disk state lives, not a protocol concern.

use std::fs;
use std::path::{Path, PathBuf};

use veil_cfg::{self, instance::LocalInstance, sovereign_flow};
use veil_proto::identity_document::IdentityDocument;

use super::output::{CommandIo, OutputEvent};

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum IdentityCliError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sovereign flow: {0}")]
    Flow(#[from] sovereign_flow::CreateIdentityError),
    #[error("password file {0} is empty or unreadable")]
    EmptyPasswordFile(PathBuf),
    #[error("extra-entropy file {0} must contain at least 32 bytes (got {1})")]
    ExtraEntropyTooShort(PathBuf, usize),
    #[error("no identity document found at {0}")]
    NoDocument(PathBuf),
    #[error("identity document decode: {0}")]
    DocumentDecode(String),
    #[error("instance state: {0}")]
    Instance(#[from] veil_cfg::instance::InstanceFileError),
    #[error("confirmation aborted: user did not retype BIP-39 words")]
    ConfirmationAborted,
    #[error("sovereign identity not provisioned: {0}")]
    SovereignLoad(String),
    #[error("name claim sign/persist failed: {0}")]
    NameClaim(String),
    #[error("pair invite failed: {0}")]
    PairInvite(String),
    #[error("uri inspect failed: {0}")]
    InspectUri(String),
    #[error("pair listen failed: {0}")]
    PairListen(String),
    #[error("pair accept failed: {0}")]
    PairAccept(String),
    #[error("export qr backup failed: {0}")]
    ExportQrBackup(String),
    #[error("import qr backup failed: {0}")]
    ImportQrBackup(String),
    #[error("standalone provisioning failed: {0}")]
    Standalone(String),
    #[error("delegate-device failed: {0}")]
    DelegateDevice(String),
    #[error(
        "identity_document.bin already exists at {0} — pass --force to \
         overwrite, or use `identity rotate` / `identity delegate-device` \
         instead"
    )]
    IdentityAlreadyExists(PathBuf),
    #[error("device pubkey file: {0}")]
    PubkeyFile(String),
    #[error("identity dht-key: {0}")]
    DhtKey(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<IdentityCliError> for veil_cfg::Result<()> {
    fn from(err: IdentityCliError) -> Self {
        Err(veil_cfg::ConfigError::ValidationFailed(err.to_string()))
    }
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

pub fn handle_identity_command<I: CommandIo>(
    io: &mut I,
    command: super::cli::IdentityCommand,
) -> veil_cfg::Result<()> {
    match command {
        super::cli::IdentityCommand::Create(args) => {
            create(io, args).map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string()))
        }
        super::cli::IdentityCommand::Show(args) => {
            show(io, args).map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string()))
        }
        super::cli::IdentityCommand::Rotate(args) => {
            rotate(io, args).map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string()))
        }
        super::cli::IdentityCommand::Restore(args) => {
            restore(io, args).map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string()))
        }
        super::cli::IdentityCommand::ClaimName(args) => {
            claim_name(io, args).map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string()))
        }
        super::cli::IdentityCommand::Qr(args) => {
            qr(io, args).map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string()))
        }
        super::cli::IdentityCommand::PairInvite(args) => pair_invite(io, args)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string())),
        super::cli::IdentityCommand::InspectUri(args) => inspect_uri(io, args)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string())),
        super::cli::IdentityCommand::PairListen(args) => pair_listen(io, args)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string())),
        super::cli::IdentityCommand::PairAccept(args) => pair_accept(io, args)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string())),
        super::cli::IdentityCommand::ExportQrBackup(args) => export_qr_backup(io, args)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string())),
        super::cli::IdentityCommand::ImportQrBackup(args) => import_qr_backup(io, args)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string())),
        super::cli::IdentityCommand::Standalone(args) => {
            standalone(io, args).map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string()))
        }
        super::cli::IdentityCommand::DelegateDevice(args) => delegate_device(io, args)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string())),
        super::cli::IdentityCommand::Migrate(args) => {
            migrate(io, args).map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string()))
        }
        super::cli::IdentityCommand::DhtKey { node_id } => dht_key(io, &node_id)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string())),
        super::cli::IdentityCommand::NameDhtKey { name } => name_dht_key(io, &name)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(e.to_string())),
    }
}

// ── name-dht-key ────────────────────────────────────────────────────────────

/// Print `blake3("veil.name_claim_dht.v1" || len_be_u16 ||
/// normalized_name)` for the supplied human-readable name. Pure
/// computation; no daemon access. Used by the devnet smoke test to
/// recursive-get a peer's signed `NameClaim` from the DHT.
fn name_dht_key<I: CommandIo>(io: &mut I, name: &str) -> Result<(), IdentityCliError> {
    let normalized = veil_proto::name_claim_v2::normalize_name(name)
        .map_err(|e| IdentityCliError::DhtKey(format!("name normalisation: {e}")))?;
    let key = veil_proto::name_claim_v2::NameClaim::dht_key(&normalized);
    let mut hex = String::with_capacity(64);
    for b in &key {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    io.emit(OutputEvent::message(hex));
    Ok(())
}

// ── dht-key ─────────────────────────────────────────────────────────────────

/// Print `blake3("veil.identity_dht.v1" || node_id)` for the supplied
/// `node_id` (64 hex chars). Pure computation; no daemon access.
/// Used by the devnet smoke test to fetch a peer's signed
/// `IdentityDocument` from the DHT via `node dht recursive-get`.
fn dht_key<I: CommandIo>(io: &mut I, node_id_hex: &str) -> Result<(), IdentityCliError> {
    let trimmed = node_id_hex.trim();
    if trimmed.len() != 64 {
        return Err(IdentityCliError::DhtKey(format!(
            "node_id must be 64 hex chars (got {})",
            trimmed.len()
        )));
    }
    let mut id = [0u8; 32];
    for (i, byte_chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(byte_chunk)
            .map_err(|e| IdentityCliError::DhtKey(format!("node_id not utf-8: {e}")))?;
        id[i] = u8::from_str_radix(s, 16)
            .map_err(|e| IdentityCliError::DhtKey(format!("node_id not hex: {e}")))?;
    }
    let key = veil_proto::identity_document::IdentityDocument::dht_key(&id);
    let mut hex = String::with_capacity(64);
    for b in &key {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    io.emit(OutputEvent::message(hex));
    Ok(())
}

// ── create ──────────────────────────────────────────────────────────────────

fn create<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityCreateArgs,
) -> Result<(), IdentityCliError> {
    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let now = now_unix_secs();

    let password = match args.password_file.as_deref() {
        Some(p) => {
            let raw = fs::read_to_string(p)?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(IdentityCliError::EmptyPasswordFile(p.to_path_buf()));
            }
            Some(trimmed.as_bytes().to_vec())
        }
        None => None,
    };

    let extra_entropy = match args.extra_entropy_file.as_deref() {
        Some(p) => {
            let bytes = fs::read(p)?;
            if bytes.len() < 32 {
                return Err(IdentityCliError::ExtraEntropyTooShort(
                    p.to_path_buf(),
                    bytes.len(),
                ));
            }
            Some(bytes)
        }
        None => None,
    };

    // parse `--algo` (default "ed25519"). Accept
    // operator-friendly aliases: "hybrid" / "ed25519+falcon512" map
    // to Ed25519Falcon512Hybrid; "falcon512" / "falcon-512" map to
    // standalone Falcon-512 (gated by `--accept-no-recovery`).
    let algo = match args.algo.as_str().trim().to_ascii_lowercase().as_str() {
        "ed25519" | "" => veil_types::SignatureAlgorithm::Ed25519,
        "hybrid" | "ed25519+falcon512" | "ed25519falcon512hybrid" => {
            veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid
        }
        "falcon512" | "falcon-512" => veil_types::SignatureAlgorithm::Falcon512,
        other => {
            return Err(IdentityCliError::Internal(format!(
                "create: unknown --algo value `{other}`; valid: \
                 ed25519 (default), hybrid, falcon512"
            )));
        }
    };

    // standalone Falcon-512 has NO BIP-39 recovery —
    // operator MUST explicitly opt in with `--accept-no-recovery`.
    // Without that flag we hard-refuse and steer them at hybrid (which
    // retains a classical recovery path).
    if matches!(algo, veil_types::SignatureAlgorithm::Falcon512) && !args.accept_no_recovery {
        return Err(IdentityCliError::Internal(
            "create: --algo=falcon512 has NO recovery path — the \
             master Falcon SK is generated from OsRng and lives ONLY \
             in <veil_dir>/master_falcon.bin.  Loss of that file \
             = TOTAL identity loss with no paper backup.  Pass \
             --accept-no-recovery to acknowledge, or use \
             --algo=hybrid which retains BIP-39-recoverable Ed25519 \
             half.  See docs/identity-hybrid-backup.md."
                .into(),
        ));
    }
    if matches!(algo, veil_types::SignatureAlgorithm::Falcon512) {
        // Loud warning to stderr-style output channel. The block of
        // `!` lines is meant to be visually unmistakable in operator
        // logs; keep the format stable across versions so that log
        // scrapers can recognise it.
        for line in [
            "!!! WARNING: standalone Falcon-512 master selected !!!",
            "!!! - NO BIP-39 paper backup exists",
            "!!! - master_falcon.bin is the SOLE recovery medium",
            "!!! - LOSS of master_falcon.bin = LOSS of identity",
            "!!! - NO @name, NO contacts, NO reputation can be restored",
            "!!! Back up master_falcon.bin to multiple independent media",
            "!!! BEFORE relying on this identity for anything important.",
        ] {
            io.emit(OutputEvent::message(line.to_owned()));
        }
    }

    if args.pow_difficulty.is_some() {
        io.emit(OutputEvent::message(
            "warning: --pow-difficulty is deprecated and has no effect; \
             identity documents no longer carry a PoW field"
                .to_owned(),
        ));
    }
    let opts = sovereign_flow::CreateIdentityOptions {
        veil_dir: veil_dir.clone(),
        save_encrypted_with_password: password,
        argon2_params_override: None,
        extra_entropy,
        instance_label: args.label,
        pow_difficulty: args
            .pow_difficulty
            .unwrap_or(DEFAULT_PRODUCTION_POW_DIFFICULTY),
        issued_at_unix: now,
        valid_until_unix: now.saturating_add(args.valid_for_secs),
        algo,
    };

    io.emit(OutputEvent::message(format!(
        "creating sovereign identity at {}",
        veil_dir.display()
    )));

    let out = sovereign_flow::create_identity(opts)?;

    // Persist the signed IdentityDocument so `show` can read it
    // back. Atomic write: tmp + rename.
    let doc_path = veil_dir.join(IDENTITY_DOCUMENT_FILE);
    atomic_write(&doc_path, &out.document.encode())?;

    emit_creation_summary(io, &out, &doc_path)?;

    // The user confirmation step — skipped for non-interactive
    // runs with `--yes-i-wrote-it-down`. Interactive prompts
    // require a TTY and stdin-no-echo; we defer that wiring to
    // a later revision. For now, emit a loud reminder when the
    // flag isn't set.
    if !args.yes_i_wrote_it_down {
        io.emit(OutputEvent::message(
            "⚠  Interactive confirmation is not yet wired in this build. \
             The library-layer flow always requires --yes-i-wrote-it-down \
             pending stdin-no-echo integration. Write the phrase down \
             BEFORE continuing to rely on this identity."
                .to_owned(),
        ));
    }

    Ok(())
}

fn emit_creation_summary<I: CommandIo>(
    io: &mut I,
    out: &sovereign_flow::CreateIdentityOutput,
    doc_path: &Path,
) -> Result<(), IdentityCliError> {
    io.emit(OutputEvent::message(format!(
        "node_id: {}",
        hex_encode(&out.node_id)
    )));
    io.emit(OutputEvent::message(format!(
        "instance_id: {}  (label = {:?})",
        hex_encode(&out.instance.instance_id),
        out.instance.label,
    )));
    io.emit(OutputEvent::message(format!(
        "identity_document saved to {}",
        doc_path.display()
    )));
    if let Some(enc) = &out.encrypted_master_path {
        io.emit(OutputEvent::message(format!(
            "encrypted master file: {}",
            enc.display()
        )));
    }
    if let Some(falcon) = &out.master_falcon_path {
        io.emit(OutputEvent::message(format!(
            "master_falcon.bin:    {}  (PRESERVE — operator-side recovery medium)",
            falcon.display()
        )));
    }
    io.emit(OutputEvent::message(String::new()));

    // ext: for standalone Falcon-512 (master_algo = 2) the
    // BIP-39 phrase is informational only — it doesn't recover the
    // master. Skip the "WRITE THIS DOWN" banner and replace with a
    // reminder that the bundle file IS the recovery medium.
    if out.document.master_algo == veil_proto::identity_document::ALGO_FALCON512 {
        io.emit(OutputEvent::message(
            "Standalone Falcon-512: BIP-39 phrase is NOT a recovery medium and is suppressed."
                .to_owned(),
        ));
        io.emit(OutputEvent::message(
            "  → master_falcon.bin is the ONLY way to restore this identity.".to_owned(),
        ));
        io.emit(OutputEvent::message(String::new()));
        return Ok(());
    }

    io.emit(OutputEvent::message(
        "BIP-39 recovery phrase (24 words) — WRITE THIS DOWN NOW:".to_owned(),
    ));
    io.emit(OutputEvent::message(String::new()));
    let words: Vec<&str> = out.master_seed_phrase.words().collect();
    for (i, chunk) in words.chunks(4).enumerate() {
        let line = chunk
            .iter()
            .enumerate()
            .map(|(j, w)| format!("{:2}. {w:<10}", i * 4 + j + 1))
            .collect::<Vec<_>>()
            .join("  ");
        io.emit(OutputEvent::message(line));
    }
    io.emit(OutputEvent::message(String::new()));
    Ok(())
}

// ── show ────────────────────────────────────────────────────────────────────

fn show<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityShowArgs,
) -> Result<(), IdentityCliError> {
    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let doc_path = veil_dir.join(IDENTITY_DOCUMENT_FILE);
    if !doc_path.exists() {
        return Err(IdentityCliError::NoDocument(doc_path));
    }
    let bytes = fs::read(&doc_path)?;
    let doc = IdentityDocument::decode(&bytes)
        .map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?;

    let inst_path = veil_cfg::instance::default_instance_path(&veil_dir);
    let instance = LocalInstance::load(&inst_path)?;

    let summary = sovereign_flow::format_identity_summary(&doc, &instance);
    for line in summary.lines() {
        io.emit(OutputEvent::message(line.to_owned()));
    }
    Ok(())
}

// ── restore ─────────────────────────────────────────────────────────────────

fn restore<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityRestoreArgs,
) -> Result<(), IdentityCliError> {
    use veil_cfg::identity_master::decode_master_seed_from_phrase;
    use veil_cfg::sovereign_flow::{RestoreIdentityOptions, restore_identity};

    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let now = now_unix_secs();

    let save_encrypted_password = match args.save_encrypted_password_file.as_deref() {
        Some(p) => {
            let raw = fs::read_to_string(p)?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(IdentityCliError::EmptyPasswordFile(p.to_path_buf()));
            }
            Some(trimmed.as_bytes().to_vec())
        }
        None => None,
    };

    // parse `--algo` (mirrors `identity create`).
    let algo = match args.algo.as_str().trim().to_ascii_lowercase().as_str() {
        "ed25519" | "" => veil_types::SignatureAlgorithm::Ed25519,
        "hybrid" | "ed25519+falcon512" | "ed25519falcon512hybrid" => {
            veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid
        }
        "falcon512" | "falcon-512" => veil_types::SignatureAlgorithm::Falcon512,
        other => {
            return Err(IdentityCliError::Internal(format!(
                "restore: unknown --algo value `{other}`; valid: \
                 ed25519 (default), hybrid, falcon512"
            )));
        }
    };

    // phrase-file handling. Required for Ed25519 and hybrid
    // (BIP-39 recovers the classical half); ignored for falcon512
    // (standalone Falcon has no BIP-39 path). When omitted on
    // falcon512 we feed the library a zero-seed (it's never used in
    // that branch); when supplied on falcon512 we noisy-warn but
    // accept the file (operator may be reusing a phrase across
    // mixed-algo identities).
    let master_seed = match (&algo, &args.phrase_file) {
        (veil_types::SignatureAlgorithm::Falcon512, None) => {
            io.emit(OutputEvent::message(
                "Standalone Falcon-512 restore: BIP-39 phrase not required (--phrase-file omitted)."
                    .to_owned(),
            ));
            zeroize::Zeroizing::new([0u8; veil_cfg::identity_master::MASTER_SEED_LEN])
        }
        (veil_types::SignatureAlgorithm::Falcon512, Some(p)) => {
            io.emit(OutputEvent::message(format!(
                "WARNING: standalone Falcon-512 restore ignores --phrase-file {} \
                 (no BIP-39 path for Falcon master).",
                p.display()
            )));
            // Decode anyway to catch obvious operator errors (typo'd
            // phrase) — but the result is dropped to a zero-seed
            // because the library doesn't consume it on this branch.
            let raw = fs::read_to_string(p)?;
            let _ = decode_master_seed_from_phrase(raw.trim()).map_err(|e| {
                IdentityCliError::DocumentDecode(format!("phrase-file decode (informational): {e}"))
            })?;
            zeroize::Zeroizing::new([0u8; veil_cfg::identity_master::MASTER_SEED_LEN])
        }
        (_, Some(p)) => {
            let phrase_raw = fs::read_to_string(p)?;
            decode_master_seed_from_phrase(phrase_raw.trim())
                .map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?
        }
        (_, None) => {
            return Err(IdentityCliError::Internal(
                "restore: --phrase-file is required for --algo={ed25519|hybrid} \
                 (BIP-39 phrase recovers the classical master half).  \
                 Omit --phrase-file only for --algo=falcon512."
                    .into(),
            ));
        }
    };

    // bundle-file handling. Required for hybrid and
    // falcon512; accepted-but-ignored for ed25519.
    let master_falcon_keypair_bytes = match (&algo, &args.master_falcon_file) {
        (veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid, Some(p))
        | (veil_types::SignatureAlgorithm::Falcon512, Some(p)) => {
            Some(fs::read(p).map_err(|e| {
                IdentityCliError::Internal(format!(
                    "restore: failed to read --master-falcon-file {}: {e}",
                    p.display()
                ))
            })?)
        }
        (veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid, None) => {
            return Err(IdentityCliError::Internal(
                "restore: --algo=hybrid requires --master-falcon-file \
                     pointing at the preserved master_falcon.bin (the \
                     BIP-39 phrase alone cannot recover the post-quantum \
                     half — see docs/identity-hybrid-backup.md)"
                    .into(),
            ));
        }
        (veil_types::SignatureAlgorithm::Falcon512, None) => {
            return Err(IdentityCliError::Internal(
                "restore: --algo=falcon512 requires --master-falcon-file \
                     pointing at the preserved master_falcon.bin (this is \
                     the SOLE recovery medium for standalone Falcon-512 — \
                     no BIP-39 path exists)"
                    .into(),
            ));
        }
        (veil_types::SignatureAlgorithm::Ed25519, Some(p)) => {
            return Err(IdentityCliError::Internal(format!(
                "restore: --master-falcon-file {} supplied but \
                     --algo is not hybrid/falcon512; classical Ed25519 \
                     restore ignores Falcon material",
                p.display()
            )));
        }
        _ => None,
    };

    if args.pow_difficulty.is_some() {
        io.emit(OutputEvent::message(
            "warning: --pow-difficulty is deprecated and has no effect; \
             identity documents no longer carry a PoW field"
                .to_owned(),
        ));
    }
    let opts = RestoreIdentityOptions {
        veil_dir: veil_dir.clone(),
        master_seed,
        // Audit L-15: the field is now Option<Zeroizing<Vec<u8>>>; `.map` moves
        // the password Vec into Zeroizing so the in-flight copy is wiped on drop.
        save_encrypted_with_password: save_encrypted_password.map(zeroize::Zeroizing::new),
        argon2_params_override: None,
        instance_label: args.label,
        pow_difficulty: args
            .pow_difficulty
            .unwrap_or(DEFAULT_PRODUCTION_POW_DIFFICULTY),
        now_unix: now,
        valid_until_unix: now.saturating_add(args.valid_for_secs),
        algo,
        master_falcon_keypair_bytes,
    };

    io.emit(OutputEvent::message(format!(
        "restoring sovereign identity at {}",
        veil_dir.display()
    )));

    let out =
        restore_identity(opts).map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?;

    io.emit(OutputEvent::message(format!(
        "node_id:         {}",
        hex_encode(&out.node_id)
    )));
    io.emit(OutputEvent::message(format!(
        "instance_id:         {}  (label = {:?})",
        hex_encode(&out.instance.instance_id),
        out.instance.label,
    )));
    io.emit(OutputEvent::message(format!(
        "identity_keys count: {}",
        out.document.identity_keys.len()
    )));
    io.emit(OutputEvent::message(format!(
        "valid_until_unix:    {}",
        out.document.valid_until_unix
    )));
    if let Some(enc) = &out.encrypted_master_path {
        io.emit(OutputEvent::message(format!(
            "encrypted master:    {}",
            enc.display()
        )));
    }
    if let Some(falcon) = &out.master_falcon_path {
        io.emit(OutputEvent::message(format!(
            "master_falcon.bin:   {}  (PRESERVE for next restore)",
            falcon.display()
        )));
    }
    io.emit(OutputEvent::message(String::new()));
    io.emit(OutputEvent::message(
        "restored.  Your @name, reputation and contact list remain \
         anchored to this node_id."
            .to_owned(),
    ));
    Ok(())
}

// ── migrate ─────────────────────────────────────────────────────

/// Mint a `MigrationCert` linking `<--from>`'s OLD identity to
/// `<--to>`'s NEW identity, signed by the OLD master keypair. CLI
/// surface for `identity migrate`.
///
/// Behaviour:
/// 1. Load OLD `IdentityDocument` from `<--from>/identity_document.bin`
///    to get old_node_id + old_master_algo + old_master_pubkey.
/// 2. Authenticate the OLD master by:
///    decoding `--from-phrase-file` to recover the BIP-39 seed
///    (mandatory for ed25519/hybrid OLD masters), OR
///    decrypting `<--from>/master.enc` with `--from-password-file`.
///    For hybrid/falcon OLD masters, additionally read the
///    `<--from>/master_falcon.bin` (or `--from-master-falcon-file`)
///    to recover the Falcon half.
/// 3. Compose the OLD master's base64 keypair material exactly the
///    way `create_identity` / `restore_identity` does so the
///    canonical `sign_message` path produces a valid cert sig.
/// 4. Load NEW `IdentityDocument` from `<--to>/identity_document.bin`
///    → extract new_node_id + new_master_algo + new_master_pubkey.
/// 5. Call `migration::sign_migration_cert` (which enforces the
///    non-downgrade rule: hybrid → ed25519 rejected).
/// 6. Atomic-write the cert blob to `--cert-out` (default
///    `<--to>/migration_cert.bin`, mode 0o644 since the cert is
///    signed-public material, not secret).
/// 7. Print a summary with the DHT key for a manual `node dht put` if the
///    operator wants to bypass the daemon's auto-publish path.
fn migrate<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityMigrateArgs,
) -> Result<(), IdentityCliError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::SigningKey;
    use std::path::PathBuf;
    use veil_cfg::identity_master::decode_master_seed_from_phrase;
    use veil_cfg::identity_master_file::load_master_seed_encrypted;
    use veil_cfg::sovereign_flow::{MASTER_FALCON_FILE, parse_master_falcon_keypair};
    use veil_crypto::identity::derive_master_sk_ed25519;
    use veil_identity::migration::{migration_cert_dht_key, sign_migration_cert};
    use veil_proto::identity_document::{
        ALGO_ED25519, ALGO_ED25519_FALCON512_HYBRID, ALGO_FALCON512, IdentityDocument,
    };
    use zeroize::Zeroizing;

    let from_dir = resolve_dir(args.from.as_deref())?;
    let to_dir: PathBuf = args.to.clone();
    let now = now_unix_secs();

    // Step 1: load OLD doc.
    let old_doc_path = from_dir.join(IDENTITY_DOCUMENT_FILE);
    if !old_doc_path.exists() {
        return Err(IdentityCliError::NoDocument(old_doc_path));
    }
    let old_doc_bytes = fs::read(&old_doc_path)?;
    let old_doc = IdentityDocument::decode(&old_doc_bytes)
        .map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?;

    // Step 4 (loaded early — we need new_doc to validate non-downgrade
    // before doing the heavy old-master load): load NEW doc.
    let new_doc_path = to_dir.join(IDENTITY_DOCUMENT_FILE);
    if !new_doc_path.exists() {
        return Err(IdentityCliError::Internal(format!(
            "migrate: --to {} has no identity_document.bin (run \
             `veil-cli identity create --veil-dir {}` first)",
            to_dir.display(),
            to_dir.display(),
        )));
    }
    let new_doc_bytes = fs::read(&new_doc_path)?;
    let new_doc = IdentityDocument::decode(&new_doc_bytes)
        .map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?;

    if old_doc.node_id == new_doc.node_id {
        return Err(IdentityCliError::Internal(format!(
            "migrate: --from and --to point at the same node_id {} — \
             nothing to migrate",
            hex_encode(&old_doc.node_id),
        )));
    }

    // Step 2 + 3: load + compose OLD master keypair material.
    //
    // The branching mirrors create_identity / restore_identity but
    // INVERTS direction: instead of creating the master, we're
    // re-loading it from on-disk + operator-supplied secrets so we
    // can sign the migration cert. The OLD master_algo dictates
    // what operator inputs are required:
    // ALGO_ED25519: BIP-39 phrase OR master.enc password.
    // ALGO_ED25519_FALCON512_HYBRID: phrase/password (Ed25519 half)
    // PLUS master_falcon.bin (Falcon half).
    // ALGO_FALCON512: master_falcon.bin alone (no BIP-39 path).
    let old_master_algo = old_doc.master_algo;
    let needs_seed = matches!(
        old_master_algo,
        ALGO_ED25519 | ALGO_ED25519_FALCON512_HYBRID
    );
    let needs_falcon_bundle = matches!(
        old_master_algo,
        ALGO_ED25519_FALCON512_HYBRID | ALGO_FALCON512
    );

    // Recover old master seed if applicable.
    let old_master_seed: Option<Zeroizing<[u8; 32]>> = if needs_seed {
        match (&args.from_phrase_file, &args.from_password_file) {
            (Some(_), Some(_)) => {
                return Err(IdentityCliError::Internal(
                    "migrate: pass exactly one of --from-phrase-file or \
                     --from-password-file for the OLD master, not both"
                        .into(),
                ));
            }
            (Some(p), None) => {
                let raw = fs::read_to_string(p)?;
                Some(
                    decode_master_seed_from_phrase(raw.trim())
                        .map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?,
                )
            }
            (None, Some(p)) => {
                let raw = fs::read_to_string(p)?;
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(IdentityCliError::EmptyPasswordFile(p.clone()));
                }
                let enc_path = from_dir.join("master.enc");
                Some(
                    load_master_seed_encrypted(&enc_path, trimmed.as_bytes())
                        .map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?,
                )
            }
            (None, None) => {
                return Err(IdentityCliError::Internal(
                    "migrate: --from-phrase-file or --from-password-file is \
                     required to authenticate the OLD master (its master_algo \
                     includes a BIP-39-recoverable Ed25519 half)"
                        .into(),
                ));
            }
        }
    } else {
        None
    };

    // Recover old Falcon keypair if applicable.
    let old_falcon_keypair: Option<(Vec<u8>, Vec<u8>)> = if needs_falcon_bundle {
        let bundle_path = args
            .from_master_falcon_file
            .clone()
            .unwrap_or_else(|| from_dir.join(MASTER_FALCON_FILE));
        if !bundle_path.exists() {
            return Err(IdentityCliError::Internal(format!(
                "migrate: OLD master_algo requires master_falcon.bin but \
                 {} doesn't exist (pass --from-master-falcon-file if it \
                 lives elsewhere)",
                bundle_path.display(),
            )));
        }
        let bytes = fs::read(&bundle_path)?;
        Some(parse_master_falcon_keypair(&bytes).map_err(|e| {
            IdentityCliError::Internal(format!("migrate: parse {}: {e}", bundle_path.display()))
        })?)
    } else {
        None
    };

    // Compose OLD master pk_b64 / sk_b64 — algo-specific framing.
    let (old_master_pk_b64, old_master_sk_b64): (String, String) = match old_master_algo {
        ALGO_ED25519 => {
            let seed = old_master_seed
                .as_ref()
                .expect("ALGO_ED25519 always sets old_master_seed");
            let sk_bytes = derive_master_sk_ed25519(seed);
            let sk = SigningKey::from_bytes(&sk_bytes);
            let pk = sk.verifying_key();
            (
                STANDARD.encode(pk.as_bytes()),
                STANDARD.encode(sk.to_bytes()),
            )
        }
        ALGO_ED25519_FALCON512_HYBRID => {
            let seed = old_master_seed
                .as_ref()
                .expect("hybrid always sets old_master_seed");
            let (falcon_sk, falcon_pk) = old_falcon_keypair
                .as_ref()
                .expect("hybrid always sets old_falcon_keypair");
            let ed_sk_bytes = derive_master_sk_ed25519(seed);
            let ed_pk = SigningKey::from_bytes(&ed_sk_bytes).verifying_key();
            // Compose hybrid pk = ed_pk(32) || falcon_pk(897), sk =
            // ed_sk(32) || u16-LE falcon_sk_len || falcon_sk. Mirrors
            // the layout in create_identity::Hybrid.
            let mut pk = Vec::with_capacity(32 + 897);
            pk.extend_from_slice(ed_pk.as_bytes());
            pk.extend_from_slice(falcon_pk);
            let mut sk = Vec::with_capacity(32 + 2 + falcon_sk.len());
            sk.extend_from_slice(&ed_sk_bytes[..]);
            sk.extend_from_slice(&(falcon_sk.len() as u16).to_le_bytes());
            sk.extend_from_slice(falcon_sk);
            (STANDARD.encode(&pk), STANDARD.encode(&sk))
        }
        ALGO_FALCON512 => {
            let (falcon_sk, falcon_pk) = old_falcon_keypair
                .as_ref()
                .expect("falcon-only always sets old_falcon_keypair");
            (STANDARD.encode(falcon_pk), STANDARD.encode(falcon_sk))
        }
        other => {
            return Err(IdentityCliError::Internal(format!(
                "migrate: OLD master_algo byte {other} is not a recognised \
                 SignatureAlgorithm — refusing to sign cert against unknown \
                 algo"
            )));
        }
    };

    // Sanity-check that the OLD master_pubkey we're about to use for
    // signing matches what's published in the OLD IdentityDocument.
    // If the operator pointed --from at a directory containing a doc
    // for a different identity than their phrase / falcon bundle
    // recovers, fail loudly rather than producing an unverifiable cert.
    let recomputed_old_pk = STANDARD
        .decode(&old_master_pk_b64)
        .map_err(|e| IdentityCliError::Internal(format!("migrate: pk b64 decode: {e}")))?;
    if recomputed_old_pk != old_doc.master_pubkey {
        return Err(IdentityCliError::Internal(format!(
            "migrate: composed OLD master_pubkey ({} bytes) doesn't match \
             {}/identity_document.bin's master_pubkey ({} bytes) — \
             operator likely pointed --from at a directory whose phrase/bundle \
             belongs to a DIFFERENT identity",
            recomputed_old_pk.len(),
            from_dir.display(),
            old_doc.master_pubkey.len(),
        )));
    }

    // Step 5: mint the cert. `sign_migration_cert` enforces:
    // non-downgrade: NEW security_tier ≥ OLD
    // validity window ≤ MAX_MIGRATION_VALIDITY_SECS (30 days)
    // issued_at < valid_until.
    let valid_until = now.saturating_add(args.valid_for_secs);
    let cert_bytes = sign_migration_cert(
        old_master_algo,
        &old_master_pk_b64,
        &old_master_sk_b64,
        old_doc.node_id,
        new_doc.node_id,
        new_doc.master_algo,
        new_doc.master_pubkey.clone(),
        now,
        valid_until,
    )
    .map_err(|e| IdentityCliError::Internal(format!("migrate: sign_migration_cert: {e}")))?;

    // Step 6: write the cert blob. Default location alongside the
    // NEW identity material — a running daemon serving --to will pick
    // it up from there and publish. Mode 0o644 because the cert is
    // self-signed-public, not secret.
    let cert_out: PathBuf = args
        .cert_out
        .clone()
        .unwrap_or_else(|| to_dir.join("migration_cert.bin"));
    if let Some(parent) = cert_out.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = cert_out.with_extension("tmp");
    {
        use std::io::Write as _;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&cert_bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &cert_out)?;

    // Step 7: emit summary.
    let dht_key = migration_cert_dht_key(&old_doc.node_id);
    io.emit(OutputEvent::message(format!(
        "migration cert minted: {} bytes",
        cert_bytes.len()
    )));
    io.emit(OutputEvent::message(format!(
        "  old_node_id:     {}  (algo={})",
        hex_encode(&old_doc.node_id),
        algo_name(old_master_algo),
    )));
    io.emit(OutputEvent::message(format!(
        "  new_node_id:     {}  (algo={})",
        hex_encode(&new_doc.node_id),
        algo_name(new_doc.master_algo),
    )));
    io.emit(OutputEvent::message(format!("  issued_at_unix:  {now}")));
    io.emit(OutputEvent::message(format!(
        "  valid_until_unix:{valid_until}  ({}s window)",
        args.valid_for_secs
    )));
    io.emit(OutputEvent::message(format!(
        "  cert written to: {}",
        cert_out.display()
    )));
    io.emit(OutputEvent::message(format!(
        "  dht_key:         {}",
        hex_encode(&dht_key)
    )));

    // Step 8: optionally publish via admin socket.
    if args.publish_immediately {
        publish_cert_via_admin_socket(
            io,
            &args.admin_socket,
            &from_dir,
            &dht_key,
            &cert_bytes,
            &cert_out,
        )?;
    } else {
        io.emit(OutputEvent::message(String::new()));
        io.emit(OutputEvent::message(
            "Next step: a running daemon serving --to will publish this \
             cert on its next maintenance tick.  Or pass \
             `--publish-immediately` to push the cert through \
             admin socket right now.  Manual fallback: \
             `veil-cli node dht put <dht_key> <cert_path>`."
                .to_owned(),
        ));
    }

    Ok(())
}

/// publish the just-minted MigrationCert via
/// `AdminCommand::DhtPublishReplicated` (local store +
/// fan-out to K closest live peers). Mirror of `bootstrap publish`'s
/// admin-socket plumbing in `cmd/handlers.rs`.
///
/// Failure modes (socket missing, daemon refuses, peer-publish times
/// out) are surfaced as `IdentityCliError::Internal` with a pointer
/// at the cert file (which is ALREADY persisted to disk before we
/// reach this function), so a manual `node dht put` retry stays
/// possible.
fn publish_cert_via_admin_socket<I: CommandIo>(
    io: &mut I,
    admin_socket_override: &Option<std::path::PathBuf>,
    from_dir: &std::path::Path,
    dht_key: &[u8; 32],
    cert_bytes: &[u8],
    cert_out: &std::path::Path,
) -> Result<(), IdentityCliError> {
    use veil_node_runtime::admin as node;

    // Default to <--from>/admin.sock. Operator can override with
    //admin-socket if their daemon's socket lives elsewhere (e.g.
    // running daemon has --config pointing at a different veil_dir).
    let socket = admin_socket_override
        .clone()
        .unwrap_or_else(|| from_dir.join("admin.sock"));

    if !node::admin_anchor_reachable_sync(&socket) {
        return Err(IdentityCliError::Internal(format!(
            "publish-immediately: admin socket `{}` not reachable.  \
             Either start a daemon serving the OLD identity first \
             (`veil-cli node run --config ...`), pass \
             `--admin-socket <path>` to point at a different daemon, \
             or drop --publish-immediately and use \
             `veil-cli node dht put {} {}` manually once a daemon \
             is up.",
            socket.display(),
            hex_encode(dht_key),
            cert_out.display(),
        )));
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            IdentityCliError::Internal(format!("publish-immediately: tokio runtime: {e}"))
        })?;
    let key_hex = hex_encode(dht_key);
    let value_hex = hex_encode(cert_bytes);
    let response = runtime
        .block_on(node::send_request(
            &socket,
            node::AdminCommand::DhtPublishReplicated {
                key: key_hex.clone(),
                value: value_hex,
            },
        ))
        .map_err(|e| {
            IdentityCliError::Internal(format!(
                "publish-immediately: admin send_request failed: {e}.  \
                 Cert is at {} — retry with `node dht put {} {}` against a \
                 running daemon.",
                cert_out.display(),
                key_hex,
                cert_out.display()
            ))
        })?;
    if let Some(err) = response.error {
        return Err(IdentityCliError::Internal(format!(
            "publish-immediately: daemon rejected publish: {err}.  \
             Cert is at {} — retry once daemon is healthy.",
            cert_out.display()
        )));
    }
    let ack = match response.result {
        Some(node::AdminResult::Ack { message }) => message,
        _ => "(no ack)".to_owned(),
    };
    io.emit(OutputEvent::message(String::new()));
    io.emit(OutputEvent::message(format!(
        "✓ cert published to DHT key {}\n  {ack}",
        key_hex
    )));
    Ok(())
}

/// Operator-readable algo name; mirror of the show formatter.
fn algo_name(b: u8) -> &'static str {
    use veil_proto::identity_document::{
        ALGO_ED25519, ALGO_ED25519_FALCON512_HYBRID, ALGO_FALCON512,
    };
    match b {
        ALGO_ED25519 => "ed25519",
        ALGO_FALCON512 => "falcon512",
        ALGO_ED25519_FALCON512_HYBRID => "ed25519+falcon512",
        _ => "<unknown>",
    }
}

// ── rotate ──────────────────────────────────────────────────────────────────

fn rotate<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityRotateArgs,
) -> Result<(), IdentityCliError> {
    use veil_cfg::identity_master::decode_master_seed_from_phrase;
    use veil_cfg::identity_master_file::load_master_seed_encrypted;
    use veil_cfg::sovereign_flow::{RotateIdentityOptions, rotate_identity};
    use zeroize::Zeroizing;

    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let now = now_unix_secs();

    if let (Some(pw), Some(_)) = (&args.password_file, &args.phrase_file) {
        return Err(IdentityCliError::EmptyPasswordFile(pw.clone()));
    }
    if args.password_file.is_none() && args.phrase_file.is_none() {
        return Err(IdentityCliError::NoDocument(
            veil_dir.join("--password-file or --phrase-file required"),
        ));
    }

    // Load master seed.
    let master_seed: Zeroizing<[u8; 32]> = if let Some(p) = &args.password_file {
        let raw = fs::read_to_string(p)?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(IdentityCliError::EmptyPasswordFile(p.clone()));
        }
        let path = veil_dir.join("master.enc");
        load_master_seed_encrypted(&path, trimmed.as_bytes())
            .map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?
    } else if let Some(p) = &args.phrase_file {
        let raw = fs::read_to_string(p)?;
        decode_master_seed_from_phrase(raw.trim())
            .map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?
    } else {
        // P1: clap's ArgGroup guarantees one of password_file /
        // phrase_file is set, but a future arg-spec change must surface
        // as a clear error rather than a release-time `panic = abort`.
        return Err(IdentityCliError::DocumentDecode(
            "rotate-sovereign-identity requires --password-file or --phrase-file".to_string(),
        ));
    };

    let opts = RotateIdentityOptions {
        veil_dir: veil_dir.clone(),
        master_seed,
        now_unix: now,
        valid_until_unix: now.saturating_add(args.valid_for_secs),
    };

    io.emit(OutputEvent::message(format!(
        "rotating sovereign identity at {}",
        veil_dir.display()
    )));

    let out = rotate_identity(opts).map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?;

    io.emit(OutputEvent::message(format!(
        "node_id:         {}",
        hex_encode(&out.document.node_id)
    )));
    io.emit(OutputEvent::message(format!(
        "valid_until_unix:    {}",
        out.document.valid_until_unix
    )));
    io.emit(OutputEvent::message(format!(
        "old sig_key_idx:     {}",
        out.old_identity_key_idx
    )));
    io.emit(OutputEvent::message(format!(
        "new sig_key_idx:     {}",
        out.new_identity_key_idx
    )));
    io.emit(OutputEvent::message(format!(
        "identity_keys count: {}",
        out.document.identity_keys.len()
    )));
    io.emit(OutputEvent::message(format!(
        "rotated at: {}",
        out.rotated_at_unix
    )));
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const IDENTITY_DOCUMENT_FILE: &str = "identity_document.bin";

/// Production-scale PoW difficulty for `identity create`. Matches
/// `IdentityPolicy::DEFAULT_POW_DIFFICULTY` so a newly-created
/// document passes peer verifiers without an operator override.
const DEFAULT_PRODUCTION_POW_DIFFICULTY: u32 = 24;

fn resolve_dir(cli_override: Option<&Path>) -> Result<PathBuf, IdentityCliError> {
    if let Some(p) = cli_override {
        return Ok(p.to_path_buf());
    }
    sovereign_flow::default_identity_dir().map_err(IdentityCliError::Io)
}

fn now_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_encode(bytes: &[u8]) -> String {
    veil_util::bytes_to_hex(bytes)
}

use veil_util::atomic_write;

// ── claim-name ──────────────────────────────────────────────────────────────

/// Sign + persist a `NameClaim` so the running daemon's 6-hour
/// republish tick (or the next startup) pushes it to the DHT.
///
/// PoW mining happens inside `sovereign.sign_name_claim` and can take
/// hundreds of milliseconds to a few seconds for rare names; the CLI
/// is synchronous for simplicity.
fn claim_name<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityClaimNameArgs,
) -> std::result::Result<(), IdentityCliError> {
    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;

    // Load the node's sovereign identity. Errors out cleanly when the
    // node hasn't been provisioned via `identity create` yet.
    let sov = veil_identity::sovereign::SovereignIdentity::load_from_dir(&veil_dir)
        .map_err(|e| IdentityCliError::SovereignLoad(e.to_string()))?;

    // Stamp `claimed_at_unix` from the CLI's clock so the persisted
    // claim has a fresh freshness-hour window matching real time.
    let now = now_unix_secs();

    let claim = sov
        .sign_name_claim(&args.name, now)
        .map_err(|e| IdentityCliError::NameClaim(e.to_string()))?;

    let path = veil_identity::sovereign::save_name_claim(&veil_dir, &claim)
        .map_err(|e| IdentityCliError::NameClaim(format!("persist: {e}")))?;

    io.emit(OutputEvent::message(format!(
        "claimed name \"{}\" for identity {}\n\
         persisted to {}\n\
         the running daemon will publish it on its next 6-hour republish tick (or on restart)",
        claim.name,
        veil_util::bytes_to_hex(sov.node_id()),
        path.display(),
    )));
    Ok(())
}

// ── qr ──────────────────────────────────────────────────────────────────────

/// Render this identity's public contact as an `veil:identity?...`
/// URI + a scannable QR code printed to the terminal.
///
/// Emits three things in order:
/// 1. The canonical URI on its own line (so users who can't scan the
///    QR can still copy-paste).
/// 2. A blank line separator.
/// 3. The QR-code matrix rendered with Unicode half-block characters
///    (▀ / ▄ / █ / space) — each terminal row encodes two QR rows so
///    the code stays roughly square even in fixed-height cells. With
///    `--ascii`, substitute `##` / ` ` for codecs that can't render
///    half-blocks.
fn qr<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityQrArgs,
) -> std::result::Result<(), IdentityCliError> {
    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let sov = veil_identity::sovereign::SovereignIdentity::load_from_dir(&veil_dir)
        .map_err(|e| IdentityCliError::SovereignLoad(e.to_string()))?;

    // Build the IdentityContact — match URI layer.
    let contact = veil_proto::identity_contact::IdentityContact {
        node_id: *sov.node_id(),
        master_algo: sov.document.master_algo,
        master_pubkey: sov.document.master_pubkey.clone(),
        name: args.name.clone(),
    };
    let uri = contact
        .to_uri()
        .map_err(|e| IdentityCliError::NameClaim(format!("contact uri: {e}")))?;

    // Encode with qrcode crate. Medium error-correction balances
    // capacity (our URIs are typically 100-200 B) against scanner
    // robustness in real-world terminal photography.
    let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| IdentityCliError::NameClaim(format!("qr encode: {e}")))?;

    let rendered = if args.ascii {
        render_qr_ascii(&code)
    } else {
        render_qr_halfblock(&code)
    };

    io.emit(OutputEvent::message(format!(
        "{uri}\n\n{rendered}\n\npoint a QR scanner at the block above to import this contact"
    )));
    Ok(())
}

/// Render a `QrCode` with Unicode half-block characters — each
/// terminal row encodes two QR-matrix rows (top/bottom → ▀ / ▄ / █ /
/// space). Produces a roughly-square output even in fixed-cell
/// terminals where each cell is ~2× taller than wide.
fn render_qr_halfblock(code: &qrcode::QrCode) -> String {
    let width = code.width();
    let matrix: Vec<bool> = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    let get = |x: usize, y: usize| -> bool {
        if x >= width || y >= width {
            false // quiet zone outside the matrix
        } else {
            matrix[y * width + x]
        }
    };

    // 4-cell quiet zone on every side per QR spec.
    const QUIET: usize = 4;
    let total = width + QUIET * 2;
    let mut out = String::new();
    let mut y = 0usize;
    while y < total {
        // Each terminal row covers rows y and y+1 of the QR matrix
        // (with quiet-zone offsetting applied per coordinate).
        let mut line = String::with_capacity(total);
        for x_term in 0..total {
            let top = get(x_term.wrapping_sub(QUIET), y.wrapping_sub(QUIET));
            let bottom = get(x_term.wrapping_sub(QUIET), (y + 1).wrapping_sub(QUIET));
            // Convention: dark module = fg; blank = bg. Terminal bg
            // is assumed dark, so we invert: QR-dark → light glyph.
            // ▀ = top-only, ▄ = bottom-only, █ = both, ' ' = neither.
            line.push(match (top, bottom) {
                (false, false) => '█',
                (false, true) => '▀',
                (true, false) => '▄',
                (true, true) => ' ',
            });
        }
        out.push_str(&line);
        out.push('\n');
        y += 2;
    }
    out
}

/// ASCII fallback — `##` for dark modules, ` ` for light. Useful
/// on terminals that can't render half-block characters cleanly.
fn render_qr_ascii(code: &qrcode::QrCode) -> String {
    let width = code.width();
    let matrix: Vec<bool> = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    const QUIET: usize = 4;
    let total = width + QUIET * 2;
    let mut out = String::new();
    for y in 0..total {
        let mut line = String::with_capacity(total * 2);
        for x in 0..total {
            let dark = x >= QUIET
                && y >= QUIET
                && x < QUIET + width
                && y < QUIET + width
                && matrix[(y - QUIET) * width + (x - QUIET)];
            line.push_str(if dark { "##" } else { "  " });
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

// ── pair-invite ───────────────────────────────────

/// Maximum `--ttl-secs` we'll sign: 1 hour. Pairing is meant to
/// happen immediately; a long-lived invite widens the pair_secret
/// exposure window without buying anything. The default
/// (`5 min`) is already what users should hit.
const PAIR_INVITE_MAX_TTL_SECS: u64 = 3600;

/// Generate a time-limited `PairingInvite` for a new device, print
/// its canonical URI + QR matrix, and display the transport endpoint
/// the target should dial after scanning.
///
/// This is the *source*-side half of the 462.30 pairing ceremony.
/// The OOB compare / master-certification / IdentityKey append are
/// performed once the target device actually dials back on the
/// transport endpoint — that's the follow-up slice.
fn pair_invite<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityPairInviteArgs,
) -> std::result::Result<(), IdentityCliError> {
    use rand_core::{OsRng, RngCore};
    use veil_proto::pairing_invite::{PAIR_SECRET_LEN, PairingUri, hash_pair_secret};

    if args.ttl_secs == 0 || args.ttl_secs > PAIR_INVITE_MAX_TTL_SECS {
        return Err(IdentityCliError::PairInvite(format!(
            "--ttl-secs must be in [1, {PAIR_INVITE_MAX_TTL_SECS}], got {}",
            args.ttl_secs
        )));
    }

    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let sov = veil_identity::sovereign::SovereignIdentity::load_from_dir(&veil_dir)
        .map_err(|e| IdentityCliError::SovereignLoad(e.to_string()))?;

    // Fresh pair_secret — 32 B, OsRng. Never persisted; lives only
    // long enough to render the QR and be re-derived by the scanner.
    let mut pair_secret = [0u8; PAIR_SECRET_LEN];
    OsRng.fill_bytes(&mut pair_secret);
    let pair_secret_hash = hash_pair_secret(&pair_secret);

    let issued_at = now_unix_secs();
    let expires_at = issued_at.saturating_add(args.ttl_secs);

    let invite = sov
        .sign_pair_invite(pair_secret_hash, issued_at, expires_at)
        .map_err(|e| IdentityCliError::PairInvite(format!("sign invite: {e}")))?;

    let uri = PairingUri {
        node_id: invite.node_id,
        pair_secret,
        endpoint: args.endpoint.clone(),
        expires_at_unix: expires_at,
    }
    .to_uri()
    .map_err(|e| IdentityCliError::PairInvite(format!("pair uri: {e}")))?;

    let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| IdentityCliError::PairInvite(format!("qr encode: {e}")))?;
    let rendered = if args.ascii {
        render_qr_ascii(&code)
    } else {
        render_qr_halfblock(&code)
    };

    io.emit(OutputEvent::message(format!(
        "{uri}\n\n{rendered}\n\
         invite expires at unix={expires_at} (ttl={}s)\n\
         endpoint: {}\n\
         scan the QR on the target device, then dial the endpoint above to complete pairing",
        args.ttl_secs, args.endpoint,
    )));
    Ok(())
}

// ── inspect-uri (target-side diagnostic for scanned QR URIs) ────────────────

/// Parse a scanned `veil:identity?…` (contact, 462.26) or
/// `veil:pair?…` (invite, 462.30) URI and pretty-print its
/// fields — no side-effects, no network calls, no disk writes.
///
/// Target-device UX hook: after scanning a QR, the operator pastes
/// the URI here to confirm it decoded cleanly and review the
/// `endpoint` / `expires_at` / `node_id` before committing
/// to `identity pair-accept` (pending) or a contact import.
fn inspect_uri<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityInspectUriArgs,
) -> std::result::Result<(), IdentityCliError> {
    use veil_proto::identity_contact::{
        ALGO_NAME_ED25519, ALGO_NAME_FALCON512, IDENTITY_CONTACT_SCHEME, IdentityContact,
    };
    use veil_proto::identity_document::{ALGO_ED25519, ALGO_FALCON512};
    use veil_proto::pairing_invite::{PAIR_URI_SCHEME, PairingUri, hash_pair_secret};

    let uri = args.uri.trim();

    // Dispatch on the scheme prefix (case-insensitive, matches the
    // parser impls) so we route to the right decoder without calling
    // both and masking errors.
    let lower_prefix = uri.split('?').next().unwrap_or("").to_ascii_lowercase();

    if lower_prefix == IDENTITY_CONTACT_SCHEME {
        let contact = IdentityContact::from_uri(uri)
            .map_err(|e| IdentityCliError::InspectUri(format!("contact uri: {e}")))?;
        let algo_name = match contact.master_algo {
            ALGO_ED25519 => ALGO_NAME_ED25519,
            ALGO_FALCON512 => ALGO_NAME_FALCON512,
            other => {
                return Err(IdentityCliError::InspectUri(format!(
                    "contact uri: unsupported master_algo byte 0x{other:02x}",
                )));
            }
        };
        io.emit(OutputEvent::message(format!(
            "scheme:         veil:identity (contact, 462.26)\n\
             node_id:    {}\n\
             master_algo:    {}\n\
             master_pubkey:  {}\n\
             name:           {}",
            hex_encode(&contact.node_id),
            algo_name,
            hex_encode(&contact.master_pubkey),
            contact.name.as_deref().unwrap_or("(none)"),
        )));
        return Ok(());
    }

    if lower_prefix == PAIR_URI_SCHEME {
        let pair = PairingUri::from_uri(uri)
            .map_err(|e| IdentityCliError::InspectUri(format!("pair uri: {e}")))?;
        let expires_in = pair.expires_at_unix.saturating_sub(now_unix_secs());
        let expiry_note = if expires_in == 0 {
            "EXPIRED (reject — the pair_secret window closed)".to_string()
        } else {
            format!("in {expires_in}s")
        };
        let hash = hash_pair_secret(&pair.pair_secret);
        io.emit(OutputEvent::message(format!(
            "scheme:            veil:pair (invite, 462.30)\n\
             node_id:       {}\n\
             endpoint:          {}\n\
             expires_at_unix:   {} ({})\n\
             pair_secret_hash:  {}",
            hex_encode(&pair.node_id),
            pair.endpoint,
            pair.expires_at_unix,
            expiry_note,
            hex_encode(&hash),
        )));
        return Ok(());
    }

    Err(IdentityCliError::InspectUri(format!(
        "unknown scheme `{lower_prefix}` — expected `{IDENTITY_CONTACT_SCHEME}` or `{PAIR_URI_SCHEME}`"
    )))
}

// ── pair-listen ────────────────────────────

/// Strip the `tcp://` scheme prefix, leaving `HOST:PORT` for
/// `TcpListener::bind` / `TcpStream::connect`. Other schemes are
/// not currently supported for pair endpoints — fail loudly.
fn parse_tcp_endpoint(endpoint: &str) -> std::result::Result<&str, String> {
    endpoint
        .strip_prefix("tcp://")
        .ok_or_else(|| format!("endpoint must start with `tcp://`, got `{endpoint}`"))
}

/// Unlock the master SK seed from either an encrypted
/// `master.enc` (via `--password-file`) or a BIP-39 paper backup
/// (via `--phrase-file`). Mirrors the pattern used by `rotate` /
/// `revoke` so operators keep a single mental model.
fn load_master_seed_for_pair(
    veil_dir: &Path,
    password_file: &Option<PathBuf>,
    phrase_file: &Option<PathBuf>,
) -> std::result::Result<zeroize::Zeroizing<[u8; 32]>, IdentityCliError> {
    use veil_cfg::identity_master::decode_master_seed_from_phrase;
    use veil_cfg::identity_master_file::load_master_seed_encrypted;

    match (password_file, phrase_file) {
        (Some(p), None) => {
            let raw = fs::read_to_string(p)?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(IdentityCliError::EmptyPasswordFile(p.clone()));
            }
            let enc_path = veil_dir.join("master.enc");
            load_master_seed_encrypted(&enc_path, trimmed.as_bytes())
                .map_err(|e| IdentityCliError::PairListen(format!("decrypt master.enc: {e}")))
        }
        (None, Some(p)) => {
            let raw = fs::read_to_string(p)?;
            decode_master_seed_from_phrase(raw.trim())
                .map_err(|e| IdentityCliError::PairListen(format!("bip-39 phrase: {e}")))
        }
        (None, None) => Err(IdentityCliError::PairListen(
            "must pass exactly one of --password-file / --phrase-file".into(),
        )),
        (Some(_), Some(_)) => Err(IdentityCliError::PairListen(
            "pass only one of --password-file / --phrase-file, not both".into(),
        )),
    }
}

/// Read a y/n answer from stdin. Blocks until a line arrives.
/// Empty line or anything not starting with `y`/`Y` counts as no.
fn prompt_yes_no_stdin(prompt: &str) -> bool {
    use std::io::{BufRead, Write};
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    line.trim_start().starts_with(['y', 'Y'])
}

fn pair_listen<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityPairListenArgs,
) -> std::result::Result<(), IdentityCliError> {
    use ed25519_dalek::SigningKey;
    use rand_core::{OsRng, RngCore};
    use veil_cfg::sovereign_flow::load_identity_sk;
    use veil_identity::pair_runtime::PairingSource;
    use veil_identity::pair_transport::run_pair_source_tcp;
    use veil_proto::pairing_invite::{PAIR_SECRET_LEN, PairingUri, hash_pair_secret};

    // 1. Resolve dir + sovereign + identity_sk + master_sk.
    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let sov = veil_identity::sovereign::SovereignIdentity::load_from_dir(&veil_dir)
        .map_err(|e| IdentityCliError::SovereignLoad(e.to_string()))?;
    let id_seed = load_identity_sk(&veil_dir)
        .map_err(|e| IdentityCliError::PairListen(format!("load identity_sk: {e}")))?;
    let identity_sk = SigningKey::from_bytes(id_seed.as_array());
    let master_seed = load_master_seed_for_pair(&veil_dir, &args.password_file, &args.phrase_file)?;
    let master_sk = SigningKey::from_bytes(&veil_crypto::identity::derive_master_sk_ed25519(
        &master_seed,
    ));

    // 2. Parse + bind.
    let host_port = parse_tcp_endpoint(&args.endpoint)
        .map_err(IdentityCliError::PairListen)?
        .to_string();

    // 3. Sign invite, render QR.
    // diff-audit M22: bound the invite TTL exactly like `pair_invite` — without
    // this, `--ttl-secs` was unbounded here, so a pair invite (which authorises
    // adoption of this identity) could be made valid for a year+.
    if args.ttl_secs == 0 || args.ttl_secs > PAIR_INVITE_MAX_TTL_SECS {
        return Err(IdentityCliError::PairListen(format!(
            "--ttl-secs must be in [1, {PAIR_INVITE_MAX_TTL_SECS}], got {}",
            args.ttl_secs
        )));
    }
    let mut pair_secret = [0u8; PAIR_SECRET_LEN];
    OsRng.fill_bytes(&mut pair_secret);
    let pair_secret_hash = hash_pair_secret(&pair_secret);

    let now = now_unix_secs();
    let expires_at = now.saturating_add(args.ttl_secs);
    let _invite = sov
        .sign_pair_invite(pair_secret_hash, now, expires_at)
        .map_err(|e| IdentityCliError::PairListen(format!("sign invite: {e}")))?;

    let uri = PairingUri {
        node_id: *sov.node_id(),
        pair_secret,
        endpoint: args.endpoint.clone(),
        expires_at_unix: expires_at,
    }
    .to_uri()
    .map_err(|e| IdentityCliError::PairListen(format!("pair uri: {e}")))?;

    let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| IdentityCliError::PairListen(format!("qr encode: {e}")))?;
    let rendered = if args.ascii {
        render_qr_ascii(&code)
    } else {
        render_qr_halfblock(&code)
    };

    io.emit(OutputEvent::message(format!(
        "{uri}\n\n{rendered}\n\
         listening on {host_port} — scan the QR on the target device\n\
         invite expires at unix={expires_at} (ttl={}s)",
        args.ttl_secs,
    )));

    // 4. Spin up a current-thread tokio runtime + run one
    // accept + ceremony. We keep the runtime scope tight so
    // any background bookkeeping is dropped before we return.
    let mut source = PairingSource::new(
        sov.document.clone(),
        identity_sk,
        master_sk,
        pair_secret,
        now,
    );
    let yes = args.yes_i_compared_codes;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| IdentityCliError::PairListen(format!("tokio runtime: {e}")))?;

    let outcome = rt
        .block_on(async move {
            run_pair_source_tcp(&host_port, &mut source, |oob| {
                if yes {
                    true
                } else {
                    prompt_yes_no_stdin(&format!("does the target show OOB code {oob}?"))
                }
            })
            .await
        })
        .map_err(|e| IdentityCliError::PairListen(e.to_string()))?;

    // 5. Persist the updated doc.
    // diff-audit M22: atomic write (tmp + fsync + rename), like every other
    // identity-doc write — a crash mid-`fs::write` here would corrupt the
    // identity document (the rest of the codebase routes these through
    // `atomic_write` for exactly this reason).
    let doc_path = veil_dir.join(IDENTITY_DOCUMENT_FILE);
    atomic_write(&doc_path, &outcome.finalized_document.encode())
        .map_err(|e| IdentityCliError::PairListen(format!("persist doc: {e}")))?;

    io.emit(OutputEvent::message(format!(
        "paired successfully — OOB={} — appended target identity_key at idx {}",
        outcome.oob_code, outcome.appended_identity_key_idx,
    )));
    Ok(())
}

fn pair_accept<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityPairAcceptArgs,
) -> std::result::Result<(), IdentityCliError> {
    use veil_cfg::sovereign_flow::save_paired_target_state;
    use veil_identity::pair_runtime::PairingTarget;
    use veil_identity::pair_transport::run_pair_target_tcp;
    use veil_proto::pairing_invite::PairingUri;

    // 1. Parse URI + check expiry + resolve dial addr.
    let uri = PairingUri::from_uri(args.uri.trim())
        .map_err(|e| IdentityCliError::PairAccept(format!("parse uri: {e}")))?;
    let now = now_unix_secs();
    if uri.expires_at_unix <= now {
        return Err(IdentityCliError::PairAccept(format!(
            "invite expired ({} < {now})",
            uri.expires_at_unix,
        )));
    }
    let host_port = parse_tcp_endpoint(&uri.endpoint)
        .map_err(IdentityCliError::PairAccept)?
        .to_string();

    // 2. Resolve target dir — must exist (we write into it). We
    // don't care whether it was previously used; the persistence
    // helper is atomic-write so re-running overwrites cleanly.
    let target_dir = resolve_dir(args.veil_dir.as_deref())?;
    fs::create_dir_all(&target_dir)?;

    // 3. Run ceremony.
    let yes = args.yes_i_compared_codes;
    // C-15: pairing-time used to verify the received document's validity windows.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut target = PairingTarget::new(uri, now_unix);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| IdentityCliError::PairAccept(format!("tokio runtime: {e}")))?;

    let outcome = rt
        .block_on(async move {
            run_pair_target_tcp(&host_port, &mut target, |oob| {
                if yes {
                    true
                } else {
                    prompt_yes_no_stdin(&format!("does the source show OOB code {oob}?"))
                }
            })
            .await
        })
        .map_err(|e| IdentityCliError::PairAccept(e.to_string()))?;

    // 4. Persist target state.  Stage 6 slice 6i — wrap in
    // `SensitiveBytesN<32>` so the seed sits in mlocked storage between
    // pair-handoff and disk persist.
    let seed: veil_util::sensitive_bytes::SensitiveBytesN<32> =
        veil_util::sensitive_bytes::SensitiveBytesN::from_bytes(outcome.target_identity_sk_seed);
    save_paired_target_state(
        &target_dir,
        &outcome.document,
        &seed,
        outcome.target_identity_key_idx,
        outcome.target_instance_id,
        &args.label,
    )
    .map_err(|e| IdentityCliError::PairAccept(format!("persist target state: {e}")))?;

    io.emit(OutputEvent::message(format!(
        "paired successfully — OOB={} — node_id={} — target subkey idx={}",
        outcome.oob_code,
        hex_encode(&outcome.document.node_id),
        outcome.target_identity_key_idx,
    )));
    Ok(())
}

// ── export-qr-backup / import-qr-backup ───────────────────────

/// Recover the raw 32-byte master_seed via either path: decrypt
/// `<veil_dir>/master.enc` (with `--password-file`) or decode
/// from a BIP-39 phrase (with `--phrase-file`). Exactly one
/// must be set — clap's `conflicts_with` enforces non-both, this
/// helper enforces non-neither.
fn read_master_seed_from_source(
    veil_dir: &Path,
    password_file: &Option<PathBuf>,
    phrase_file: &Option<PathBuf>,
) -> std::result::Result<zeroize::Zeroizing<[u8; 32]>, IdentityCliError> {
    use veil_cfg::identity_master::decode_master_seed_from_phrase;
    use veil_cfg::identity_master_file::load_master_seed_encrypted;
    match (password_file, phrase_file) {
        (Some(p), None) => {
            let raw = fs::read_to_string(p)?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(IdentityCliError::EmptyPasswordFile(p.clone()));
            }
            let path = veil_dir.join("master.enc");
            load_master_seed_encrypted(&path, trimmed.as_bytes())
                .map_err(|e| IdentityCliError::ExportQrBackup(format!("decrypt master.enc: {e}")))
        }
        (None, Some(p)) => {
            let raw = fs::read_to_string(p)?;
            decode_master_seed_from_phrase(raw.trim())
                .map_err(|e| IdentityCliError::ExportQrBackup(format!("bip-39 phrase: {e}")))
        }
        (None, None) => Err(IdentityCliError::ExportQrBackup(
            "must pass exactly one of --password-file / --phrase-file".into(),
        )),
        (Some(_), Some(_)) => Err(IdentityCliError::ExportQrBackup(
            "pass only one of --password-file / --phrase-file, not both".into(),
        )),
    }
}

fn read_password_file_trimmed(path: &Path) -> std::result::Result<Vec<u8>, IdentityCliError> {
    let raw = fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(IdentityCliError::EmptyPasswordFile(path.to_path_buf()));
    }
    Ok(trimmed.as_bytes().to_vec())
}

fn export_qr_backup<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityExportQrBackupArgs,
) -> std::result::Result<(), IdentityCliError> {
    use veil_cfg::identity_master_qr::encode_master_backup_uri;

    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let master_seed =
        read_master_seed_from_source(&veil_dir, &args.password_file, &args.phrase_file)?;
    let qr_password = read_password_file_trimmed(&args.qr_password_file)?;

    let uri = encode_master_backup_uri(&master_seed, &qr_password)
        .map_err(|e| IdentityCliError::ExportQrBackup(format!("encrypt: {e}")))?;

    let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| IdentityCliError::ExportQrBackup(format!("qr encode: {e}")))?;
    let rendered = if args.ascii {
        render_qr_ascii(&code)
    } else {
        render_qr_halfblock(&code)
    };

    io.emit(OutputEvent::message(format!(
        "{uri}\n\n{rendered}\n\
         photograph the QR above and store it offline\n\
         WARNING: the QR password ({}B) is NOT in the QR — store it \
         out-of-band (verbal, sealed envelope, separate password manager).  \
         filming the QR alone is not enough to compromise the identity, \
         losing the password makes the backup unrecoverable",
        qr_password.len(),
    )));
    Ok(())
}

fn import_qr_backup<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityImportQrBackupArgs,
) -> std::result::Result<(), IdentityCliError> {
    use veil_cfg::identity_master_qr::decode_master_backup_uri;
    use veil_cfg::sovereign_flow::{RestoreIdentityOptions, restore_identity};

    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let password = read_password_file_trimmed(&args.password_file)?;

    let master_seed = decode_master_backup_uri(args.uri.trim(), &password)
        .map_err(|e| IdentityCliError::ImportQrBackup(format!("decode uri: {e}")))?;

    let now = now_unix_secs();
    let out = restore_identity(RestoreIdentityOptions {
        veil_dir: veil_dir.clone(),
        master_seed,
        save_encrypted_with_password: None,
        argon2_params_override: None,
        instance_label: args.label.clone(),
        pow_difficulty: veil_cfg::identity_policy::IdentityPolicy::DEFAULT_POW_DIFFICULTY,
        now_unix: now,
        valid_until_unix: now + 7 * 86_400,
        algo: veil_types::SignatureAlgorithm::Ed25519,
        master_falcon_keypair_bytes: None,
    })
    .map_err(|e| IdentityCliError::ImportQrBackup(format!("restore: {e}")))?;

    io.emit(OutputEvent::message(format!(
        "restored node_id={} into {}\n\
         instance_label={} — instance_id files written by restore_identity",
        hex_encode(&out.node_id),
        veil_dir.display(),
        args.label,
    )));
    Ok(())
}

// ── standalone ─────────────────────────────────────────────────

/// Provision a standalone (single-device, no separate master) sovereign
/// identity into `<veil_dir>/identity_document.bin`. The lone
/// device key — generated fresh here from OsRng — IS the master key:
/// `node_id == device_id == BLAKE3(device_pubkey)`.
///
/// Idempotent only with `--force`; refuses to clobber an existing
/// identity by default to protect against accidental re-provisioning.
fn standalone<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityStandaloneArgs,
) -> std::result::Result<(), IdentityCliError> {
    use ed25519_dalek::SigningKey;
    use rand_core::{OsRng, RngCore};
    use veil_cfg::sovereign_flow::save_standalone_identity_to_dir;

    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let doc_path = veil_dir.join(IDENTITY_DOCUMENT_FILE);
    if doc_path.exists() && !args.force {
        return Err(IdentityCliError::IdentityAlreadyExists(doc_path));
    }

    // Generate a fresh device SK seed — standalone identities use
    // OsRng directly because there's no master_seed to derive from.
    // Stage 6 slice 6i — mlocked storage from OsRng output forward.
    let mut seed: veil_util::sensitive_bytes::SensitiveBytesN<32> =
        veil_util::sensitive_bytes::SensitiveBytesN::new();
    OsRng.fill_bytes(seed.as_mut_array());
    let device_pk = SigningKey::from_bytes(seed.as_array()).verifying_key();

    let now = now_unix_secs();
    let valid_until = now.saturating_add(args.valid_for_secs);
    let doc = save_standalone_identity_to_dir(&veil_dir, &seed, now, valid_until)
        .map_err(|e| IdentityCliError::Standalone(e.to_string()))?;

    io.emit(OutputEvent::message(format!(
        "standalone sovereign identity provisioned at {}",
        veil_dir.display(),
    )));
    io.emit(OutputEvent::message(format!(
        "node_id:           {}",
        hex_encode(&doc.node_id),
    )));
    io.emit(OutputEvent::message(format!(
        "device_pubkey:     {}",
        hex_encode(device_pk.as_bytes()),
    )));
    io.emit(OutputEvent::message(format!(
        "valid_until_unix:  {valid_until}",
    )));
    io.emit(OutputEvent::message(
        "no master keypair, no BIP-39 phrase, no master.enc — \
         the device IS the master.  Re-issue happens automatically \
         at half-validity via the maintenance loop."
            .to_owned(),
    ));
    Ok(())
}

// ── delegate-device ────────────────────────────────────────────

/// Master-side: append a fresh `IdentityKey` certifying a new device's
/// pubkey to the existing `IdentityDocument`. Master_sk is loaded from
/// `--password-file` (decrypts `master.enc`) or `--phrase-file` (BIP-39).
///
/// The output path defaults to `<veil_dir>/identity_document.bin`
/// (overwrites in place); pass `--out` to write the updated document
/// to a separate file for inspection / transport to the target device.
fn delegate_device<I: CommandIo>(
    io: &mut I,
    args: super::cli::IdentityDelegateDeviceArgs,
) -> std::result::Result<(), IdentityCliError> {
    use ed25519_dalek::{Signer, SigningKey};
    use veil_cfg::identity_master::decode_master_seed_from_phrase;
    use veil_cfg::identity_master_file::load_master_seed_encrypted;
    use veil_crypto::identity::{
        certify_message as build_certify, compute_node_id, derive_master_sk_ed25519,
    };
    use veil_proto::identity_document::{
        ALGO_ED25519, DOC_SIG_CONTEXT, IdentityKey, MAX_FRESHNESS_WINDOW_SECS, MAX_IDENTITY_KEYS,
    };
    use zeroize::Zeroizing;

    let veil_dir = resolve_dir(args.veil_dir.as_deref())?;
    let now = now_unix_secs();
    let window = args.valid_for_secs;
    if window == 0 || window > MAX_FRESHNESS_WINDOW_SECS {
        return Err(IdentityCliError::DelegateDevice(format!(
            "valid_for_secs {window} out of range (must be > 0, ≤ \
             MAX_FRESHNESS_WINDOW_SECS = {MAX_FRESHNESS_WINDOW_SECS})"
        )));
    }
    let valid_until = now.saturating_add(window);

    // 1. Load + decode existing document.
    let doc_path = veil_dir.join(IDENTITY_DOCUMENT_FILE);
    if !doc_path.exists() {
        return Err(IdentityCliError::NoDocument(doc_path));
    }
    let bytes = fs::read(&doc_path)?;
    let mut doc = IdentityDocument::decode(&bytes)
        .map_err(|e| IdentityCliError::DocumentDecode(e.to_string()))?;

    // 2. Cap check.
    if doc.identity_keys.len() >= MAX_IDENTITY_KEYS {
        return Err(IdentityCliError::DelegateDevice(format!(
            "MAX_IDENTITY_KEYS ({MAX_IDENTITY_KEYS}) would be exceeded \
             (current = {})",
            doc.identity_keys.len(),
        )));
    }

    // 3. Read the new device's pubkey (raw 32 bytes OR 64 hex chars).
    let device_pubkey = read_pubkey_file(&args.pubkey_file)?;
    if device_pubkey.len() != 32 {
        return Err(IdentityCliError::PubkeyFile(format!(
            "expected 32 bytes, got {}",
            device_pubkey.len(),
        )));
    }
    // Reject the obvious self-delegation footgun: master is already
    // identity_keys[0] in standalone docs; delegating to a key that
    // matches an existing subkey would be wasted bytes.
    for (idx, k) in doc.identity_keys.iter().enumerate() {
        if k.pubkey == device_pubkey {
            return Err(IdentityCliError::DelegateDevice(format!(
                "device pubkey already present as identity_keys[{idx}] — \
                 use `identity rotate` to extend its validity instead"
            )));
        }
    }
    let device_id = compute_node_id(&device_pubkey);

    // 4. Load master_sk from --password-file OR --phrase-file (xor).
    if args.password_file.is_some() && args.phrase_file.is_some() {
        return Err(IdentityCliError::DelegateDevice(
            "--password-file and --phrase-file are mutually exclusive".into(),
        ));
    }
    let master_seed: Zeroizing<[u8; 32]> = if let Some(p) = &args.password_file {
        let raw = fs::read_to_string(p)?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(IdentityCliError::EmptyPasswordFile(p.clone()));
        }
        load_master_seed_encrypted(&veil_dir.join("master.enc"), trimmed.as_bytes())
            .map_err(|e| IdentityCliError::DelegateDevice(format!("decrypt master.enc: {e}")))?
    } else if let Some(p) = &args.phrase_file {
        let raw = fs::read_to_string(p)?;
        decode_master_seed_from_phrase(raw.trim())
            .map_err(|e| IdentityCliError::DelegateDevice(format!("phrase decode: {e}")))?
    } else {
        return Err(IdentityCliError::DelegateDevice(
            "exactly one of --password-file / --phrase-file is required".into(),
        ));
    };

    // 5. Verify master matches the document's node_id.
    let master_sk_bytes = derive_master_sk_ed25519(&master_seed);
    let master_sk = SigningKey::from_bytes(&master_sk_bytes);
    let master_pk = master_sk.verifying_key();
    let computed_node_id = compute_node_id(master_pk.as_bytes());
    if computed_node_id != doc.node_id {
        return Err(IdentityCliError::DelegateDevice(format!(
            "master_seed does not match the existing identity: \
             computed node_id {} but document carries {}",
            hex_encode(&computed_node_id),
            hex_encode(&doc.node_id),
        )));
    }

    // 6. Master signs the new delegation cert.
    let cert_msg = build_certify(
        &doc.node_id,
        ALGO_ED25519,
        &device_pubkey,
        &device_id,
        now,
        valid_until,
    );
    let cert_sig = master_sk.sign(&cert_msg);

    // 7. Append the new IdentityKey. We do NOT bump sig_key_idx —
    // the source device keeps signing with its own subkey. The
    // target device, after receiving this updated doc + a
    // `device_sig_key_idx.bin` override (currently produced by
    // the pairing flow, can also be hand-written), will pick up
    // its own subkey index.
    doc.identity_keys.push(IdentityKey {
        algo: ALGO_ED25519,
        pubkey: device_pubkey.clone(),
        device_id,
        valid_from_unix: now,
        valid_until_unix: valid_until,
        master_sig: cert_sig.to_bytes().to_vec(),
    });
    let new_idx = (doc.identity_keys.len() - 1) as u16;

    // 8. Re-sign the document with the source device's identity_sk
    // (still the active subkey at doc.sig_key_idx).
    use veil_cfg::sovereign_flow::load_identity_sk;
    let active_seed = load_identity_sk(&veil_dir)
        .map_err(|e| IdentityCliError::DelegateDevice(format!("load identity_sk: {e}")))?;
    let active_sk = SigningKey::from_bytes(active_seed.as_array());
    doc.issued_at_unix = now;
    // Bump the document-level window forward to whichever is larger:
    // the existing window or the freshly-delegated subkey's window.
    if valid_until > doc.valid_until_unix {
        doc.valid_until_unix = valid_until;
    }
    let mut doc_msg = Vec::with_capacity(DOC_SIG_CONTEXT.len() + 512);
    doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
    doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
    doc.document_sig = active_sk.sign(&doc_msg).to_bytes().to_vec();

    // 9. Write updated document.
    let used_out_override = args.out.is_some();
    let out_path = args.out.unwrap_or_else(|| doc_path.clone());
    veil_util::atomic_write(&out_path, &doc.encode())?;

    io.emit(OutputEvent::message(format!(
        "delegated device {} for node_id {}",
        hex_encode(&device_pubkey),
        hex_encode(&doc.node_id),
    )));
    io.emit(OutputEvent::message(format!(
        "new IdentityKey index: {new_idx}",
    )));
    io.emit(OutputEvent::message(format!(
        "delegation valid until: {valid_until}",
    )));
    io.emit(OutputEvent::message(format!(
        "updated document written to {}",
        out_path.display(),
    )));
    if used_out_override {
        io.emit(OutputEvent::message(
            "transport this file to the target device and drop into \
             <target_veil_dir>/identity_document.bin (alongside the \
             target's device_identity_sk.bin)."
                .to_owned(),
        ));
    }
    Ok(())
}

/// Read a 32-byte Ed25519 pubkey from a file. Accepts either:
/// * 32 raw bytes (binary encoding), or
/// * 64 lowercase hex characters on a single line (with optional
///   trailing newline / whitespace).
fn read_pubkey_file(path: &Path) -> std::result::Result<Vec<u8>, IdentityCliError> {
    let bytes = fs::read(path).map_err(IdentityCliError::Io)?;
    if bytes.len() == 32 {
        return Ok(bytes);
    }
    // Try hex. Strip ASCII whitespace.
    let s = std::str::from_utf8(&bytes)
        .map_err(|e| IdentityCliError::PubkeyFile(format!("not valid utf-8: {e}")))?
        .trim();
    if s.len() != 64 {
        return Err(IdentityCliError::PubkeyFile(format!(
            "expected 32 raw bytes or 64 hex chars, got {} bytes / {} chars",
            bytes.len(),
            s.len(),
        )));
    }
    let mut out = vec![0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = parse_hex_nibble(chunk[0]).ok_or_else(|| {
            IdentityCliError::PubkeyFile(format!("non-hex char at pos {}", i * 2))
        })?;
        let lo = parse_hex_nibble(chunk[1]).ok_or_else(|| {
            IdentityCliError::PubkeyFile(format!("non-hex char at pos {}", i * 2 + 1))
        })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn parse_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use veil_identity::sovereign::NAME_CLAIMS_DIR;

    /// Capture emitted events for assertion.
    #[derive(Default)]
    struct RecordingIo {
        events: Vec<OutputEvent>,
    }
    impl CommandIo for RecordingIo {
        fn emit(&mut self, event: OutputEvent) {
            self.events.push(event);
        }
    }

    impl RecordingIo {
        fn all_messages(&self) -> String {
            self.events
                .iter()
                .filter_map(|e| match e {
                    OutputEvent::Message { message } => Some(message.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    }

    fn tempdir() -> PathBuf {
        crate::test_support::scratch_dir("veil-sovereign-cli")
    }

    fn create_args(veil_dir: PathBuf) -> super::super::cli::IdentityCreateArgs {
        super::super::cli::IdentityCreateArgs {
            veil_dir: Some(veil_dir),
            label: "test-laptop".into(),
            // Use #[cfg(test)] default difficulty (8) via library flow.
            // We pass None here and let sovereign_flow pick; but
            // create uses DEFAULT_PRODUCTION_POW_DIFFICULTY (24) if
            // None — which would hang tests. So we pass an explicit
            // low difficulty here.
            pow_difficulty: Some(8),
            valid_for_secs: 7 * 24 * 3600,
            password_file: None,
            extra_entropy_file: None,
            yes_i_wrote_it_down: true,
            algo: "ed25519".into(),
            accept_no_recovery: false,
        }
    }

    #[test]
    fn create_writes_document_and_emits_phrase() {
        let dir = tempdir();
        let mut io = RecordingIo::default();
        create(&mut io, create_args(dir.clone())).unwrap();

        // Document persisted.
        assert!(dir.join(IDENTITY_DOCUMENT_FILE).exists());
        assert!(dir.join("instance_id").exists());

        // Summary messages include the BIP-39 phrase.
        let msgs = io.all_messages();
        assert!(msgs.contains("node_id:"));
        assert!(msgs.contains("BIP-39"));
        // 24 BIP-39 words — the phrase block has 6 lines of 4 words.
        let word_lines = msgs
            .lines()
            .filter(|l| l.trim_start().starts_with(char::is_numeric) && l.contains('.'))
            .count();
        assert!(word_lines >= 6, "expected ≥ 6 word-lines, got {word_lines}");
    }

    #[test]
    fn create_respects_password_file() {
        let dir = tempdir();
        let pw_path = dir.join("password");
        fs::write(&pw_path, "correct horse battery staple\n").unwrap();
        let mut args = create_args(dir.clone());
        args.password_file = Some(pw_path);

        let mut io = RecordingIo::default();
        create(&mut io, args).unwrap();
        assert!(
            dir.join("master.enc").exists(),
            "encrypted master file written"
        );
    }

    #[test]
    fn create_rejects_empty_password_file() {
        let dir = tempdir();
        let pw_path = dir.join("empty_password");
        fs::write(&pw_path, "  \n").unwrap();
        let mut args = create_args(dir);
        args.password_file = Some(pw_path);
        let err = create(&mut RecordingIo::default(), args).unwrap_err();
        assert!(
            matches!(err, IdentityCliError::EmptyPasswordFile(_)),
            "{err:?}"
        );
    }

    /// hybrid create at the CLI level. Verifies the algo-byte
    /// reaches sovereign_flow, master_falcon.bin lands in veil_dir
    /// and the output `master_algo` line shows `ed25519+falcon512`.
    #[test]
    fn create_with_algo_hybrid_writes_falcon_master() {
        let dir = tempdir();
        let mut args = create_args(dir.clone());
        args.algo = "hybrid".into();
        let mut io = RecordingIo::default();
        create(&mut io, args).unwrap();

        // master_falcon.bin lives in veil_dir with framed `OFAM` magic.
        let falcon_path = dir.join(veil_cfg::sovereign_flow::MASTER_FALCON_FILE);
        assert!(falcon_path.exists(), "master_falcon.bin must be created");
        let bytes = fs::read(&falcon_path).unwrap();
        assert_eq!(
            &bytes[..4],
            veil_cfg::sovereign_flow::MASTER_FALCON_MAGIC,
            "master_falcon.bin must start with OFAM magic"
        );

        // identity_document.bin's master_algo byte = 3 (hybrid).
        let doc_bytes = fs::read(dir.join(IDENTITY_DOCUMENT_FILE)).unwrap();
        let doc = veil_proto::identity_document::IdentityDocument::decode(&doc_bytes).unwrap();
        assert_eq!(
            doc.master_algo,
            veil_proto::identity_document::ALGO_ED25519_FALCON512_HYBRID,
        );
        assert_eq!(doc.master_pubkey.len(), 32 + 897);
    }

    /// standalone Falcon-512 master is rejected at the CLI
    /// boundary (mirror of the sovereign_flow rejection — defence in
    /// depth).
    #[test]
    fn create_rejects_standalone_falcon_via_cli() {
        let dir = tempdir();
        let mut args = create_args(dir);
        args.algo = "falcon512".into();
        let err = create(&mut RecordingIo::default(), args).unwrap_err();
        match err {
            IdentityCliError::Internal(msg) => {
                assert!(msg.contains("falcon512"), "msg={msg}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    /// unknown --algo value rejected with clear message.
    #[test]
    fn create_rejects_unknown_algo_value() {
        let dir = tempdir();
        let mut args = create_args(dir);
        args.algo = "bogus".into();
        let err = create(&mut RecordingIo::default(), args).unwrap_err();
        match err {
            IdentityCliError::Internal(msg) => {
                assert!(
                    msg.contains("unknown") && msg.contains("bogus"),
                    "msg={msg}"
                );
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    /// hybrid restore — full create→ collect bundle → fresh
    /// dir → restore via CLI surface reproduces the same node_id and
    /// re-saves master_falcon.bin.
    #[test]
    fn restore_with_algo_hybrid_reproduces_node_id() {
        // Step 1: hybrid create in original_dir.
        let original_dir = tempdir();
        let mut create_args_h = create_args(original_dir.clone());
        create_args_h.algo = "hybrid".into();
        let mut create_io = RecordingIo::default();
        create(&mut create_io, create_args_h).unwrap();
        let create_msgs = create_io.all_messages();
        // Extract node_id from emitted "node_id: <hex>" line.
        let original_node_id_hex = create_msgs
            .lines()
            .find_map(|l| {
                l.strip_prefix("node_id: ")
                    .or_else(|| l.strip_prefix("node_id:    "))
            })
            .map(str::trim)
            .expect("create must emit node_id");
        // Extract phrase: 24 numbered words on 6 lines after the
        // "BIP-39 recovery phrase" header. Concatenate them in order.
        let phrase = extract_bip39_phrase(&create_msgs);

        // Step 2: persist phrase to a file and copy master_falcon.bin to
        // a fresh location (operator preserves both backups).
        let scratch = tempdir();
        let phrase_path = scratch.join("phrase.txt");
        fs::write(&phrase_path, &phrase).unwrap();
        let bundle_path = scratch.join("master_falcon.bin");
        fs::copy(
            original_dir.join(veil_cfg::sovereign_flow::MASTER_FALCON_FILE),
            &bundle_path,
        )
        .unwrap();

        // Step 3: restore in a fresh veil_dir.
        let fresh_dir = tempdir();
        let restore_args_h = super::super::cli::IdentityRestoreArgs {
            veil_dir: Some(fresh_dir.clone()),
            phrase_file: Some(phrase_path),
            label: "restored-hybrid".into(),
            save_encrypted_password_file: None,
            pow_difficulty: Some(8),
            valid_for_secs: 7 * 24 * 3600,
            algo: "hybrid".into(),
            master_falcon_file: Some(bundle_path),
        };
        let mut restore_io = RecordingIo::default();
        restore(&mut restore_io, restore_args_h).unwrap();

        // Step 4: assert restored node_id == original.
        let restore_msgs = restore_io.all_messages();
        let restored_node_id_hex = restore_msgs
            .lines()
            .find_map(|l| l.strip_prefix("node_id:         "))
            .map(str::trim)
            .expect("restore must emit node_id");
        assert_eq!(
            restored_node_id_hex, original_node_id_hex,
            "hybrid restore must reproduce the original node_id"
        );
        // master_falcon.bin re-emitted under the new veil_dir.
        assert!(
            fresh_dir
                .join(veil_cfg::sovereign_flow::MASTER_FALCON_FILE)
                .exists(),
            "master_falcon.bin must be re-saved on hybrid restore"
        );
    }

    /// full `identity migrate` happy-path — Ed25519 OLD
    /// → hybrid NEW, mints a cert that decodes + verifies against OLD
    /// master pubkey.
    #[test]
    fn migrate_ed25519_to_hybrid_produces_verifiable_cert() {
        use std::time::SystemTime;
        use veil_identity::migration::{
            decode_migration_cert, migration_cert_dht_key, pubkey_bytes_to_b64,
            verify_migration_cert,
        };

        // Step 1: create OLD ed25519 identity AND extract its phrase.
        let old_dir = tempdir();
        let mut old_args = create_args(old_dir.clone());
        old_args.algo = "ed25519".into();
        let mut old_io = RecordingIo::default();
        create(&mut old_io, old_args).unwrap();
        let old_msgs = old_io.all_messages();
        let phrase = extract_bip39_phrase(&old_msgs);
        let phrase_path = old_dir.join("phrase.txt");
        fs::write(&phrase_path, &phrase).unwrap();
        let old_doc_bytes = fs::read(old_dir.join(IDENTITY_DOCUMENT_FILE)).unwrap();
        let old_doc =
            veil_proto::identity_document::IdentityDocument::decode(&old_doc_bytes).unwrap();

        // Step 2: create NEW hybrid identity in a fresh dir.
        let new_dir = tempdir();
        let mut new_args = create_args(new_dir.clone());
        new_args.algo = "hybrid".into();
        create(&mut RecordingIo::default(), new_args).unwrap();
        let new_doc_bytes = fs::read(new_dir.join(IDENTITY_DOCUMENT_FILE)).unwrap();
        let new_doc =
            veil_proto::identity_document::IdentityDocument::decode(&new_doc_bytes).unwrap();

        // Step 3: run `identity migrate`.
        let mig_args = super::super::cli::IdentityMigrateArgs {
            from: Some(old_dir.clone()),
            to: new_dir.clone(),
            from_phrase_file: Some(phrase_path),
            from_password_file: None,
            from_master_falcon_file: None,
            cert_out: None,
            valid_for_secs: 7 * 24 * 3600,
            publish_immediately: false,
            admin_socket: None,
        };
        let mut mig_io = RecordingIo::default();
        migrate(&mut mig_io, mig_args).unwrap();

        // Cert blob landed at default location.
        let cert_path = new_dir.join("migration_cert.bin");
        assert!(cert_path.exists(), "default cert path must be written");
        let cert_bytes = fs::read(&cert_path).unwrap();
        let cert = decode_migration_cert(&cert_bytes).unwrap();
        assert_eq!(cert.old_node_id, old_doc.node_id);
        assert_eq!(cert.new_node_id, new_doc.node_id);
        assert_eq!(cert.new_master_algo, new_doc.master_algo);

        // Cert verifies against OLD master pubkey (the canonical sig
        // check the resolver does on every chain hop).
        let old_master_b64 = pubkey_bytes_to_b64(&old_doc.master_pubkey);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        verify_migration_cert(&cert, &old_master_b64, now)
            .expect("freshly-minted cert must verify");

        // Summary printed expected fields.
        let mig_msgs = mig_io.all_messages();
        assert!(mig_msgs.contains("migration cert minted"));
        assert!(mig_msgs.contains("dht_key:"));
        let dht_key_hex = hex_encode(&migration_cert_dht_key(&old_doc.node_id));
        assert!(mig_msgs.contains(&dht_key_hex));
    }

    /// non-downgrade enforcement — hybrid OLD → ed25519 NEW
    /// must be rejected by `migrate` (delegates to
    /// `sign_migration_cert`'s SecurityDowngrade).
    #[test]
    fn migrate_rejects_security_downgrade() {
        // OLD = hybrid (tier 3); NEW = ed25519 (tier 1).
        let old_dir = tempdir();
        let mut old_args = create_args(old_dir.clone());
        old_args.algo = "hybrid".into();
        let mut old_io = RecordingIo::default();
        create(&mut old_io, old_args).unwrap();
        let old_msgs = old_io.all_messages();
        // Hybrid emits BIP-39 phrase same as Ed25519.
        let phrase = extract_bip39_phrase(&old_msgs);
        let phrase_path = old_dir.join("phrase.txt");
        fs::write(&phrase_path, &phrase).unwrap();

        let new_dir = tempdir();
        let mut new_args = create_args(new_dir.clone());
        new_args.algo = "ed25519".into();
        create(&mut RecordingIo::default(), new_args).unwrap();

        let mig_args = super::super::cli::IdentityMigrateArgs {
            from: Some(old_dir),
            to: new_dir,
            from_phrase_file: Some(phrase_path),
            from_password_file: None,
            from_master_falcon_file: None,
            cert_out: None,
            valid_for_secs: 7 * 24 * 3600,
            publish_immediately: false,
            admin_socket: None,
        };
        let err = migrate(&mut RecordingIo::default(), mig_args).unwrap_err();
        match err {
            IdentityCliError::Internal(msg) => {
                assert!(
                    msg.contains("downgrade") || msg.contains("Downgrade"),
                    "expected security-downgrade rejection, got: {msg}"
                );
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    /// --from and --to pointing at the same node_id is a
    /// no-op operator error — fail fast.
    #[test]
    fn migrate_rejects_same_node_id() {
        let dir = tempdir();
        let mut args = create_args(dir.clone());
        args.algo = "ed25519".into();
        let mut io = RecordingIo::default();
        create(&mut io, args).unwrap();
        let msgs = io.all_messages();
        let phrase = extract_bip39_phrase(&msgs);
        let phrase_path = dir.join("phrase.txt");
        fs::write(&phrase_path, &phrase).unwrap();

        let mig_args = super::super::cli::IdentityMigrateArgs {
            from: Some(dir.clone()),
            to: dir, // ← same dir as --from.
            from_phrase_file: Some(phrase_path),
            from_password_file: None,
            from_master_falcon_file: None,
            cert_out: None,
            valid_for_secs: 7 * 24 * 3600,
            publish_immediately: false,
            admin_socket: None,
        };
        let err = migrate(&mut RecordingIo::default(), mig_args).unwrap_err();
        match err {
            IdentityCliError::Internal(msg) => {
                assert!(msg.contains("same node_id"), "msg={msg}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    /// `--publish-immediately` without a running daemon on the
    /// admin-socket fails gracefully — the cert STILL lands on disk
    /// (so retry stays possible), and the error message points the operator
    /// at the manual `node dht put` workaround.
    #[test]
    fn migrate_publish_immediately_falls_through_when_daemon_missing() {
        let old_dir = tempdir();
        let mut old_args = create_args(old_dir.clone());
        old_args.algo = "ed25519".into();
        let mut old_io = RecordingIo::default();
        create(&mut old_io, old_args).unwrap();
        let phrase = extract_bip39_phrase(&old_io.all_messages());
        let phrase_path = old_dir.join("phrase.txt");
        fs::write(&phrase_path, &phrase).unwrap();

        let new_dir = tempdir();
        let mut new_args = create_args(new_dir.clone());
        new_args.algo = "hybrid".into();
        create(&mut RecordingIo::default(), new_args).unwrap();

        // Point at a path that's guaranteed not to exist as a socket.
        let bogus_socket = old_dir.join("nonexistent-admin.sock");
        let mig_args = super::super::cli::IdentityMigrateArgs {
            from: Some(old_dir),
            to: new_dir.clone(),
            from_phrase_file: Some(phrase_path),
            from_password_file: None,
            from_master_falcon_file: None,
            cert_out: None,
            valid_for_secs: 7 * 24 * 3600,
            publish_immediately: true,
            admin_socket: Some(bogus_socket),
        };
        let err = migrate(&mut RecordingIo::default(), mig_args).unwrap_err();
        match err {
            IdentityCliError::Internal(msg) => {
                assert!(
                    msg.contains("admin socket") && msg.contains("not reachable"),
                    "expected reachability error, got: {msg}"
                );
                assert!(
                    msg.contains("node dht put"),
                    "error must point operator at manual fallback: {msg}"
                );
            }
            other => panic!("expected Internal, got {other:?}"),
        }
        // CRITICAL: the cert MUST still be persisted to disk despite
        // the publish failure — otherwise operator loses minted-but-
        // unpublished cert and has to re-mint after fixing daemon.
        assert!(
            new_dir.join("migration_cert.bin").exists(),
            "cert must persist to disk even when --publish-immediately fails"
        );
    }

    ///to without identity_document.bin fails fast
    /// pointing operator at `identity create` first.
    #[test]
    fn migrate_rejects_unprovisioned_target() {
        let old_dir = tempdir();
        let mut old_args = create_args(old_dir.clone());
        old_args.algo = "ed25519".into();
        let mut io = RecordingIo::default();
        create(&mut io, old_args).unwrap();
        let phrase = extract_bip39_phrase(&io.all_messages());
        let phrase_path = old_dir.join("phrase.txt");
        fs::write(&phrase_path, &phrase).unwrap();

        let unprovisioned = tempdir();
        let mig_args = super::super::cli::IdentityMigrateArgs {
            from: Some(old_dir),
            to: unprovisioned, // empty dir, no identity_document.bin
            from_phrase_file: Some(phrase_path),
            from_password_file: None,
            from_master_falcon_file: None,
            cert_out: None,
            valid_for_secs: 7 * 24 * 3600,
            publish_immediately: false,
            admin_socket: None,
        };
        let err = migrate(&mut RecordingIo::default(), mig_args).unwrap_err();
        match err {
            IdentityCliError::Internal(msg) => {
                assert!(msg.contains("identity create"), "msg={msg}");
                assert!(msg.contains("no identity_document.bin"), "msg={msg}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    /// ext: standalone Falcon-512 create requires
    /// --accept-no-recovery; without it the CLI raises a loud error.
    #[test]
    fn create_falcon512_requires_accept_no_recovery() {
        let dir = tempdir();
        let mut args = create_args(dir);
        args.algo = "falcon512".into();
        let err = create(&mut RecordingIo::default(), args).unwrap_err();
        match err {
            IdentityCliError::Internal(msg) => {
                assert!(
                    msg.contains("--accept-no-recovery"),
                    "expected --accept-no-recovery in msg, got: {msg}"
                );
                assert!(msg.contains("TOTAL identity loss"), "msg={msg}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    /// ext: standalone Falcon-512 create with
    /// --accept-no-recovery emits the loud warning, skips the BIP-39
    /// phrase, and persists master_falcon.bin with master_algo=2.
    #[test]
    fn create_falcon512_with_accept_no_recovery_skips_phrase() {
        let dir = tempdir();
        let mut args = create_args(dir.clone());
        args.algo = "falcon512".into();
        args.accept_no_recovery = true;
        let mut io = RecordingIo::default();
        create(&mut io, args).unwrap();

        let msgs = io.all_messages();
        assert!(
            msgs.contains("WARNING: standalone Falcon-512"),
            "loud warning missing"
        );
        assert!(
            msgs.contains("master_falcon.bin is the SOLE recovery medium"),
            "recovery medium reminder missing"
        );
        assert!(
            !msgs.contains("BIP-39 recovery phrase (24 words)"),
            "BIP-39 phrase emission should be suppressed"
        );
        assert!(
            msgs.contains("BIP-39 phrase is NOT a recovery medium"),
            "phrase-suppression note missing"
        );
        assert!(
            dir.join(veil_cfg::sovereign_flow::MASTER_FALCON_FILE)
                .exists()
        );
        let doc_bytes = fs::read(dir.join(IDENTITY_DOCUMENT_FILE)).unwrap();
        let doc = veil_proto::identity_document::IdentityDocument::decode(&doc_bytes).unwrap();
        assert_eq!(
            doc.master_algo,
            veil_proto::identity_document::ALGO_FALCON512
        );
        assert_eq!(doc.master_pubkey.len(), 897);
    }

    /// ext: standalone Falcon-512 restore using bundle
    /// alone (no --phrase-file) reproduces the same node_id.
    #[test]
    fn restore_falcon512_bundle_alone_reproduces_node_id() {
        let original_dir = tempdir();
        let mut create_args_f = create_args(original_dir.clone());
        create_args_f.algo = "falcon512".into();
        create_args_f.accept_no_recovery = true;
        let mut create_io = RecordingIo::default();
        create(&mut create_io, create_args_f).unwrap();
        let create_msgs = create_io.all_messages();
        let original_node_id_hex = create_msgs
            .lines()
            .find_map(|l| {
                l.strip_prefix("node_id: ")
                    .or_else(|| l.strip_prefix("node_id:    "))
            })
            .map(str::trim)
            .expect("create must emit node_id");

        let scratch = tempdir();
        let bundle_path = scratch.join("master_falcon.bin");
        fs::copy(
            original_dir.join(veil_cfg::sovereign_flow::MASTER_FALCON_FILE),
            &bundle_path,
        )
        .unwrap();

        let fresh_dir = tempdir();
        let restore_args_f = super::super::cli::IdentityRestoreArgs {
            veil_dir: Some(fresh_dir.clone()),
            phrase_file: None,
            label: "falcon-restored".into(),
            save_encrypted_password_file: None,
            pow_difficulty: Some(8),
            valid_for_secs: 7 * 24 * 3600,
            algo: "falcon512".into(),
            master_falcon_file: Some(bundle_path),
        };
        let mut restore_io = RecordingIo::default();
        restore(&mut restore_io, restore_args_f).unwrap();

        let restore_msgs = restore_io.all_messages();
        let restored_node_id_hex = restore_msgs
            .lines()
            .find_map(|l| l.strip_prefix("node_id:         "))
            .map(str::trim)
            .expect("restore must emit node_id");
        assert_eq!(
            restored_node_id_hex, original_node_id_hex,
            "Falcon-only restore must reproduce the node_id from bundle alone"
        );
        assert!(
            restore_msgs.contains("BIP-39 phrase not required"),
            "restore output should note phrase-not-required: {restore_msgs}"
        );
    }

    /// ext: standalone Falcon-512 restore without a bundle fails
    /// with a pointer at master_falcon.bin (NOT at any phrase-related fix).
    #[test]
    fn restore_falcon512_rejects_missing_bundle() {
        let fresh_dir = tempdir();
        let args_f = super::super::cli::IdentityRestoreArgs {
            veil_dir: Some(fresh_dir),
            phrase_file: None,
            label: "should-fail".into(),
            save_encrypted_password_file: None,
            pow_difficulty: Some(8),
            valid_for_secs: 7 * 24 * 3600,
            algo: "falcon512".into(),
            master_falcon_file: None,
        };
        let err = restore(&mut RecordingIo::default(), args_f).unwrap_err();
        match err {
            IdentityCliError::Internal(msg) => {
                assert!(msg.contains("falcon512"), "msg={msg}");
                assert!(msg.contains("SOLE recovery medium"), "msg={msg}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    /// hybrid restore without --master-falcon-file fails fast
    /// with a clear operator-facing message (no silent degrade to
    /// Ed25519-only).
    #[test]
    fn restore_hybrid_rejects_missing_master_falcon_file() {
        // Need a valid BIP-39 phrase to get past the decode step
        // before reaching the algo-handling code.
        let original_dir = tempdir();
        create(
            &mut RecordingIo::default(),
            create_args(original_dir.clone()),
        )
        .unwrap();
        let scratch = tempdir();
        let phrase_path = scratch.join("phrase.txt");
        // Reuse the phrase the create just produced — read it from the
        // recording. (Unit-test convenience: we don't actually care
        // who's signing; we just need parse-able phrase bytes.)
        let _ = original_dir;
        // Build a valid phrase via the master_seed library so the
        // decode step passes and we exercise the post-decode rejection.
        use veil_cfg::identity_master::generate_master_seed;
        let seed = generate_master_seed();
        let phrase = veil_cfg::identity_master::encode_master_seed_to_phrase(&seed)
            .unwrap()
            .to_string();
        fs::write(&phrase_path, &phrase).unwrap();

        let fresh_dir = tempdir();
        let args_h = super::super::cli::IdentityRestoreArgs {
            veil_dir: Some(fresh_dir),
            phrase_file: Some(phrase_path),
            label: "restored".into(),
            save_encrypted_password_file: None,
            pow_difficulty: Some(8),
            valid_for_secs: 7 * 24 * 3600,
            algo: "hybrid".into(),
            master_falcon_file: None, // ← operator forgot the bundle.
        };
        let err = restore(&mut RecordingIo::default(), args_h).unwrap_err();
        match err {
            IdentityCliError::Internal(msg) => {
                assert!(
                    msg.contains("master-falcon-file") && msg.contains("hybrid"),
                    "expected hybrid + master-falcon-file in msg, got: {msg}"
                );
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    /// Helper for the hybrid restore test: pulls the 24-word BIP-39
    /// phrase out of the create handler's message stream. The phrase
    /// is emitted as 6 lines of 4 words each, where each word is
    /// preceded by `<n>. ` (number + dot + space).
    fn extract_bip39_phrase(msgs: &str) -> String {
        let mut words: Vec<(usize, String)> = Vec::new();
        for line in msgs.lines() {
            for token in line.split_whitespace() {
                if let Some(rest) = token.strip_suffix('.')
                    && let Ok(n) = rest.parse::<usize>()
                {
                    // The next whitespace-delimited token on the same
                    // line is the word — accumulate (idx, word).
                    if (1..=24).contains(&n) {
                        // We can't peek at the iterator here since
                        // we re-iterate by line; collect indices and
                        // backfill below.
                        words.push((n, String::new()));
                        continue;
                    }
                }
            }
        }
        // Re-walk the message stream collecting (n, word) pairs.
        words.clear();
        for line in msgs.lines() {
            let mut toks = line.split_whitespace().peekable();
            while let Some(t) = toks.next() {
                if let Some(rest) = t.strip_suffix('.')
                    && let Ok(n) = rest.parse::<usize>()
                    && (1..=24).contains(&n)
                    && let Some(word) = toks.next()
                {
                    words.push((n, word.to_string()));
                }
            }
        }
        words.sort_by_key(|(n, _)| *n);
        assert_eq!(
            words.len(),
            24,
            "expected 24 BIP-39 words, got {}",
            words.len()
        );
        words
            .into_iter()
            .map(|(_, w)| w)
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn create_rejects_short_extra_entropy_file() {
        let dir = tempdir();
        let ent_path = dir.join("short_entropy");
        fs::write(&ent_path, "only a few bytes").unwrap();
        let mut args = create_args(dir);
        args.extra_entropy_file = Some(ent_path);
        let err = create(&mut RecordingIo::default(), args).unwrap_err();
        assert!(
            matches!(err, IdentityCliError::ExtraEntropyTooShort(_, _)),
            "{err:?}"
        );
    }

    #[test]
    fn create_accepts_long_extra_entropy_file() {
        let dir = tempdir();
        let ent_path = dir.join("good_entropy");
        fs::write(&ent_path, [0x42u8; 64]).unwrap();
        let mut args = create_args(dir.clone());
        args.extra_entropy_file = Some(ent_path);
        create(&mut RecordingIo::default(), args).unwrap();
        assert!(dir.join(IDENTITY_DOCUMENT_FILE).exists());
    }

    #[test]
    fn show_after_create_renders_full_summary() {
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let mut io = RecordingIo::default();
        show(
            &mut io,
            super::super::cli::IdentityShowArgs {
                veil_dir: Some(dir),
            },
        )
        .unwrap();
        let msgs = io.all_messages();
        assert!(msgs.contains("node_id:"));
        assert!(msgs.contains("issued_at_unix:"));
        assert!(msgs.contains("local_instance_id:"));
    }

    #[test]
    fn show_without_create_reports_missing_document() {
        let dir = tempdir();
        let err = show(
            &mut RecordingIo::default(),
            super::super::cli::IdentityShowArgs {
                veil_dir: Some(dir),
            },
        )
        .unwrap_err();
        assert!(matches!(err, IdentityCliError::NoDocument(_)), "{err:?}");
    }

    #[test]
    fn create_then_show_preserves_node_id() {
        let dir = tempdir();
        let mut io_create = RecordingIo::default();
        create(&mut io_create, create_args(dir.clone())).unwrap();
        let created_msgs = io_create.all_messages();
        let created_line = created_msgs
            .lines()
            .find(|l| l.trim_start().starts_with("node_id:"))
            .expect("create emits node_id line");

        let mut io_show = RecordingIo::default();
        show(
            &mut io_show,
            super::super::cli::IdentityShowArgs {
                veil_dir: Some(dir),
            },
        )
        .unwrap();
        let shown_msgs = io_show.all_messages();
        let shown_line = shown_msgs
            .lines()
            .find(|l| l.trim_start().starts_with("node_id:"))
            .expect("show emits node_id line");

        let created_hex = created_line.split_whitespace().last().unwrap();
        let shown_hex = shown_line.split_whitespace().last().unwrap();
        assert_eq!(created_hex, shown_hex);
    }

    #[test]
    fn second_create_in_same_dir_reuses_instance_id_but_rotates_identity() {
        // instance_id is per-device stable per 462.11; creating a
        // new identity in the same dir is equivalent to the user
        // saying "wipe and start over" — they get a new node_id
        // but the local instance_id persists.
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();
        let first_doc = fs::read(dir.join(IDENTITY_DOCUMENT_FILE)).unwrap();

        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();
        let second_doc = fs::read(dir.join(IDENTITY_DOCUMENT_FILE)).unwrap();

        let d1 = IdentityDocument::decode(&first_doc).unwrap();
        let d2 = IdentityDocument::decode(&second_doc).unwrap();
        assert_ne!(d1.node_id, d2.node_id);
        // device_id is deterministic from the active subkey
        // pubkey, so each fresh `create` (which generates a fresh
        // `identity_sk`) produces a fresh device_id too.
        assert_ne!(
            d1.identity_keys[0].device_id, d2.identity_keys[0].device_id,
            "fresh create must produce a distinct device_id"
        );
    }

    // ── claim-name ─────────────────────────────────────────────────────────

    fn claim_args(veil_dir: PathBuf, name: &str) -> super::super::cli::IdentityClaimNameArgs {
        super::super::cli::IdentityClaimNameArgs {
            veil_dir: Some(veil_dir),
            name: name.to_string(),
        }
    }

    #[test]
    fn claim_name_writes_persisted_file_and_announces() {
        let dir = tempdir();
        // Provision an identity first — claim-name needs a loaded sovereign.
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let mut io = RecordingIo::default();
        claim_name(&mut io, claim_args(dir.clone(), "alice")).unwrap();

        // File persisted at the canonical path.
        let path = dir.join(NAME_CLAIMS_DIR).join("alice.bin");
        assert!(path.exists(), "claim file {:?} must exist", path);

        // Decodes as a valid NameClaim with the right name.
        let bytes = fs::read(&path).unwrap();
        let claim = veil_proto::name_claim_v2::NameClaim::decode(&bytes).unwrap();
        assert_eq!(claim.name, "alice");

        // Output message reports the claim and the persisted path.
        let msg = io.all_messages();
        assert!(msg.contains("claimed name \"alice\""), "got: {msg}");
        assert!(msg.contains("alice.bin"), "got: {msg}");
    }

    #[test]
    fn claim_name_rejects_non_normalizable() {
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let mut io = RecordingIo::default();
        let err = claim_name(&mut io, claim_args(dir, "alíce")).unwrap_err();
        assert!(matches!(err, IdentityCliError::NameClaim(_)), "{err:?}");
    }

    #[test]
    fn claim_name_reports_unprovisioned_sovereign() {
        // Running `identity claim-name` on a dir with no identity —
        // should report `SovereignLoad`, not panic or silently
        // corrupt a file.
        let dir = tempdir();
        let mut io = RecordingIo::default();
        let err = claim_name(&mut io, claim_args(dir, "bob")).unwrap_err();
        assert!(matches!(err, IdentityCliError::SovereignLoad(_)), "{err:?}");
    }

    #[test]
    fn claim_name_is_idempotent_on_repeat() {
        // Claiming the same name twice overwrites cleanly (re-sign
        // + re-save is a legal operation — peers tie-break on
        // NameClaim PoW + claimed_at_unix).
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let mut io = RecordingIo::default();
        claim_name(&mut io, claim_args(dir.clone(), "carol")).unwrap();
        claim_name(&mut io, claim_args(dir.clone(), "carol")).unwrap();

        // Still exactly one file.
        let entries: Vec<_> = fs::read_dir(dir.join(NAME_CLAIMS_DIR)).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    // ── qr ─────────────────────────────────────────────────────────────────

    fn qr_args(
        veil_dir: PathBuf,
        name: Option<String>,
        ascii: bool,
    ) -> super::super::cli::IdentityQrArgs {
        super::super::cli::IdentityQrArgs {
            veil_dir: Some(veil_dir),
            name,
            ascii,
        }
    }

    #[test]
    fn qr_emits_uri_and_halfblock_matrix() {
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let mut io = RecordingIo::default();
        qr(&mut io, qr_args(dir, None, false)).unwrap();
        let msg = io.all_messages();

        assert!(msg.starts_with("veil:identity?"), "URI prefix: {msg}");
        // Half-block renderer uses these four glyphs.
        assert!(
            msg.contains('█') || msg.contains('▀') || msg.contains('▄'),
            "expected half-block glyph in output: {msg}"
        );
        assert!(msg.contains("point a QR scanner"));
    }

    #[test]
    fn qr_ascii_fallback_uses_hashes() {
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let mut io = RecordingIo::default();
        qr(&mut io, qr_args(dir, None, true)).unwrap();
        let msg = io.all_messages();
        assert!(
            msg.contains("##"),
            "ASCII renderer emits ## for dark: {msg}"
        );
        // Half-block glyphs must not appear when --ascii is set.
        assert!(!msg.contains('▀'));
        assert!(!msg.contains('▄'));
    }

    #[test]
    fn qr_name_flag_embeds_in_uri() {
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let mut io = RecordingIo::default();
        qr(&mut io, qr_args(dir, Some("alice".into()), true)).unwrap();
        let msg = io.all_messages();
        assert!(
            msg.contains("name=alice"),
            "uri should carry the ?name=alice param: {msg}"
        );
    }

    #[test]
    fn qr_without_identity_reports_unprovisioned() {
        let dir = tempdir();
        let err = qr(&mut RecordingIo::default(), qr_args(dir, None, false)).unwrap_err();
        assert!(matches!(err, IdentityCliError::SovereignLoad(_)), "{err:?}");
    }

    // ── pair-invite ────────────────────────────────────────────────────────

    fn pair_args(
        veil_dir: PathBuf,
        ttl_secs: u64,
        endpoint: &str,
        ascii: bool,
    ) -> super::super::cli::IdentityPairInviteArgs {
        super::super::cli::IdentityPairInviteArgs {
            veil_dir: Some(veil_dir),
            ttl_secs,
            endpoint: endpoint.into(),
            ascii,
        }
    }

    #[test]
    fn pair_invite_emits_uri_and_halfblock_matrix() {
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let mut io = RecordingIo::default();
        pair_invite(&mut io, pair_args(dir, 300, "tcp://10.0.0.5:45000", false)).unwrap();
        let msg = io.all_messages();

        assert!(msg.starts_with("veil:pair?"), "uri prefix: {msg}");
        assert!(
            msg.contains('█') || msg.contains('▀') || msg.contains('▄'),
            "expected half-block glyph: {msg}"
        );
        assert!(msg.contains("endpoint: tcp://10.0.0.5:45000"));
        assert!(msg.contains("invite expires at unix="));
    }

    #[test]
    fn pair_invite_ascii_fallback_uses_hashes() {
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let mut io = RecordingIo::default();
        pair_invite(&mut io, pair_args(dir, 120, "tcp://127.0.0.1:9000", true)).unwrap();
        let msg = io.all_messages();
        assert!(msg.contains("##"), "ASCII renderer emits ##: {msg}");
        assert!(!msg.contains('▀'));
        assert!(!msg.contains('▄'));
    }

    #[test]
    fn pair_invite_uri_matches_signed_invite_hash() {
        use veil_proto::pairing_invite::{PairingUri, hash_pair_secret};

        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let mut io = RecordingIo::default();
        pair_invite(&mut io, pair_args(dir, 300, "tcp://10.0.0.5:45000", true)).unwrap();
        let msg = io.all_messages();

        // Extract the URI from the first line and round-trip parse it.
        let uri_line = msg.lines().next().expect("at least one line");
        let parsed = PairingUri::from_uri(uri_line).expect("valid pair URI");

        // The published hash is the BLAKE3(pair_secret) — the target
        // scanning the URI must be able to recompute it. We can't
        // compare against the signed `PairingInvite` without the
        // source's bytes, but we *can* assert the two fields the
        // target sees are consistent with the hash-pair-secret flow:
        // the URI embedded endpoint survives round-trip, and the
        // pair_secret hashes to a 32-byte digest (non-zero).
        assert_eq!(parsed.endpoint, "tcp://10.0.0.5:45000");
        let h = hash_pair_secret(&parsed.pair_secret);
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn pair_invite_rejects_oversized_ttl() {
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let err = pair_invite(
            &mut RecordingIo::default(),
            pair_args(dir, 24 * 3600, "tcp://127.0.0.1:9000", true),
        )
        .unwrap_err();
        assert!(matches!(err, IdentityCliError::PairInvite(_)), "{err:?}");
    }

    #[test]
    fn pair_invite_rejects_zero_ttl() {
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let err = pair_invite(
            &mut RecordingIo::default(),
            pair_args(dir, 0, "tcp://127.0.0.1:9000", true),
        )
        .unwrap_err();
        assert!(matches!(err, IdentityCliError::PairInvite(_)), "{err:?}");
    }

    #[test]
    fn pair_invite_without_identity_reports_unprovisioned() {
        let dir = tempdir();
        let err = pair_invite(
            &mut RecordingIo::default(),
            pair_args(dir, 300, "tcp://127.0.0.1:9000", true),
        )
        .unwrap_err();
        assert!(matches!(err, IdentityCliError::SovereignLoad(_)), "{err:?}");
    }

    #[test]
    fn pair_invite_rejects_bad_endpoint() {
        // Reserved URI characters in endpoint must be rejected by
        // the PairingUri::to_uri validator surfaced as PairInvite.
        let dir = tempdir();
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();

        let err = pair_invite(
            &mut RecordingIo::default(),
            pair_args(dir, 300, "tcp://hostname?evil=1", true),
        )
        .unwrap_err();
        assert!(matches!(err, IdentityCliError::PairInvite(_)), "{err:?}");
    }

    // ── inspect-uri ────────────────────────────────────────────────────────

    fn inspect_args(uri: &str) -> super::super::cli::IdentityInspectUriArgs {
        super::super::cli::IdentityInspectUriArgs { uri: uri.into() }
    }

    #[test]
    fn inspect_uri_decodes_contact() {
        use veil_proto::identity_contact::{ALGO_NAME_ED25519, IdentityContact};
        use veil_proto::identity_document::ALGO_ED25519;
        let contact = IdentityContact {
            node_id: [0x11; 32],
            master_algo: ALGO_ED25519,
            master_pubkey: vec![0x22; 32],
            name: Some("bob".into()),
        };
        let uri = contact.to_uri().unwrap();

        let mut io = RecordingIo::default();
        inspect_uri(&mut io, inspect_args(&uri)).unwrap();
        let msg = io.all_messages();
        assert!(msg.contains("veil:identity (contact"), "{msg}");
        assert!(msg.contains(ALGO_NAME_ED25519));
        assert!(msg.contains(&"11".repeat(32)));
        assert!(msg.contains("name:           bob"));
    }

    #[test]
    fn inspect_uri_decodes_contact_without_name() {
        use veil_proto::identity_contact::IdentityContact;
        use veil_proto::identity_document::ALGO_ED25519;
        let c = IdentityContact {
            node_id: [0x55; 32],
            master_algo: ALGO_ED25519,
            master_pubkey: vec![0x66; 32],
            name: None,
        };
        let uri = c.to_uri().unwrap();
        let mut io = RecordingIo::default();
        inspect_uri(&mut io, inspect_args(&uri)).unwrap();
        let msg = io.all_messages();
        assert!(msg.contains("name:           (none)"), "{msg}");
    }

    #[test]
    fn inspect_uri_decodes_pair_invite() {
        use veil_proto::pairing_invite::{PairingUri, hash_pair_secret};
        let uri_obj = PairingUri {
            node_id: [0xAA; 32],
            pair_secret: [0xBB; 32],
            endpoint: "tcp://10.0.0.5:45000".into(),
            expires_at_unix: now_unix_secs() + 300,
        };
        let uri = uri_obj.to_uri().unwrap();

        let mut io = RecordingIo::default();
        inspect_uri(&mut io, inspect_args(&uri)).unwrap();
        let msg = io.all_messages();
        assert!(msg.contains("veil:pair (invite"), "{msg}");
        assert!(msg.contains("endpoint:          tcp://10.0.0.5:45000"));
        assert!(msg.contains(&hex_encode(&hash_pair_secret(&uri_obj.pair_secret))));
        assert!(msg.contains("(in "), "expected future-expiry note: {msg}");
    }

    #[test]
    fn inspect_uri_reports_expired_pair_invite() {
        use veil_proto::pairing_invite::PairingUri;
        let uri_obj = PairingUri {
            node_id: [0x00; 32],
            pair_secret: [0x01; 32],
            endpoint: "tcp://1.2.3.4:9".into(),
            expires_at_unix: 1, // unix=1970, deeply expired
        };
        let uri = uri_obj.to_uri().unwrap();
        let mut io = RecordingIo::default();
        inspect_uri(&mut io, inspect_args(&uri)).unwrap();
        let msg = io.all_messages();
        assert!(msg.contains("EXPIRED"), "{msg}");
    }

    #[test]
    fn inspect_uri_rejects_unknown_scheme() {
        let err = inspect_uri(
            &mut RecordingIo::default(),
            inspect_args("veil:identiti?id=deadbeef"),
        )
        .unwrap_err();
        assert!(matches!(err, IdentityCliError::InspectUri(_)), "{err:?}");
    }

    #[test]
    fn inspect_uri_rejects_malformed_contact() {
        // Right scheme, wrong body — parser must surface the error
        // with the `contact uri:` prefix so operators can tell which
        // decoder rejected it.
        let err = inspect_uri(
            &mut RecordingIo::default(),
            inspect_args("veil:identity?id=notahex"),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("contact uri"), "{msg}");
    }

    #[test]
    fn inspect_uri_rejects_malformed_pair() {
        let err = inspect_uri(
            &mut RecordingIo::default(),
            inspect_args("veil:pair?id=nothexreally"),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("pair uri"), "{msg}");
    }

    // ── pair-listen + pair-accept ─────────────────────
    //
    // The crypto-level end-to-end is already covered by the
    // `pair_transport::tests::tcp_wrappers_end_to_end_happy_path`
    // test (same state machines + same TCP wrappers the CLI
    // calls). Here we only cover CLI arg-handling / error-
    // surface paths that aren't exercised there.

    #[test]
    fn pair_accept_rejects_expired_invite() {
        let tgt_dir = tempdir();
        // Craft a pair URI whose expires_at is in the past.
        use veil_proto::pairing_invite::PairingUri;
        let uri = PairingUri {
            node_id: [0xAB; 32],
            pair_secret: [0xCD; 32],
            endpoint: "tcp://127.0.0.1:65535".into(),
            expires_at_unix: 1, // unix=1970
        }
        .to_uri()
        .unwrap();

        let args = super::super::cli::IdentityPairAcceptArgs {
            uri,
            veil_dir: Some(tgt_dir),
            label: "phone".into(),
            yes_i_compared_codes: true,
        };
        let err = pair_accept(&mut RecordingIo::default(), args).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("expired"), "{msg}");
    }

    #[test]
    fn pair_accept_rejects_non_tcp_endpoint() {
        let tgt_dir = tempdir();
        use veil_proto::pairing_invite::PairingUri;
        let uri = PairingUri {
            node_id: [0xAB; 32],
            pair_secret: [0xCD; 32],
            endpoint: "ws://127.0.0.1:1234".into(),
            expires_at_unix: now_unix_secs() + 300,
        }
        .to_uri()
        .unwrap();
        let args = super::super::cli::IdentityPairAcceptArgs {
            uri,
            veil_dir: Some(tgt_dir),
            label: "phone".into(),
            yes_i_compared_codes: true,
        };
        let err = pair_accept(&mut RecordingIo::default(), args).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("tcp://"), "{msg}");
    }

    // ── export-qr-backup / import-qr-backup ────────────────────────────────

    /// Provision an identity with `master.enc` written via a
    /// fast Argon2id override — same pattern as `provision_source_with_encrypted_master`
    /// but kept private to this module's tests.
    fn provision_with_master_enc(password: &[u8]) -> (PathBuf, PathBuf) {
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
        let dir = tempdir();
        let pw_path = dir.join("password");
        fs::write(&pw_path, std::str::from_utf8(password).unwrap()).unwrap();
        let now = now_unix_secs();
        create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: Some(password.to_vec()),
            argon2_params_override: Some((16 * 1024, 1, 1)),
            extra_entropy: None,
            instance_label: "test".into(),
            pow_difficulty: veil_cfg::identity_policy::IdentityPolicy::DEFAULT_POW_DIFFICULTY,
            issued_at_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .expect("create identity with master.enc");
        (dir, pw_path)
    }

    #[test]
    fn export_qr_backup_emits_uri_and_qr_block() {
        let pw = b"correct-horse";
        let (dir, master_pw_path) = provision_with_master_enc(pw);
        let qr_pw_path = dir.join("qr_password");
        fs::write(&qr_pw_path, "qr-cold-storage").unwrap();

        let mut io = RecordingIo::default();
        let args = super::super::cli::IdentityExportQrBackupArgs {
            veil_dir: Some(dir),
            password_file: Some(master_pw_path),
            phrase_file: None,
            qr_password_file: qr_pw_path,
            ascii: true,
        };
        export_qr_backup(&mut io, args).expect("export ok");
        let msg = io.all_messages();
        assert!(msg.starts_with("veil:master-backup?"), "{msg}");
        assert!(msg.contains("v=1"));
        assert!(msg.contains("data="));
        // ASCII renderer emits "##" for dark modules.
        assert!(msg.contains("##"));
        assert!(msg.contains("WARNING"));
    }

    #[test]
    fn export_then_import_round_trips_node_id() {
        use veil_identity::sovereign::SovereignIdentity;

        let pw = b"shared-pw";
        let (src_dir, master_pw_path) = provision_with_master_enc(pw);
        let qr_pw_path = src_dir.join("qr_password");
        fs::write(&qr_pw_path, "qr-secret").unwrap();

        // Capture the source's node_id BEFORE export so we
        // can verify import recovers it.
        let src_sov = SovereignIdentity::load_from_dir(&src_dir).unwrap();
        let original_node_id = *src_sov.node_id();

        // Export.
        let mut io_export = RecordingIo::default();
        export_qr_backup(
            &mut io_export,
            super::super::cli::IdentityExportQrBackupArgs {
                veil_dir: Some(src_dir),
                password_file: Some(master_pw_path),
                phrase_file: None,
                qr_password_file: qr_pw_path.clone(),
                ascii: true,
            },
        )
        .unwrap();
        let uri = io_export
            .all_messages()
            .lines()
            .next()
            .expect("at least one line")
            .to_string();
        assert!(uri.starts_with("veil:master-backup?"));

        // Import into a brand-new dir.
        let restored_dir = tempdir();
        let mut io_import = RecordingIo::default();
        import_qr_backup(
            &mut io_import,
            super::super::cli::IdentityImportQrBackupArgs {
                uri,
                password_file: qr_pw_path,
                veil_dir: Some(restored_dir.clone()),
                label: "phone".into(),
            },
        )
        .expect("import ok");

        let restored_sov =
            SovereignIdentity::load_from_dir(&restored_dir).expect("restored dir loads");
        assert_eq!(
            restored_sov.node_id(),
            &original_node_id,
            "import-qr-backup must recover the same node_id",
        );
        // Per-device subkey is fresh — restore generates a new one.
        let original_subkey = &src_sov.document.identity_keys[src_sov.sig_key_idx as usize].pubkey;
        let restored_subkey =
            &restored_sov.document.identity_keys[restored_sov.sig_key_idx as usize].pubkey;
        assert_ne!(
            original_subkey, restored_subkey,
            "restored device must mint its own identity_sk subkey",
        );

        let import_msg = io_import.all_messages();
        assert!(import_msg.contains("restored node_id="));
        assert!(import_msg.contains(&hex_encode(&original_node_id)));
    }

    #[test]
    fn export_via_phrase_file_works() {
        // Provision an identity, capture the BIP-39 phrase that
        // `create_identity` would normally print, write it to a
        // file, then export-qr-backup via --phrase-file.
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
        let dir = tempdir();
        let now = now_unix_secs();
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "test".into(),
            pow_difficulty: veil_cfg::identity_policy::IdentityPolicy::DEFAULT_POW_DIFFICULTY,
            issued_at_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();
        let phrase_str = out.master_seed_phrase.to_string();
        let phrase_path = dir.join("phrase");
        fs::write(&phrase_path, &phrase_str).unwrap();
        let qr_pw_path = dir.join("qr_password");
        fs::write(&qr_pw_path, "secret-pw").unwrap();

        let mut io = RecordingIo::default();
        export_qr_backup(
            &mut io,
            super::super::cli::IdentityExportQrBackupArgs {
                veil_dir: Some(dir),
                password_file: None,
                phrase_file: Some(phrase_path),
                qr_password_file: qr_pw_path,
                ascii: true,
            },
        )
        .unwrap();
        let msg = io.all_messages();
        assert!(msg.starts_with("veil:master-backup?"));
    }

    #[test]
    fn export_rejects_missing_seed_source() {
        let dir = tempdir();
        let qr_pw = dir.join("qr_pw");
        fs::write(&qr_pw, "x").unwrap();
        let err = export_qr_backup(
            &mut RecordingIo::default(),
            super::super::cli::IdentityExportQrBackupArgs {
                veil_dir: Some(dir),
                password_file: None,
                phrase_file: None,
                qr_password_file: qr_pw,
                ascii: true,
            },
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("password-file") && msg.contains("phrase-file"),
            "{msg}",
        );
    }

    #[test]
    fn import_rejects_wrong_password() {
        let pw = b"src-pw";
        let (src_dir, master_pw_path) = provision_with_master_enc(pw);
        let qr_pw_path = src_dir.join("qr_password");
        fs::write(&qr_pw_path, "right-pw").unwrap();

        // Export with the right password.
        let mut io_export = RecordingIo::default();
        export_qr_backup(
            &mut io_export,
            super::super::cli::IdentityExportQrBackupArgs {
                veil_dir: Some(src_dir),
                password_file: Some(master_pw_path),
                phrase_file: None,
                qr_password_file: qr_pw_path,
                ascii: true,
            },
        )
        .unwrap();
        let uri = io_export.all_messages().lines().next().unwrap().to_string();

        // Import with the wrong password.
        let restored_dir = tempdir();
        let bad_pw_path = restored_dir.join("bad_pw");
        fs::write(&bad_pw_path, "wrong-pw").unwrap();
        let err = import_qr_backup(
            &mut RecordingIo::default(),
            super::super::cli::IdentityImportQrBackupArgs {
                uri,
                password_file: bad_pw_path,
                veil_dir: Some(restored_dir),
                label: "phone".into(),
            },
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("decode uri"), "{msg}");
    }

    #[test]
    fn import_rejects_malformed_uri() {
        let dir = tempdir();
        let pw_path = dir.join("pw");
        fs::write(&pw_path, "x").unwrap();
        let err = import_qr_backup(
            &mut RecordingIo::default(),
            super::super::cli::IdentityImportQrBackupArgs {
                uri: "not-a-valid-uri".into(),
                password_file: pw_path,
                veil_dir: Some(dir),
                label: "phone".into(),
            },
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("decode uri"), "{msg}");
    }

    #[test]
    fn pair_listen_rejects_missing_master_unlock() {
        let dir = tempdir();
        // Provision without master.enc so load_master_seed_for_pair fails.
        create(&mut RecordingIo::default(), create_args(dir.clone())).unwrap();
        let args = super::super::cli::IdentityPairListenArgs {
            veil_dir: Some(dir),
            endpoint: "tcp://127.0.0.1:65535".into(),
            ttl_secs: 300,
            password_file: None,
            phrase_file: None,
            ascii: true,
            yes_i_compared_codes: true,
        };
        let err = pair_listen(&mut RecordingIo::default(), args).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("password-file") || msg.contains("phrase-file"),
            "{msg}"
        );
    }

    // ── standalone + delegate-device CLI tests ─────────────

    fn standalone_args(veil_dir: PathBuf) -> super::super::cli::IdentityStandaloneArgs {
        super::super::cli::IdentityStandaloneArgs {
            veil_dir: Some(veil_dir),
            valid_for_secs: 7 * 24 * 3600,
            force: false,
        }
    }

    #[test]
    fn standalone_writes_doc_and_loads_via_sovereign_identity() {
        use veil_identity::sovereign::SovereignIdentity;
        let dir = tempdir();
        let mut io = RecordingIo::default();
        standalone(&mut io, standalone_args(dir.clone())).unwrap();

        // Both files exist.
        assert!(dir.join(IDENTITY_DOCUMENT_FILE).exists());
        assert!(
            dir.join(veil_cfg::sovereign_flow::DEVICE_IDENTITY_SK_FILE)
                .exists()
        );

        // Doc loads + reports standalone.
        let sov = SovereignIdentity::load_from_dir(&dir).unwrap();
        assert!(sov.is_standalone(), "must be standalone (master == device)");

        // Output mentions node_id.
        let msgs = io.all_messages();
        assert!(msgs.contains("node_id:"));
        assert!(msgs.contains("standalone"));
    }

    #[test]
    fn standalone_refuses_to_clobber_without_force() {
        let dir = tempdir();
        // First call writes the doc.
        standalone(&mut RecordingIo::default(), standalone_args(dir.clone())).unwrap();
        // Second call without --force fails.
        let err =
            standalone(&mut RecordingIo::default(), standalone_args(dir.clone())).unwrap_err();
        assert!(
            matches!(err, IdentityCliError::IdentityAlreadyExists(_)),
            "{err:?}",
        );
    }

    #[test]
    fn standalone_force_overwrites_existing() {
        use veil_identity::sovereign::SovereignIdentity;
        let dir = tempdir();
        // First standalone provisioning.
        standalone(&mut RecordingIo::default(), standalone_args(dir.clone())).unwrap();
        let sov_a = SovereignIdentity::load_from_dir(&dir).unwrap();
        let node_id_a = *sov_a.node_id();
        drop(sov_a);

        //force overwrites with a fresh seed → fresh node_id.
        let mut args = standalone_args(dir.clone());
        args.force = true;
        standalone(&mut RecordingIo::default(), args).unwrap();
        let sov_b = SovereignIdentity::load_from_dir(&dir).unwrap();
        assert_ne!(
            sov_b.node_id(),
            &node_id_a,
            "--force must rotate to a fresh standalone identity",
        );
    }

    fn delegate_args(
        veil_dir: PathBuf,
        pubkey_file: PathBuf,
        phrase_file: PathBuf,
    ) -> super::super::cli::IdentityDelegateDeviceArgs {
        super::super::cli::IdentityDelegateDeviceArgs {
            veil_dir: Some(veil_dir),
            pubkey_file,
            password_file: None,
            phrase_file: Some(phrase_file),
            valid_for_secs: 7 * 24 * 3600,
            out: None,
        }
    }

    #[test]
    fn delegate_device_appends_subkey_and_doc_verifies() {
        use ed25519_dalek::SigningKey;
        use rand_core::{OsRng, RngCore};
        use veil_identity::verify::verify_identity_document;

        let dir = tempdir();

        // Provision a master identity. Use the library's create_identity
        // directly so we can capture the BIP-39 phrase + write it to a
        // file delegate_device can re-read.
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
        let now = now_unix_secs();
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "src".into(),
            pow_difficulty: 8,
            issued_at_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();

        // Write the BIP-39 phrase to a file for delegate-device.
        let phrase_path = dir.join("phrase.txt");
        fs::write(&phrase_path, out.master_seed_phrase.to_string()).unwrap();

        // Generate a fresh "target device" Ed25519 keypair and write its
        // pubkey as 64 hex chars to a file delegate-device can read.
        let mut tgt_seed = [0u8; 32];
        OsRng.fill_bytes(&mut tgt_seed);
        let tgt_sk = SigningKey::from_bytes(&tgt_seed);
        let tgt_pk = tgt_sk.verifying_key();
        let pubkey_path = dir.join("target_pubkey.hex");
        fs::write(&pubkey_path, hex_encode(tgt_pk.as_bytes())).unwrap();

        // Run delegate-device.
        let mut io = RecordingIo::default();
        delegate_device(
            &mut io,
            delegate_args(dir.clone(), pubkey_path, phrase_path),
        )
        .unwrap();

        // Doc on disk now has 2 keys and verifies.
        let bytes = fs::read(dir.join(IDENTITY_DOCUMENT_FILE)).unwrap();
        let doc = IdentityDocument::decode(&bytes).unwrap();
        assert_eq!(doc.identity_keys.len(), 2);
        assert_eq!(doc.identity_keys[1].pubkey, tgt_pk.as_bytes());
        verify_identity_document(&doc, now + 100).expect("doc verifies");

        // sig_key_idx is unchanged — source still signs with its own key.
        assert_eq!(doc.sig_key_idx, out.document.sig_key_idx);

        // Output mentions the new device.
        let msgs = io.all_messages();
        assert!(msgs.contains(&hex_encode(tgt_pk.as_bytes())));
        assert!(msgs.contains("new IdentityKey index"));
    }

    #[test]
    fn delegate_device_rejects_pubkey_already_present() {
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};

        let dir = tempdir();
        let now = now_unix_secs();
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "src".into(),
            pow_difficulty: 8,
            issued_at_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();
        let phrase_path = dir.join("phrase.txt");
        fs::write(&phrase_path, out.master_seed_phrase.to_string()).unwrap();

        // Try to delegate to the EXISTING subkey's pubkey — must reject.
        let pubkey_path = dir.join("dup_pubkey.hex");
        fs::write(
            &pubkey_path,
            hex_encode(&out.document.identity_keys[0].pubkey),
        )
        .unwrap();

        let err = delegate_device(
            &mut RecordingIo::default(),
            delegate_args(dir.clone(), pubkey_path, phrase_path),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("already present"), "{msg}");
    }

    #[test]
    fn delegate_device_rejects_wrong_master_phrase() {
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};

        let dir = tempdir();
        let now = now_unix_secs();
        let _out = create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "src".into(),
            pow_difficulty: 8,
            issued_at_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();

        // Write a bogus phrase from a fresh master_seed → won't match.
        use veil_cfg::identity_master::{encode_master_seed_to_phrase, generate_master_seed};
        let bogus_seed = generate_master_seed();
        let bogus_phrase = encode_master_seed_to_phrase(&bogus_seed).unwrap();
        let phrase_path = dir.join("bogus_phrase.txt");
        fs::write(&phrase_path, bogus_phrase.to_string()).unwrap();

        let pubkey_path = dir.join("target.hex");
        fs::write(&pubkey_path, hex_encode(&[0xAAu8; 32])).unwrap();

        let err = delegate_device(
            &mut RecordingIo::default(),
            delegate_args(dir, pubkey_path, phrase_path),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("does not match"),
            "expected master mismatch error, got: {msg}",
        );
    }

    #[test]
    fn delegate_device_rejects_short_pubkey_file() {
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};

        let dir = tempdir();
        let now = now_unix_secs();
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "src".into(),
            pow_difficulty: 8,
            issued_at_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();
        let phrase_path = dir.join("phrase.txt");
        fs::write(&phrase_path, out.master_seed_phrase.to_string()).unwrap();

        // Truncated pubkey: 16 bytes instead of 32.
        let pubkey_path = dir.join("short.bin");
        fs::write(&pubkey_path, [0xAAu8; 16]).unwrap();

        let err = delegate_device(
            &mut RecordingIo::default(),
            delegate_args(dir, pubkey_path, phrase_path),
        )
        .unwrap_err();
        assert!(matches!(err, IdentityCliError::PubkeyFile(_)), "{err:?}",);
    }

    #[test]
    fn read_pubkey_file_accepts_raw_bytes() {
        let dir = tempdir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pubkey.bin");
        fs::write(&path, [0xAAu8; 32]).unwrap();
        let out = read_pubkey_file(&path).unwrap();
        assert_eq!(out, vec![0xAAu8; 32]);
    }

    #[test]
    fn read_pubkey_file_accepts_hex() {
        let dir = tempdir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pubkey.hex");
        let pk = vec![0xCDu8; 32];
        fs::write(&path, hex_encode(&pk)).unwrap();
        let out = read_pubkey_file(&path).unwrap();
        assert_eq!(out, pk);
    }

    #[test]
    fn read_pubkey_file_rejects_garbage() {
        let dir = tempdir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("garbage.txt");
        fs::write(&path, b"not even hex, also wrong length").unwrap();
        let err = read_pubkey_file(&path).unwrap_err();
        assert!(matches!(err, IdentityCliError::PubkeyFile(_)), "{err:?}");
    }
}
