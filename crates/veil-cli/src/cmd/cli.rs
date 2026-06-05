use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use veil_cfg::SignatureAlgorithm;
use veil_cfg::identity_policy::IdentityPolicy;

use super::output::OutputFormatArg;

#[derive(Parser, Debug)]
#[command(name = "veil-cli", version)]
pub struct Cli {
    /// Path to the config file (default: auto-located).
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Output format: text (default) or json.
    #[arg(long, value_enum, default_value_t = OutputFormatArg::Text)]
    pub output_format: OutputFormatArg,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Manage the node configuration file.
    Config(ConfigArgs),
    /// Generate and manage cryptographic key pairs and PoW nonces.
    Key(KeyArgs),
    /// Start, stop, and inspect the veil node.
    Node(NodeArgs),
    /// Manage listeners (inbound transport endpoints).
    Listen(ListenArgs),
    /// Manage known peers in the config.
    Peers(PeersArgs),
    /// Inspect active sessions.
    Sessions(SessionsArgs),
    /// Low-level debugging tools (transport, peer connections, packet capture).
    Debug(DebugArgs),
    /// Peer Exchange (PEX) introspection.
    Pex(PexArgs),
    /// Sovereign-identity management.
    Identity(IdentityArgs),
    /// Out-of-band bootstrap invites. Generate / consume
    /// QR-/URL-style invites so a brand-new node can join the network
    /// without depending on a hardcoded seed list (which a state-level
    /// censor can simply IP-block).
    Bootstrap(BootstrapArgs),
    /// Trusted-listener invite bundles (Phase 5c+).  Out-of-band sharing
    /// of `Trusted` / `Hidden` listener URIs that are NOT advertised on
    /// PEX or DHT — the operator emits а signed CBOR bundle that carries
    /// (node_id, vk, transport URI, PSK, expiry) and hands it к the
    /// recipient through any side channel (QR scan, encrypted chat,
    /// physical paper).  Distinct от `bootstrap invite`: bootstrap
    /// invites are public-listener handoff, `invite` bundles carry per-
    /// listener PSK material so the recipient can complete the obfs4-PSK
    /// handshake against а listener no one else can find.
    Invite(InviteArgs),
    /// Private-veil-network admin tooling: generate owner key,
    /// issue membership certs, inspect existing certs. Required by
    /// operators standing up а private network (`[network].mode =
    /// "private"`); public-mode nodes don't need any of these.
    Network(NetworkArgs),
    /// Self-update: check for / apply signed updates from the
    /// operator's manifest endpoints. Requires the
    /// `[update]` config section. Works without a running node —
    /// fetch + verify + state-file all happen out-of-band.
    Update(UpdateArgs),
    /// Mobile-mode controls. Toggles runtime flags
    /// that GUI wrappers / mobile-app onPause-onResume hooks
    /// normally drive via the IPC API. Useful for: mobile app
    /// integrators testing their integration without writing IPC
    /// code; cron-based cellular saving (flip background mode at
    /// night); headless deployments where the daemon acts as a
    /// mobile gateway. Requires a running node.
    Mobile(MobileArgs),
    /// Windows Service integration: register / unregister the node
    /// with the Service Control Manager so it auto-starts on boot.
    /// Non-Windows platforms reject all subcommands with a clear
    /// message.
    Service(ServiceArgs),
}

#[derive(Args, Debug)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub command: ServiceCommand,
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    /// Register the current binary as a Windows service. The service
    /// auto-starts on boot and launches with the supplied `--config`
    /// (or the default-located config when none is given).
    Install {
        /// Config file to pass to the service. Stored in the service's
        /// `ImagePath` command-line, so the binary must still be
        /// accessible at its current location after install.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Deregister the service. Stops it first if currently running.
    Uninstall,
    /// Entry point invoked by the Service Control Manager. Operators
    /// should not call this directly — use `install` + `sc start
    /// VeilNode` instead.
    #[command(hide = true)]
    Run,
}

#[derive(Args, Debug)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub command: IdentityCommand,
}

#[derive(Subcommand, Debug)]
pub enum IdentityCommand {
    /// Create a fresh sovereign identity. Displays the 24-word
    /// BIP-39 paper-backup phrase, mines the document PoW, and
    /// persists the per-device `instance_id` to the veil
    /// config dir.
    Create(IdentityCreateArgs),
    /// Pretty-print an identity from its on-disk state
    /// (instance_id + the most-recent signed IdentityDocument).
    Show(IdentityShowArgs),
    /// Rotate this device's active `identity_sk`. Loads the
    /// master seed from the BIP-39 phrase or encrypted master
    /// file, generates a fresh identity subkey, master-certifies
    /// it, bumps document_version, and persists the updated
    /// signed document.
    Rotate(IdentityRotateArgs),
    /// Restore a sovereign identity on a fresh device from the
    /// 24-word BIP-39 paper-backup phrase. The master-level
    /// `node_id` (stable across device loss) is reconstructed;
    /// a fresh device-local `identity_sk` is generated and
    /// master-certified under the recovered seed.
    Restore(IdentityRestoreArgs),
    /// Claim a human-readable name for this sovereign identity.
    /// Mines rarity-proportional PoW, signs with the active
    /// `identity_sk`, and persists the signed `NameClaim` under
    /// `<veil_dir>/name_claims/<name>.bin`. The running
    /// daemon picks it up on its next 6-hour republish tick (or
    /// on restart) and publishes to the DHT so peers resolving
    /// `@<name>` can find this identity.
    ClaimName(IdentityClaimNameArgs),
    /// Render this identity's public contact as an `veil:identity?...`
    /// URI + a scannable QR code printed to the terminal. Used
    /// for in-person contact exchange: Alice runs `identity qr`
    /// Bob points his phone camera at the screen, Bob's scanner
    /// gets the URI + (optionally via the URI's `?name=...`
    /// parameter) the preferred display name.
    Qr(IdentityQrArgs),
    /// Generate a time-limited pairing invite that lets a new
    /// device join this sovereign identity (source
    /// side). Signs a `PairingInvite` with the active identity_sk
    /// prints the canonical `veil:pair?...` URI + QR code, and
    /// displays the target-device transport endpoint. The target
    /// device scans the QR; the master-certification + OOB compare
    /// are performed once the target dials back (follow-up slice).
    PairInvite(IdentityPairInviteArgs),
    /// Parse and pretty-print an `veil:identity?…` (contact) or
    /// `veil:pair?…` (invite) URI without performing any
    /// side-effects. Target-side diagnostic: lets the operator
    /// confirm a scanned QR decoded cleanly and review the fields
    /// (endpoint, expiry, node_id, …) before running the full
    /// pair / contact-import flow.
    InspectUri(IdentityInspectUriArgs),
    /// Bind a TCP listener, display the canonical `veil:pair?…`
    /// URI + QR, accept one pairing dial-back, run the source
    /// side of the ceremony, and persist the updated
    /// `IdentityDocument` to disk on success. Requires the
    /// master-file password so the freshly-minted target subkey
    /// can be master-certified.
    PairListen(IdentityPairListenArgs),
    /// Dial the endpoint encoded in a scanned `veil:pair?…`
    /// URI, run the target side of the ceremony, and on success
    /// persist the paired identity state (document + fresh
    /// identity_sk seed + sig_key_idx override + instance_id)
    /// into the target's `--veil-dir`.
    PairAccept(IdentityPairAcceptArgs),
    /// Encrypt this device's master_seed and emit it as a
    /// scannable `veil:master-backup?…` QR.
    /// The QR is the **photo-grade** disaster-recovery backup
    /// for the case where both the BIP-39 paper phrase AND the
    /// `master.enc` file are gone. Decrypting requires the QR
    /// password — convey it out-of-band (verbal, sealed
    /// envelope, separate password manager). Filming the QR
    /// alone is insufficient to compromise the identity.
    ExportQrBackup(IdentityExportQrBackupArgs),
    /// Decrypt a `veil:master-backup?…` URI back to a
    /// master_seed and `restore_identity` into `--veil-dir`.
    /// Used to recover from a photographed QR backup when
    /// neither the BIP-39 phrase nor the `master.enc` file is
    /// available. Same end-state as `identity restore` from
    /// BIP-39: node_id is recovered, a fresh per-device
    /// identity_sk is generated.
    ImportQrBackup(IdentityImportQrBackupArgs),
    /// provision a single-device "standalone" sovereign
    /// identity where the device key IS the master key (no separate
    /// master keypair, no BIP-39 ceremony, no `master.enc` file).
    /// `node_id == device_id == BLAKE3(device_pubkey)`. This is
    /// the default UX for phone-only / laptop-only users and
    /// matches what the runtime auto-builds on first start when no
    /// `identity_document.bin` exists.
    Standalone(IdentityStandaloneArgs),
    /// master-side delegation issuance. Sign a fresh
    /// `IdentityKey` for a new device's pubkey and append it to
    /// the existing `IdentityDocument`. Run this on the device
    /// holding the master seed; the resulting updated document is
    /// transported (USB / QR / scp) to the target device.
    DelegateDevice(IdentityDelegateDeviceArgs),
    /// mint a `MigrationCert` linking the OLD identity
    /// (in `--from`) к the NEW identity (in `--to`), signed by the
    /// OLD master keypair. The cert is written к
    /// `<--to>/migration_cert.bin` (override с `--cert-out`).
    /// Operators who want the cert published to the DHT need a
    /// running daemon — point the daemon at the new veil_dir и
    /// it picks up the cert на the next maintenance tick (or use
    /// `node dht put` directly с the printed dht-key).
    ///
    /// Security non-downgrade is enforced: the NEW identity's
    /// master_algo MUST have security_tier ≥ the OLD's
    /// (`hybrid > falcon512 > ed25519`). Hybrid → ed25519 will
    /// be rejected at sign time.
    Migrate(IdentityMigrateArgs),
    /// Compute the DHT key under which an `IdentityDocument` is
    /// published, given its `node_id`. No I/O — pure
    /// `blake3("veil.identity_dht.v1" || node_id)`. Used by the
    /// devnet smoke test to fetch a peer's signed identity from the
    /// network via `node dht recursive-get`.
    DhtKey {
        /// 32-byte node_id as 64 lowercase hex chars.
        #[arg(value_name = "NODE_ID")]
        node_id: String,
    },
    /// Compute the DHT key under which a `NameClaim` is published
    /// given the claimed human-readable name. The name is run
    /// through the same NameClaim V2 normaliser the daemon uses
    /// (lowercase ASCII; `[a-z0-9#_-]` only). No I/O — pure
    /// `blake3("veil.name_claim_dht.v1" || len_be_u16 ||
    /// normalized_name)`. Counterpart of `dht-key` for the
    /// human-readable-naming layer of the sovereign-identity bundle.
    NameDhtKey {
        /// The name to claim (e.g. `alice`).
        #[arg(value_name = "NAME")]
        name: String,
    },
}

#[derive(Args, Debug)]
pub struct IdentityQrArgs {
    /// Overrides `~/.config/veil` (or `$VEIL_IDENTITY_DIR`)
    /// as the source directory.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Optional preferred display name to embed in the URI.
    /// Passed through the `NameClaim V2` normaliser — non-ASCII /
    /// homoglyph characters are rejected. Usually the same name
    /// the operator ran `identity claim-name` with.
    #[arg(long)]
    pub name: Option<String>,

    /// Emit ASCII blocks instead of Unicode half-blocks. Useful
    /// on terminals that can't render the half-block characters
    /// cleanly or where copy-paste safety matters.
    #[arg(long)]
    pub ascii: bool,
}

#[derive(Args, Debug)]
pub struct IdentityPairListenArgs {
    /// Overrides `~/.config/veil` as the source directory.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Transport endpoint advertised in the QR and bound to
    /// locally. Form: `tcp://HOST:PORT`. Reserved characters
    /// (`&`, `=`, `?`, `#`) are forbidden. The HOST:PORT is the
    /// literal bind addr — pass `0.0.0.0:45000` for wildcard
    /// binding, a private IP for LAN-only pairings, etc.
    #[arg(long)]
    pub endpoint: String,

    /// Invite TTL in seconds — capped at 1 h by the signer
    /// (`PAIR_INVITE_MAX_TTL_SECS`). The listener itself has no
    /// deadline; closing the process aborts the pending pair.
    #[arg(long, default_value_t = 300)]
    pub ttl_secs: u64,

    /// Path to a file whose first line is the master-file
    /// password. Used to decrypt `<veil_dir>/master.enc`
    /// (written by `identity create --password-file …`). Exactly
    /// one of `--password-file` / `--phrase-file` must be set.
    #[arg(long)]
    pub password_file: Option<PathBuf>,

    /// Path to a file containing the 24-word BIP-39 phrase
    /// (single line, whitespace-separated). Alternative to
    /// `--password-file` for users who only kept the paper
    /// backup.
    #[arg(long)]
    pub phrase_file: Option<PathBuf>,

    /// Emit ASCII blocks in the QR rendering instead of
    /// Unicode half-blocks (fallback for terminals that can't
    /// render the half-block glyphs).
    #[arg(long)]
    pub ascii: bool,

    /// Skip the interactive "do the codes match?" prompt.
    /// Intended for scripted tests — production pairings must
    /// leave this unset so the operator can visually compare.
    #[arg(long)]
    pub yes_i_compared_codes: bool,
}

#[derive(Args, Debug)]
pub struct IdentityPairAcceptArgs {
    /// Scanned `veil:pair?…` URI (positional argument so the
    /// operator can paste it directly).
    pub uri: String,

    /// Target's state directory. MUST be distinct from the
    /// source's — this command writes a fresh identity_sk + doc
    /// + sig_key_idx override + instance_id here.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Operator-chosen human label for this device (e.g.
    /// `"phone"`, `"laptop"`, `"home-server"`). Stored in the
    /// `instance_id` file.
    #[arg(long, default_value = "target")]
    pub label: String,

    /// Skip the interactive "do the codes match?" prompt.
    #[arg(long)]
    pub yes_i_compared_codes: bool,
}

#[derive(Args, Debug)]
pub struct IdentityExportQrBackupArgs {
    /// Overrides `~/.config/veil` as the source directory
    /// (used to locate `master.enc` when `--password-file` is set).
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Decrypt this device's existing `master.enc` using the
    /// password in this file (one line, trimmed). Mutually
    /// exclusive with `--phrase-file`.
    #[arg(long, conflicts_with = "phrase_file")]
    pub password_file: Option<PathBuf>,

    /// Decode the master_seed from a 24-word BIP-39 phrase in
    /// this file (whitespace-separated). Mutually exclusive
    /// with `--password-file`.
    #[arg(long, conflicts_with = "password_file")]
    pub phrase_file: Option<PathBuf>,

    /// Encrypt the QR payload with the password in this file.
    /// Required. Convey this password out-of-band — never
    /// alongside the QR photo.
    #[arg(long)]
    pub qr_password_file: PathBuf,

    /// Emit ASCII blocks instead of Unicode half-blocks.
    #[arg(long)]
    pub ascii: bool,
}

#[derive(Args, Debug)]
pub struct IdentityImportQrBackupArgs {
    /// The scanned `veil:master-backup?…` URI (positional).
    pub uri: String,

    /// Decrypt the QR payload with the password in this file.
    #[arg(long)]
    pub password_file: PathBuf,

    /// Target veil directory where the restored identity
    /// state will be written. MUST be empty / fresh — the
    /// restore writes `identity_document.bin`
    /// `device_identity_sk.bin`, and an `instance_id` file.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Operator-chosen label for the restored device's
    /// instance. Stored in the `instance_id` file.
    #[arg(long, default_value = "restored")]
    pub label: String,
}

#[derive(Args, Debug)]
pub struct IdentityInspectUriArgs {
    /// The URI string (copy-pasted from a scanner or QR tool).
    /// Accepts both `veil:identity?…` and `veil:pair?…`
    /// schemes; rejects anything else with a clear error.
    pub uri: String,
}

#[derive(Args, Debug)]
pub struct IdentityPairInviteArgs {
    /// Overrides `~/.config/veil` (or `$VEIL_IDENTITY_DIR`)
    /// as the source directory.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Invite validity window in seconds. Must be small — the
    /// invite is one-shot and should be used within minutes. Hard
    /// capped to 1 hour to keep `pair_secret` exposure tight.
    #[arg(long, default_value_t = 300)]
    pub ttl_secs: u64,

    /// Transport endpoint hint encoded in the QR so the target
    /// device knows where to dial after scanning
    /// (e.g. `tcp://192.168.1.5:45000`). Reserved characters
    /// `&`, `=`, `?`, `#` are forbidden.
    #[arg(long)]
    pub endpoint: String,

    /// Emit ASCII blocks instead of Unicode half-blocks, for
    /// terminals that can't render the half-block characters.
    #[arg(long)]
    pub ascii: bool,
}

#[derive(Args, Debug)]
pub struct IdentityClaimNameArgs {
    /// Overrides `~/.config/veil` (or `$VEIL_IDENTITY_DIR`)
    /// as the source directory.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// The name to claim (e.g. `alice`). Normalised to lowercase
    /// ASCII; `[a-z0-9#_-]` only — Unicode / homoglyphs rejected
    /// at sign time.
    pub name: String,
}

#[derive(Args, Debug)]
pub struct IdentityCreateArgs {
    /// Overrides `~/.config/veil` (or `$VEIL_IDENTITY_DIR`)
    /// as the destination directory.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Human-readable label for this first instance
    /// (e.g. "laptop", "home-server").
    #[arg(long, default_value = "primary")]
    pub label: String,

    /// **Inert / deprecated.** Retained for CLI back-compat with
    /// pre-refactor scripts. Identity documents no longer carry а
    /// document-level PoW (`IdentityDocument.pow_nonce` was removed
    /// в Phase 6.50.b). The value is accepted but does not influence
    /// the created identity. Will be removed в а future major version.
    #[arg(long, hide = true)]
    pub pow_difficulty: Option<u32>,

    /// Validity window in seconds (document `valid_until_unix` =
    /// now + this). Capped by protocol to 30 days.
    #[arg(long, default_value_t = 7 * 24 * 3600)]
    pub valid_for_secs: u64,

    /// Read an encrypted-master-file password from this file
    /// (one line, trimmed). If set, a `master.enc` file is
    /// written alongside the BIP-39 paper backup.
    #[arg(long)]
    pub password_file: Option<PathBuf>,

    /// Read caller-supplied entropy (at least 32 bytes) from this
    /// file and mix it into the master_seed draw.
    #[arg(long)]
    pub extra_entropy_file: Option<PathBuf>,

    /// Suppress the interactive retype-3-words confirmation.
    /// Intended for non-interactive scripts / CI; must not be
    /// used for user-facing identity creation per
    /// `docs/opsec-user-guide.md`.
    #[arg(long)]
    pub yes_i_wrote_it_down: bool,

    /// master-key algorithm. Three options:
    /// * `ed25519` (default) — classical, fastest verify, BIP-39
    ///   fully recoverable.
    /// * `hybrid` (= `ed25519+falcon512`) — composite signatures
    ///   from BOTH classical и Falcon-512 components. BIP-39
    ///   phrase recovers ONLY the Ed25519 half; the file
    ///   `<veil_dir>/master_falcon.bin` (created automatically
    ///   mode 0o600) is the SOLE copy of the post-quantum half.
    ///   Operators MUST back up that file alongside the paper
    ///   phrase or the identity degrades to classical-only on
    ///   restore (changing the node_id).
    /// * `falcon512` — pure post-quantum master, NO classical
    ///   half. Has **NO BIP-39 recovery path at all** — the SK is
    ///   OsRng-derived и lives ONLY in `master_falcon.bin`. Loss
    ///   of that file = total identity loss with no paper backup.
    ///   Requires the explicit `--accept-no-recovery` flag.
    #[arg(long, default_value = "ed25519")]
    pub algo: String,

    /// explicit acknowledgement that operator
    /// understands `--algo=falcon512` standalone has NO recovery
    /// path beyond the on-disk `master_falcon.bin` file. The CLI
    /// refuses to mint a standalone Falcon-512 identity без this
    /// flag. Hybrid и Ed25519 paths ignore it.
    #[arg(long)]
    pub accept_no_recovery: bool,
}

#[derive(Args, Debug)]
pub struct IdentityShowArgs {
    /// Overrides `~/.config/veil` (or `$VEIL_IDENTITY_DIR`)
    /// as the source directory.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct IdentityRestoreArgs {
    /// Overrides the default veil config directory on the new
    /// device. Directory is created if missing.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Path to a plaintext file containing the 24-word BIP-39
    /// recovery phrase (whitespace-delimited, case-insensitive).
    /// Required for `--algo=ed25519` и `--algo=hybrid`. IGNORED
    /// for `--algo=falcon512` (standalone Falcon has no BIP-39
    /// path; pass `--master-falcon-file` instead).
    #[arg(long)]
    pub phrase_file: Option<PathBuf>,

    /// Label this restored device with a human-readable name.
    #[arg(long, default_value = "restored")]
    pub label: String,

    /// If set, save an Argon2id-encrypted copy of the recovered
    /// master seed at `<veil_dir>/master.enc` using the
    /// password from this file (one line, trimmed).
    #[arg(long)]
    pub save_encrypted_password_file: Option<PathBuf>,

    /// **Inert / deprecated.** See `IdentityCreateArgs::pow_difficulty`
    /// for the rationale. Retained for CLI back-compat.
    #[arg(long, hide = true)]
    pub pow_difficulty: Option<u32>,

    /// Validity window in seconds.
    #[arg(long, default_value_t = 7 * 24 * 3600)]
    pub valid_for_secs: u64,

    /// master-key algorithm (mirror of `identity create
    ///algo`). Default `ed25519`; use `hybrid` (=
    /// `ed25519+falcon512`) к restore a post-quantum hybrid identity.
    /// Hybrid restore REQUIRES `--master-falcon-file` к point at the
    /// preserved `master_falcon.bin` bundle — without it the function
    /// returns `MissingFalconMaster` rather than silently degrading к
    /// Ed25519-only (which would change the node_id и lose name-claim
    /// continuity). Standalone `falcon512` is rejected.
    #[arg(long, default_value = "ed25519")]
    pub algo: String,

    /// path к the preserved `master_falcon.bin` framed
    /// keypair bundle (`OFAM` magic, see [`MASTER_FALCON_FILE`]).
    /// Required when `--algo=hybrid`; ignored otherwise. The bundle
    /// is read into memory once и passed through к `restore_identity`
    /// — после успешного restore a fresh copy is written к the new
    /// `<veil_dir>/master_falcon.bin`.
    #[arg(long)]
    pub master_falcon_file: Option<PathBuf>,
}

/// arguments for `identity standalone`.
#[derive(Args, Debug)]
pub struct IdentityStandaloneArgs {
    /// Overrides `~/.config/veil` (or `$VEIL_IDENTITY_DIR`)
    /// as the destination directory. Created if missing.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Validity window in seconds for the self-signed delegation.
    /// The maintenance loop re-issues at half-validity (so a
    /// long-running standalone node never lapses). Capped by
    /// protocol to 30 days.
    #[arg(long, default_value_t = 7 * 24 * 3600)]
    pub valid_for_secs: u64,

    /// Refuse to overwrite an existing `identity_document.bin` in
    /// `--veil-dir`. Default: refuse. Pass `--force` to
    /// reprovision a standalone identity over the top of an existing
    /// one (intended for tests + first-run "I want to start over"
    /// flows).
    #[arg(long)]
    pub force: bool,
}

/// arguments for `identity delegate-device`.
#[derive(Args, Debug)]
pub struct IdentityDelegateDeviceArgs {
    /// Source veil dir (master holder). Must contain an existing
    /// `identity_document.bin` + the `master.enc` / phrase / seed
    /// file required to decrypt master_sk.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Path to a file containing the new device's 32-byte Ed25519
    /// public key. The file may be either:
    /// * 32 raw bytes (binary), or
    /// * 64 lowercase hex characters on a single line.
    ///
    /// Use whichever the target device's tooling produced.
    #[arg(long)]
    pub pubkey_file: PathBuf,

    /// Read the encrypted-master-file password from this file.
    /// Mutually exclusive with `--phrase-file`.
    #[arg(long)]
    pub password_file: Option<PathBuf>,

    /// Read a 24-word BIP-39 recovery phrase from this file.
    /// Mutually exclusive with `--password-file`.
    #[arg(long)]
    pub phrase_file: Option<PathBuf>,

    /// Validity window in seconds for the delegation. Capped by
    /// protocol to 30 days. Default 7 days matches the runtime's
    /// auto-reissue half-validity tick.
    #[arg(long, default_value_t = 7 * 24 * 3600)]
    pub valid_for_secs: u64,

    /// Path to write the updated `IdentityDocument`. Default:
    /// `<veil_dir>/identity_document.bin` (overwrites in place).
    /// Pass an alternate path (e.g. `/tmp/doc.bin`) when the operator
    /// wants to inspect the file before transporting it to the target
    /// device.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct IdentityRotateArgs {
    /// Overrides the default veil config directory.
    #[arg(long)]
    pub veil_dir: Option<PathBuf>,

    /// Read the encrypted-master-file password from this file.
    /// Mutually exclusive with `--phrase-file`.
    #[arg(long)]
    pub password_file: Option<PathBuf>,

    /// Read a 24-word BIP-39 recovery phrase from this file.
    /// Mutually exclusive with `--password-file`.
    #[arg(long)]
    pub phrase_file: Option<PathBuf>,

    /// Retained for CLI back-compat with pre-refactor scripts.
    /// Identity documents no longer carry PoW so this value is
    /// inert — the rotate flow accepts it without using it.
    #[arg(long)]
    pub pow_difficulty: Option<u32>,

    /// Validity window in seconds for the new document.
    #[arg(long, default_value_t = 7 * 24 * 3600)]
    pub valid_for_secs: u64,
}

/// master-key migration — mint a `MigrationCert`
/// linking the OLD identity к the NEW identity (already minted в
/// `--to`) и signed by the OLD master keypair.
///
/// Pre-flight assumptions:
/// * Operator has run `identity create` (or restored) on the NEW
///   `--to` directory FIRST — i.e. `<--to>/identity_document.bin`
///   already exists and binds к the NEW master.
/// * Operator can authenticate the OLD master either via
///   `--from-phrase-file` (BIP-39 phrase) или
///   `--from-password-file` (master.enc password). Hybrid /
///   standalone Falcon identities additionally read
///   `<--from>/master_falcon.bin`.
#[derive(Args, Debug)]
pub struct IdentityMigrateArgs {
    /// Veil config directory of the OLD (source) identity.
    /// Defaults to the same logic as other identity commands
    /// (`~/.config/veil` или `$VEIL_IDENTITY_DIR`).
    #[arg(long)]
    pub from: Option<PathBuf>,

    /// Veil config directory of the NEW (target) identity.
    /// MUST already contain a freshly-minted `identity_document.bin`
    /// (run `identity create` here BEFORE `identity migrate`).
    #[arg(long)]
    pub to: PathBuf,

    /// 24-word BIP-39 recovery phrase for the OLD master. Required
    /// для Ed25519 / hybrid OLD masters; NOT applicable к
    /// standalone-Falcon OLD masters (they have no BIP-39 path).
    /// Mutually exclusive с `--from-password-file`.
    #[arg(long)]
    pub from_phrase_file: Option<PathBuf>,

    /// `master.enc` password for the OLD master. Alternative к
    /// `--from-phrase-file`.
    #[arg(long)]
    pub from_password_file: Option<PathBuf>,

    /// Path к the OLD `master_falcon.bin` (framed OFAM bundle).
    /// Required if the OLD master_algo is `hybrid` or `falcon512`.
    /// Defaults to `<--from>/master_falcon.bin` if omitted.
    #[arg(long)]
    pub from_master_falcon_file: Option<PathBuf>,

    /// Where к write the signed `MigrationCert` blob. Default:
    /// `<--to>/migration_cert.bin`. This file is what the running
    /// daemon serving the NEW identity should publish to the DHT
    /// под `migration_cert_dht_key(old_node_id)`. CLI prints the
    /// DHT key on success so operators can manually `node dht put`
    /// if they prefer.
    #[arg(long)]
    pub cert_out: Option<PathBuf>,

    /// Validity window in seconds for the migration cert. Capped
    /// at MAX_MIGRATION_VALIDITY_SECS (30 days) — chains migrate
    /// fast и certs should expire quickly so operators can't
    /// accidentally republish stale rotations.
    #[arg(long, default_value_t = 7 * 24 * 3600)]
    pub valid_for_secs: u64,

    /// после mint'a cert'а опубликовать его в DHT
    /// немедленно через `AdminCommand::DhtPublishReplicated` (
    /// signed-bundle publish path — local store + fan-out to К closest
    /// live peers). Требует, чтобы запущенный daemon обслуживал
    /// `--admin-socket` (default: `<--from>/admin.sock`). Без флага
    /// CLI пишет cert только на диск, и оператор должен либо
    /// дождаться daemon's republish tick, либо запустить
    /// `node dht put` вручную.
    ///
    /// Failure modes (admin-socket недоступен, peer-публикация
    /// timed out) сурфачатся как ошибки CLI с указанием на cert
    /// файл, который УЖЕ записан — так что повторная попытка через
    /// `node dht put <dht_key> <cert_path>` остаётся возможна.
    #[arg(long)]
    pub publish_immediately: bool,

    /// путь к admin-socket для `--publish-immediately`.
    /// Defaults к `<--from>/admin.sock`. Игнорируется без
    /// `--publish-immediately`.
    #[arg(long)]
    pub admin_socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Args, Clone, Debug)]
pub struct DifficultyArgs {
    /// PoW difficulty: minimum number of leading zero bits required in the nonce hash.
    #[arg(
        short = 'd',
        long = "difficulty",
        default_value_t = IdentityPolicy::DEFAULT_POW_DIFFICULTY
    )]
    pub difficulty: u32,
}

/// deployment-profile preset for `config init`. Affects
/// the generated `config.toml` defaults — does NOT change the runtime
/// behaviour of an already-running node (operator can edit the file
/// freely after init). Mirror of the user-facing
/// `docs/internal/censorship-target.md` doc.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ConfigProfile {
    /// Dev-friendly defaults: plain TCP on `:9000`, rustls TLS, no SNI
    /// override. Suitable for local testing and CI.
    #[default]
    Dev,
    /// Censorship-resistant deployment target: `wss://0.0.0.0:443`
    /// `default_sni = "www.cloudflare.com"`, mesh enabled, with
    /// inline comments reminding the operator to build with
    /// `--features tls-boring`. See
    /// `docs/internal/censorship-target.md`.
    CensorshipTarget,
    /// Mobile / battery-powered leaf node. Stamps:
    /// `[mobile]` with `low_battery_threshold_pct = 30` so probe
    /// intervals throttle 4× when the device drops below 30 %
    /// battery.
    /// `[mesh]` with `autodiscover_gateway = true` so a leaf
    /// behind CGN-NAT finds upstream gateways via beacon
    ///
    /// `global.discovered_peers_cache_path` set under the platform
    /// config dir so handshake-confirmed peers survive restarts
    /// — critical on a phone where the OS may kill
    /// the binary at any time.
    ///
    /// Identity + listen are left to the operator: a leaf typically
    /// uses no `[[listen]]` entry (outbound-only) and connects to
    /// gateways via the cached + auto-discovered list.
    Mobile,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Print the path to the active config file.
    Locate,
    /// Create a new config file with a freshly generated identity.
    Init {
        /// Where to write the config file (default: platform config directory).
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
        #[command(flatten)]
        difficulty: DifficultyArgs,
        /// Overwrite an existing config file.
        #[arg(short, long)]
        force: bool,
        /// deployment-profile preset. When set, the
        /// generated config is pre-tuned for the given environment
        /// instead of the dev-friendly default. See
        /// `docs/internal/censorship-target.md` for the full rationale.
        ///
        /// Profiles:
        /// * `dev` (default) — plain TCP on 9000, rustls TLS, no SNI override.
        /// * `censorship-target` — `wss://0.0.0.0:443`, `default_sni
        /// = "www.cloudflare.com"`, mesh enabled, comments
        ///   reminding operator to build with `--features tls-boring`.
        #[arg(long, value_name = "NAME", default_value = "dev")]
        profile: ConfigProfile,
    },
    /// Print the current config in its native format.
    Show,
    /// Validate the config file; use --fix to auto-correct fixable issues.
    Validate {
        /// Automatically fix fixable validation errors and rewrite the config.
        #[arg(long)]
        fix: bool,
    },
    /// Read a single config value by dot-separated key (e.g. identity.algo).
    Get {
        #[arg(value_name = "KEY")]
        key: String,
    },
    /// Write a single config value by dot-separated key.
    Set {
        #[arg(value_name = "KEY")]
        key: String,
        #[arg(value_name = "VALUE")]
        value: String,
    },
    /// Publish the local `bootstrap_peers` list into the DHT under the
    /// well-known bootstrap-bundle key. Other operators can run `config
    /// fetch` to pull this list and update their own configs without a
    /// binary rebuild.
    Publish,
    /// Fetch the bootstrap-bundle from the DHT and merge it into the local
    /// config's `bootstrap_peers`. Requires an already-running
    /// node with admin socket reachable.
    Fetch {
        /// Print the fetched bundle to stdout without updating the config.
        #[arg(long)]
        dry_run: bool,
    },
    /// Sign the active config file in place using the operator's
    /// `[identity]` keypair (Этап 11 slice 11b).  After signing, the
    /// file gains а `# VEIL_CONFIG_SIGNATURE_V1: <base64>` comment
    /// header at the top.  Subsequent loads verify the signature и
    /// surface а WARN log if it fails — see slice 11a docstring on
    /// `veil_cfg::signed_config` для the threat model.
    ///
    /// Re-signing an already-signed file replaces the previous
    /// signature header.  The operator's `[identity].private_key`
    /// must be present и match the file's `[identity].public_key`;
    /// otherwise the call fails fast (no partial write).
    Sign {
        /// Unix timestamp embedded in the signed envelope.  Defaults
        /// к `SystemTime::now()` so re-signing always advances the
        /// `issued_at_unix` field.
        #[arg(long, value_name = "UNIX_SECS")]
        issued_at: Option<u64>,
        /// Print the signed config к stdout instead of writing back
        /// to the file.  Useful для dry-run or piping into а secure
        /// storage system.
        #[arg(long)]
        stdout: bool,
    },
}

#[derive(Args, Debug)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub command: KeyCommand,
}

#[derive(Args, Debug)]
pub struct DebugArgs {
    #[command(subcommand)]
    pub command: DebugCommand,
}

#[derive(Args, Debug)]
pub struct NodeArgs {
    #[command(subcommand)]
    pub command: NodeCommand,
}

#[derive(Args, Debug)]
pub struct PeersArgs {
    #[command(subcommand)]
    pub command: PeersCommand,
}

#[derive(Args, Debug)]
pub struct ListenArgs {
    #[command(subcommand)]
    pub command: ListenCommand,
}

#[derive(Args, Debug)]
pub struct SessionsArgs {
    #[command(subcommand)]
    pub command: SessionsCommand,
}

#[derive(Args, Debug)]
pub struct PexArgs {
    #[command(subcommand)]
    pub command: PexCommand,
}

#[derive(Subcommand, Debug)]
pub enum PexCommand {
    /// Show PEX state: discovered peers, active walks, last walk time.
    Status,
}

/// — out-of-band bootstrap invites.
#[derive(Args, Debug)]
pub struct BootstrapArgs {
    #[command(subcommand)]
    pub command: BootstrapCommand,
}

#[derive(Subcommand, Debug)]
pub enum BootstrapCommand {
    /// Emit an `veil:bootstrap?...` URI (and optional QR) for the
    /// **first listen entry + current identity** so a friend can scan
    /// it and `bootstrap join` into the network without needing the
    /// hardcoded seed list. The URI is safe to share publicly — it
    /// only carries `(public_key, transport, nonce)`, no secrets.
    ///
    /// With `--password`, the URI is wrapped in an Argon2id +
    /// ChaCha20-Poly1305 envelope and emitted as an
    /// `veil:pair?b=…` URL — the operator distributes the URL
    /// over a public channel (forum, paste, social media) and the
    /// password over a private channel (Telegram, in-person). The
    /// recipient must redeem with `bootstrap join --password …`.
    Invite {
        /// Also render an ASCII / half-block QR alongside the URI.
        #[arg(long, default_value_t = false)]
        qr: bool,
        /// Wrap the invite in a password-protected envelope (
        /// Distribute the URL on a large public channel
        /// and the password on a small private channel.
        ///
        /// DEPRECATED: argv secrets leak via `ps` / `/proc/<pid>/cmdline`
        /// and shell history — prefer `--password-file`.
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,
        /// Read the envelope password from a file (`-` reads stdin) instead
        /// of passing it on the command line. Trailing whitespace is
        /// trimmed. Takes precedence over `--password`.
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
        /// Sign the invite with the local `[identity]` keypair (
        /// Recipient verifies the signature against your
        /// pubkey, distributed out-of-band. Output URL uses the
        /// `veil:signed-invite?…` scheme. Mutually exclusive with
        /// `--password`; combine the two by signing the encrypted URL
        /// in two passes if both attestation AND channel secrecy are
        /// needed.
        #[arg(long, default_value_t = false)]
        sign: bool,
        /// Validity window for `--sign` in seconds (default 1 hour;
        /// hard-capped at 1 year by the signed-invite codec).
        #[arg(long, value_name = "SECS", default_value_t = 3600)]
        expiry_secs: u64,
    },
    /// Decode a scanned `veil:bootstrap?...` (or
    /// `veil:pair?…` when `--password` is given) URI and append
    /// the resulting `BootstrapPeer` to the local config's
    /// `[[bootstrap_peers]]` section. Idempotent — duplicate
    /// entries (same `public_key`) are deduplicated, not appended
    /// twice.
    Join {
        /// The full `veil:bootstrap?...`, `veil:pair?…` or
        /// `veil:signed-invite?…` URI. Use shell quoting since
        /// the URI contains `?` and `&`.
        #[arg(long, value_name = "URI")]
        uri: String,
        /// Password for an `veil:pair?…` URI. Required for
        /// encrypted invites; ignored for plain `veil:bootstrap?…`.
        ///
        /// DEPRECATED: argv secrets leak via `ps` / `/proc/<pid>/cmdline`
        /// and shell history — prefer `--password-file`.
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,
        /// Read the password from a file (`-` reads stdin) instead of
        /// passing it on the command line. Trailing whitespace is trimmed.
        /// Takes precedence over `--password`.
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
        /// Expected issuer pubkey (base64) for an
        /// `veil:signed-invite?…` URI. Required for signed invites
        /// — without it we'd accept any envelope whose internal
        /// signature is consistent, which provides no trust signal.
        #[arg(long, value_name = "PUBKEY")]
        verify_issuer: Option<String>,
    },
    /// Decode a scanned URI and pretty-print the resulting
    /// `BootstrapPeer` WITHOUT writing to config — useful as a
    /// "what's in this QR before I trust it" preflight. Pass
    /// `--password` for an `veil:pair?…` URL.
    Decode {
        /// The full `veil:bootstrap?...`, `veil:pair?…` or
        /// `veil:signed-invite?…` URI.
        #[arg(long, value_name = "URI")]
        uri: String,
        /// Password for an `veil:pair?…` URI.
        ///
        /// DEPRECATED: argv secrets leak via `ps` / `/proc/<pid>/cmdline`
        /// and shell history — prefer `--password-file`.
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,
        /// Read the password from a file (`-` reads stdin) instead of
        /// passing it on the command line. Trailing whitespace is trimmed.
        /// Takes precedence over `--password`.
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
        /// Optional expected issuer pubkey for an
        /// `veil:signed-invite?…` URI. When omitted, decode
        /// proceeds without trust verification and prints the
        /// envelope's claimed issuer so the operator can decide
        /// whether to trust it before issuing `bootstrap join`.
        #[arg(long, value_name = "PUBKEY")]
        verify_issuer: Option<String>,
    },
}

/// — trusted-listener invite bundles (Phase 5c+).
#[derive(Args, Debug)]
pub struct InviteArgs {
    #[command(subcommand)]
    pub command: InviteCommand,
}

#[derive(Subcommand, Debug)]
pub enum InviteCommand {
    /// Generate a signed `InviteBundleV1` for а configured listener и
    /// emit it as base32 text + optional QR.  The recipient takes the
    /// bundle и runs `invite accept` to install the listener's PSK и
    /// add the inviter as а bootstrap peer.
    ///
    /// Requires:
    /// * `[identity]` is configured (Ed25519 only — bundle signing
    ///   currently expects ed25519-dalek `SigningKey`).
    /// * The selected listener has `visibility = "trusted"` or
    ///   `"hidden"` (we refuse к emit invites for `Public` listeners
    ///   so operators don't accidentally distribute а PSK that's
    ///   redundant — anyone can find Public via PEX).
    /// * The listener carries а `psk_file` so the bundle can embed
    ///   the actual PSK bytes the recipient needs.
    Create {
        /// Numeric listener ID (decimal or `0x…` hex) as shown в `listen
        /// list`.  Must reference а Trusted / Hidden listener.
        #[arg(long, value_name = "LISTEN_ID")]
        listener_id: veil_cfg::ListenId,
        /// Validity window в seconds.  Capped at 1 year by sanity check
        /// here; bundle itself carries а raw `exp` unix timestamp so
        /// downstream verifiers can apply their own policies.
        #[arg(long, value_name = "SECS", default_value_t = 7 * 24 * 3600)]
        validity_secs: u64,
        /// Optional human-readable label encoded into the bundle (e.g.
        /// "family group"). ≤ 64 bytes after UTF-8 encoding.
        #[arg(long, value_name = "TEXT")]
        label: Option<String>,
        /// Write the base32 bundle к а file instead of stdout. Useful
        /// for piping into email / messenger attachments without shell
        /// escaping the long base32 string.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Also render а Unicode-art QR code beneath the base32 bundle
        /// so the recipient can scan it of the terminal с а phone camera.
        #[arg(long, default_value_t = false)]
        qr: bool,
    },
    /// Decode + verify an `InviteBundleV1` и install its material into
    /// the local config: append the inviter to `[[bootstrap_peers]]`
    /// (idempotent on node_id) и write the embedded PSK к а file under
    /// `<veil_dir>/invite_psks/` для future re-use.  Stops with а
    /// clear error if the bundle's signature, expiry, or version checks
    /// fail.
    Accept {
        /// Input path containing the base32 bundle text. Use `-` к read
        /// от stdin (paste the bundle text).
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
        /// Optional override для where the PSK is saved. Default:
        /// `<config_dir>/invite_psks/<node_id_hex>.psk`. File is
        /// created с 0o600 perms.
        #[arg(long, value_name = "FILE")]
        psk_out: Option<PathBuf>,
        /// Skip mutating the on-disk config — just verify the bundle и
        /// drop the PSK file. Useful когда the operator wants к review
        /// the inviter manually before adding к bootstrap_peers.
        #[arg(long, default_value_t = false)]
        no_update_config: bool,
    },
    /// Decode + verify а bundle и pretty-print its fields, WITHOUT any
    /// side effects.  Recipient-side preflight: "before I `accept`,
    /// what's inside this thing?"
    Decode {
        /// Input file (base32 text). `-` reads from stdin.
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
    },
}

/// — operator-facing CLI for mobile-mode controls.
#[derive(Args, Debug)]
pub struct MobileArgs {
    #[command(subcommand)]
    pub command: MobileCommand,
}

#[derive(Subcommand, Debug)]
pub enum MobileCommand {
    /// Toggle the runtime's `mobile_background_mode` flag. When
    /// `on`, per-session keepalive intervals are multiplied by
    /// `mobile.background_keepalive_multiplier` (60× by default
    /// on the mobile profile, so 30s → 30 min) so sessions
    /// survive OS-level app suspension. When `off`, foreground
    /// cadence is restored within the next recomputation tick
    /// (≤ 60s). No-op on nodes where the multiplier is 1 (the
    /// non-mobile default).
    BackgroundMode {
        /// `on` enables background mode (long keepalive); `off`
        /// disables (foreground cadence). No default — operator
        /// must specify intent explicitly.
        #[arg(value_enum)]
        state: OnOff,
    },
}

/// On/off choice for the mobile-mode CLI subcommands. Custom
/// enum (instead of `bool`) so clap treats it as a positional
/// value choice (`on` / `off`) instead of a `--state` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

impl OnOff {
    pub fn as_bool(self) -> bool {
        matches!(self, Self::On)
    }
}

/// — operator-facing CLI for the signed-update mechanism.
#[derive(Args, Debug)]
pub struct UpdateArgs {
    #[command(subcommand)]
    pub command: UpdateCommand,
}

// `large_enum_variant`: this is a clap `Subcommand`. The `SignManifest` variant
// carries the release-only signing args; the enum is built exactly once per CLI
// invocation (never stored in bulk), so the size gap is irrelevant. Boxing the
// field is not an option either — clap's `Args` derive does not flatten through
// `Box<_>`, so it would break the subcommand.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum UpdateCommand {
    /// Check whether a newer signed manifest is published at the
    /// operator's endpoints. Reads `[update]` from config + the
    /// installed-version state file (when configured); fetches
    /// each manifest URL with failover; verifies issuer signature
    /// and SHA-256 of the binary in the manifest; prints either
    /// "up to date" or "v1.2.3 available — released YYYY-MM-DD".
    /// Exits with status 0 = up-to-date, 1 = update available, 2 = error.
    Check,
    /// Apply a published update: fetch + SHA-256-verify the binary
    /// atomically replace `update.install_path`, persist the new
    /// release_unix to `update.installed_version_path`. Identity
    /// files are NOT touched. Requires both `update.install_path`
    /// and `update.installed_version_path` to be set in config.
    /// Operator restarts the process out-of-band (systemd /
    /// `veil-cli node restart` / SIGTERM-and-respawn) AFTER
    /// this command exits 0; the new binary takes effect on next
    /// `exec`. No-op when no update is available.
    Apply,
    /// build + sign an `UpdateManifest` for a freshly-built
    /// binary. Used by the release CI workflow to produce the signed
    /// blob that operators distribute alongside the binary. The
    /// manifest is written to stdout (or `--output` file) as raw
    /// bytes; consumers of the binary fetch this manifest, verify
    /// the signature against a known issuer pubkey, and SHA-256-check
    /// the binary they downloaded against `binary_sha256` в the
    /// manifest before installing.
    SignManifest(SignManifestArgs),
}

/// Args для `veil-cli update sign-manifest`.
#[derive(Args, Debug)]
pub struct SignManifestArgs {
    /// Path к the built binary file. SHA-256 будет computed of this
    /// file and embedded в the manifest.
    #[arg(long)]
    pub binary: std::path::PathBuf,

    /// Semantic version string for this release (e.g. "1.2.3").
    #[arg(long)]
    pub version: String,

    /// Minimum version that can apply this update — recorded in the signed
    /// manifest. NOTE (audit cycle-5): this value is signed but the
    /// receiver-side gate is NOT yet implemented (no installed-version
    /// comparison), so it does NOT currently refuse skip-migration upgrades.
    /// Deferred gate tracked in TASKS.md.
    #[arg(long)]
    pub min_compatible_version: String,

    /// Target triple (e.g. "x86_64-unknown-linux-gnu"). Update-check
    /// matches this against the running platform; mismatched
    /// platforms are silently skipped так that ONE manifest URL set
    /// can serve manifests for multiple targets.
    #[arg(long)]
    pub platform_target: String,

    /// One or more URLs where the binary is hosted (≤ 8). Multiple
    /// URLs let operators publish to separate CDNs for anti-takedown
    /// resilience — `veil-cli update apply` tries each in order
    /// until SHA-256 verification passes.
    #[arg(long = "binary-url", required = true, num_args = 1..)]
    pub binary_urls: Vec<String>,

    /// Path к the issuer's identity TOML file (same shape as
    /// `[identity]` в node config — `algo`, `public_key`, `private_key`).
    /// The release-signing key is typically distinct от a daemon
    /// identity; cold-storage in operator's HSM / paper backup.
    #[arg(long)]
    pub identity: std::path::PathBuf,

    /// Output path for the signed manifest bytes. When omitted
    /// writes к stdout.
    #[arg(long, short)]
    pub output: Option<std::path::PathBuf>,

    /// Override the manifest's `release_unix` timestamp. Defaults
    /// to current time; operators may pin к `SOURCE_DATE_EPOCH` for
    /// reproducible-build verification (manifest bytes deterministic
    /// от inputs).
    #[arg(long)]
    pub release_unix: Option<u64>,
}

#[derive(Args, Clone, Debug, Default)]
pub struct TlsMaterialArgs {
    /// Path to the PEM-encoded TLS certificate file.
    #[arg(long = "tls-cert", value_name = "FILE")]
    pub tls_cert: Option<PathBuf>,
    /// Path to the PEM-encoded TLS private key file.
    #[arg(long = "tls-key", value_name = "FILE")]
    pub tls_key: Option<PathBuf>,
    /// Path to the PEM-encoded CA certificate used to verify the remote peer.
    #[arg(long = "tls-ca-cert", value_name = "FILE")]
    pub tls_ca_cert: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum NodeCommand {
    /// Start the veil node (background by default; use --foreground to stay in terminal).
    Run {
        /// Run in the foreground instead of spawning a background daemon.
        #[arg(long)]
        foreground: bool,
        #[arg(long, hide = true)]
        daemon_child: bool,
        /// Start daemon без а config file using an ephemeral stub
        /// identity, и await а runtime `admin apply-config` к provide
        /// the actual config.
        ///
        /// Use cases:
        /// * **Messenger / embedded** — app keeps the real config in а
        ///   secure storage backend (Keychain / EncryptedSharedPreferences /
        ///   future TPM-sealed store) и avoids ever writing it to а
        ///   regular file.  Pair с `admin apply-config --no-persist`.
        /// * **Orchestrated provisioning** — start daemons за headed-up
        ///   identity, then push generated configs at deploy-time без
        ///   shipping the config file alongside the binary.
        ///
        /// The stub identity is а **fresh per-daemon-run Ed25519 keypair**;
        /// it lives только в RAM, ephemeral working files (mlkem.key etc.)
        /// land в а per-run temp directory that's cleaned up on shutdown.
        /// Network listens и peers are empty until `apply-config` arrives.
        #[arg(long)]
        defer_init: bool,
    },
    /// Stop the running node gracefully.
    Stop,
    /// Restart the running node (stop + start).
    Restart,
    /// Reload the config file without restarting (SIGHUP equivalent).
    Reload,
    /// Apply а new config to the running daemon без going через the filesystem.
    ///
    /// Distinct от `reload`: reads the config TOML bytes inline (от а
    /// file path или stdin) и pushes them к the daemon over IPC.  Used by:
    ///
    /// * **Messenger build** — app keeps config в а secure storage backend
    ///   (Keychain / EncryptedSharedPreferences / future TPM-sealed store)
    ///   и passes the bytes к the embedded daemon at startup.  Defaults to
    ///   `--no-persist` so the bytes never touch the regular filesystem.
    /// * **Server admin** — orchestration tools (Terraform / ansible / scripts)
    ///   piping the rendered config к `apply-config -` directly без an
    ///   intermediate file (more atomic than `cp + reload`).  Use `--persist`
    ///   so the new config survives daemon restarts.
    /// * **Deferred-init** — combined с `node run --defer-init`, this is
    ///   the path the daemon promotes от "stub" к "fully operational".
    ApplyConfig {
        /// Path к the config TOML file, or `-` к read from stdin.
        #[arg(value_name = "PATH_OR_DASH")]
        path: std::path::PathBuf,
        /// Persist the new config к the daemon's `config_path` on disk
        /// after а successful apply.  Default is **no-persist** —
        /// matches the messenger / embedded use case where the host
        /// owns config storage в an external secure backend.
        #[arg(long)]
        persist: bool,
    },
    /// Show a summary of the running node (node ID, uptime, session count, etc.).
    Show,
    /// List all active listeners and their transport URIs.
    Listens,
    /// Report node health: tick counter + session count + loop status.
    Health,
    /// Show bandwidth utilization (inbound/outbound limits, bytes passed/dropped).
    Bandwidth,
    // ── Introspection ───────────────────────────────────────────
    /// Show a snapshot of all runtime metrics counters.
    Metrics,
    /// DHT introspection: K/V store, routing table, manual get/put.
    Dht(DhtArgs),
    /// resolve a sovereign `IdentityDocument` from the DHT
    /// and run full cryptographic verification (signature chain
    /// expiry windows, sig_key_idx bounds, node_id ↔ master_pubkey
    /// binding, and substitution check `doc.node_id == requested`).
    ///
    /// Distinct from `node dht recursive-get` — that returns raw bytes
    /// the operator must interpret manually (and probably skips the
    /// signature step). This verb is the only safe surface for any
    /// caller that wants to act on the resolved identity.
    ResolveIdentity {
        /// 32-byte node_id as 64 lowercase hex chars.
        #[arg(value_name = "NODE_ID")]
        node_id: String,
        /// Maximum total resolve time in milliseconds (DHT walk + verify).
        #[arg(long, default_value = "5000")]
        timeout_ms: u64,
    },
    /// resolve `@name` → ValidatedIdentity, walking the
    /// `NameClaim` → `IdentityDocument` chain with full verification
    /// (PoW difficulty, freshness-hour skew, name-binding check
    /// signature against the document's active subkey). Accepts
    /// either `alice` or `@alice`.
    ResolveName {
        /// The name to resolve, with or without leading `@`.
        #[arg(value_name = "NAME")]
        name: String,
        /// Maximum total resolve time in milliseconds.
        #[arg(long, default_value = "5000")]
        timeout_ms: u64,
    },
    /// probe NAT traversal candidates for a peer
    /// by routing through any currently-connected peer as the
    /// signaling coordinator. Surfaces the target's `NatProbeReply`
    /// candidates that a phone behind CGN-NAT could feed into UDP
    /// hole-punching to establish a direct path to another NAT'd peer.
    ///
    /// Tries up to 4 coordinators (closer-to-target peers first by
    /// XOR distance), per-coordinator timeout configurable.
    NatProbe {
        /// 32-byte node_id of the peer whose candidates we want.
        #[arg(value_name = "TARGET_NODE_ID")]
        target_node_id: String,
        /// Per-coordinator timeout in milliseconds. Total time
        /// bounded by 4× this value (max coordinator attempts).
        #[arg(long, default_value = "2000")]
        per_coordinator_timeout_ms: u64,
    },
    /// List attachment records in the local discovery directory.
    DiscoveryList,
    /// List node IDs currently attached to this gateway.
    GatewayList,
    /// leaf-side mesh status — list auto-discovered gateways
    /// (best-first by latency+battery score) with active/standby state
    /// RTT, battery, freshness. Answers "why am I (not) connected via X".
    MeshStatus,
    /// bootstrap-chain diag — show the operator the state of
    /// every bootstrap defense layer (operator-curated peers, builtin
    /// seeds, DNS bootstrap domain, discovered-peer cache from prior
    /// runs). Pure snapshot, no probes. Answers "if a censor takes
    /// down my known seed IPs tomorrow, what fallback do I have?".
    BootstrapStatus,
    /// update-mechanism status snapshot. Renders
    /// "configured? installed_release_unix? auto-poll cadence?
    /// background mode active?" — operator verifies setup AND
    /// GUI tray icons render badges WITHOUT grepping logs OR
    /// re-running the network-touching `update check`. No
    /// network I/O.
    UpdateStatus,
    /// mobile-mode runtime status snapshot.
    /// Renders battery level + scaling factors + config — answers
    /// "why is my keepalive 30 min when I expected 30s?".
    /// Complements `update-status`; both pure read-over-state.
    MobileStatus,
    /// List all non-expired route cache entries. Optional `<dst_node_id>`
    /// filter narrows output to a single destination — useful when the cache
    /// has hundreds of entries and you want to see "what paths do I have for
    /// peer X right now, and is multi-path active?".
    Routes {
        /// Optional destination node-id (64 hex chars) to filter on. When
        /// omitted, prints every cached destination.
        #[arg(value_name = "DST_NODE_ID")]
        dst_node_id: Option<String>,
    },
    /// Manually trigger a route discovery search.
    DiscoverySearch,
    /// Hot-standby transport handover).
    ///
    /// Spawns a one-shot warm-probe that dials `--alt-uri` and runs the
    /// three-frame handoff protocol on the primary session to `--peer`.
    /// On success the session keeps its `session_id` and AEAD state but
    /// its underlying byte pipe moves to the new transport — no OVL1
    /// re-handshake.
    ///
    /// Typical operator use: switch a peer's TLS session to WSS when a
    /// middlebox starts dropping TLS traffic. Example:
    ///
    /// veil-cli node swap-transport \
    ///peer <64-hex node_id> \
    ///alt-uri wss://peer.example:8443/veil
    ///
    /// Both ends must run a build that includes stage (b)/(d) of
    /// (this command ships only the initiator-side drive; the accept-side
    /// peek-and-dispatch is always on).
    SwapTransport {
        /// 64-hex `node_id` of the peer whose primary session to migrate.
        #[arg(long = "peer", value_name = "NODE_ID")]
        peer_node_id: String,
        /// Transport URI to dial (e.g. `tls://peer:9906`
        /// `wss://peer:8443/veil`). Scheme does not have to differ
        /// from the primary — the command is happy to migrate within
        /// the same scheme if the operator asks for that.
        #[arg(long = "alt-uri", value_name = "URI")]
        alt_uri: String,
    },
}

#[derive(Args, Debug)]
pub struct DhtArgs {
    #[command(subcommand)]
    pub command: DhtCommand,
}

#[derive(Subcommand, Debug)]
pub enum DhtCommand {
    /// List all key-value pairs stored in the local DHT node store.
    List,
    /// Show the DHT Kademlia routing table contacts.
    Routing,
    /// Look up a key in the local DHT store.
    Get {
        #[arg(value_name = "KEY", help = "32-byte key as 64 hex chars")]
        key: String,
    },
    /// Look up a key via a recursive `FIND_VALUE` walk through the DHT.
    /// Tries the local store first; if not found, sends the query to
    /// the K closest active session peers and waits for a reply.
    /// Used by the devnet smoke test to verify cross-node DHT lookup.
    RecursiveGet {
        #[arg(value_name = "KEY", help = "32-byte key as 64 hex chars")]
        key: String,
        /// Maximum time to wait for a recursive response in milliseconds.
        #[arg(long, default_value = "2000")]
        timeout_ms: u64,
    },
    /// Store a key-value pair directly in the local DHT node store.
    Put {
        #[arg(value_name = "KEY", help = "32-byte key as 64 hex chars")]
        key: String,
        #[arg(value_name = "VALUE", help = "Value bytes as hex")]
        value: String,
    },
    /// 486.4: store a key-value pair locally AND fan out
    /// к the K closest live peers in keyspace via the Kademlia
    /// replication path. Used by `bootstrap publish` and by
    /// `identity migrate --publish-immediately`; exposed as a
    /// generic CLI verb so operators can republish arbitrary
    /// content (e.g. a freshly-restored IdentityDocument that
    /// dropped off the DHT after every replica's TTL expired).
    /// `--value-file` is a convenience: the file's contents are
    /// hex-encoded и sent as the value. Mutually exclusive с
    /// `--value` (raw hex).
    PublishReplicated {
        #[arg(value_name = "KEY", help = "32-byte key as 64 hex chars")]
        key: String,
        /// Value bytes as hex string (mutually exclusive с
        /// `--value-file`).
        #[arg(long, conflicts_with = "value_file")]
        value: Option<String>,
        /// Read value bytes from this file и hex-encode automatically.
        #[arg(long)]
        value_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum PeersCommand {
    /// List all configured peers.
    List,
    /// Add a new peer to the config.
    Add {
        /// Signature algorithm of the peer's key pair.
        #[arg(long, value_name = "ALGO", default_value = "ed25519")]
        algo: veil_cfg::SignatureAlgorithm,
        /// Peer's base64-encoded public key.
        #[arg(value_name = "PUBLIC_KEY")]
        public_key: String,
        /// Peer's base64-encoded PoW nonce.
        #[arg(value_name = "NONCE")]
        nonce: String,
        /// Transport URI to reach the peer (e.g. tcp://1.2.3.4:7001).
        #[arg(value_name = "TRANSPORT")]
        transport: String,
        /// stage (c): alternate transport URI for hot-standby
        /// auto-swap. When the primary transport starts dropping writes
        /// past the configured threshold, the runtime auto-migrates this
        /// session onto this URI without a re-handshake. Optional.
        #[arg(long = "alt-uri", value_name = "URI")]
        alt_uri: Option<String>,
        #[command(flatten)]
        tls: TlsMaterialArgs,
    },
    /// Remove a peer from the config by peer ID, node ID, or public key.
    Del {
        /// Numeric peer ID as shown in `peers list`.
        #[arg(value_name = "PEER_ID")]
        peer_id: Option<veil_cfg::PeerId>,
        /// Remove by node ID (64 hex chars).
        #[arg(long = "by-node-id", value_name = "NODE_ID")]
        by_node_id: Option<veil_cfg::NodeId>,
        /// Remove by base64-encoded public key.
        #[arg(long = "by-public-key", value_name = "PUBLIC_KEY")]
        by_public_key: Option<String>,
    },
    /// Ban a node ID (persisted across restarts).
    Ban {
        #[arg(value_name = "NODE_ID", help = "Hex-encoded 32-byte node ID to ban")]
        node_id: String,
    },
    /// Lift a ban previously applied with `peers ban`.
    Unban {
        #[arg(value_name = "NODE_ID", help = "Hex-encoded 32-byte node ID to unban")]
        node_id: String,
    },
    /// List all currently active bans.
    Banned,
}

#[derive(Subcommand, Debug)]
pub enum ListenCommand {
    /// List all configured listeners and their current state.
    List,
    /// Add a new listener to the config.
    Add {
        /// Transport URI to bind (e.g. tcp://0.0.0.0:7001).
        #[arg(value_name = "TRANSPORT")]
        transport: String,
        /// Advertised address sent to peers in RouteResponse.
        /// Overrides `transport` when advertising to peers (e.g. behind a reverse proxy).
        #[arg(long, value_name = "URI")]
        advertise: Option<String>,
        /// Relay node-id (base64, 32 bytes) reachable by peers to access this listener indirectly.
        #[arg(long, value_name = "NODE_ID_BASE64")]
        relay: Option<String>,
        #[command(flatten)]
        tls: TlsMaterialArgs,
    },
    /// Remove a listener from the config by its ID.
    Del {
        /// Numeric listener ID as shown in `listen list`.
        #[arg(value_name = "LISTEN_ID")]
        listen_id: veil_cfg::ListenId,
    },
}

#[derive(Subcommand, Debug)]
pub enum SessionsCommand {
    /// List all currently active sessions.
    List {
        /// Print full 64-hex node_ids and 16-hex link_ids (default truncates
        /// to first 12 chars for terminal readability).
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Kill (disconnect) a session by link_id.
    Kill {
        #[arg(
            value_name = "LINK_ID",
            help = "Link ID (hex, e.g. 0x0000000000000003)"
        )]
        link_id: String,
    },
    /// Ban a node ID (same as `peers ban`).
    Ban {
        #[arg(value_name = "NODE_ID", help = "Hex-encoded 32-byte node ID to ban")]
        node_id: String,
    },
    /// Unban a node ID (same as `peers unban`).
    Unban {
        #[arg(value_name = "NODE_ID", help = "Hex-encoded 32-byte node ID to unban")]
        node_id: String,
    },
    /// List all currently active bans (same as `peers banned`).
    Banned,
}

#[derive(Subcommand, Debug)]
pub enum DebugCommand {
    /// Low-level transport diagnostics (raw listen / connect).
    Transport(DebugTransportArgs),
    /// Debug peer connection handling.
    Peers(DebugPeersArgs),
    /// Debug node-level accept loop.
    Node(DebugNodeArgs),
    /// Send veil-level ping probes and measure RTT.
    Ping {
        #[arg(value_name = "NODE_ID", help = "Target node ID (64 hex chars)")]
        node_id: String,
        #[arg(
            short = 'c',
            long,
            default_value_t = 4,
            help = "Number of probes to send"
        )]
        count: u32,
        #[arg(long, default_value_t = 1000, help = "Interval between probes (ms)")]
        interval: u64,
        #[arg(long, default_value_t = 5000, help = "Per-probe timeout (ms)")]
        timeout: u64,
    },
    /// Traceroute through the veil network.
    Trace {
        #[arg(value_name = "NODE_ID", help = "Target node ID (64 hex chars)")]
        node_id: String,
        #[arg(short = 'm', long, default_value_t = 8, help = "Maximum hops")]
        max_hops: u8,
        #[arg(long, default_value_t = 5000, help = "Per-hop timeout (ms)")]
        timeout: u64,
    },
    /// Send an app message via source-routed relay path (audit batch 2026-05-23).
    ///
    /// Bypasses DHT lookups + route-cache gossip — каждый relay просто
    /// forwards к the next node listed в `--path`.  Works в any
    /// topology где the path's session-chain is intact (linear, mesh,
    /// или anything в between).  Used for connectivity testing в
    /// pathological topologies где DHT walks structurally fail.
    RelaySend {
        #[arg(
            long,
            value_name = "NODE_IDS",
            help = "Comma-separated list of hex node_ids forming the path \
                    (first = first hop after sender; last = ultimate destination)",
            required = true
        )]
        path: String,
        #[arg(
            long,
            value_name = "APP_ID_HEX",
            help = "Destination app_id (64 hex chars)",
            required = true
        )]
        app_id: String,
        #[arg(
            long,
            value_name = "ENDPOINT_ID",
            help = "Destination endpoint number",
            required = true
        )]
        endpoint_id: u32,
        #[arg(
            long,
            value_name = "DATA_HEX",
            help = "Payload bytes as а hex string (use \"\" для empty)",
            default_value = ""
        )]
        data: String,
    },
    /// Query historical hop-by-hop trace records from the in-memory ring
    /// buffer for a given `trace_id` (sampling rate is `routing.trace_sample_rate`).
    TraceQuery {
        #[arg(
            value_name = "TRACE_ID",
            help = "Trace ID to query (decimal or 0x-prefixed hex)"
        )]
        trace_id: String,
    },
    /// Capture live veil frames from the running node.
    Capture {
        #[arg(
            long,
            value_name = "NODE_ID",
            help = "Filter by peer node ID (64 hex chars)"
        )]
        node_id: Option<String>,
        #[arg(
            long,
            value_name = "FAMILY",
            help = "Filter by frame family number (0=Session,1=Control,2=Discovery,3=Delivery,4=App,8=Routing,9=Diag)"
        )]
        family: Option<u8>,
        #[arg(short = 'n', long, help = "Stop after N frames")]
        limit: Option<u32>,
        #[arg(
            short = 'o',
            long,
            value_name = "FILE",
            help = "Write JSON output to file"
        )]
        output: Option<PathBuf>,
        #[arg(
            short = 'v',
            long,
            help = "Print full hex+ASCII body dump for each frame"
        )]
        verbose: bool,
    },
}

#[derive(Args, Debug)]
pub struct DebugTransportArgs {
    #[command(subcommand)]
    pub command: DebugTransportCommand,
}

#[derive(Args, Debug)]
pub struct DebugPeersArgs {
    #[command(subcommand)]
    pub command: DebugPeersCommand,
}

#[derive(Args, Debug)]
pub struct DebugNodeArgs {
    #[command(subcommand)]
    pub command: DebugNodeCommand,
}

#[derive(Subcommand, Debug)]
pub enum DebugTransportCommand {
    /// Open a raw listener on the given transport URI and print incoming frames.
    Listen {
        /// Transport URI to bind (e.g. tcp://127.0.0.1:9999).
        #[arg(value_name = "TRANSPORT")]
        transport: String,
        #[command(flatten)]
        options: DebugTransportOverrideArgs,
    },
    /// Open a raw connection to the given transport URI and print frames.
    Connect {
        /// Transport URI to connect (e.g. tcp://127.0.0.1:9999).
        #[arg(value_name = "TRANSPORT")]
        transport: String,
        #[command(flatten)]
        options: DebugTransportOverrideArgs,
    },
}

#[derive(Subcommand, Debug)]
pub enum DebugPeersCommand {
    /// Initiate a direct peer connection by peer ID (bypassing the reconnect scheduler).
    Connect {
        /// Numeric peer ID as shown in `peers list`.
        #[arg(value_name = "PEER_ID")]
        peer_id: veil_cfg::PeerId,
    },
    /// Dump the runtime's live non-configured peer table.
    /// Live equivalent of `peers_discovered.json` without reading from disk.
    Discovered,
}

#[derive(Subcommand, Debug)]
pub enum DebugNodeCommand {
    /// Accept a single inbound OVL1 connection on a listener (for manual testing).
    Accept {
        /// Numeric listener ID as shown in `listen list`.
        #[arg(value_name = "LISTEN_ID")]
        listen_id: veil_cfg::ListenId,
    },
}

#[derive(Args, Clone, Debug, Default)]
pub struct DebugTransportOverrideArgs {
    #[command(flatten)]
    pub tls: TlsMaterialArgs,
}

#[derive(Subcommand, Debug)]
pub enum KeyCommand {
    /// Generate a new key pair and write it to the config.
    Gen(KeyGenArgs),
    /// Print the public key and node ID from the current config.
    Show,
    /// Print detailed key information (algorithm, node ID, nonce difficulty).
    Info,
    /// Mine a PoW nonce for the current identity key.
    Nonce(KeyNonceArgs),
}

#[derive(Args, Debug)]
pub struct KeyGenArgs {
    /// Overwrite an existing key in the config.
    #[arg(short, long)]
    pub force: bool,
    /// Print the generated keys to stdout instead of writing to the config.
    #[arg(short = 'o', long)]
    pub output: bool,
    /// Signature algorithm to use (default: ed25519).
    #[arg(long, value_enum)]
    pub algo: Option<SignatureAlgorithmArg>,
}

#[derive(Args, Debug)]
pub struct KeyNonceArgs {
    #[command(flatten)]
    pub difficulty: DifficultyArgs,
    /// Maximum time to spend searching for a valid nonce (seconds).
    #[arg(short, long, default_value_t = IdentityPolicy::DEFAULT_POW_TIMEOUT_SECS)]
    pub timeout: u64,
    /// Resume search from this base64-encoded nonce value instead of zero.
    #[arg(short = 'f', long = "from")]
    pub from: Option<String>,
    /// Number of parallel search threads (default: number of logical CPUs).
    #[arg(long)]
    pub threads: Option<usize>,
    /// Public key (base64). If omitted, read [identity] in the config.
    #[arg(long = "public-key")]
    pub public_key: Option<String>,
    /// Private key (base64). If omitted, read [identity] in the config.
    ///
    /// DEPRECATED: argv secrets leak via `ps` / `/proc/<pid>/cmdline` and
    /// shell history — prefer `--private-key-file`.
    #[arg(long = "private-key")]
    pub private_key: Option<String>,
    /// Read the private key (base64) from a file (`-` reads stdin) instead
    /// of passing it on the command line. Trailing whitespace is trimmed.
    /// Takes precedence over `--private-key`.
    #[arg(long = "private-key-file", value_name = "PATH")]
    pub private_key_file: Option<PathBuf>,
    /// Signature algorithm of the key pair (default: ed25519).
    #[arg(long, value_enum)]
    pub algo: Option<SignatureAlgorithmArg>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SignatureAlgorithmArg {
    Ed25519,
    Falcon512,
}

impl From<SignatureAlgorithmArg> for SignatureAlgorithm {
    fn from(value: SignatureAlgorithmArg) -> Self {
        match value {
            SignatureAlgorithmArg::Ed25519 => Self::Ed25519,
            SignatureAlgorithmArg::Falcon512 => Self::Falcon512,
        }
    }
}

/// — private-veil-network admin tooling.
#[derive(Args, Debug)]
pub struct NetworkArgs {
    #[command(subcommand)]
    pub command: NetworkCommand,
}

#[derive(Subcommand, Debug)]
pub enum NetworkCommand {
    /// Generate а fresh network-owner keypair и write the keys к
    /// disk. The owner pubkey ends up в every member's
    /// `[network].owner_pubkey` config slot; the owner private key
    /// stays on the operator's admin workstation. ANYONE с the
    /// owner private key can issue admin certs, so guard it carefully
    /// (offline storage, hardware token, GPG-encrypted backup).
    GenOwner {
        /// Path where the public key is written (base64 + newline).
        #[arg(long, value_name = "PATH")]
        pub_out: PathBuf,
        /// Path where the private key is written (base64 + newline).
        /// Mode 0600 на Unix.
        #[arg(long, value_name = "PATH")]
        priv_out: PathBuf,
        /// Owner signing algorithm. Default `ed25519`.
        #[arg(long, value_enum, default_value_t = SignatureAlgorithmArg::Ed25519)]
        algo: SignatureAlgorithmArg,
    },
    /// Generate а random 32-byte `network_id` и print it as hex
    /// (suitable for `[network].network_id`). One-shot — no state
    /// persisted; rerun if you lose it.
    GenNetworkId,
    /// Sign а membership cert for а member node. The owner private
    /// key reads от `--owner-priv`. The member's `node_id` (BLAKE3
    /// of their pubkey) is the cert's binding identity — the member
    /// proves ownership at handshake via the existing OVL1 signature
    /// exchange.
    SignMember {
        /// Path к the owner public-key file (от `gen-owner`).
        #[arg(long, value_name = "PATH")]
        owner_pub: PathBuf,
        /// Path к the owner private-key file (от `gen-owner`).
        #[arg(long, value_name = "PATH")]
        owner_priv: PathBuf,
        /// Owner signing algorithm (must match `gen-owner`'s).
        #[arg(long, value_enum, default_value_t = SignatureAlgorithmArg::Ed25519)]
        algo: SignatureAlgorithmArg,
        /// Target network's `network_id` (64-char hex).
        #[arg(long, value_name = "HEX64")]
        network_id: String,
        /// Member's `node_id` (BLAKE3 of pubkey), 64-char hex.
        #[arg(long, value_name = "HEX64")]
        member_node_id: String,
        /// Set `admin: true` so this member can author DHT-replicated
        /// bans. Without this flag the cert authorises connection
        /// only.
        #[arg(long, default_value_t = false)]
        admin: bool,
        /// Cert validity window в days от now. Default 365. Ignored
        /// when `--no-expiry` is passed.
        #[arg(
            long,
            value_name = "DAYS",
            default_value_t = 365,
            conflicts_with = "no_expiry"
        )]
        valid_days: u32,
        /// Mint а cert що never expires. Useful for fleet members where
        /// the operator wants к manage revocation only via DHT-ban
        /// records или by rotating the network's `owner_pubkey`.
        /// Sets `valid_until_unix = 0` (sentinel) на the wire.
        ///
        /// Trade-off: revoking а single device без rotating the owner
        /// key requires DHT-ban propagation; if the device is offline /
        /// air-gapped the ban won't reach it until it re-joins.
        #[arg(long, default_value_t = false)]
        no_expiry: bool,
        /// Path where the encoded cert blob is written (binary).
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    /// Decode a cert blob и dump its fields. Read-only — verifies
    /// nothing about the owner signature (use `verify-cert` for that).
    InspectCert {
        /// Path к the encoded cert blob.
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Verify а cert blob against а network owner's public key. Prints
    /// the cert fields on success или the error reason on failure.
    VerifyCert {
        /// Path к the encoded cert blob.
        #[arg(value_name = "PATH")]
        cert: PathBuf,
        /// Path к the owner public key (base64).
        #[arg(long, value_name = "PATH")]
        owner_pub: PathBuf,
        /// Owner signing algorithm.
        #[arg(long, value_enum, default_value_t = SignatureAlgorithmArg::Ed25519)]
        algo: SignatureAlgorithmArg,
        /// Expected `network_id` (64-char hex).
        #[arg(long, value_name = "HEX64")]
        network_id: String,
    },
    /// Issue а DHT-replicated ban via the running daemon's admin
    /// socket. Requires this node к be configured `[network].mode =
    /// "private"` AND its local cert flagged `admin: true`. The ban
    /// fan-outs to K closest peers и propagates network-wide; every
    /// member applies on its next ban-sync tick (~60 s).
    Ban {
        /// Target node-id (BLAKE3 of pubkey), 64-char hex. Or an
        /// alias resolved by the running daemon (peer alias, link_id).
        #[arg(value_name = "NODE_ID")]
        node_id: String,
        /// Optional ban reason — surfaces в admin-audit log on the
        /// admin node and в `list-bans` on every receiver. Defaults к
        /// `"admin ban"` when omitted.
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_config_init_difficulty() {
        let cli = Cli::try_parse_from(["veil-cli", "config", "init", "--difficulty", "7"])
            .expect("cli parses");

        assert_eq!(cli.output_format, OutputFormatArg::Text);

        match cli.command {
            Command::Config(ConfigArgs {
                command:
                    ConfigCommand::Init {
                        difficulty, force, ..
                    },
            }) => {
                assert_eq!(difficulty.difficulty, 7);
                assert!(!force);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parses_key_nonce_difficulty() {
        let cli = Cli::try_parse_from(["veil-cli", "key", "nonce", "--difficulty", "9"])
            .expect("cli parses");

        match cli.command {
            Command::Key(KeyArgs {
                command: KeyCommand::Nonce(KeyNonceArgs { difficulty, .. }),
            }) => assert_eq!(difficulty.difficulty, 9),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn rejects_removed_legacy_dificult_flag() {
        let err = Cli::try_parse_from(["veil-cli", "key", "nonce", "--dificult", "9"])
            .expect_err("legacy alias must be rejected");

        assert!(err.to_string().contains("--dificult"));
    }

    #[test]
    fn preserves_default_difficulty_for_config_init() {
        let cli = Cli::try_parse_from(["veil-cli", "config", "init"]).expect("cli parses");

        match cli.command {
            Command::Config(ConfigArgs {
                command: ConfigCommand::Init { difficulty, .. },
            }) => assert_eq!(
                difficulty.difficulty,
                IdentityPolicy::DEFAULT_POW_DIFFICULTY
            ),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn preserves_default_difficulty_for_key_nonce() {
        let cli = Cli::try_parse_from(["veil-cli", "key", "nonce"]).expect("cli parses");

        match cli.command {
            Command::Key(KeyArgs {
                command: KeyCommand::Nonce(KeyNonceArgs { difficulty, .. }),
            }) => assert_eq!(
                difficulty.difficulty,
                IdentityPolicy::DEFAULT_POW_DIFFICULTY
            ),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parses_output_format_jsonl() {
        let cli = Cli::try_parse_from(["veil-cli", "--output-format", "jsonl", "key", "info"])
            .expect("cli parses");

        assert_eq!(cli.output_format, OutputFormatArg::Jsonl);
    }

    #[test]
    fn parses_node_run_foreground() {
        let cli =
            Cli::try_parse_from(["veil-cli", "node", "run", "--foreground"]).expect("cli parses");

        match cli.command {
            Command::Node(NodeArgs {
                command:
                    NodeCommand::Run {
                        foreground,
                        daemon_child,
                        defer_init,
                    },
            }) => {
                assert!(foreground);
                assert!(!daemon_child);
                assert!(!defer_init);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parses_node_dht_get() {
        let key = "aabbccdd".repeat(8);
        let cli =
            Cli::try_parse_from(["veil-cli", "node", "dht", "get", &key]).expect("cli parses");
        match cli.command {
            Command::Node(NodeArgs {
                command:
                    NodeCommand::Dht(DhtArgs {
                        command: DhtCommand::Get { key: k },
                    }),
            }) => {
                assert_eq!(k, key);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parses_node_dht_put() {
        let key = "aabbccdd".repeat(8);
        let value = "deadbeef";
        let cli = Cli::try_parse_from(["veil-cli", "node", "dht", "put", &key, value])
            .expect("cli parses");
        match cli.command {
            Command::Node(NodeArgs {
                command:
                    NodeCommand::Dht(DhtArgs {
                        command: DhtCommand::Put { key: k, value: v },
                    }),
            }) => {
                assert_eq!(k, key);
                assert_eq!(v, value);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parses_node_discovery_list() {
        let cli = Cli::try_parse_from(["veil-cli", "node", "discovery-list"]).expect("cli parses");
        match cli.command {
            Command::Node(NodeArgs {
                command: NodeCommand::DiscoveryList,
            }) => {}
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parses_node_gateway_list() {
        let cli = Cli::try_parse_from(["veil-cli", "node", "gateway-list"]).expect("cli parses");
        match cli.command {
            Command::Node(NodeArgs {
                command: NodeCommand::GatewayList,
            }) => {}
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parses_node_routes() {
        let cli = Cli::try_parse_from(["veil-cli", "node", "routes"]).expect("cli parses");
        match cli.command {
            Command::Node(NodeArgs {
                command: NodeCommand::Routes { dst_node_id: None },
            }) => {}
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parses_peers_ban_unban() {
        let node = "aabbccdd".repeat(8);
        let cli = Cli::try_parse_from(["veil-cli", "peers", "ban", &node]).expect("cli parses ban");
        match cli.command {
            Command::Peers(PeersArgs {
                command: PeersCommand::Ban { node_id },
            }) => {
                assert_eq!(node_id, node);
            }
            _ => panic!("unexpected ban command"),
        }

        let cli =
            Cli::try_parse_from(["veil-cli", "peers", "unban", &node]).expect("cli parses unban");
        match cli.command {
            Command::Peers(PeersArgs {
                command: PeersCommand::Unban { node_id },
            }) => {
                assert_eq!(node_id, node);
            }
            _ => panic!("unexpected unban command"),
        }
    }
}
