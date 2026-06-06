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
    /// Generate and manage key pairs and their proof-of-work nonces.
    ///
    /// A nonce is a small number mined so the key's hash meets a
    /// difficulty target — cheap to check, costly to forge, which makes
    /// spamming fake identities expensive.
    Key(KeyArgs),
    /// Start, stop, and inspect the veil node.
    Node(NodeArgs),
    /// Manage listeners — the addresses your node accepts connections on.
    Listen(ListenArgs),
    /// Manage the known peers saved in your config.
    Peers(PeersArgs),
    /// Inspect the connections your node currently has open.
    Sessions(SessionsArgs),
    /// Low-level debugging tools (transport, peer connections, packet capture).
    Debug(DebugArgs),
    /// Inspect peer exchange (PEX) — how your node discovers other peers.
    ///
    /// PEX is the gossip layer that lets nodes swap lists of peers they
    /// know about, so you find new peers without a central directory.
    Pex(PexArgs),
    /// Manage your sovereign identity (your long-lived cryptographic name).
    Identity(IdentityArgs),
    /// Create and redeem bootstrap invites that get a brand-new node onto
    /// the network.
    ///
    /// A bootstrap invite is a short QR code or URL you share so a friend's
    /// fresh node can find its first peer. This avoids relying on a built-in
    /// list of seed servers, which a country-level censor could simply block
    /// by IP address.
    Bootstrap(BootstrapArgs),
    /// Share access to a private listener that is not publicly advertised.
    ///
    /// Some listeners are marked "trusted" or "hidden" and are never gossiped
    /// over PEX or the DHT, so nobody can find them on their own. To let
    /// someone in, you generate a signed invite bundle and hand it to them
    /// over any side channel you trust (a scanned QR code, an encrypted chat,
    /// even paper).
    ///
    /// The bundle packs everything the recipient needs to connect: your node
    /// ID, public key, transport address, the shared secret (PSK) for that
    /// listener, and an expiry time.
    ///
    /// How this differs from `bootstrap invite`: a bootstrap invite just
    /// points at a public listener. An `invite` bundle also carries the
    /// per-listener shared secret, which is what lets the recipient connect
    /// to a listener no one else can even see.
    Invite(InviteArgs),
    /// Run your own private network: create the owner key and issue or
    /// inspect membership certificates.
    ///
    /// Use these commands when you set `[network].mode = "private"` to stand
    /// up a closed, invite-only network. Nodes on the default public network
    /// never need them.
    Network(NetworkArgs),
    /// Check for and install signed software updates.
    ///
    /// Fetches an update manifest from the endpoints in your `[update]`
    /// config section, verifies its signature and the binary's checksum,
    /// then (for `apply`) swaps in the new binary. No running node is
    /// required — everything happens on its own.
    Update(UpdateArgs),
    /// Switch the node between foreground and battery-saving background mode.
    ///
    /// On a phone, a GUI wrapper normally flips this automatically when the
    /// app is paused or resumed. These commands let you do it by hand —
    /// handy when testing a mobile integration, scripting a "go quiet at
    /// night" cron job to save cellular data, or running a headless mobile
    /// gateway. Requires a running node.
    Mobile(MobileArgs),
    /// Install or remove the node as a Windows service so it starts on boot.
    ///
    /// Registers with the Windows Service Control Manager. On non-Windows
    /// platforms every subcommand fails with a clear message.
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
    /// Create a brand-new identity.
    ///
    /// Shows your 24-word recovery phrase (BIP-39 — write it down; it is the
    /// only way to recover the identity), mines its proof-of-work, and saves
    /// a per-device instance ID into your veil config directory.
    Create(IdentityCreateArgs),
    /// Show the identity stored on this device.
    ///
    /// Pretty-prints the saved instance ID and the most recent signed
    /// identity document.
    Show(IdentityShowArgs),
    /// Roll over this device's signing subkey to a fresh one.
    ///
    /// Loads the master seed (from your recovery phrase or encrypted master
    /// file), generates a new per-device subkey, signs it with the master
    /// key, bumps the document version, and saves the updated document.
    /// Routine key hygiene that does not change your identity's name.
    Rotate(IdentityRotateArgs),
    /// Restore an identity onto a new device from its recovery phrase.
    ///
    /// From the 24-word phrase, rebuilds your permanent identity name
    /// (which survives losing the old device) and generates a fresh
    /// per-device signing subkey under the recovered master seed.
    Restore(IdentityRestoreArgs),
    /// Claim a human-readable name (like `@alice`) for this identity.
    ///
    /// Mines proof-of-work (more for shorter, rarer names), signs the claim
    /// with your active subkey, and saves it under
    /// `<veil_dir>/name_claims/<name>.bin`. A running node publishes it to
    /// the DHT on its next 6-hour cycle (or at restart) so that peers
    /// looking up `@<name>` can find you.
    ClaimName(IdentityClaimNameArgs),
    /// Show your contact details as a QR code so others can add you.
    ///
    /// Prints a `veil:identity?...` link plus a scannable QR code in the
    /// terminal — useful for exchanging contacts in person. The other
    /// person scans it and gets your link, optionally including a preferred
    /// display name.
    Qr(IdentityQrArgs),
    /// Create an invite that adds a new device to this identity (run on the
    /// device you already have).
    ///
    /// Prints a one-time `veil:pair?...` link and QR code, plus the address
    /// the new device should connect back to. The new device scans it; the
    /// two finish pairing — including a code you compare on both screens —
    /// when it connects back.
    PairInvite(IdentityPairInviteArgs),
    /// Decode a scanned `veil:identity?…` (contact) or `veil:pair?…` (invite)
    /// link and print its contents — without changing anything.
    ///
    /// A safe preview: confirm a scanned QR decoded cleanly and review its
    /// fields (address, expiry, node ID, …) before you run the real pairing
    /// or contact-import command.
    InspectUri(IdentityInspectUriArgs),
    /// Wait for a new device to pair (run on the device you already have).
    ///
    /// Opens a listening port, prints the `veil:pair?…` link and QR code,
    /// then accepts one incoming pairing connection and completes it. On
    /// success the updated identity document is saved to disk. Needs your
    /// master-file password so it can sign the new device's subkey.
    PairListen(IdentityPairListenArgs),
    /// Join an existing identity by pairing from the new device.
    ///
    /// Connects to the address in a scanned `veil:pair?…` link, completes
    /// the pairing, and on success saves this device's identity state
    /// (document, fresh signing key, and instance ID) into its
    /// `--veil-dir`.
    PairAccept(IdentityPairAcceptArgs),
    /// Make an encrypted "last resort" backup of your identity as a QR code.
    ///
    /// Encrypts this device's master seed into a `veil:master-backup?…` QR
    /// you can photograph and store safely. Use it when both your paper
    /// recovery phrase AND your `master.enc` file are gone. Decrypting needs
    /// the separate QR password — share that out-of-band (spoken aloud, in a
    /// sealed envelope, or in a password manager), never with the photo.
    /// A photo of the QR alone cannot unlock the identity.
    ExportQrBackup(IdentityExportQrBackupArgs),
    /// Restore your identity from a `veil:master-backup?…` QR backup.
    ///
    /// Decrypts the backup (made by `export-qr-backup`) and restores the
    /// identity into `--veil-dir`. Use this when you have neither the paper
    /// recovery phrase nor the `master.enc` file. The end result is the same
    /// as a normal restore: your permanent name comes back and a fresh
    /// per-device signing key is generated.
    ImportQrBackup(IdentityImportQrBackupArgs),
    /// Create a simple single-device identity (no separate master key).
    ///
    /// Here the device key IS the master key — there is no separate master
    /// keypair, no recovery-phrase ceremony, and no `master.enc` file. This
    /// is the easy default for phone-only or laptop-only users, and matches
    /// what the node builds automatically on first start when no identity
    /// exists yet. The trade-off: there is no multi-device pairing and no
    /// paper recovery.
    Standalone(IdentityStandaloneArgs),
    /// Authorize an additional device to act for this identity.
    ///
    /// Run this on the device holding the master seed: it signs the new
    /// device's public key and adds it to your identity document. Move the
    /// updated document to the new device however you like (USB, QR, scp).
    DelegateDevice(IdentityDelegateDeviceArgs),
    /// Move to a new identity while proving it is still you (migration
    /// certificate).
    ///
    /// Signs a certificate linking your OLD identity (in `--from`) to your
    /// NEW one (in `--to`) using the old master key, so peers trust the
    /// hand-off. The certificate is written to `<--to>/migration_cert.bin`
    /// (override with `--cert-out`). To publish it to the DHT you need a
    /// running node pointed at the new directory — it picks the certificate
    /// up on its next maintenance cycle (or run `node dht put` yourself with
    /// the printed DHT key).
    ///
    /// You cannot downgrade security: the new identity's algorithm must be at
    /// least as strong as the old one (`hybrid > falcon512 > ed25519`), so a
    /// hybrid-to-ed25519 move is refused at sign time.
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

    /// **Deprecated and ignored.** Kept only so older scripts keep
    /// working. Identity documents no longer carry a document-level
    /// proof-of-work, so this value has no effect. It will be removed in a
    /// future major version.
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

    /// Which signature algorithm the master key uses. Three choices:
    ///
    /// * `ed25519` (default) — classical, fastest to verify, fully
    ///   recoverable from the 24-word phrase.
    /// * `hybrid` (= `ed25519+falcon512`) — signs with BOTH a classical and
    ///   a post-quantum (Falcon-512) key. The recovery phrase restores ONLY
    ///   the classical half; the file `<veil_dir>/master_falcon.bin` (created
    ///   automatically, mode 0o600) is the ONLY copy of the post-quantum
    ///   half. You MUST back up that file alongside the paper phrase, or a
    ///   restore falls back to classical-only and your identity name changes.
    /// * `falcon512` — pure post-quantum master, no classical half. It has
    ///   **no recovery phrase at all** — the secret key lives ONLY in
    ///   `master_falcon.bin`, so losing that file means total, unrecoverable
    ///   loss of the identity. Requires the explicit `--accept-no-recovery`
    ///   flag.
    #[arg(long, default_value = "ed25519")]
    pub algo: String,

    /// Confirm you understand that a standalone `--algo=falcon512` identity
    /// has NO recovery path other than the `master_falcon.bin` file on disk.
    /// The CLI refuses to create one without this flag. The `hybrid` and
    /// `ed25519` paths ignore it.
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

    /// Path to a plaintext file holding the 24-word recovery phrase
    /// (whitespace-separated, case-insensitive). Required for
    /// `--algo=ed25519` and `--algo=hybrid`. Ignored for `--algo=falcon512`
    /// (standalone Falcon has no recovery phrase; use
    /// `--master-falcon-file` instead).
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

    /// Which master-key algorithm to restore (must match what `identity
    /// create --algo` used). Default `ed25519`; use `hybrid`
    /// (= `ed25519+falcon512`) to restore a post-quantum hybrid identity.
    /// A hybrid restore REQUIRES `--master-falcon-file` pointing at your
    /// saved `master_falcon.bin` — without it the restore fails outright
    /// rather than quietly dropping to Ed25519-only (which would change your
    /// identity name and break your claimed `@name`). Standalone `falcon512`
    /// cannot be restored this way and is rejected.
    #[arg(long, default_value = "ed25519")]
    pub algo: String,

    /// Path to your saved `master_falcon.bin` file (the post-quantum half of
    /// a hybrid master). Required when `--algo=hybrid`; ignored otherwise.
    /// After a successful restore a fresh copy is written to the new
    /// `<veil_dir>/master_falcon.bin`.
    #[arg(long)]
    pub master_falcon_file: Option<PathBuf>,
}

/// Arguments for `identity standalone`.
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

/// Arguments for `identity delegate-device`.
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

/// Arguments for `identity migrate` — sign a `MigrationCert` linking the
/// OLD identity to the NEW one (already created in `--to`), using the OLD
/// master key.
///
/// Before running, make sure:
/// * You already ran `identity create` (or restore) in the NEW `--to`
///   directory, so `<--to>/identity_document.bin` exists and belongs to the
///   new master.
/// * You can unlock the OLD master, either with `--from-phrase-file` (the
///   recovery phrase) or `--from-password-file` (the `master.enc` password).
///   Hybrid and standalone-Falcon identities also read
///   `<--from>/master_falcon.bin`.
#[derive(Args, Debug)]
pub struct IdentityMigrateArgs {
    /// Veil config directory of the OLD (source) identity.
    /// Defaults the same way as other identity commands
    /// (`~/.config/veil` or `$VEIL_IDENTITY_DIR`).
    #[arg(long)]
    pub from: Option<PathBuf>,

    /// Veil config directory of the NEW (target) identity.
    /// MUST already contain a freshly-minted `identity_document.bin`
    /// (run `identity create` here BEFORE `identity migrate`).
    #[arg(long)]
    pub to: PathBuf,

    /// 24-word recovery phrase for the OLD master. Required for Ed25519 and
    /// hybrid old masters; not used for standalone-Falcon masters (they have
    /// no recovery phrase). Cannot be combined with `--from-password-file`.
    #[arg(long)]
    pub from_phrase_file: Option<PathBuf>,

    /// `master.enc` password for the OLD master. An alternative to
    /// `--from-phrase-file`.
    #[arg(long)]
    pub from_password_file: Option<PathBuf>,

    /// Path to the OLD `master_falcon.bin` file. Required when the old
    /// master uses `hybrid` or `falcon512`. Defaults to
    /// `<--from>/master_falcon.bin` if omitted.
    #[arg(long)]
    pub from_master_falcon_file: Option<PathBuf>,

    /// Where to write the signed migration certificate. Default:
    /// `<--to>/migration_cert.bin`. This is the file the running node for
    /// the NEW identity should publish to the DHT. On success the command
    /// prints the DHT key so you can publish it yourself with `node dht put`
    /// if you prefer.
    #[arg(long)]
    pub cert_out: Option<PathBuf>,

    /// How long the certificate stays valid, in seconds. Capped at 30 days —
    /// migrations happen quickly and the certificate should expire soon so
    /// stale ones cannot be replayed later.
    #[arg(long, default_value_t = 7 * 24 * 3600)]
    pub valid_for_secs: u64,

    /// Publish the certificate to the DHT right away instead of waiting.
    ///
    /// Pushes it through a running node — saved locally and copied out to the
    /// closest live peers. This needs a node already serving `--admin-socket`
    /// (default `<--from>/admin.sock`). Without this flag the command only
    /// writes the certificate to disk, and you wait for the node's next
    /// republish cycle or run `node dht put` by hand.
    ///
    /// If publishing fails (no admin socket, or the peer push times out) the
    /// command reports an error but still points you at the certificate file,
    /// which is already written — so you can retry with
    /// `node dht put <dht_key> <cert_path>`.
    #[arg(long)]
    pub publish_immediately: bool,

    /// Path to the admin socket for `--publish-immediately`. Defaults to
    /// `<--from>/admin.sock`. Ignored unless `--publish-immediately` is set.
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

/// Starter preset for `config init`. It only seeds the defaults written
/// into the new `config.toml` — it does NOT change an already-running
/// node, and you are free to edit the file afterwards.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ConfigProfile {
    /// Developer-friendly defaults: plain TCP on `:9000`, rustls TLS, no SNI
    /// override. Good for local testing and CI.
    #[default]
    Dev,
    /// Tuned to resist censorship: `wss://0.0.0.0:443`,
    /// `default_sni = "www.cloudflare.com"`, mesh enabled, plus inline
    /// comments reminding you to build with `--features tls-boring`.
    CensorshipTarget,
    /// For a mobile or battery-powered leaf node. Seeds:
    ///
    /// * `[mobile]` with `low_battery_threshold_pct = 30`, so probing slows
    ///   to a quarter speed once the battery drops below 30%.
    /// * `[mesh]` with `autodiscover_gateway = true`, so a leaf stuck behind
    ///   a carrier-grade NAT can find upstream gateways automatically.
    /// * `global.discovered_peers_cache_path` under the platform config
    ///   directory, so confirmed peers survive restarts — important on a
    ///   phone, where the OS may kill the app at any time.
    ///
    /// Identity and listeners are left to you: a leaf usually has no
    /// `[[listen]]` entry (outbound only) and reaches gateways through the
    /// cached and auto-discovered list.
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
        /// Starter preset to tune the generated config for a particular
        /// environment instead of the developer default.
        ///
        /// Profiles:
        /// * `dev` (default) — plain TCP on 9000, rustls TLS, no SNI override.
        /// * `censorship-target` — `wss://0.0.0.0:443`,
        ///   `default_sni = "www.cloudflare.com"`, mesh enabled, with comments
        ///   reminding you to build with `--features tls-boring`.
        /// * `mobile` — battery-aware leaf node (see the `--profile mobile`
        ///   value help for details).
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
    /// Sign the config file with your `[identity]` key so tampering can be
    /// detected.
    ///
    /// Signing adds a `# VEIL_CONFIG_SIGNATURE_V1: <base64>` comment line at
    /// the top of the file. From then on, loading the config checks that
    /// signature and logs a warning if it no longer matches.
    ///
    /// Signing a file that is already signed replaces the old signature line.
    /// Your `[identity].private_key` must be present and match the file's
    /// `[identity].public_key`, or the command stops without writing
    /// anything.
    Sign {
        /// Unix timestamp to record inside the signature. Defaults to the
        /// current time, so re-signing always moves this forward.
        #[arg(long, value_name = "UNIX_SECS")]
        issued_at: Option<u64>,
        /// Print the signed config to stdout instead of writing it back to
        /// the file. Useful for a dry run or piping into secure storage.
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

/// Out-of-band bootstrap invites.
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
        /// Lock the invite in a password-protected envelope. Hand out the URL
        /// on a wide public channel and the password on a small private one,
        /// so neither alone is enough to use the invite.
        ///
        /// DEPRECATED: a password on the command line can leak via `ps`,
        /// `/proc/<pid>/cmdline`, and shell history — prefer
        /// `--password-file`.
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,
        /// Read the envelope password from a file (`-` reads stdin) instead
        /// of passing it on the command line. Trailing whitespace is
        /// trimmed. Takes precedence over `--password`.
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
        /// Sign the invite with your local `[identity]` key so the recipient
        /// can confirm it really came from you (verified against your public
        /// key, which you share separately). The output URL uses the
        /// `veil:signed-invite?…` scheme. Cannot be combined with
        /// `--password`; if you need both proof-of-origin AND a private
        /// channel, sign first and then encrypt the resulting URL.
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

/// Invite bundles for trusted / hidden (non-advertised) listeners.
#[derive(Args, Debug)]
pub struct InviteArgs {
    #[command(subcommand)]
    pub command: InviteCommand,
}

#[derive(Subcommand, Debug)]
pub enum InviteCommand {
    /// Create a signed invite bundle for one of your listeners.
    ///
    /// Outputs the bundle as base32 text (and optionally a QR code). The
    /// recipient runs `invite accept` on it to install the listener's shared
    /// secret (PSK) and add you as a bootstrap peer.
    ///
    /// Requires:
    /// * `[identity]` is configured (Ed25519 only — bundle signing currently
    ///   supports Ed25519 keys).
    /// * The chosen listener is `visibility = "trusted"` or `"hidden"`. The
    ///   CLI refuses to make invites for `Public` listeners, since their
    ///   shared secret would be pointless — anyone can already find a public
    ///   listener via PEX.
    /// * The listener has a `psk_file`, so the bundle can include the shared
    ///   secret the recipient needs.
    Create {
        /// Listener ID (decimal or `0x…` hex) as shown in `listen list`.
        /// Must be a trusted or hidden listener.
        #[arg(long, value_name = "LISTEN_ID")]
        listener_id: veil_cfg::ListenId,
        /// How long the invite stays valid, in seconds. Capped at 1 year
        /// here; the bundle stores a raw expiry timestamp, so anyone
        /// verifying it later can also apply their own policy.
        #[arg(long, value_name = "SECS", default_value_t = 7 * 24 * 3600)]
        validity_secs: u64,
        /// Optional human-readable label baked into the bundle (e.g.
        /// "family group"). At most 64 bytes once UTF-8 encoded.
        #[arg(long, value_name = "TEXT")]
        label: Option<String>,
        /// Write the base32 bundle to a file instead of stdout. Handy for
        /// attaching to an email or message without the shell mangling the
        /// long base32 string.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Also draw a QR code beneath the base32 bundle so the recipient can
        /// scan it off the screen with a phone camera.
        #[arg(long, default_value_t = false)]
        qr: bool,
    },
    /// Accept an invite bundle and install what it contains.
    ///
    /// Verifies the bundle, then adds the inviter to `[[bootstrap_peers]]`
    /// (no duplicate if already present) and saves the embedded shared secret
    /// (PSK) to a file under `<veil_dir>/invite_psks/` for later use. Stops
    /// with a clear error if the bundle's signature, expiry, or version is
    /// bad.
    Accept {
        /// Path to the file holding the base32 bundle text. Use `-` to read
        /// it from stdin (paste the bundle).
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
        /// Optional override for where the shared secret is saved. Default:
        /// `<config_dir>/invite_psks/<node_id_hex>.psk`. The file is created
        /// with 0o600 permissions.
        #[arg(long, value_name = "FILE")]
        psk_out: Option<PathBuf>,
        /// Do not touch the config file — just verify the bundle and write
        /// out the shared-secret file. Useful when you want to review the
        /// inviter by hand before adding them to your bootstrap peers.
        #[arg(long, default_value_t = false)]
        no_update_config: bool,
    },
    /// Verify an invite bundle and print its contents, without changing
    /// anything.
    ///
    /// A recipient-side preview: "before I `accept` this, what's actually
    /// inside it?"
    Decode {
        /// Input file (base32 text). `-` reads from stdin.
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
    },
}

/// Mobile-mode controls (foreground vs. background / battery-saving).
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

/// Controls for the signed software-update mechanism.
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
    /// See whether a newer signed release is available.
    ///
    /// Reads `[update]` from your config (and the installed-version file, if
    /// set), fetches each manifest URL with failover, and verifies the
    /// publisher's signature and the binary's checksum. Prints either
    /// "up to date" or "v1.2.3 available — released YYYY-MM-DD".
    ///
    /// Exit codes: 0 = up to date, 1 = update available, 2 = error.
    Check,
    /// Download and install a published update.
    ///
    /// Fetches the new binary, checks its SHA-256, atomically swaps it into
    /// `update.install_path`, and records the new release time in
    /// `update.installed_version_path`. Your identity files are left
    /// untouched. Both of those config paths must be set.
    ///
    /// After this exits 0, restart the process yourself (systemd,
    /// `veil-cli node restart`, or stop-and-respawn) — the new binary takes
    /// effect on the next start. Does nothing if no update is available.
    Apply,
    /// Build and sign an update manifest for a freshly built binary.
    ///
    /// Used by the release pipeline to produce the signed blob that operators
    /// hand out alongside a binary. The manifest is written to stdout (or the
    /// `--output` file) as raw bytes. Whoever downloads the binary fetches
    /// this manifest, checks its signature against a known publisher key, and
    /// verifies the binary's SHA-256 against the manifest before installing.
    SignManifest(SignManifestArgs),
}

/// Arguments for `veil-cli update sign-manifest`.
#[derive(Args, Debug)]
pub struct SignManifestArgs {
    /// Path to the built binary file. Its SHA-256 is computed and recorded in
    /// the manifest.
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

    /// Target triple (e.g. "x86_64-unknown-linux-gnu"). `update check`
    /// matches this against the running platform and silently skips
    /// manifests for other platforms, so one set of manifest URLs can serve
    /// several targets.
    #[arg(long)]
    pub platform_target: String,

    /// One or more URLs where the binary is hosted (≤ 8). Multiple
    /// URLs let operators publish to separate CDNs for anti-takedown
    /// resilience — `veil-cli update apply` tries each in order
    /// until SHA-256 verification passes.
    #[arg(long = "binary-url", required = true, num_args = 1..)]
    pub binary_urls: Vec<String>,

    /// Path to the publisher's identity TOML file (same shape as `[identity]`
    /// in a node config — `algo`, `public_key`, `private_key`). The
    /// release-signing key is usually separate from any node identity and
    /// kept in cold storage (an HSM or paper backup).
    #[arg(long)]
    pub identity: std::path::PathBuf,

    /// Where to write the signed manifest bytes. Writes to stdout when
    /// omitted.
    #[arg(long, short)]
    pub output: Option<std::path::PathBuf>,

    /// Override the manifest's `release_unix` timestamp. Defaults to the
    /// current time; you can pin it to `SOURCE_DATE_EPOCH` for reproducible
    /// builds (so the manifest bytes depend only on the inputs).
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
        /// Start the daemon with no config file, using a throwaway temporary
        /// identity, and wait for a later `admin apply-config` to supply the
        /// real config.
        ///
        /// Use cases:
        /// * **Messenger / embedded** — the app keeps the real config in a
        ///   secure store (Keychain, EncryptedSharedPreferences, a future
        ///   TPM-sealed store) and never writes it to an ordinary file. Pair
        ///   this with `admin apply-config --no-persist`.
        /// * **Orchestrated provisioning** — start daemons first, then push
        ///   their generated configs at deploy time, without shipping the
        ///   config file next to the binary.
        ///
        /// The temporary identity is a **fresh Ed25519 keypair for this run
        /// only**; it lives purely in RAM, and short-lived working files
        /// (mlkem.key and so on) go in a per-run temp directory that is
        /// cleaned up at shutdown. No listeners or peers are active until
        /// `apply-config` arrives.
        #[arg(long)]
        defer_init: bool,
    },
    /// Stop the running node gracefully.
    Stop,
    /// Restart the running node (stop + start).
    Restart,
    /// Reload the config file without restarting (SIGHUP equivalent).
    Reload,
    /// Push a new config to the running daemon without writing it to disk.
    ///
    /// Unlike `reload`, this reads the config TOML directly (from a file path
    /// or stdin) and hands the bytes to the daemon over its admin channel.
    /// Used for:
    ///
    /// * **Messenger build** — the app keeps the config in a secure store
    ///   (Keychain, EncryptedSharedPreferences, a future TPM-sealed store)
    ///   and passes the bytes to the embedded daemon at startup. Defaults to
    ///   `--no-persist` so the bytes never hit the ordinary filesystem.
    /// * **Server admin** — orchestration tools (Terraform, Ansible, scripts)
    ///   pipe the rendered config straight to `apply-config -` with no
    ///   intermediate file (more atomic than `cp` then `reload`). Use
    ///   `--persist` so the new config survives daemon restarts.
    /// * **Deferred init** — together with `node run --defer-init`, this is
    ///   how the daemon goes from its temporary identity to fully
    ///   operational.
    ApplyConfig {
        /// Path to the config TOML file, or `-` to read it from stdin.
        #[arg(value_name = "PATH_OR_DASH")]
        path: std::path::PathBuf,
        /// After a successful apply, also write the new config to the
        /// daemon's `config_path` on disk. The default is no-persist, which
        /// matches the messenger / embedded case where the host keeps config
        /// in its own secure store.
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
    /// Look up another node's identity on the DHT and fully verify it.
    ///
    /// Fetches the signed identity document for a node ID and checks
    /// everything: the signature chain, expiry windows, key bounds, that the
    /// node ID matches the master key, and that the document is the one you
    /// asked for (not a swapped-in substitute).
    ///
    /// Prefer this over `node dht recursive-get`, which just returns raw
    /// bytes you'd have to verify yourself. This is the safe way to look up
    /// an identity you intend to act on.
    ResolveIdentity {
        /// 32-byte node_id as 64 lowercase hex chars.
        #[arg(value_name = "NODE_ID")]
        node_id: String,
        /// Maximum total resolve time in milliseconds (DHT walk + verify).
        #[arg(long, default_value = "5000")]
        timeout_ms: u64,
    },
    /// Look up who owns a `@name` and fully verify the result.
    ///
    /// Follows the name claim through to its identity document, checking the
    /// proof-of-work, freshness, and that the name is really signed by that
    /// identity's active key. Accepts either `alice` or `@alice`.
    ResolveName {
        /// The name to resolve, with or without leading `@`.
        #[arg(value_name = "NAME")]
        name: String,
        /// Maximum total resolve time in milliseconds.
        #[arg(long, default_value = "5000")]
        timeout_ms: u64,
    },
    /// Discover the network addresses another peer could be reached at
    /// (NAT traversal).
    ///
    /// Asks a peer you're already connected to relay the request, and reports
    /// the target's candidate addresses. A device stuck behind a carrier-grade
    /// NAT can feed these into UDP hole-punching to open a direct path to
    /// another NAT'd peer.
    ///
    /// Tries up to 4 relays (closest to the target first); the per-relay
    /// timeout is configurable.
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
    /// Show which mesh gateways this leaf node is using and why.
    ///
    /// Lists the gateways found automatically, best first (scored on latency
    /// and battery), with each one's active/standby state, round-trip time,
    /// battery, and freshness. Answers "why am I (or am I not) connected
    /// through gateway X?".
    MeshStatus,
    /// Show the state of every way your node can find its first peer.
    ///
    /// A read-only snapshot (no probing) of each bootstrap fallback layer:
    /// your own curated peers, the built-in seed list, the DNS bootstrap
    /// domain, and peers cached from previous runs. Answers "if a censor
    /// blocks my known seed IPs tomorrow, what do I fall back to?".
    BootstrapStatus,
    /// Show the software-update status without touching the network.
    ///
    /// Reports whether updates are configured, the installed release, the
    /// auto-check interval, and whether background mode is active. Lets you
    /// (or a GUI tray icon) confirm the setup without reading logs or running
    /// the network-touching `update check`.
    UpdateStatus,
    /// Show the current mobile / battery-saving status.
    ///
    /// Reports battery level, the scaling factors in effect, and the relevant
    /// config — answers "why is my keepalive 30 minutes when I expected 30
    /// seconds?". Like `update-status`, it only reads existing state.
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
    /// Move an open session to a different transport without reconnecting.
    ///
    /// Dials `--alt-uri` and hands off the existing session to `--peer` onto
    /// it. The session keeps its identity and encryption state — only the
    /// underlying connection changes, so there is no fresh handshake and no
    /// interruption.
    ///
    /// Typical use: move a peer's TLS session to WSS when a middlebox starts
    /// dropping TLS traffic. Example:
    ///
    ///   veil-cli node swap-transport \
    ///     --peer <64-hex node_id> \
    ///     --alt-uri wss://peer.example:8443/veil
    ///
    /// Both ends must run a build that supports transport handover. This
    /// command only drives the initiating side; the receiving side handles
    /// handovers automatically.
    SwapTransport {
        /// 64-hex `node_id` of the peer whose session to move.
        #[arg(long = "peer", value_name = "NODE_ID")]
        peer_node_id: String,
        /// Transport URI to dial (e.g. `tls://peer:9906` or
        /// `wss://peer:8443/veil`). The scheme need not differ from the
        /// current one — moving within the same scheme is fine.
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
    /// Store a key-value pair locally AND replicate it to the network.
    ///
    /// Saves the pair on this node and copies it out to the closest live
    /// peers in the keyspace. Used internally by `bootstrap publish` and
    /// `identity migrate --publish-immediately`, and exposed here so you can
    /// re-publish arbitrary data yourself — for example an identity document
    /// that fell off the DHT after every copy's lifetime expired.
    ///
    /// `--value-file` is a shortcut: the file's contents are hex-encoded for
    /// you. It cannot be combined with `--value` (raw hex).
    PublishReplicated {
        #[arg(value_name = "KEY", help = "32-byte key as 64 hex chars")]
        key: String,
        /// Value bytes as a hex string (cannot be combined with
        /// `--value-file`).
        #[arg(long, conflicts_with = "value_file")]
        value: Option<String>,
        /// Read value bytes from this file and hex-encode them automatically.
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
    /// Send an app message along an explicit relay path you specify.
    ///
    /// Skips DHT lookups and route gossip entirely — each relay simply
    /// forwards to the next node listed in `--path`. This works in any
    /// topology where the sessions along that path are already connected
    /// (linear, mesh, or anything in between), so it is handy for testing
    /// connectivity in awkward layouts where automatic DHT routing fails.
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
            help = "Payload bytes as a hex string (use \"\" for empty)",
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

/// Admin tooling for running your own private network.
#[derive(Args, Debug)]
pub struct NetworkArgs {
    #[command(subcommand)]
    pub command: NetworkCommand,
}

#[derive(Subcommand, Debug)]
pub enum NetworkCommand {
    /// Create the network owner keypair and write both keys to disk.
    ///
    /// The owner public key goes into every member's
    /// `[network].owner_pubkey` config slot; the owner private key stays on
    /// your admin machine. ANYONE with the owner private key can issue admin
    /// certificates, so guard it carefully (offline storage, a hardware
    /// token, an encrypted backup).
    GenOwner {
        /// Path where the public key is written (base64 + newline).
        #[arg(long, value_name = "PATH")]
        pub_out: PathBuf,
        /// Path where the private key is written (base64 + newline).
        /// Created with mode 0600 on Unix.
        #[arg(long, value_name = "PATH")]
        priv_out: PathBuf,
        /// Owner signing algorithm. Default `ed25519`.
        #[arg(long, value_enum, default_value_t = SignatureAlgorithmArg::Ed25519)]
        algo: SignatureAlgorithmArg,
    },
    /// Generate a random 32-byte `network_id` and print it as hex.
    ///
    /// Goes into `[network].network_id`. One-shot — nothing is saved, so
    /// rerun if you lose it.
    GenNetworkId,
    /// Issue a membership certificate for one member node.
    ///
    /// Signs with the owner private key from `--owner-priv`. The certificate
    /// is bound to the member's `node_id` (the BLAKE3 hash of their public
    /// key); the member proves it owns that key during the normal connection
    /// handshake.
    SignMember {
        /// Path to the owner public-key file (from `gen-owner`).
        #[arg(long, value_name = "PATH")]
        owner_pub: PathBuf,
        /// Path to the owner private-key file (from `gen-owner`).
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
        /// How many days the certificate stays valid, counting from now.
        /// Default 365. Ignored when `--no-expiry` is passed.
        #[arg(
            long,
            value_name = "DAYS",
            default_value_t = 365,
            conflicts_with = "no_expiry"
        )]
        valid_days: u32,
        /// Issue a certificate that never expires. Useful for fleet members
        /// where you would rather handle revocation only through DHT bans or
        /// by rotating the network's `owner_pubkey`.
        ///
        /// Trade-off: revoking a single device without rotating the owner key
        /// relies on the DHT ban reaching it. If that device is offline or
        /// air-gapped, the ban won't take effect until it reconnects.
        #[arg(long, default_value_t = false)]
        no_expiry: bool,
        /// Path where the encoded cert blob is written (binary).
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    /// Decode a certificate and print its fields. Read-only — it does NOT
    /// check the owner signature (use `verify-cert` for that).
    InspectCert {
        /// Path to the encoded certificate file.
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Verify a certificate against a network owner's public key. Prints the
    /// certificate's fields on success, or the reason it failed.
    VerifyCert {
        /// Path to the encoded certificate file.
        #[arg(value_name = "PATH")]
        cert: PathBuf,
        /// Path to the owner public key (base64).
        #[arg(long, value_name = "PATH")]
        owner_pub: PathBuf,
        /// Owner signing algorithm.
        #[arg(long, value_enum, default_value_t = SignatureAlgorithmArg::Ed25519)]
        algo: SignatureAlgorithmArg,
        /// Expected `network_id` (64-char hex).
        #[arg(long, value_name = "HEX64")]
        network_id: String,
    },
    /// Ban a node across the whole private network.
    ///
    /// Issues a DHT-replicated ban through the running daemon's admin socket.
    /// This node must be configured `[network].mode = "private"` AND hold a
    /// local certificate marked `admin: true`. The ban is copied out to the
    /// closest peers and spreads network-wide; every member applies it on its
    /// next ban-sync cycle (about every 60 s).
    Ban {
        /// Target node ID (the BLAKE3 hash of the public key), 64 hex chars.
        /// You can also pass an alias the running daemon can resolve (a peer
        /// alias or link ID).
        #[arg(value_name = "NODE_ID")]
        node_id: String,
        /// Optional reason for the ban — shown in the admin audit log here and
        /// in `list-bans` on every node that receives it. Defaults to
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
