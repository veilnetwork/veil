use std::path::{Path, PathBuf};

#[cfg(unix)]
extern crate libc;

use veil_cfg;
use veil_cfg::identity_ops::{IdentityPowParams, IdentityProvisionParams};

use super::{
    cli::ConfigCommand,
    identity::IdentityService,
    output::{CommandIo, OutputEvent},
};

pub trait ConfigOps {
    fn default_init_path(&self) -> std::path::PathBuf;
    fn prepare_init_path(&self, path: &Path, force: bool) -> veil_cfg::Result<std::path::PathBuf>;
    fn locate_config(&self, config_arg: Option<&Path>) -> veil_cfg::Result<std::path::PathBuf>;
    fn read_raw_config(&self, path: &Path) -> veil_cfg::Result<String>;
    fn load_config(&self, path: &Path) -> veil_cfg::Result<veil_cfg::Config>;
    fn save_config(&self, path: &Path, config: &veil_cfg::Config) -> veil_cfg::Result<()>;
    /// Atomically write a raw string back to the config file.  Used
    /// by `config sign` (slice 11b) — the signed output includes
    /// comment-line signature headers that `save_config` would lose
    /// (it round-trips through the parsed Config struct).
    fn write_raw_config(&self, path: &Path, content: &str) -> veil_cfg::Result<()>;
}

#[derive(Debug)]
pub struct CommandContext<'a, I, O> {
    pub config_arg: Option<&'a Path>,
    pub io: I,
    pub ops: O,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ConfigHandle<'a, O> {
    config_arg: Option<&'a Path>,
    ops: &'a O,
}

#[derive(Clone, Debug)]
pub(crate) enum ConfigMutation<T> {
    Save(T),
    Keep(T),
}

impl<T> ConfigMutation<T> {
    pub(crate) fn save(result: T) -> Self {
        Self::Save(result)
    }

    pub(crate) fn keep(result: T) -> Self {
        Self::Keep(result)
    }
}

pub(crate) struct ConfigCommandService;

impl<'a, I, O> CommandContext<'a, I, O>
where
    O: ConfigOps,
{
    pub(crate) fn config(&self) -> ConfigHandle<'_, O> {
        ConfigHandle::new(self.config_arg, &self.ops)
    }
}

impl<'a, O> ConfigHandle<'a, O>
where
    O: ConfigOps,
{
    pub(crate) fn new(config_arg: Option<&'a Path>, ops: &'a O) -> Self {
        Self { config_arg, ops }
    }

    pub(crate) fn default_init_path(&self) -> PathBuf {
        self.ops.default_init_path()
    }

    pub(crate) fn prepare_init_path(&self, path: &Path, force: bool) -> veil_cfg::Result<PathBuf> {
        self.ops.prepare_init_path(path, force)
    }

    pub(crate) fn locate(&self) -> veil_cfg::Result<PathBuf> {
        self.ops.locate_config(self.config_arg)
    }

    pub(crate) fn load(&self, path: &Path) -> veil_cfg::Result<veil_cfg::Config> {
        self.ops.load_config(path)
    }

    pub(crate) fn save(&self, path: &Path, config: &veil_cfg::Config) -> veil_cfg::Result<()> {
        self.ops.save_config(path, config)
    }

    pub(crate) fn try_locate(&self) -> veil_cfg::Result<Option<PathBuf>> {
        match self.locate() {
            Ok(path) => Ok(Some(path)),
            Err(veil_cfg::ConfigError::NotFound) => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub(crate) fn load_existing(&self) -> veil_cfg::Result<(PathBuf, veil_cfg::Config)> {
        let path = self.locate()?;
        let config = self.load(&path)?;
        Ok((path, config))
    }

    pub(crate) fn read_existing_raw(&self) -> veil_cfg::Result<(PathBuf, String)> {
        let path = self.locate()?;
        let content = self.ops.read_raw_config(&path)?;
        Ok((path, content))
    }

    pub(crate) fn update_existing<T>(
        &self,
        action: impl FnOnce(&Path, &mut veil_cfg::Config) -> veil_cfg::Result<ConfigMutation<T>>,
    ) -> veil_cfg::Result<T> {
        let (path, mut config) = self.load_existing()?;
        match action(&path, &mut config)? {
            ConfigMutation::Save(result) => {
                self.save(&path, &config)?;
                Ok(result)
            }
            ConfigMutation::Keep(result) => Ok(result),
        }
    }
}

pub fn handle_config_command<I: CommandIo, O: ConfigOps>(
    context: CommandContext<'_, I, O>,
    command: ConfigCommand,
) -> veil_cfg::Result<()> {
    ConfigCommandService::handle(context, command)
}

/// stamp profile-specific defaults onto a freshly-built
/// `Config` before it's written to disk. Operator can edit the file
/// freely afterwards — this only affects what `config init` *starts
/// with*.
///
/// See `docs/internal/censorship-target.md` for the full rationale
/// behind the censorship-target preset. Each branch is intentionally
/// terse because every default carries a comment in the generated
/// TOML (added by serde via field-doc round-trip), so the operator's
/// reading material is the file itself.
pub(crate) fn apply_profile_defaults(
    loaded: &mut veil_cfg::Config,
    profile: super::cli::ConfigProfile,
) {
    use super::cli::ConfigProfile;
    match profile {
        ConfigProfile::Dev => {
            // No-op: the `Config::default` is already dev-friendly.
        }
        ConfigProfile::CensorshipTarget => {
            // Listen on `wss://0.0.0.0:443` so traffic blends with
            // ordinary HTTPS (port 443 is the only port a typical
            // network-layer censor reliably whitelists).
            //
            // We don't fill in `tls_cert` / `tls_key` here — operator
            // MUST provide their own (self-signed or PKI-issued); the
            // generated config carries empty fields the operator
            // edits before first start.
            loaded.listen.push(veil_cfg::ListenConfig {
                id: veil_cfg::ListenId::new(1),
                transport: "wss://0.0.0.0:443".to_owned(),
                advertise: None,
                relay: None,
                tls_cert: Some("/etc/veil/server.pem".to_owned()),
                tls_key: Some("/etc/veil/server.key".to_owned()),
                tls_ca_cert: None,
                ..Default::default()
            });
            // ClientHello SNI override — outbound TLS handshakes carry
            // a popular CDN domain instead of the actual veil
            // hostname, defeating SNI-based DPI.
            loaded.transport.default_sni = Some("www.cloudflare.com".to_owned());
            // Mesh enabled with `autodiscover_gateway = true` so leaves
            // behind CGN-NAT can find this gateway via beacon.
            loaded.mesh = Some(veil_cfg::MeshConfig {
                bind_addr: "0.0.0.0:9100".to_owned(),
                realm_id: "0".repeat(32),
                realm_psk: None,
                beacon_addr: "255.255.255.255:9100".to_owned(),
                autodiscover_gateway: true,
                autodiscover_max_concurrent: 3,
                beacon_dedup_window_secs: 3,
                autodiscover_persist_path: None,
                // Secure posture (C-03): reject unsigned beacons, and -- since
                // this profile explicitly sets up beacon-based gateway
                // discovery -- opt into advertising the gateway role (the
                // global default keeps role_flags off so non-gateway nodes
                // don't reveal their role to a passive on-link observer).
                require_signed_beacons: true,
                advertise_role_in_beacon: true,
            });
        }
        ConfigProfile::Mobile => {
            // Battery-aware probe throttling — kicks in below 30 %.
            // Multiplier = default 4 means probes happen 4× less
            // often when the phone is low; deadline-driven phases
            // (eviction, re-mint, sovereign re-issue) are NOT
            // throttled.
            loaded.mobile = veil_cfg::MobileConfig {
                low_battery_threshold_pct: Some(30),
                low_battery_multiplier: 4,
                // when GUI wrapper / mobile app calls
                // SetMobileBackgroundMode(true) on onPause hook
                // multiply per-session keepalive by 60 — 30s base
                // → 30 min, well under default idle_timeout (24h)
                // so the session survives suspension. Foreground
                // resume → multiplier off → next keepalive within
                // 30s, peer notices we're alive again.
                background_keepalive_multiplier: 60,
                // deferred slices remain off by default
                // even on the mobile profile — they require on-device
                // measurement to confirm the radio-on / CPU drain
                // they target is actually material. Operator can flip
                // either independently in `[mobile]` after measuring.
                low_battery_throttle_maintenance: false,
                outbound_batch_window_ms: None,
            };
            // Leaf behind CGN-NAT finds upstream gateways via mesh
            // beacons. Mesh is per-LAN so this works whether the
            // phone is on home WiFi, café WiFi, or tethered.
            loaded.mesh = Some(veil_cfg::MeshConfig {
                bind_addr: "0.0.0.0:9100".to_owned(),
                realm_id: "0".repeat(32),
                realm_psk: None,
                beacon_addr: "255.255.255.255:9100".to_owned(),
                autodiscover_gateway: true,
                autodiscover_max_concurrent: 3,
                beacon_dedup_window_secs: 3,
                autodiscover_persist_path: None,
                // Secure posture (C-03): reject unsigned beacons, and -- since
                // this profile explicitly sets up beacon-based gateway
                // discovery -- opt into advertising the gateway role (the
                // global default keeps role_flags off so non-gateway nodes
                // don't reveal their role to a passive on-link observer).
                require_signed_beacons: true,
                advertise_role_in_beacon: true,
            });
            // Persist handshake-confirmed peers across restarts
            //. The OS may kill the binary at any
            // time on mobile — without persistence, every relaunch
            // re-bootstraps from scratch and burns extra battery
            // probing dead seeds.
            loaded.global.discovered_peers_cache_path =
                Some("/var/lib/veil/discovered_peers.json".to_owned());
            // cap concurrent sessions at 64 instead of
            // the desktop default 512. Each session ≈ 50-100 KB
            // of TLS state + queues + timers; 64 sessions ≈ 3-6 MB
            // ceiling — fits comfortably even on 1-2 GB RAM phones.
            // Without this cap a node on a busy LAN (popular WiFi
            // 100+ peers via PEX) could grow session count past
            // what budget hardware can sustain → OOM-kill.
            loaded.session.max_concurrent = 64;
            // rotate sessions every 30 min to defeat
            // long-lived-connection DPI fingerprint. Normal HTTPS
            // browser sessions live for seconds-to-minutes; an
            // veil session lasting hours stands out. At 30
            // min cadence rotation cost = 48 fresh handshakes/day
            // per active session — small overhead vs censor-evasion
            // win. Desktop / relay nodes (where long-lived
            // connections aren't censored) can leave None via
            // explicit `[session].max_age_secs = 0` override.
            loaded.session.max_age_secs = Some(1_800);
            // b: per-peer byte-rate cap. Composes
            // orthogonally with node-aggregate `capacity.max_inbound_
            // bandwidth_kbps` — node-aggregate prevents
            // total runaway, per-peer prevents single-peer-flood
            // from saturating the user's cellular quota even when
            // node-aggregate has headroom (real-world censor
            // scenario: single sybil peer gets through all upper
            // defences, sends 100 KB/s of garbage frames to mobile
            // user → without per-peer cap, eats user's monthly
            // 1-5 GB cellular quota in ~10 hours). 64 KB/s = 512
            // kbps per peer is enough for real chat / signaling
            // patterns, blocks the runaway-flood scenario. Default
            // burst = 4× rate (256 KB) absorbs legitimate-but-
            // bursty traffic on first frame.
            loaded.abuse.per_peer_bytes_per_sec = Some(65_536);
            // cellular-friendly bandwidth caps. Default
            // 100 Mbit/s ceiling is wildly too high for a 1-5 GB
            // monthly cap user — a single runaway DHT walk or
            // misbehaving peer could eat the entire monthly quota
            // in minutes. Inbound 2 Mbit/s = 256 KB/s = ~15 MB/min
            // (1 GB takes ~70 min sustained), outbound 500 kbps =
            // 63 KB/s = ~3.7 MB/min (1 GB takes ~5 h sustained) —
            // both well above typical foreground app traffic
            // (< 100 kbps avg for chat / signaling) but hard-stop
            // any runaway pattern before it bills the user.
            // WiFi-only mobile nodes can override [capacity]
            // section; the cellular case is the worst case so we
            // optimise for it (most-network-apps convention).
            loaded.capacity.max_inbound_bandwidth_kbps = 2_000;
            loaded.capacity.max_outbound_bandwidth_kbps = 500;
            // stretch update-check cadence to 24 h
            // (default behaviour: no auto-poll until operator sets
            // an interval). Keeps the auto-poll task a no-op
            // when [update] isn't configured (slice-9 spawn guards
            // require manifest_urls + issuer_pk too); when the
            // operator DOES configure [update], they get a
            // cellular-friendly poll cadence by default — saves
            // ~6× cellular data vs the 4 h cadence reasonable for
            // server nodes.
            loaded.update.check_interval_secs = Some(86_400);
            // Cap DHT-store memory tighter than the Core ~400 MB default:
            // budget phones can't afford it. 128 MB byte cap + a matching
            // ~8k-entry cap (8k × 16 KiB = 128 MB worst case) keep the store
            // bounded both ways. Overridable in `[dht]` (a WiFi-only mobile
            // node with RAM to spare can raise these).
            loaded.dht.max_store_bytes = Some(128_000_000);
            loaded.dht.max_store_entries = 8_000;
        }
    }
}

impl ConfigCommandService {
    fn handle<I: CommandIo, O: ConfigOps>(
        mut context: CommandContext<'_, I, O>,
        command: ConfigCommand,
    ) -> veil_cfg::Result<()> {
        match command {
            ConfigCommand::Locate => Self::locate(&mut context),
            ConfigCommand::Init {
                path,
                difficulty,
                force,
                profile,
            } => Self::init(&mut context, path, difficulty.difficulty, force, profile),
            ConfigCommand::Show { reveal_secrets } => Self::show(&mut context, reveal_secrets),
            ConfigCommand::Validate { fix } => Self::validate(&mut context, fix),
            ConfigCommand::Get {
                key,
                reveal_secrets,
            } => Self::get(&mut context, &key, reveal_secrets),
            ConfigCommand::Set { key, value } => Self::set(&mut context, &key, &value),
            ConfigCommand::Publish => Self::publish_bundle(&mut context),
            ConfigCommand::Fetch { dry_run } => Self::fetch_bundle(&mut context, dry_run),
            ConfigCommand::Sign { issued_at, stdout } => {
                Self::sign(&mut context, issued_at, stdout)
            }
        }
    }

    fn locate<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
    ) -> veil_cfg::Result<()> {
        let path = context.config().locate()?;
        context.io.emit(OutputEvent::config_path(path));
        Ok(())
    }

    fn init<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
        path: Option<PathBuf>,
        difficulty: u32,
        force: bool,
        profile: super::cli::ConfigProfile,
    ) -> veil_cfg::Result<()> {
        let path = Self::init_config_with_identity_using(
            context,
            path,
            difficulty,
            force,
            profile,
            |context, difficulty| {
                IdentityService::generate_identity_with_nonce(
                    &mut context.io,
                    IdentityProvisionParams {
                        pow: IdentityPowParams {
                            difficulty,
                            ..IdentityPowParams::default()
                        },
                        ..IdentityProvisionParams::default()
                    },
                )
            },
        )?;
        context.io.emit(OutputEvent::config_path(path));
        Ok(())
    }

    fn init_config_with_identity_using<I, O, F>(
        context: &mut CommandContext<'_, I, O>,
        path: Option<PathBuf>,
        difficulty: u32,
        force: bool,
        profile: super::cli::ConfigProfile,
        generate_identity: F,
    ) -> veil_cfg::Result<PathBuf>
    where
        I: CommandIo,
        O: ConfigOps,
        F: FnOnce(&mut CommandContext<'_, I, O>, u32) -> veil_cfg::Result<veil_cfg::IdentityConfig>,
    {
        let path = {
            let config = context.config();
            let path = path.unwrap_or_else(|| config.default_init_path());
            config.prepare_init_path(&path, force)?
        };
        let identity = normalize_identity_config(generate_identity(context, difficulty)?)?;
        let mut loaded = veil_cfg::Config {
            identity: Some(identity),
            ..veil_cfg::Config::default()
        };
        if loaded.global.admin_socket.is_none() {
            loaded.global.admin_socket = Some(veil_cfg::default_admin_socket_uri(&path));
        }
        // profile-specific defaults. Applied AFTER identity
        // generation so the identity bytes are independent of the
        // profile choice. See `apply_profile_defaults` for what each
        // profile changes.
        apply_profile_defaults(&mut loaded, profile);
        context.config().save(&path, &loaded)?;
        Ok(path)
    }

    fn show<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
        reveal_secrets: bool,
    ) -> veil_cfg::Result<()> {
        let (_path, content) = context.config().read_existing_raw()?;
        let content = if reveal_secrets {
            content
        } else {
            redact_secrets_structured(&content)
        };
        context.io.emit(OutputEvent::config_contents(content));
        Ok(())
    }

    fn validate<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
        fix: bool,
    ) -> veil_cfg::Result<()> {
        if fix {
            let fixed = apply_validation_fixes(&context.config())?;
            context.io.emit(OutputEvent::validation_fixed(fixed));
            Ok(())
        } else {
            let (_path, loaded) = context.config().load_existing()?;
            validate_loaded(&mut context.io, &loaded)
        }
    }

    fn get<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
        key: &str,
        reveal_secrets: bool,
    ) -> veil_cfg::Result<()> {
        if is_secret_config_key(key) && !reveal_secrets {
            return Err(veil_cfg::ConfigError::CommandFailed(format!(
                "`{key}` is a secret value; re-run with --reveal-secrets to print it \
                 (it will be written to stdout — avoid logs / shared terminals)."
            )));
        }
        let (_path, loaded) = context.config().load_existing()?;
        context
            .io
            .emit(OutputEvent::config_value(veil_cfg::get(&loaded, key)?));
        Ok(())
    }

    fn set<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
        key: &str,
        value: &str,
    ) -> veil_cfg::Result<()> {
        let path = set_existing_value(&context.config(), key, value)?;
        context.io.emit(OutputEvent::config_path(path));
        Ok(())
    }

    /// publish local `bootstrap_peers` into the DHT
    /// under the well-known bundle key. Other operators' nodes can fetch
    /// [`ConfigCommand::Fetch`] / `node bootstrap fetch`.
    ///
    /// hardening: the bundle is signed with the running node's
    /// `[identity]` keypair before publishing, and uses the K-closest
    /// replication path instead of
    /// the legacy local-only `DhtPut`. Without these the bundle was
    /// (a) trivially forgeable by anyone who could reach the bundle's
    /// DHT slot, and (b) never actually propagated past the publisher's
    /// own DHT shard — making the cross-node bootstrap-rotation feature
    /// inert.
    pub(crate) fn publish_bundle<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
    ) -> veil_cfg::Result<()> {
        use veil_bootstrap as bootstrap;
        use veil_node_runtime::admin as node;

        let (config_path, loaded) = context.config().load_existing()?;
        if loaded.bootstrap_peers.is_empty() {
            return Err(veil_cfg::ConfigError::CommandFailed(
                "config.bootstrap_peers is empty — nothing to publish. \
                 Add at least one entry under [[bootstrap_peers]] first."
                    .to_owned(),
            ));
        }
        let identity = loaded.identity.as_ref().ok_or_else(|| {
            veil_cfg::ConfigError::CommandFailed(
                "config.identity is empty — the running node must sign \
                 the bundle with its identity keypair before publishing. \
                 Run `veil-cli identity create` first."
                    .to_owned(),
            )
        })?;
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let signed = bootstrap::sign_bundle(
            &loaded.bootstrap_peers,
            &identity.public_key,
            &identity.private_key,
            identity.algo,
            issued_at,
        )
        .map_err(|e| veil_cfg::ConfigError::CommandFailed(format!("sign bundle: {e}")))?;
        if signed.len() > veil_proto::budget::MAX_DHT_VALUE_BYTES {
            return Err(veil_cfg::ConfigError::ValidationFailed(format!(
                "encoded signed bundle is {} bytes, exceeds DHT value \
                 limit {} — reduce bootstrap_peers count",
                signed.len(),
                veil_proto::budget::MAX_DHT_VALUE_BYTES,
            )));
        }
        let socket =
            node::admin_socket_path(&loaded, config_path.parent()).map_err(map_node_err)?;
        if !node::admin_anchor_reachable_sync(&socket) {
            return Err(veil_cfg::ConfigError::CommandFailed(format!(
                "admin socket `{}` was not found; start the node with `veil-cli node run`",
                socket.display()
            )));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(veil_cfg::ConfigError::Io)?;
        let key_hex = veil_util::bytes_to_hex(&bootstrap::bootstrap_bundle_dht_key());
        let value_hex = veil_util::bytes_to_hex(&signed);
        let response = runtime
            .block_on(node::send_request(
                &socket,
                node::AdminCommand::DhtPublishReplicated {
                    key: key_hex.clone(),
                    value: value_hex,
                },
            ))
            .map_err(map_node_err)?;
        if let Some(err) = response.error {
            return Err(veil_cfg::ConfigError::CommandFailed(err));
        }
        let ack = match response.result {
            Some(node::AdminResult::Ack { message }) => message,
            _ => "(no ack)".to_owned(),
        };
        context.io.emit(OutputEvent::message(format!(
            "published {} bootstrap peer(s) as {}-byte SIGNED bundle to DHT key {}\n{ack}",
            loaded.bootstrap_peers.len(),
            signed.len(),
            key_hex,
        )));
        Ok(())
    }

    /// Sign the active config file in place using the operator's
    /// `[identity]` keypair (slice 11b).  Calls
    /// `veil_cfg::signed_config::sign_config` with the raw file
    /// content + identity keys and writes the result back atomically
    /// (or prints to stdout if `--stdout`).
    ///
    /// Pre-conditions:
    /// * `[identity].public_key` / `[identity].private_key` must both be
    ///   present (the active config — same keys used for bootstrap-bundle
    ///   signing).
    /// * If `issued_at_unix` is None, defaults to `SystemTime::now()`.
    ///
    /// Re-signing an already-signed config replaces the previous
    /// signature header (the canonical-message stripping is idempotent).
    pub(crate) fn sign<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
        issued_at_override: Option<u64>,
        to_stdout: bool,
    ) -> veil_cfg::Result<()> {
        // Step 1 — load the parsed config to extract the identity keys.
        // Note: this implicitly verifies any existing signature (warn-
        // only) — operators get a chance to see "current signature is
        // OK" before re-signing.
        let (config_path, loaded) = context.config().load_existing()?;
        let identity = loaded.identity.as_ref().ok_or_else(|| {
            veil_cfg::ConfigError::CommandFailed(
                "config.identity is empty — `config sign` needs a keypair \
                 to sign with.  Run `veil-cli identity create` first."
                    .to_owned(),
            )
        })?;
        if identity.public_key.is_empty() || identity.private_key.is_empty() {
            return Err(veil_cfg::ConfigError::CommandFailed(
                "config.identity.{public_key,private_key} must both be \
                 non-empty to sign — partial keypair detected."
                    .to_owned(),
            ));
        }

        // Step 2 — read the raw file content (preserves any existing
        // signature header so the sign helper can strip + replace it).
        let raw = context.ops.read_raw_config(&config_path)?;

        // Step 3 — derive issued_at (now() if override is None).
        let issued_at = issued_at_override.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });

        // Step 4 — sign.  Fails fast on key-pair / algorithm mismatch
        // before any write happens.
        let signed = veil_cfg::signed_config::sign_config(
            &raw,
            &identity.public_key,
            &identity.private_key,
            identity.algo,
            issued_at,
        )
        .map_err(|e| veil_cfg::ConfigError::CommandFailed(format!("sign config: {e}")))?;

        // Step 5 — emit OR write atomically back to the file.
        if to_stdout {
            context.io.emit(OutputEvent::config_contents(signed));
        } else {
            context.ops.write_raw_config(&config_path, &signed)?;
            context.io.emit(OutputEvent::message(format!(
                "signed config at {} (algo={:?}, issued_at_unix={issued_at}, \
                 issuer_pk={}…); subsequent loads will verify the signature \
                 and WARN on failure — see veil_cfg.signed_config logs",
                config_path.display(),
                identity.algo,
                &identity.public_key[..identity.public_key.len().min(16)],
            )));
        }
        Ok(())
    }

    /// fetch the signed bundle from the DHT and merge
    /// into local config. With `dry_run=true` just prints the fetched entries.
    ///
    /// hardening: uses recursive DHT walk (cross-node) instead of
    /// local-only `DhtGet`, decodes the wire envelope as a SIGNED bundle
    /// and verifies the operator's signature before merging anything into
    /// config. Without the verify step any peer who could reach the
    /// bundle slot could inject malicious peers into every fetcher's
    /// `[[bootstrap_peers]]` — bootstrapping new devices straight into
    /// an attacker-controlled subnet.
    pub(crate) fn fetch_bundle<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
        dry_run: bool,
    ) -> veil_cfg::Result<()> {
        use veil_bootstrap as bootstrap;
        use veil_node_runtime::admin as node;

        let (config_path, mut loaded) = context.config().load_existing()?;
        let socket =
            node::admin_socket_path(&loaded, config_path.parent()).map_err(map_node_err)?;
        if !node::admin_anchor_reachable_sync(&socket) {
            return Err(veil_cfg::ConfigError::CommandFailed(format!(
                "admin socket `{}` was not found; start the node with `veil-cli node run`",
                socket.display()
            )));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(veil_cfg::ConfigError::Io)?;
        let key_hex = veil_util::bytes_to_hex(&bootstrap::bootstrap_bundle_dht_key());
        let response = runtime
            .block_on(node::send_request(
                &socket,
                node::AdminCommand::DhtRecursiveGet {
                    key: key_hex.clone(),
                    timeout_ms: 5000,
                },
            ))
            .map_err(map_node_err)?;
        if let Some(err) = response.error {
            return Err(veil_cfg::ConfigError::CommandFailed(err));
        }
        let Some(node::AdminResult::DhtValue {
            value_hex: Some(hex),
            ..
        }) = response.result
        else {
            return Err(veil_cfg::ConfigError::CommandFailed(format!(
                "no bundle found at DHT key {key_hex} — operator has not \
                 published one yet, or recursive DHT walk timed out"
            )));
        };
        let envelope_bytes =
            parse_hex_bytes(&hex).map_err(veil_cfg::ConfigError::ValidationFailed)?;

        // decode + verify the signed envelope before
        // touching any of the inner peers. Pinning the issuer pubkey
        // is operator policy. Priority order (strict-pin first):
        //
        // 1. `global.trusted_bundle_issuer_pubkey` set →
        // strict pin against that pubkey; reject mismatch loudly.
        // This is the production downstream-user path: operator
        // distributes their pubkey out-of-band (paper, website
        // on another jurisdiction, friend), user pins it.
        //
        // 2. Running node has `[identity]` matching the envelope's
        // claimed issuer → self-published bundle path (operator
        // fetching their own bundle for verification).
        //
        // 3. Otherwise → no anchor (`None`) — verify internal
        // consistency only, surface issuer pubkey to operator
        // for OOB spot-check. Useful for first-time setup and
        // development; production deployments should set
        // `trusted_bundle_issuer_pubkey` explicitly.
        let signed = bootstrap::decode_signed_bundle(&envelope_bytes).map_err(|e| {
            veil_cfg::ConfigError::ValidationFailed(format!("decode signed bundle: {e}",))
        })?;
        // Fail closed on a broken clock: `unwrap_or(0)` would set `now = 0`, and
        // the bundle-expiry check (`now > issued_at + MAX_BUNDLE_AGE`) would then
        // always be false — silently disabling freshness and accepting an
        // arbitrarily-old (replayed) signed bundle. The runtime HTTPS path already
        // fails closed here; mirror it. (audit M-1.)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| {
                veil_cfg::ConfigError::ValidationFailed(
                    "system clock is before UNIX_EPOCH — refusing to verify \
                     bootstrap-bundle freshness"
                        .to_owned(),
                )
            })?;
        let pinned_issuer = loaded.global.trusted_bundle_issuer_pubkey.as_deref();
        let expected: Option<&str> = if let Some(pinned) = pinned_issuer {
            // Strict pin: reject mismatch BEFORE running the crypto
            // check (saves CPU, but mostly: gives the operator a
            // clearer error message than the underlying
            // `IssuerMismatch` from `verify_signed_bundle`).
            if pinned != signed.issuer_pk {
                return Err(veil_cfg::ConfigError::CommandFailed(format!(
                    "bootstrap fetch: bundle issuer {} does not match \
                     pinned `trusted_bundle_issuer_pubkey` {} — refusing \
                     to merge attacker-controlled peers.  Either update \
                     the pin to the new operator pubkey, or remove \
                     `trusted_bundle_issuer_pubkey` to fall back to \
                     no-anchor mode.",
                    &signed.issuer_pk[..signed.issuer_pk.len().min(16)],
                    &pinned[..pinned.len().min(16)],
                )));
            }
            Some(pinned)
        } else {
            // No pin set → fall back to "self-published" mode if the
            // running node's identity matches the envelope, else
            // accept any internally-consistent signature.
            loaded
                .identity
                .as_ref()
                .filter(|i| i.public_key == signed.issuer_pk)
                .map(|i| i.public_key.as_str())
        };
        // H-2: when `expected` is None (no pin AND the envelope issuer is not
        // this node's own identity), `verify_signed_bundle` only checks internal
        // consistency — ANY attacker keypair passes. Capture that here; we refuse
        // to MERGE such an unauthenticated bundle below unless the operator has
        // explicitly opted into unsigned bootstrap.
        let is_no_anchor = expected.is_none();
        let peers = bootstrap::verify_signed_bundle(&signed, expected, now).map_err(|e| {
            veil_cfg::ConfigError::ValidationFailed(format!("verify signed bundle: {e}",))
        })?;
        let issuer_short: String = signed.issuer_pk.chars().take(16).collect();

        if dry_run {
            context.io.emit(OutputEvent::message(format!(
                "fetched + verified {} bootstrap peer(s) from DHT \
                 (issuer={issuer_short}…, dry-run, not writing to config):\n{}",
                peers.len(),
                peers
                    .iter()
                    .map(|p| format!(
                        "  - {} ({}...)",
                        p.transport,
                        &p.public_key[..p.public_key.len().min(16)]
                    ))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )));
            return Ok(());
        }

        // H-2: refuse to persist unauthenticated peers (no pin, issuer != our
        // identity) unless the operator explicitly opted into unsigned bootstrap
        // — mirrors the runtime BootstrapHttpsPolicy gate (service_tasks.rs).
        // Dry-run already returned above, so inspection still works without the
        // opt-in (an operator can dry-run to read the issuer, then pin it).
        if is_no_anchor && !loaded.global.legacy_allow_unsigned_bootstrap {
            return Err(veil_cfg::ConfigError::CommandFailed(format!(
                "bootstrap fetch: bundle issuer {issuer_short}… is not pinned and \
                 does not match this node's identity — refusing to merge \
                 unauthenticated bootstrap peers. Set `trusted_bundle_issuer_pubkey` \
                 to pin the operator's pubkey, or set \
                 `legacy_allow_unsigned_bootstrap = true` to opt into unsigned \
                 bootstrap (dev/testnet only).",
            )));
        }

        let count = peers.len();
        loaded.bootstrap_peers = peers;
        // Never persist a config that would fail to load: validate the merged
        // result (e.g. malformed peer transports from a crafted bundle) before
        // writing it to disk.
        let report = veil_cfg::validate(&loaded);
        if !report.is_valid() {
            return Err(veil_cfg::ConfigError::ValidationFailed(
                report.format_issues(),
            ));
        }
        context.config().save(&config_path, &loaded)?;
        context.io.emit(OutputEvent::message(format!(
            "merged {count} signed bootstrap peer(s) (issuer={issuer_short}…) into {}",
            config_path.display(),
        )));
        Ok(())
    }
}

fn map_node_err(err: veil_node_runtime::NodeError) -> veil_cfg::ConfigError {
    match err {
        veil_node_runtime::NodeError::Config(e) => e,
        veil_node_runtime::NodeError::Io(e) => veil_cfg::ConfigError::Io(e),
        other => veil_cfg::ConfigError::CommandFailed(other.to_string()),
    }
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length: {}", s.len()));
    }
    // Operate on bytes, not `&str` slices: `&s[i..i + 2]` panics when the
    // index lands inside a multi-byte UTF-8 char (e.g. "€a" is 4 bytes, so the
    // even-length check passes but s[0..2] cuts the 3-byte '€' mid-char).
    s.as_bytes()
        .chunks(2)
        .enumerate()
        .map(|(j, chunk)| {
            let pair = std::str::from_utf8(chunk)
                .map_err(|_| format!("non-ASCII hex at offset {}", j * 2))?;
            u8::from_str_radix(pair, 16)
                .map_err(|e| format!("invalid hex at offset {}: {e}", j * 2))
        })
        .collect()
}

fn normalize_identity_config(
    mut identity: veil_cfg::IdentityConfig,
) -> veil_cfg::Result<veil_cfg::IdentityConfig> {
    identity.node_id = Some(veil_cfg::NodeId::from_public_key(
        identity.algo,
        &identity.public_key,
    )?);
    Ok(identity)
}

fn apply_validation_fixes<O: ConfigOps>(config: &ConfigHandle<'_, O>) -> veil_cfg::Result<usize> {
    let report = config.update_existing(|_path, config| {
        let report = veil_cfg::validate_and_fix(config)?;
        if report.is_valid() {
            Ok(if report.fixed > 0 {
                ConfigMutation::save(report)
            } else {
                ConfigMutation::keep(report)
            })
        } else {
            Err(veil_cfg::ConfigError::ValidationFailed(
                report.format_issues(),
            ))
        }
    })?;

    Ok(report.fixed)
}

fn validate_loaded(io: &mut impl CommandIo, config: &veil_cfg::Config) -> veil_cfg::Result<()> {
    let report = veil_cfg::validate(config);
    // Non-fatal advisories are surfaced regardless of validity so a
    // pre-deploy `config validate` catches risky-but-permitted defaults
    // (e.g. a push relay left with require_wake_hmac = false) before the
    // daemon ever runs — without failing the config.
    if report.has_warnings() {
        io.emit(OutputEvent::message(format!(
            "configuration warnings (non-fatal):\n{}",
            report.format_warnings()
        )));
    }
    if report.is_valid() {
        io.emit(OutputEvent::ValidationPassed);
        Ok(())
    } else {
        Err(veil_cfg::ConfigError::ValidationFailed(
            report.format_issues(),
        ))
    }
}

/// Dot-separated config keys whose value is secret and must not be printed by
/// `config get` without an explicit `--reveal-secrets`.
/// Inline-secret config field names (TOML keys whose VALUE is a secret, not a
/// file path). Used by both the raw-text redactor and the dotted-key gate so a
/// new inline secret only has to be added in one place. `*_file`/`*_path`
/// variants are deliberately excluded (leaking a path is not leaking the key).
const SECRET_FIELD_NAMES: &[&str] = &["private_key", "key_passphrase", "realm_psk"];

fn is_secret_config_key(key: &str) -> bool {
    // Compare the final dotted segment against the inline-secret field set, so
    // both `identity.private_key` and `mesh.realm_psk` are covered.
    let leaf = key.trim().to_ascii_lowercase();
    let leaf = leaf.rsplit('.').next().unwrap_or(leaf.as_str());
    SECRET_FIELD_NAMES.contains(&leaf)
}

/// Redact the value of secret TOML keys in raw config text for `config show`.
/// Matches the [`SECRET_FIELD_NAMES`] assignments (any indentation) and
/// replaces the value, leaving structure/comments intact. `*_file`/`*_path`
/// variants (e.g. `key_passphrase_file`) are NOT redacted — the prefix check
/// requires the next non-space byte to be `=`, so `key_passphrase_file = …`
/// (next byte `_`) is left alone.
/// Redact secret config fields by parsing the config into its typed model and
/// blanking every key whose name is in [`SECRET_FIELD_NAMES`], recursively
/// (audit cycle-8 H3). This replaces a fragile line-prefix heuristic that
/// `config show` used, which leaked secrets written as quoted keys
/// (`"private_key" = …`), dotted keys (`identity.private_key = …`), inline
/// tables (`identity = { private_key = … }`), and — entirely — in JSON configs
/// (`"private_key": …`, which the TOML `key =` heuristic never matched).
///
/// The redacted output is re-serialized from the parsed model, so comments and
/// original formatting are not preserved (use `--reveal-secrets` to see the raw
/// file). Falls back to the line heuristic only if the content fails to parse.
fn redact_secrets_structured(content: &str) -> String {
    const REDACTED: &str = "<redacted — rerun with --reveal-secrets>";
    // A JSON config is the only one that starts with '{'; TOML starts with a
    // key or `[section]`.
    if content.trim_start().starts_with('{') {
        return match serde_json::from_str::<serde_json::Value>(content) {
            Ok(mut v) => {
                redact_json_value(&mut v, REDACTED);
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| redact_secret_lines(content))
            }
            Err(_) => redact_secret_lines(content),
        };
    }
    match toml::from_str::<toml::Table>(content) {
        Ok(mut table) => {
            redact_toml_table(&mut table, REDACTED);
            toml::to_string_pretty(&table).unwrap_or_else(|_| redact_secret_lines(content))
        }
        Err(_) => redact_secret_lines(content),
    }
}

/// Recursively blank secret keys in a parsed TOML table. The `toml` crate models
/// both `[section]` tables and inline `{ … }` tables as `Value::Table`, so a
/// single recursion covers both (and dotted keys, which parse to nested tables).
fn redact_toml_table(table: &mut toml::Table, redacted: &str) {
    for (key, val) in table.iter_mut() {
        if SECRET_FIELD_NAMES.contains(&key.as_str()) {
            *val = toml::Value::String(redacted.to_string());
            continue;
        }
        match val {
            toml::Value::Table(t) => redact_toml_table(t, redacted),
            toml::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    if let toml::Value::Table(t) = item {
                        redact_toml_table(t, redacted);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Recursively blank secret keys in a parsed JSON value.
fn redact_json_value(v: &mut serde_json::Value, redacted: &str) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if SECRET_FIELD_NAMES.contains(&k.as_str()) {
                    *val = serde_json::Value::String(redacted.to_string());
                } else {
                    redact_json_value(val, redacted);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_value(item, redacted);
            }
        }
        _ => {}
    }
}

fn redact_secret_lines(content: &str) -> String {
    const REDACTED: &str = "\"<redacted — rerun with --reveal-secrets>\"";
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim_start();
        let is_secret = SECRET_FIELD_NAMES.iter().any(|k| {
            trimmed
                .strip_prefix(k)
                .map(|rest| matches!(rest.trim_start().as_bytes().first(), Some(b'=')))
                .unwrap_or(false)
        });
        if is_secret {
            let indent_len = line.len() - trimmed.len();
            let key = trimmed.split('=').next().unwrap_or(trimmed).trim_end();
            out.push_str(&line[..indent_len]);
            out.push_str(key);
            out.push_str(" = ");
            out.push_str(REDACTED);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn set_existing_value<O: ConfigOps>(
    config: &ConfigHandle<'_, O>,
    key: &str,
    value: &str,
) -> veil_cfg::Result<PathBuf> {
    config.update_existing(|path, config| {
        veil_cfg::set(config, key, value)?;
        Ok(ConfigMutation::save(path.to_path_buf()))
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::cmd::{
        adapters::StdConfigOps,
        test_support::{BufferIo, MockConfigOps},
    };
    use veil_cfg::SignatureAlgorithm;

    #[test]
    fn parse_hex_bytes_rejects_non_ascii_without_panic() {
        // "€a" is 4 bytes ('€' = 3 + 'a' = 1), so the even-length gate passes;
        // the old `&s[0..2]` cut the 3-byte char mid-boundary and panicked.
        assert!(parse_hex_bytes("€a").is_err());
        // Odd byte length still rejected cleanly.
        assert!(parse_hex_bytes("abc").is_err());
        // Happy path unaffected.
        assert_eq!(parse_hex_bytes("0a0b0c").unwrap(), vec![0x0a, 0x0b, 0x0c]);
    }

    #[test]
    fn command_io_collects_validate_output() {
        let mut io = BufferIo::default();
        let config = veil_cfg::Config::default();

        validate_loaded(&mut io, &config).unwrap();

        assert_eq!(io.output, "config is valid\n");
    }

    #[test]
    fn show_uses_abstract_io_and_config_ops() {
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops: MockConfigOps {
                locate_path: std::path::PathBuf::from("/tmp/config.toml"),
                raw_config: "[global]\nruntime_flavor = \"multi_thread\"\n".to_owned(),
                ..MockConfigOps::default()
            },
        };

        ConfigCommandService::show(&mut context, false).unwrap();

        assert_eq!(
            context.io.output,
            "[global]\nruntime_flavor = \"multi_thread\"\n"
        );
    }

    #[test]
    fn show_redacts_private_key_by_default() {
        let raw = "[identity]\nalgo = \"ed25519\"\nprivate_key = \"SUPERSECRET\"\nkey_passphrase_file = \"/etc/veil/pass\"\n";
        let redacted = redact_secret_lines(raw);
        assert!(
            !redacted.contains("SUPERSECRET"),
            "private_key value must be redacted: {redacted}"
        );
        assert!(redacted.contains("private_key = \"<redacted"));
        // non-secret keys (and the *_file path, which is not the secret) survive.
        assert!(redacted.contains("algo = \"ed25519\""));
        assert!(redacted.contains("key_passphrase_file = \"/etc/veil/pass\""));
    }

    /// audit cycle-8 H3: the structured redactor must catch the spellings the
    /// old line heuristic leaked — dotted keys, quoted keys, inline tables, and
    /// JSON configs entirely.
    #[test]
    fn redact_structured_covers_dotted_quoted_inline_json_h3() {
        // dotted key
        let r = redact_secrets_structured("identity.private_key = \"SECRETD\"\n");
        assert!(!r.contains("SECRETD"), "dotted-key secret leaked: {r}");

        // quoted key
        let r = redact_secrets_structured("[identity]\n\"private_key\" = \"SECRETQ\"\n");
        assert!(!r.contains("SECRETQ"), "quoted-key secret leaked: {r}");

        // inline table
        let r = redact_secrets_structured(
            "identity = { algo = \"ed25519\", private_key = \"SECRETI\" }\n",
        );
        assert!(!r.contains("SECRETI"), "inline-table secret leaked: {r}");

        // JSON config (the old TOML `key =` heuristic never matched these)
        let r = redact_secrets_structured(
            "{\"identity\":{\"private_key\":\"SECRETJ\",\"algo\":\"ed25519\"},\
             \"mesh\":{\"realm_psk\":\"SECRETP\"}}",
        );
        assert!(!r.contains("SECRETJ"), "JSON private_key leaked: {r}");
        assert!(!r.contains("SECRETP"), "JSON realm_psk leaked: {r}");

        // Non-secret values survive and the redaction marker is present.
        assert!(r.contains("ed25519"));
        assert!(r.contains("redacted"));
    }

    #[test]
    fn get_secret_key_refused_without_flag() {
        assert!(is_secret_config_key("identity.private_key"));
        assert!(is_secret_config_key("identity.key_passphrase"));
        assert!(is_secret_config_key("mesh.realm_psk"));
        assert!(!is_secret_config_key("identity.algo"));
        assert!(!is_secret_config_key("identity.key_passphrase_file"));
    }

    #[test]
    fn show_redacts_realm_psk_inline_secret() {
        let raw = "[mesh]\nenabled = true\nrealm_psk = \"BASE64SECRETPSK\"\n";
        let redacted = redact_secret_lines(raw);
        assert!(
            !redacted.contains("BASE64SECRETPSK"),
            "realm_psk must be redacted: {redacted}"
        );
        assert!(redacted.contains("realm_psk = \"<redacted"));
        assert!(redacted.contains("enabled = true"));
    }

    #[test]
    fn init_config_with_identity_does_not_create_file_when_generation_fails() {
        let io = BufferIo::default();
        let ops = StdConfigOps;
        let root = unique_temp_dir("veil-init-fail");
        let path = root.join("config.toml");

        let mut context = CommandContext {
            config_arg: None,
            io,
            ops,
        };

        let err = ConfigCommandService::init_config_with_identity_using(
            &mut context,
            Some(path.clone()),
            7,
            false,
            crate::cmd::cli::ConfigProfile::Dev,
            |_context, _difficulty| Err(veil_cfg::ConfigError::PowWorkerDisconnected),
        )
        .expect_err("generation must fail");

        assert!(matches!(err, veil_cfg::ConfigError::PowWorkerDisconnected));
        assert!(!path.exists(), "config file must not be created on failure");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn init_config_with_identity_saves_generated_identity_once_ready() {
        let io = BufferIo::default();
        let ops = StdConfigOps;
        let root = unique_temp_dir("veil-init-success");
        let path = root.join("config.toml");
        let keypair = crate::test_support::ed25519_keypair();

        let mut context = CommandContext {
            config_arg: None,
            io,
            ops,
        };

        let saved_path = ConfigCommandService::init_config_with_identity_using(
            &mut context,
            Some(path.clone()),
            7,
            false,
            crate::cmd::cli::ConfigProfile::Dev,
            |_context, difficulty| {
                assert_eq!(difficulty, 7);
                Ok(veil_cfg::IdentityConfig {
                    algo: SignatureAlgorithm::Ed25519,
                    role: Default::default(),
                    public_key: keypair.public_key.clone(),
                    private_key: keypair.private_key.clone(),
                    nonce: "AAAAAA==".to_owned(),
                    node_id: None,
                    key_passphrase: None,
                    key_passphrase_file: None,
                    key_passphrase_prompt: false,
                    lazy_mining: true,
                    max_lazy_difficulty: 64,
                })
            },
        )
        .expect("generation must succeed");

        assert_eq!(saved_path, path);
        assert!(path.exists(), "config file must be written on success");

        let loaded = veil_cfg::load_config(&path).expect("config must be readable");
        let identity = loaded.identity.expect("identity must be saved");
        assert_eq!(identity.algo, SignatureAlgorithm::Ed25519);
        assert_eq!(identity.public_key, keypair.public_key);
        assert_eq!(identity.private_key, keypair.private_key);
        assert_eq!(identity.nonce, "AAAAAA==");
        assert_eq!(
            identity.node_id,
            Some(
                veil_cfg::NodeId::from_public_key(
                    SignatureAlgorithm::Ed25519,
                    &identity.public_key
                )
                .unwrap()
            )
        );
        #[cfg(unix)]
        assert_eq!(
            loaded.global.admin_socket,
            Some(format!("unix://{}", path.with_extension("sock").display()))
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn init_config_assigns_default_admin_socket_next_to_config() {
        let io = BufferIo::default();
        let ops = StdConfigOps;
        let root = unique_temp_dir("veil-init-admin-socket");
        let path = root.join("custom.toml");
        let keypair = crate::test_support::ed25519_keypair();

        let mut context = CommandContext {
            config_arg: None,
            io,
            ops,
        };

        let saved_path = ConfigCommandService::init_config_with_identity_using(
            &mut context,
            Some(path.clone()),
            7,
            false,
            crate::cmd::cli::ConfigProfile::Dev,
            |_context, _difficulty| {
                Ok(veil_cfg::IdentityConfig {
                    algo: SignatureAlgorithm::Ed25519,
                    role: Default::default(),
                    public_key: keypair.public_key.clone(),
                    private_key: keypair.private_key.clone(),
                    nonce: "AAAAAA==".to_owned(),
                    node_id: None,
                    key_passphrase: None,
                    key_passphrase_file: None,
                    key_passphrase_prompt: false,
                    lazy_mining: true,
                    max_lazy_difficulty: 64,
                })
            },
        )
        .expect("generation must succeed");

        assert_eq!(saved_path, path);
        let loaded = veil_cfg::load_config(&saved_path).expect("config must load");
        #[cfg(unix)]
        assert_eq!(
            loaded.global.admin_socket,
            Some(format!(
                "unix://{}",
                saved_path.with_extension("sock").display()
            ))
        );
        #[cfg(not(unix))]
        assert!(
            loaded
                .global
                .admin_socket
                .as_deref()
                .is_some_and(|s| s.starts_with("tcp://127.0.0.1")),
            "non-unix init must default to TCP loopback admin socket, got {:?}",
            loaded.global.admin_socket,
        );

        let _ = fs::remove_dir_all(&root);
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}-{unique}"))
    }

    /// `--profile dev` is a no-op on top of `Config::default` —
    /// the generated config must equal a default-constructed one (modulo
    /// the identity that the caller injects separately).
    #[test]
    fn epic480_5_dev_profile_leaves_defaults_intact() {
        let mut config = veil_cfg::Config::default();
        let baseline = config.clone();
        super::apply_profile_defaults(&mut config, crate::cmd::cli::ConfigProfile::Dev);
        assert_eq!(
            config, baseline,
            "dev profile must not change anything from Config::default()"
        );
    }

    /// `--profile censorship-target` must stamp:
    /// a `wss://0.0.0.0:443` listen entry
    /// `transport.default_sni = Some("www.cloudflare.com")`
    /// mesh enabled with `autodiscover_gateway = true`.
    #[test]
    fn epic480_5_censorship_target_profile_sets_anti_dpi_defaults() {
        let mut config = veil_cfg::Config::default();
        super::apply_profile_defaults(
            &mut config,
            crate::cmd::cli::ConfigProfile::CensorshipTarget,
        );

        // Listen on wss://0.0.0.0:443
        assert_eq!(config.listen.len(), 1, "expected exactly one listen entry");
        let listen = &config.listen[0];
        assert_eq!(listen.transport, "wss://0.0.0.0:443");
        assert!(
            listen.tls_cert.is_some(),
            "TLS cert path placeholder must be present"
        );
        assert!(
            listen.tls_key.is_some(),
            "TLS key path placeholder must be present"
        );

        // Default SNI for outbound TLS handshakes
        assert_eq!(
            config.transport.default_sni.as_deref(),
            Some("www.cloudflare.com")
        );

        // Mesh enabled with autodiscover
        let mesh = config.mesh.as_ref().expect("mesh must be configured");
        assert!(
            mesh.autodiscover_gateway,
            "leaves can't auto-find this gateway without autodiscover_gateway = true"
        );
    }

    /// 483.5 + 481.5 + 478 + 487.3: `--profile mobile`
    /// must stamp every knob a battery-powered leaf node needs to
    /// be a good citizen out of the box.
    #[test]
    fn epic480_5_mobile_profile_sets_battery_mesh_and_cache_defaults() {
        let mut config = veil_cfg::Config::default();
        super::apply_profile_defaults(&mut config, crate::cmd::cli::ConfigProfile::Mobile);

        // Battery throttle engaged at 30%.
        assert_eq!(
            config.mobile.low_battery_threshold_pct,
            Some(30),
            "mobile profile must enable battery-aware throttling"
        );
        assert_eq!(
            config.mobile.low_battery_multiplier, 4,
            "mobile profile must set the canonical 4x multiplier"
        );
        // background-mode preserves sessions through
        // OS suspension. 60× = 30s base → 30 min — survives most
        // background suspensions, well under default idle_timeout.
        assert_eq!(
            config.mobile.background_keepalive_multiplier, 60,
            "mobile profile must set 60× background keepalive multiplier"
        );

        // Mesh autodiscover for leaf-on-NAT.
        let mesh = config
            .mesh
            .as_ref()
            .expect("mobile profile must configure mesh for NAT-traversal");
        assert!(
            mesh.autodiscover_gateway,
            "mobile profile must enable autodiscover_gateway"
        );

        // Discovered-peer cache path set so handshake-confirmed peers
        // survive the OS killing the app.
        assert!(
            config.global.discovered_peers_cache_path.is_some(),
            "mobile profile must persist discovered-peer cache across restarts"
        );

        // Mobile profile leaves listen + identity to the operator —
        // a pure leaf typically has no [[listen]] entry.
        assert!(
            config.listen.is_empty(),
            "mobile leaf should have no [[listen]] entry by default"
        );

        // session cap MUST be lowered for budget devices.
        // 64 sessions × ~50-100 KB ≈ 3-6 MB ceiling, fits 1-2 GB RAM
        // phones comfortably. Default would have been 512 (desktop).
        assert_eq!(
            config.session.max_concurrent, 64,
            "mobile profile MUST cap max_concurrent at 64 for budget-phone RAM"
        );

        // DHT store memory capped tighter than the Core ~400 MB default:
        // 128 MB byte cap + ~8k-entry cap (8k × 16 KiB = 128 MB worst case).
        assert_eq!(
            config.dht.max_store_bytes,
            Some(128_000_000),
            "mobile profile MUST cap DHT store at ~128 MB"
        );
        assert_eq!(
            config.dht.max_store_entries, 8_000,
            "mobile profile MUST lower the DHT entry cap to match the 128 MB byte cap"
        );
    }

    /// default `max_concurrent` is 1000 (raised from 512 alongside the
    /// capacity-referral work, which added a hard ceiling of
    /// `max_concurrent + referral_headroom`). Was 65,536 in pre-builds —
    /// lowered as a breaking change for "no working network yet"
    /// deployment. Mobile profile lowers further to 64.
    #[test]
    fn epic487_3_default_max_concurrent_is_budget_friendly() {
        let config = veil_cfg::Config::default();
        assert_eq!(
            config.session.max_concurrent, 1000,
            "default max_concurrent must be 1000 — budget desktops fit, \
             dedicated relays raise via config"
        );
    }

    /// every profile must compose with the `Dev` baseline
    /// such that running `Dev` immediately after profile-X is a no-op
    /// (i.e. profile-X doesn't accidentally mutate fields that `Dev`
    /// would expect to be at default). Sanity check that catches
    /// future profile-stamping bugs that flip global state.
    ///
    /// Updated for : mobile profile now LEGITIMATELY tweaks
    /// `[session].max_concurrent` for budget-RAM ceilings.
    /// Updated for : mobile profile now LEGITIMATELY tweaks
    /// `[capacity]` bandwidth caps for cellular budget users +
    /// `[update].check_interval_secs` for cellular-friendly poll
    /// cadence. Those fields are excluded from the "unchanged" check;
    /// every OTHER field in those sections must still match baseline.
    #[test]
    fn epic480_5_mobile_profile_does_not_touch_unrelated_sections() {
        let baseline = veil_cfg::Config::default();
        let mut config = veil_cfg::Config::default();
        super::apply_profile_defaults(&mut config, crate::cmd::cli::ConfigProfile::Mobile);

        // Sections the mobile profile MUST leave alone entirely.
        assert_eq!(
            config.transport, baseline.transport,
            "mobile must not touch [transport]"
        );
        assert_eq!(
            config.routing, baseline.routing,
            "mobile must not touch [routing]"
        );
        // [dht]: mobile lowers ONLY the two memory caps (128 MB / 8k entries)
        // vs the Core default; other dht knobs must match baseline.
        assert_eq!(config.dht.max_store_bytes, Some(128_000_000));
        assert_eq!(config.dht.max_store_entries, 8_000);
        assert_eq!(
            config.dht.republish_interval_secs, baseline.dht.republish_interval_secs,
            "mobile must not touch unrelated [dht] knobs"
        );
        assert_eq!(config.dht.participate, baseline.dht.participate);
        assert_eq!(
            config.dht.per_origin_max_bytes,
            baseline.dht.per_origin_max_bytes
        );
        assert_eq!(
            config.bootstrap_peers, baseline.bootstrap_peers,
            "mobile must not touch [[bootstrap_peers]]"
        );

        // Session: only `max_concurrent` and
        // `max_age_secs` may differ. Every OTHER
        // [session] knob must match baseline — keepalive, idle
        // timeout, queue depths, rekey thresholds etc.
        let mut session_baseline_with_mobile_tweaks = baseline.session.clone();
        session_baseline_with_mobile_tweaks.max_concurrent = 64;
        session_baseline_with_mobile_tweaks.max_age_secs = Some(1_800);
        assert_eq!(
            config.session, session_baseline_with_mobile_tweaks,
            "mobile profile may ONLY tweak session.max_concurrent and \
             session.max_age_secs; every other [session] knob must match baseline"
        );

        // Capacity: only the two bandwidth caps may differ
        //. Every other [capacity] knob (load shedding
        // thresholds, hysteresis, congestion watermarks) must match
        // baseline — those are correctness-sensitive and mobile
        // shouldn't silently retune them.
        let mut capacity_baseline_with_cellular_caps = baseline.capacity.clone();
        capacity_baseline_with_cellular_caps.max_inbound_bandwidth_kbps = 2_000;
        capacity_baseline_with_cellular_caps.max_outbound_bandwidth_kbps = 500;
        assert_eq!(
            config.capacity, capacity_baseline_with_cellular_caps,
            "mobile profile may ONLY tweak capacity.max_*_bandwidth_kbps; \
             every other [capacity] knob must match baseline"
        );

        // Update: only check_interval_secs may differ.
        // Manifest URLs + issuer pk MUST stay None — auto-poll is
        // a no-op without them; mobile profile cannot inject an
        // update endpoint that the operator didn't configure.
        let mut update_baseline_with_cellular_cadence = baseline.update.clone();
        update_baseline_with_cellular_cadence.check_interval_secs = Some(86_400);
        assert_eq!(
            config.update, update_baseline_with_cellular_cadence,
            "mobile profile may ONLY tweak update.check_interval_secs; \
             every other [update] knob must match baseline (no surreptitious endpoint injection)"
        );
    }

    /// regression — verify the actual cellular-friendly
    /// values are what we expect (in case future edits drift them
    /// without the regression test catching it via the
    /// "unchanged sections" check above).
    #[test]
    fn epic483_6_mobile_profile_caps_bandwidth_for_cellular_quota() {
        let mut config = veil_cfg::Config::default();
        super::apply_profile_defaults(&mut config, crate::cmd::cli::ConfigProfile::Mobile);
        assert_eq!(
            config.capacity.max_inbound_bandwidth_kbps, 2_000,
            "mobile profile must cap inbound at 2 Mbit/s for cellular quota safety"
        );
        assert_eq!(
            config.capacity.max_outbound_bandwidth_kbps, 500,
            "mobile profile must cap outbound at 500 kbps for cellular quota safety"
        );
        assert_eq!(
            config.update.check_interval_secs,
            Some(86_400),
            "mobile profile must stretch update-check to 24h for cellular bandwidth saving"
        );
    }

    /// mobile profile sets connection-rotation interval
    /// to defeat long-lived-connection DPI fingerprint. Lock in
    /// the 30-min cadence so a future edit doesn't silently drift
    /// and lose the censorship-resistance property.
    #[test]
    fn epic488_1_mobile_profile_sets_session_rotation_interval() {
        let mut config = veil_cfg::Config::default();
        super::apply_profile_defaults(&mut config, crate::cmd::cli::ConfigProfile::Mobile);
        assert_eq!(
            config.session.max_age_secs,
            Some(1_800),
            "mobile profile must rotate sessions every 30 min for DPI evasion"
        );
    }

    /// b: mobile profile sets per-peer byte-rate cap.
    /// Lock in the 64 KB/s value so a future edit doesn't drift
    /// and lose the single-peer-flood defence.
    #[test]
    fn epic483_6b_mobile_profile_sets_per_peer_byte_rate() {
        let mut config = veil_cfg::Config::default();
        super::apply_profile_defaults(&mut config, crate::cmd::cli::ConfigProfile::Mobile);
        assert_eq!(
            config.abuse.per_peer_bytes_per_sec,
            Some(65_536),
            "mobile profile must cap per-peer byte rate at 64 KB/s for cellular quota safety"
        );
        // Default burst NOT set explicitly — resolved helper returns 4× rate.
        assert_eq!(
            config.abuse.per_peer_byte_burst, None,
            "mobile profile leaves burst at default (resolved = 4× rate)"
        );
        assert_eq!(
            config.abuse.resolved_per_peer_byte_burst(),
            Some(4 * 65_536),
            "default-resolved burst = 4× rate (4-second burst window)"
        );
    }

    // ── ConfigCommand::Sign (Phase 11 slice 11b) ────────────────────────

    /// `config sign --stdout` produces signed output that verifies under
    /// the same keypair and against the canonical-message rules from
    /// slice 11a.  Uses MockConfigOps so the test runs without disk I/O.
    #[test]
    fn epic11b_config_sign_stdout_produces_verifiable_envelope() {
        let keypair = crate::test_support::ed25519_keypair();
        // Minimal config with identity + a representative `[global]` field
        // so the canonical TOML body is non-empty.
        let raw_config = format!(
            "[global]\nruntime_flavor = \"multi_thread\"\n\n\
             [identity]\nalgo = \"ed25519\"\n\
             public_key = \"{}\"\nprivate_key = \"{}\"\n\
             nonce = \"AAAAAA==\"\n",
            keypair.public_key, keypair.private_key,
        );
        let loaded = veil_cfg::Config {
            identity: Some(veil_cfg::IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key.clone(),
                private_key: keypair.private_key.clone(),
                nonce: "AAAAAA==".to_owned(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: false,
                max_lazy_difficulty: 0,
            }),
            ..veil_cfg::Config::default()
        };

        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops: MockConfigOps {
                locate_path: std::path::PathBuf::from("/tmp/config.toml"),
                raw_config,
                loaded_config: loaded,
            },
        };

        ConfigCommandService::sign(&mut context, Some(1_700_000_000), /* stdout */ true)
            .expect("sign must succeed on a well-formed config");

        let signed = context.io.output.clone();
        assert!(
            signed.starts_with("# VEIL_CONFIG_SIGNATURE_V1: "),
            "stdout output must begin with the signature header; got: {}",
            &signed[..signed.len().min(80)],
        );
        let verified =
            veil_cfg::signed_config::verify_signed_config(&signed, Some(&keypair.public_key))
                .expect("re-verify roundtrip");
        assert_eq!(verified.issued_at_unix, 1_700_000_000);
        assert!(
            verified
                .unsigned_toml
                .contains("runtime_flavor = \"multi_thread\"")
        );
    }

    /// Missing `[identity]` block surfaces a structured error before
    /// any write happens — protects operators against accidentally
    /// trashing an unsigned-by-design config.
    #[test]
    fn epic11b_config_sign_refuses_when_identity_missing() {
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops: MockConfigOps {
                locate_path: std::path::PathBuf::from("/tmp/config.toml"),
                raw_config: "[global]\nruntime_flavor = \"multi_thread\"\n".to_owned(),
                loaded_config: veil_cfg::Config::default(), // no identity
            },
        };
        let err = ConfigCommandService::sign(&mut context, None, true).expect_err("must fail-fast");
        let msg = format!("{err}");
        assert!(
            msg.contains("config.identity is empty") || msg.contains("identity create"),
            "error must direct operator to `identity create`; got: {msg}",
        );
    }
}
