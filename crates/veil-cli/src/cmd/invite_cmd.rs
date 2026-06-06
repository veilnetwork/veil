//! CLI handler for `veil-cli invite …` — Phase 5d.
//!
//! Generates / consumes [`veil_invite::InviteBundleV1`] for trusted /
//! hidden listeners that are not advertised on PEX or DHT.  The bundle
//! is a bearer credential — anyone holding a valid bundle can complete
//! the obfs4-PSK handshake against the embedded transport URI.  It differs
//! from `bootstrap invite` (which just hands off a public listener) in that
//! an invite bundle carries the actual PSK bytes; bootstrap invites carry
//! only a transport URI and identity public key.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use veil_invite::{InviteBundleV1, create_bundle};

use veil_cfg::{self, BootstrapPeer, ListenId, SignatureAlgorithm, Visibility};

use super::{
    cli::{InviteArgs, InviteCommand},
    handlers::{CommandContext, ConfigOps},
    output::{CommandIo, OutputEvent},
};

pub fn handle_invite_command<I: CommandIo, O: ConfigOps>(
    mut context: CommandContext<'_, I, O>,
    args: InviteArgs,
) -> veil_cfg::Result<()> {
    match args.command {
        InviteCommand::Create {
            listener_id,
            validity_secs,
            label,
            output,
            qr,
        } => create_invite(&mut context, listener_id, validity_secs, label, output, qr),
        InviteCommand::Accept {
            input,
            psk_out,
            no_update_config,
        } => accept_invite(&mut context, &input, psk_out, no_update_config),
        InviteCommand::Decode { input } => decode_invite(&mut context, &input),
    }
}

// Loose sanity ceiling — `veil-invite` does not enforce а max
// validity itself; we cap at 1 year here so operators can't accidentally
// emit а bundle that survives а multi-year rotation cadence.
const MAX_VALIDITY_SECS: u64 = 365 * 24 * 3600;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn create_invite<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    listener_id: ListenId,
    validity_secs: u64,
    label: Option<String>,
    output: Option<PathBuf>,
    qr: bool,
) -> veil_cfg::Result<()> {
    if validity_secs == 0 || validity_secs > MAX_VALIDITY_SECS {
        return Err(veil_cfg::ConfigError::ValidationFailed(format!(
            "validity_secs must be 1..={MAX_VALIDITY_SECS}, got {validity_secs}",
        )));
    }

    let (config_path, config) = context.config().load_existing()?;

    let identity = config.identity.as_ref().ok_or_else(|| {
        veil_cfg::ConfigError::CommandFailed(
            "config has no `[identity]` — run `veil-cli identity standalone` first".into(),
        )
    })?;
    if !matches!(identity.algo, SignatureAlgorithm::Ed25519) {
        return Err(veil_cfg::ConfigError::ValidationFailed(format!(
            "invite create requires an Ed25519 identity (veil-invite signs with \
             ed25519-dalek); current identity uses {:?}",
            identity.algo,
        )));
    }
    let signing_key = signing_key_from_b64(&identity.private_key)?;

    let listen = config
        .listen
        .iter()
        .find(|l| l.id == listener_id)
        .ok_or_else(|| {
            veil_cfg::ConfigError::ValidationFailed(format!(
                "unknown listen_id `{listener_id}` — check `veil-cli listen list`",
            ))
        })?;

    if matches!(listen.visibility, Visibility::Public) {
        return Err(veil_cfg::ConfigError::ValidationFailed(format!(
            "listener {listener_id} has visibility=public — public listeners are advertised \
             via PEX/DHT, so an invite bundle would just leak а redundant PSK. \
             Mark the listener `visibility = \"trusted\"` or `\"hidden\"` first.",
        )));
    }

    let psk_path = listen.psk_file.clone().ok_or_else(|| {
        veil_cfg::ConfigError::ValidationFailed(format!(
            "listener {listener_id} has no `psk_file` — invite bundles must embed а PSK; \
             configure `psk_file = \"…\"` or fall back к а deployment-wide \
             `transport.obfs4_psk_file` AND set it explicitly on the listener.",
        ))
    })?;
    let psk = read_psk_file(&resolve_relative(&config_path, &psk_path))?;

    let transport_uri = listen
        .advertise
        .clone()
        .unwrap_or_else(|| listen.transport.clone());

    let exp = now_unix().saturating_add(validity_secs);
    let bundle = create_bundle(&signing_key, transport_uri.clone(), psk, exp, label.clone())
        .map_err(|e| {
            veil_cfg::ConfigError::ValidationFailed(format!("invite bundle build failed: {e}"))
        })?;
    let text = bundle
        .to_base32()
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("base32 encode: {e}")))?;

    let qr_block = if qr {
        let q = bundle
            .to_qr_ansi()
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("qr render: {e}")))?;
        format!("\n{q}")
    } else {
        String::new()
    };

    if let Some(file) = output {
        write_file_0o600(&file, text.as_bytes())?;
        context.io.emit(OutputEvent::message(format!(
            "wrote invite bundle к {} ({} bytes base32 | nid={} | exp_unix={}){}",
            file.display(),
            text.len(),
            short_hex(&bundle.nid),
            bundle.exp,
            qr_block,
        )));
    } else {
        context.io.emit(OutputEvent::message(format!(
            "{text}\n# nid={} exp_unix={} validity_secs={}{}",
            short_hex(&bundle.nid),
            bundle.exp,
            validity_secs,
            qr_block,
        )));
    }
    Ok(())
}

fn accept_invite<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    input: &Path,
    psk_out: Option<PathBuf>,
    no_update_config: bool,
) -> veil_cfg::Result<()> {
    let raw = read_input(input)?;
    let bundle = InviteBundleV1::from_base32(&raw).map_err(|e| {
        veil_cfg::ConfigError::ValidationFailed(format!("decode invite bundle: {e}"))
    })?;
    bundle.verify(now_unix()).map_err(|e| {
        veil_cfg::ConfigError::ValidationFailed(format!("verify invite bundle: {e}"))
    })?;

    // Drop PSK before mutating config so the operator can't be left
    // в а half-installed state (PSK missing but bootstrap_peers
    // appended).  Filesystem write first, config edit second.
    let (config_path, mut config) = context.config().load_existing()?;
    let psk_path = match psk_out {
        Some(p) => p,
        None => default_psk_path(&config_path, &bundle.nid),
    };
    if let Some(parent) = psk_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            veil_cfg::ConfigError::CommandFailed(format!(
                "create psk dir {}: {e}",
                parent.display()
            ))
        })?;
    }
    let psk_b64 = STANDARD.encode(&bundle.psk);
    write_file_0o600(&psk_path, psk_b64.as_bytes())?;

    let inviter_pk_b64 = STANDARD.encode(&bundle.vk);
    let mut config_msg = format!("psk saved → {}\n", psk_path.display());

    if !no_update_config {
        let already_present = config
            .bootstrap_peers
            .iter()
            .any(|p| p.public_key == inviter_pk_b64);
        if already_present {
            config_msg.push_str("bootstrap_peers already contains this inviter — no-op\n");
        } else {
            config.bootstrap_peers.push(BootstrapPeer {
                transport: bundle.tr.clone(),
                public_key: inviter_pk_b64.clone(),
                nonce: veil_cfg::default_nonce_base64(),
                algo: SignatureAlgorithm::Ed25519,
                tls_cert: None,
                tls_ca_cert: None,
            });
            context.config().save(&config_path, &config)?;
            config_msg.push_str(&format!(
                "added bootstrap_peer pk={}… transport={} → {}\n",
                &inviter_pk_b64[..inviter_pk_b64.len().min(12)],
                bundle.tr,
                config_path.display(),
            ));
        }
    } else {
        config_msg.push_str("--no-update-config: config left untouched\n");
    }

    context.io.emit(OutputEvent::message(format!(
        "invite verified (nid={}, exp_unix={}, label={}):\n{config_msg}",
        short_hex(&bundle.nid),
        bundle.exp,
        bundle.lbl.as_deref().unwrap_or("(none)"),
    )));
    Ok(())
}

fn decode_invite<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    input: &Path,
) -> veil_cfg::Result<()> {
    let raw = read_input(input)?;
    let bundle = InviteBundleV1::from_base32(&raw).map_err(|e| {
        veil_cfg::ConfigError::ValidationFailed(format!("decode invite bundle: {e}"))
    })?;
    // `verify` checks sig + identity binding + expiry.  Decode is а
    // diagnostic so we still call it (а bundle that fails verify isn't
    // worth printing) but report expiry separately for clarity.
    let verified = bundle.verify(now_unix());
    let verify_status = match &verified {
        Ok(()) => "ok".to_owned(),
        Err(e) => format!("FAILED: {e}"),
    };
    context.io.emit(OutputEvent::message(format!(
        "v:              {}\nnid:            {}\nvk:             {}\ntr:             {}\npsk:            {} bytes (redacted)\nexp_unix:       {}\nlabel:          {}\nverification:   {}",
        bundle.v,
        short_hex(&bundle.nid),
        short_hex(&bundle.vk),
        bundle.tr,
        bundle.psk.len(),
        bundle.exp,
        bundle.lbl.as_deref().unwrap_or("(none)"),
        verify_status,
    )));
    Ok(())
}

// ── helpers ─────────────────────────────────────────────────────────

fn signing_key_from_b64(b64: &str) -> veil_cfg::Result<SigningKey> {
    let raw = STANDARD
        .decode(b64.trim())
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("identity sk base64: {e}")))?;
    if raw.len() != 32 {
        return Err(veil_cfg::ConfigError::ValidationFailed(format!(
            "identity sk: expected 32 raw bytes after base64-decode, got {}",
            raw.len(),
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw);
    Ok(SigningKey::from_bytes(&seed))
}

fn read_psk_file(path: &Path) -> veil_cfg::Result<[u8; 32]> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        veil_cfg::ConfigError::CommandFailed(format!("read psk file {}: {e}", path.display()))
    })?;
    let bytes = STANDARD.decode(raw.trim()).map_err(|e| {
        veil_cfg::ConfigError::ValidationFailed(format!(
            "psk file {} not base64: {e}",
            path.display()
        ))
    })?;
    if bytes.len() != 32 {
        return Err(veil_cfg::ConfigError::ValidationFailed(format!(
            "psk file {} decoded к {} bytes, expected 32",
            path.display(),
            bytes.len(),
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_relative(config_path: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else if let Some(parent) = config_path.parent() {
        parent.join(p)
    } else {
        p.to_path_buf()
    }
}

fn default_psk_path(config_path: &Path, nid: &[u8]) -> PathBuf {
    let base = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let hex = nid.iter().map(|b| format!("{b:02x}")).collect::<String>();
    base.join("invite_psks").join(format!("{hex}.psk"))
}

fn read_input(input: &Path) -> veil_cfg::Result<String> {
    if input == Path::new("-") {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| veil_cfg::ConfigError::CommandFailed(format!("read stdin: {e}")))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(input).map_err(|e| {
            veil_cfg::ConfigError::CommandFailed(format!("read {}: {e}", input.display()))
        })
    }
}

fn write_file_0o600(path: &Path, content: &[u8]) -> veil_cfg::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            veil_cfg::ConfigError::CommandFailed(format!(
                "create parent dir {}: {e}",
                parent.display()
            ))
        })?;
    }
    // Atomic, owner-only write: `atomic_write` creates the file 0600 at
    // creation time (O_NOFOLLOW + random temp file + fsync + rename), so the
    // PSK bearer secret is never momentarily world-readable. The previous
    // `fs::write` (created at umask, typically 0644) followed by a separate
    // `chmod` left both a readable window and a 0644 file if the process died
    // between the two calls.
    veil_util::atomic_write(path, content)
        .map_err(|e| veil_cfg::ConfigError::CommandFailed(format!("write {}: {e}", path.display())))
}

fn short_hex(bytes: &[u8]) -> String {
    let take = bytes.len().min(8);
    let mut s = String::with_capacity(take * 2 + 2);
    for b in &bytes[..take] {
        s.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > take {
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn signing_key_round_trip_matches_generation_format() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let b64 = STANDARD.encode(sk.to_bytes());
        let recovered = signing_key_from_b64(&b64).unwrap();
        assert_eq!(recovered.to_bytes(), sk.to_bytes());
    }

    #[test]
    fn signing_key_rejects_wrong_length() {
        let too_short = STANDARD.encode([0u8; 16]);
        let err = signing_key_from_b64(&too_short).unwrap_err();
        assert!(err.to_string().contains("expected 32"));
    }

    #[test]
    fn signing_key_rejects_bad_base64() {
        let err = signing_key_from_b64("not!base64$").unwrap_err();
        assert!(err.to_string().contains("base64"));
    }

    #[test]
    fn default_psk_path_uses_config_parent_and_hex_nid() {
        let config = Path::new("/etc/veil/node.toml");
        let nid = [0xab; 32];
        let p = default_psk_path(config, &nid);
        assert_eq!(
            p,
            PathBuf::from(
                "/etc/veil/invite_psks/abababababababababababababababababababababababababababababababab.psk"
            )
        );
    }

    #[test]
    fn resolve_relative_under_config_parent() {
        let config = Path::new("/etc/veil/node.toml");
        assert_eq!(
            resolve_relative(config, Path::new("secrets/psk")),
            PathBuf::from("/etc/veil/secrets/psk"),
        );
        assert_eq!(
            resolve_relative(config, Path::new("/abs/psk")),
            PathBuf::from("/abs/psk"),
        );
    }

    #[test]
    fn short_hex_truncates_with_ellipsis() {
        let s = short_hex(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
        assert_eq!(s, "0102030405060708…");
        assert_eq!(short_hex(&[0xaa, 0xbb]), "aabb");
    }

    #[test]
    fn read_psk_file_validates_length() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("psk");
        std::fs::write(&p, STANDARD.encode([0x33u8; 16])).unwrap();
        let err = read_psk_file(&p).unwrap_err();
        assert!(err.to_string().contains("expected 32"));
    }

    #[test]
    fn read_psk_file_accepts_valid_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("psk");
        std::fs::write(&p, STANDARD.encode([0x77u8; 32])).unwrap();
        let bytes = read_psk_file(&p).unwrap();
        assert_eq!(bytes, [0x77u8; 32]);
    }

    #[test]
    fn write_file_0o600_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nested/sub/file");
        write_file_0o600(&p, b"hello").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    // ── Phase 5d end-to-end: create → file → accept ────────────────────

    use crate::cmd::handlers::CommandContext;
    use crate::cmd::test_support::BufferIo;
    use std::cell::RefCell;
    use std::rc::Rc;
    use veil_cfg::{Config, IdentityConfig, ListenConfig, ListenId, Visibility};

    /// Stateful in-memory `ConfigOps` — unlike `MockConfigOps`, persists
    /// saves so the create → accept flow can observe `bootstrap_peers`
    /// mutation.
    #[derive(Clone, Debug)]
    struct StatefulConfigOps {
        path: PathBuf,
        state: Rc<RefCell<Config>>,
    }

    impl ConfigOps for StatefulConfigOps {
        fn default_init_path(&self) -> PathBuf {
            self.path.clone()
        }
        fn prepare_init_path(&self, path: &Path, _force: bool) -> veil_cfg::Result<PathBuf> {
            Ok(path.to_path_buf())
        }
        fn locate_config(&self, _config_arg: Option<&Path>) -> veil_cfg::Result<PathBuf> {
            Ok(self.path.clone())
        }
        fn read_raw_config(&self, _path: &Path) -> veil_cfg::Result<String> {
            Ok(String::new())
        }
        fn load_config(&self, _path: &Path) -> veil_cfg::Result<Config> {
            Ok(self.state.borrow().clone())
        }
        fn save_config(&self, _path: &Path, config: &Config) -> veil_cfg::Result<()> {
            *self.state.borrow_mut() = config.clone();
            Ok(())
        }

        fn write_raw_config(&self, _path: &Path, _content: &str) -> veil_cfg::Result<()> {
            // Slice 11b: test stub — fixture acks the
            // raw-write path without persisting к disk.
            Ok(())
        }
    }

    /// End-to-end: an inviter with a configured Trusted listener emits a
    /// bundle to a file; the recipient consumes the bundle and ends up
    /// with (a) the PSK saved at the expected default path, (b) the
    /// inviter appended to bootstrap_peers with the right transport URI and
    /// public_key derived from the bundle's `vk`.
    #[test]
    fn create_accept_round_trip_e2e() {
        use ed25519_dalek::SigningKey;

        // ── inviter setup ───────────────────────────────────────────
        let inviter_dir = tempfile::tempdir().unwrap();
        let inviter_config_path = inviter_dir.path().join("node.toml");
        let inviter_psk_path = inviter_dir.path().join("listener.psk");

        // Write а 32-byte PSK base64-encoded к the psk_file location.
        let psk_bytes = [0x77u8; 32];
        std::fs::write(&inviter_psk_path, STANDARD.encode(psk_bytes)).unwrap();

        // Generate а deterministic Ed25519 identity для the inviter.
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk_b64 = STANDARD.encode(sk.verifying_key().to_bytes());
        let sk_b64 = STANDARD.encode(sk.to_bytes());

        let inviter_config = Config {
            identity: Some(IdentityConfig {
                algo: veil_cfg::SignatureAlgorithm::Ed25519,
                public_key: pk_b64.clone(),
                private_key: sk_b64,
                ..IdentityConfig::default()
            }),
            listen: vec![ListenConfig {
                id: ListenId::new(1),
                transport: "obfs4-tcp://203.0.113.7:5556".to_owned(),
                visibility: Visibility::Trusted,
                psk_file: Some(inviter_psk_path.clone()),
                ..ListenConfig::default()
            }],
            ..Config::default()
        };

        let inviter_state = Rc::new(RefCell::new(inviter_config));
        let inviter_ops = StatefulConfigOps {
            path: inviter_config_path.clone(),
            state: Rc::clone(&inviter_state),
        };
        let mut inviter_ctx = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops: inviter_ops,
        };

        // Emit the bundle к а file so we don't have к parse stdout
        // mixed с the trailing comment line.
        let bundle_path = inviter_dir.path().join("invite.txt");
        create_invite(
            &mut inviter_ctx,
            ListenId::new(1),
            7 * 24 * 3600,
            Some("family".to_owned()),
            Some(bundle_path.clone()),
            false, // qr
        )
        .expect("create_invite must succeed");

        // File should exist + contain base32 text.
        let bundle_text = std::fs::read_to_string(&bundle_path).unwrap();
        assert!(!bundle_text.trim().is_empty());

        // ── recipient setup ────────────────────────────────────────
        let recipient_dir = tempfile::tempdir().unwrap();
        let recipient_config_path = recipient_dir.path().join("node.toml");

        let recipient_config = Config::default();
        let recipient_state = Rc::new(RefCell::new(recipient_config));
        let recipient_ops = StatefulConfigOps {
            path: recipient_config_path.clone(),
            state: Rc::clone(&recipient_state),
        };
        let mut recipient_ctx = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops: recipient_ops,
        };

        accept_invite(&mut recipient_ctx, &bundle_path, None, false)
            .expect("accept_invite must succeed");

        // (a) PSK file written к the default path (under recipient's
        //     config dir, hex-encoded node_id filename).
        let expected_nid = *blake3::hash(&sk.verifying_key().to_bytes()).as_bytes();
        let nid_hex: String = expected_nid.iter().map(|b| format!("{b:02x}")).collect();
        let psk_out_path = recipient_dir
            .path()
            .join("invite_psks")
            .join(format!("{nid_hex}.psk"));
        let saved_psk_b64 = std::fs::read_to_string(&psk_out_path)
            .expect("recipient should have written the PSK to default_psk_path");
        let saved_psk = STANDARD.decode(saved_psk_b64.trim()).unwrap();
        assert_eq!(saved_psk, psk_bytes, "PSK round-trip mismatch");

        // (b) bootstrap_peers appended с the inviter's pubkey.
        let after = recipient_state.borrow();
        assert_eq!(after.bootstrap_peers.len(), 1);
        let added = &after.bootstrap_peers[0];
        assert_eq!(added.public_key, pk_b64);
        assert_eq!(added.transport, "obfs4-tcp://203.0.113.7:5556");
        assert!(matches!(added.algo, veil_cfg::SignatureAlgorithm::Ed25519));
    }

    /// `accept` is idempotent — running it twice doesn't duplicate the
    /// bootstrap_peers entry.
    #[test]
    fn accept_is_idempotent_on_same_inviter() {
        use ed25519_dalek::SigningKey;

        let dir = tempfile::tempdir().unwrap();
        let psk_path = dir.path().join("listener.psk");
        std::fs::write(&psk_path, STANDARD.encode([0x11u8; 32])).unwrap();

        // Build а bundle directly via the veil-invite crate (no need
        // к round-trip through create_invite — это test focuses on
        // accept's dedup behaviour).
        let sk = SigningKey::from_bytes(&[0x88u8; 32]);
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86_400;
        let bundle = veil_invite::create_bundle(
            &sk,
            "obfs4-tcp://10.0.0.1:5556".to_owned(),
            [0x11u8; 32],
            exp,
            None,
        )
        .unwrap();
        let bundle_path = dir.path().join("invite.txt");
        std::fs::write(&bundle_path, bundle.to_base32().unwrap()).unwrap();

        let config_path = dir.path().join("node.toml");
        let state = Rc::new(RefCell::new(Config::default()));
        let ops = StatefulConfigOps {
            path: config_path,
            state: Rc::clone(&state),
        };
        let mut ctx = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        accept_invite(&mut ctx, &bundle_path, None, false).unwrap();
        accept_invite(&mut ctx, &bundle_path, None, false).unwrap();

        assert_eq!(
            state.borrow().bootstrap_peers.len(),
            1,
            "second accept must not duplicate the bootstrap_peer",
        );
    }

    /// `--no-update-config` writes the PSK file but leaves
    /// `bootstrap_peers` untouched.
    #[test]
    fn accept_with_no_update_config_leaves_peers_empty() {
        use ed25519_dalek::SigningKey;

        let dir = tempfile::tempdir().unwrap();
        let sk = SigningKey::from_bytes(&[0x33u8; 32]);
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let bundle = veil_invite::create_bundle(
            &sk,
            "obfs4-tcp://10.0.0.2:5556".to_owned(),
            [0x44u8; 32],
            exp,
            None,
        )
        .unwrap();
        let bundle_path = dir.path().join("invite.txt");
        std::fs::write(&bundle_path, bundle.to_base32().unwrap()).unwrap();

        let config_path = dir.path().join("node.toml");
        let state = Rc::new(RefCell::new(Config::default()));
        let ops = StatefulConfigOps {
            path: config_path,
            state: Rc::clone(&state),
        };
        let mut ctx = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        accept_invite(&mut ctx, &bundle_path, None, true).unwrap();

        assert!(
            state.borrow().bootstrap_peers.is_empty(),
            "--no-update-config must NOT touch bootstrap_peers",
        );
        // PSK file should still exist.
        let nid = *blake3::hash(&sk.verifying_key().to_bytes()).as_bytes();
        let nid_hex: String = nid.iter().map(|b| format!("{b:02x}")).collect();
        let psk_out_path = dir
            .path()
            .join("invite_psks")
            .join(format!("{nid_hex}.psk"));
        assert!(psk_out_path.exists(), "PSK file should be saved regardless");
    }

    /// Public-visibility listener rejected at create time — operator
    /// would otherwise leak a PSK redundantly (Public listeners are
    /// already discoverable through PEX/DHT).
    #[test]
    fn create_rejects_public_visibility_listener() {
        use ed25519_dalek::SigningKey;

        let dir = tempfile::tempdir().unwrap();
        let psk_path = dir.path().join("listener.psk");
        std::fs::write(&psk_path, STANDARD.encode([0x55u8; 32])).unwrap();

        let sk = SigningKey::from_bytes(&[0x66u8; 32]);
        let config = Config {
            identity: Some(IdentityConfig {
                algo: veil_cfg::SignatureAlgorithm::Ed25519,
                public_key: STANDARD.encode(sk.verifying_key().to_bytes()),
                private_key: STANDARD.encode(sk.to_bytes()),
                ..IdentityConfig::default()
            }),
            listen: vec![ListenConfig {
                id: ListenId::new(1),
                transport: "obfs4-tcp://0.0.0.0:5556".to_owned(),
                visibility: Visibility::Public, // <-- the rejection trigger
                psk_file: Some(psk_path),
                ..ListenConfig::default()
            }],
            ..Config::default()
        };

        let state = Rc::new(RefCell::new(config));
        let ops = StatefulConfigOps {
            path: dir.path().join("node.toml"),
            state,
        };
        let mut ctx = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        let err = create_invite(
            &mut ctx,
            ListenId::new(1),
            3600,
            None,
            Some(dir.path().join("invite.txt")),
            false,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("visibility=public"));
    }
}
