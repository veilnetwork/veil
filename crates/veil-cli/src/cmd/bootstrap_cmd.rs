//! CLI handler for `veil-cli bootstrap …`.

use veil_bootstrap::encrypted_invite::{ENCRYPTED_INVITE_SCHEME, decrypt_invite, encrypt_invite};
use veil_bootstrap::invite::{decode_uri, encode_uri};
use veil_bootstrap::signed_invite::{
    SIGNED_INVITE_SCHEME, decode_signed_invite, sign_invite, verify_signed_invite,
};
use veil_cfg::{self, BootstrapPeer};

use super::{
    cli::{BootstrapArgs, BootstrapCommand},
    handlers::{CommandContext, ConfigOps},
    output::{CommandIo, OutputEvent},
};

pub fn handle_bootstrap_command<I: CommandIo, O: ConfigOps>(
    mut context: CommandContext<'_, I, O>,
    args: BootstrapArgs,
) -> veil_cfg::Result<()> {
    match args.command {
        BootstrapCommand::Invite {
            qr,
            password,
            password_file,
            sign,
            expiry_secs,
        } => {
            let password = super::util::resolve_secret_arg(
                password,
                password_file.as_deref(),
                "--password",
                "--password-file",
            )?;
            bootstrap_invite(&mut context, qr, password.as_deref(), sign, expiry_secs)
        }
        BootstrapCommand::Join {
            uri,
            password,
            password_file,
            verify_issuer,
        } => {
            let password = super::util::resolve_secret_arg(
                password,
                password_file.as_deref(),
                "--password",
                "--password-file",
            )?;
            bootstrap_join(
                &mut context,
                &uri,
                password.as_deref(),
                verify_issuer.as_deref(),
            )
        }
        BootstrapCommand::Decode {
            uri,
            password,
            password_file,
            verify_issuer,
        } => {
            let password = super::util::resolve_secret_arg(
                password,
                password_file.as_deref(),
                "--password",
                "--password-file",
            )?;
            bootstrap_decode(
                &mut context,
                &uri,
                password.as_deref(),
                verify_issuer.as_deref(),
            )
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decode any of the three URI families into a [`BootstrapPeer`].
/// Shared by `join` + `decode` so both accept the full URI family
/// with the same error messages and trust semantics.
fn decode_any_uri(
    uri: &str,
    password: Option<&str>,
    expected_issuer_pk: Option<&str>,
) -> veil_cfg::Result<BootstrapPeer> {
    if uri.starts_with(SIGNED_INVITE_SCHEME) {
        if password.is_some() {
            return Err(veil_cfg::ConfigError::ValidationFailed(
                "`--password` was provided but URI is `veil:signed-invite?…`; \
                 signed and encrypted envelopes are independent — pass only one"
                    .into(),
            ));
        }
        let envelope = decode_signed_invite(uri).map_err(|e| {
            veil_cfg::ConfigError::ValidationFailed(format!("decode signed invite: {e}"))
        })?;
        verify_signed_invite(&envelope, expected_issuer_pk, now_unix()).map_err(|e| {
            veil_cfg::ConfigError::ValidationFailed(format!("verify signed invite: {e}"))
        })
    } else if uri.starts_with(ENCRYPTED_INVITE_SCHEME) {
        if expected_issuer_pk.is_some() {
            return Err(veil_cfg::ConfigError::ValidationFailed(
                "`--verify-issuer` was provided but URI is `veil:pair?…`; \
                 encrypted envelopes carry no issuer signature — omit `--verify-issuer`"
                    .into(),
            ));
        }
        let pw = password.ok_or_else(|| {
            veil_cfg::ConfigError::ValidationFailed(
                "URI is password-protected (`veil:pair?…`); pass `--password <PW>`".into(),
            )
        })?;
        decrypt_invite(uri, pw)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("decrypt invite: {e}")))
    } else {
        if password.is_some() {
            return Err(veil_cfg::ConfigError::ValidationFailed(
                "`--password` was provided but URI is not `veil:pair?…`; \
                 omit the password OR repaste the encrypted URL"
                    .into(),
            ));
        }
        if expected_issuer_pk.is_some() {
            return Err(veil_cfg::ConfigError::ValidationFailed(
                "`--verify-issuer` was provided but URI is not `veil:signed-invite?…`; \
                 omit `--verify-issuer` OR repaste the signed URL"
                    .into(),
            ));
        }
        decode_uri(uri)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("decode uri: {e}")))
    }
}

/// `bootstrap invite` — assemble a `BootstrapPeer` from the local
/// config (first listen entry + current identity) and emit its
/// canonical URI. Variants:
///
/// * `--password <PW>` → wrap in encrypted envelope.
/// * `--sign` → sign with `[identity]` keypair.
/// * `--qr` → render an ASCII / half-block QR.
///
/// Encrypted and signed are mutually exclusive at this layer because
/// the underlying envelopes nest in either order — operators that need
/// both can emit the encrypted URL and sign it manually as a follow-up
/// step. Erroring on the combo here keeps the CLI surface obvious.
fn bootstrap_invite<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    render_qr: bool,
    password: Option<&str>,
    sign: bool,
    expiry_secs: u64,
) -> veil_cfg::Result<()> {
    if sign && password.is_some() {
        return Err(veil_cfg::ConfigError::ValidationFailed(
            "--sign and --password are mutually exclusive at this layer; \
             pick one (signing carries the issuer's pubkey for attestation; \
             password carries the channel-encryption shared secret)"
                .into(),
        ));
    }
    let (_path, config) = context.config().load_existing()?;
    let identity = config.identity.as_ref().ok_or_else(|| {
        veil_cfg::ConfigError::CommandFailed(
            "config has no `[identity]` — run `veil-cli identity standalone` first".into(),
        )
    })?;
    let listen = config.listen.first().ok_or_else(|| {
        veil_cfg::ConfigError::CommandFailed(
            "config has no `[[listen]]` entry — add one before issuing a bootstrap invite \
             (the invite needs an address peers can dial)"
                .into(),
        )
    })?;
    // Prefer the explicit `advertise` address (e.g. nginx-fronted public
    // hostname) over the bind address — the recipient needs to reach US
    // not loopback. Falls back to `transport` (= bind) when no
    // `advertise` is set.
    let transport = listen
        .advertise
        .clone()
        .unwrap_or_else(|| listen.transport.clone());
    let peer = veil_cfg::BootstrapPeer {
        transport,
        public_key: identity.public_key.clone(),
        nonce: identity.nonce.clone(),
        algo: identity.algo,
        // TLS material is not embedded in the invite — recipients use
        // their own trust store / out-of-band cert verification.
        tls_cert: None,
        tls_ca_cert: None,
    };
    let uri = if sign {
        sign_invite(
            &peer,
            &identity.public_key,
            &identity.private_key,
            identity.algo,
            now_unix(),
            expiry_secs,
        )
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("sign invite: {e}")))?
    } else if let Some(pw) = password {
        encrypt_invite(&peer, pw)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("encrypt invite: {e}")))?
    } else {
        encode_uri(&peer)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("encode uri: {e}")))?
    };

    if render_qr {
        // Reuse the same qrcode crate already wired for sovereign-identity QRs.
        let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("qr encode: {e}")))?;
        let qr_text = render_qr_halfblock(&code);
        context
            .io
            .emit(OutputEvent::message(format!("{uri}\n\n{qr_text}")));
    } else {
        context.io.emit(OutputEvent::message(uri));
    }
    Ok(())
}

/// `bootstrap join --uri...` — decode the URI (plain, encrypted, or
/// signed) and append the resulting `BootstrapPeer` to the local
/// config's `bootstrap_peers` (idempotent — same `public_key` is not
/// appended twice).
fn bootstrap_join<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    uri: &str,
    password: Option<&str>,
    verify_issuer: Option<&str>,
) -> veil_cfg::Result<()> {
    // Hard requirement: signed invites without `--verify-issuer` would
    // be added based on the envelope's CLAIMED issuer with no external
    // trust signal. Refuse — the operator should explicitly declare
    // who they expect to have signed it.
    if uri.starts_with(SIGNED_INVITE_SCHEME) && verify_issuer.is_none() {
        return Err(veil_cfg::ConfigError::ValidationFailed(
            "URI is a signed invite (`veil:signed-invite?…`); \
             pass `--verify-issuer <PUBKEY>` so the signature is checked \
             against an issuer pubkey you trust"
                .into(),
        ));
    }
    let peer = decode_any_uri(uri, password, verify_issuer)?;
    let (path, mut loaded) = context.config().load_existing()?;
    if loaded
        .bootstrap_peers
        .iter()
        .any(|p| p.public_key == peer.public_key)
    {
        context.io.emit(OutputEvent::message(format!(
            "bootstrap peer with public_key={} already in [[bootstrap_peers]] — no-op",
            short_pk(&peer.public_key),
        )));
        return Ok(());
    }
    let pk_short = short_pk(&peer.public_key);
    let transport = peer.transport.clone();
    loaded.bootstrap_peers.push(peer);
    context.config().save(&path, &loaded)?;
    context.io.emit(OutputEvent::message(format!(
        "added bootstrap peer pk={pk_short} transport={transport} → {}",
        path.display(),
    )));
    Ok(())
}

/// `bootstrap decode --uri...` — pretty-print the peer fields without
/// touching the config file. Useful as a preflight for "what's in
/// this QR before I trust it". Accepts plain, encrypted, and signed
/// URIs. For signed URIs without `--verify-issuer`, the envelope's
/// claimed issuer pubkey is printed in an `UNVERIFIED` block — operator
/// must compare it against the issuer's pubkey from an out-of-band
/// channel before trusting the inner peer.
fn bootstrap_decode<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    uri: &str,
    password: Option<&str>,
    verify_issuer: Option<&str>,
) -> veil_cfg::Result<()> {
    let mut prefix = String::new();
    if uri.starts_with(SIGNED_INVITE_SCHEME) && verify_issuer.is_none() {
        // Show the claimed issuer up-front so the operator can compare
        // before deciding to trust.
        let envelope = decode_signed_invite(uri).map_err(|e| {
            veil_cfg::ConfigError::ValidationFailed(format!("decode signed invite: {e}"))
        })?;
        prefix = format!(
            "UNVERIFIED — signed envelope claims issuer:\n  pubkey:  {}\n  algo:    {:?}\n  issued:  unix={}\n  expires: unix={}\n\
             \n\
             Pass `--verify-issuer <PUBKEY>` to check the signature \
             against an issuer key you trust.\n\n",
            envelope.issuer_pk, envelope.issuer_algo, envelope.issued_at_unix, envelope.expiry_unix,
        );
    }
    let peer = decode_any_uri(uri, password, verify_issuer)?;
    let tls_cert_status = peer
        .tls_cert
        .as_ref()
        .map(|_| "present")
        .unwrap_or("(none)");
    let tls_ca_status = peer
        .tls_ca_cert
        .as_ref()
        .map(|_| "present")
        .unwrap_or("(none)");
    context.io.emit(OutputEvent::message(format!(
        "{prefix}transport:    {}\npublic_key:   {}\nnonce:        {}\nalgo:         {:?}\ntls_cert:     {}\ntls_ca_cert:  {}",
        peer.transport,
        peer.public_key,
        peer.nonce,
        peer.algo,
        tls_cert_status,
        tls_ca_status,
    )));
    Ok(())
}

fn short_pk(pk: &str) -> String {
    if pk.len() > 12 {
        format!("{}…", &pk[..12])
    } else {
        pk.to_owned()
    }
}

/// QR rendering helper — copy of the half-block style used by
/// `cmd/sovereign_identity.rs::render_qr_halfblock` so output looks
/// consistent across `identity qr` and `bootstrap invite --qr`.
/// Kept private here (sovereign-identity's helper is not pub).
fn render_qr_halfblock(code: &qrcode::QrCode) -> String {
    let width = code.width();
    let modules: Vec<bool> = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    // Render two rows per character using upper + lower half-block.
    let mut out = String::new();
    let mut y = 0;
    while y < width {
        for x in 0..width {
            let top = modules[y * width + x];
            let bottom = if y + 1 < width {
                modules[(y + 1) * width + x]
            } else {
                false
            };
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_cfg::{BootstrapPeer, SignatureAlgorithm};

    /// Standalone smoke test — short_pk produces predictable output.
    #[test]
    fn short_pk_truncates_long_keys() {
        assert_eq!(short_pk("abcdefghijklmnop"), "abcdefghijkl…");
        assert_eq!(short_pk("short"), "short");
    }

    /// Round-trip via the public encode/decode APIs (a full handler
    /// integration test lives outside this file because it touches
    /// the filesystem; the URL encoding contract is the cross-cutting
    /// invariant we care about).
    #[test]
    fn epic481_1_encode_decode_round_trips_through_handler_layer() {
        let peer = BootstrapPeer {
            transport: "tcp://10.1.2.3:9000".to_owned(),
            public_key: "AAAA".to_owned(),
            nonce: "BBBB".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        };
        let uri = encode_uri(&peer).unwrap();
        let back = decode_uri(&uri).unwrap();
        assert_eq!(peer, back);
    }

    fn sample_peer() -> BootstrapPeer {
        BootstrapPeer {
            transport: "tcp://10.1.2.3:9000".to_owned(),
            public_key: "AAAA".to_owned(),
            nonce: "BBBB".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }
    }

    /// dispatcher routes encrypted URLs to decrypt path.
    #[test]
    fn epic481_2_decode_either_routes_encrypted_uri_with_password() {
        let peer = sample_peer();
        let url = encrypt_invite(&peer, "pw").unwrap();
        let back = decode_any_uri(&url, Some("pw"), None).unwrap();
        assert_eq!(back, peer);
    }

    /// encrypted URL without password surfaces actionable error.
    #[test]
    fn epic481_2_decode_either_encrypted_without_password_actionable_error() {
        let url = encrypt_invite(&sample_peer(), "pw").unwrap();
        let err = decode_any_uri(&url, None, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("password-protected"),
            "error must hint that password is required: {msg}"
        );
    }

    /// a `--password` on a plain URI is rejected, NOT silently
    /// ignored — the operator likely pasted the wrong URI from clipboard
    /// and we want them to notice rather than join the wrong network.
    #[test]
    fn epic481_2_decode_either_plain_uri_with_password_rejected_loudly() {
        let plain = encode_uri(&sample_peer()).unwrap();
        let err = decode_any_uri(&plain, Some("pw"), None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not `veil:pair?…`") || msg.contains("repaste the encrypted URL"),
            "error must explain the mismatch: {msg}"
        );
    }

    /// plain URI without password takes the existing path.
    #[test]
    fn epic481_2_decode_either_plain_uri_without_password_works() {
        let peer = sample_peer();
        let plain = encode_uri(&peer).unwrap();
        let back = decode_any_uri(&plain, None, None).unwrap();
        assert_eq!(back, peer);
    }

    fn sign_url_for(peer: &BootstrapPeer) -> (String, String) {
        let kp = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519);
        let url = sign_invite(
            peer,
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
            now_unix(),
            3600,
        )
        .unwrap();
        (url, kp.public_key)
    }

    /// signed URI + matching --verify-issuer succeeds.
    #[test]
    fn epic481_3_dispatcher_signed_with_matching_issuer_returns_peer() {
        let peer = sample_peer();
        let (url, issuer_pk) = sign_url_for(&peer);
        let back = decode_any_uri(&url, None, Some(&issuer_pk)).unwrap();
        assert_eq!(back, peer);
    }

    /// signed URI + WRONG --verify-issuer is rejected loudly
    /// NOT silently accepted because the internal signature is consistent.
    #[test]
    fn epic481_3_dispatcher_signed_with_wrong_issuer_rejected() {
        let (url, _) = sign_url_for(&sample_peer());
        let other_pk = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519).public_key;
        let err = decode_any_uri(&url, None, Some(&other_pk)).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("issuer pubkey mismatch") || msg.contains("expected"),
            "wrong issuer must be flagged: {msg}"
        );
    }

    /// signed URI without --verify-issuer at the dispatcher
    /// layer still succeeds (caller's responsibility to require it for
    /// `bootstrap join`; dispatcher is a thin wrapper). But `bootstrap
    /// join` enforces the requirement separately, tested below.
    #[test]
    fn epic481_3_dispatcher_signed_without_issuer_validates_internal_sig() {
        let peer = sample_peer();
        let (url, _) = sign_url_for(&peer);
        let back = decode_any_uri(&url, None, None).unwrap();
        assert_eq!(
            back, peer,
            "internal-consistency check must still recover peer"
        );
    }

    /// passing --password on a signed URI is rejected
    /// (mutually exclusive at the dispatcher).
    #[test]
    fn epic481_3_dispatcher_signed_with_password_rejected() {
        let (url, issuer_pk) = sign_url_for(&sample_peer());
        let err = decode_any_uri(&url, Some("pw"), Some(&issuer_pk)).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("signed and encrypted envelopes are independent"),
            "signed + password combo must be flagged: {msg}"
        );
    }

    /// passing --verify-issuer on an encrypted URI is rejected
    /// (encrypted envelopes carry no issuer signature).
    #[test]
    fn epic481_3_dispatcher_encrypted_with_verify_issuer_rejected() {
        let url = encrypt_invite(&sample_peer(), "pw").unwrap();
        let other_pk = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519).public_key;
        let err = decode_any_uri(&url, Some("pw"), Some(&other_pk)).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("encrypted envelopes carry no issuer signature"),
            "encrypted + verify-issuer combo must be flagged: {msg}"
        );
    }

    /// passing --verify-issuer on a plain URI is rejected.
    #[test]
    fn epic481_3_dispatcher_plain_with_verify_issuer_rejected() {
        let plain = encode_uri(&sample_peer()).unwrap();
        let other_pk = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519).public_key;
        let err = decode_any_uri(&plain, None, Some(&other_pk)).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not `veil:signed-invite?…`"),
            "plain + verify-issuer combo must be flagged: {msg}"
        );
    }

    /// C-14: `bootstrap … --password-file <path>` reads the password from a
    /// file (trailing newline trimmed) so the secret never lands in argv.
    #[test]
    fn password_file_is_read_and_trimmed() {
        let dir = crate::test_support::scratch_dir("veil-cli-bootstrap-pw");
        let pw_path = dir.join("pw");
        std::fs::write(&pw_path, "hunter2\n").unwrap();
        let resolved = super::super::util::resolve_secret_arg(
            None,
            Some(pw_path.as_path()),
            "--password",
            "--password-file",
        )
        .unwrap();
        assert_eq!(resolved.as_deref(), Some("hunter2"));
    }

    /// An empty / whitespace-only `--password-file` is rejected rather than
    /// silently producing an empty password.
    #[test]
    fn empty_password_file_is_rejected() {
        let dir = crate::test_support::scratch_dir("veil-cli-bootstrap-pw-empty");
        let pw_path = dir.join("pw");
        std::fs::write(&pw_path, "   \n").unwrap();
        let err = super::super::util::resolve_secret_arg(
            None,
            Some(pw_path.as_path()),
            "--password",
            "--password-file",
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("empty"),
            "empty password-file must be rejected: {err}"
        );
    }

    /// The deprecated argv form still resolves (the one-line stderr warning
    /// is a side effect; here we just assert the value passes through).
    #[test]
    fn argv_password_still_resolves() {
        let resolved = super::super::util::resolve_secret_arg(
            Some("pw".to_owned()),
            None,
            "--password",
            "--password-file",
        )
        .unwrap();
        assert_eq!(resolved.as_deref(), Some("pw"));
    }
}
