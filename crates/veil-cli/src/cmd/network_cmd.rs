//! CLI handler for `veil-cli network …` — private-veil-network
//! admin tooling. Operators use these commands к set up а private
//! network (generate owner key, sign member certs) и inspect/verify
//! existing certs.
//!
//! Public-mode nodes don't need any of these commands — leaving
//! `[network]` config blank keeps the open-veil behaviour.

use std::fs;
#[cfg(unix)]
use std::io::Write;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use tokio::runtime::Builder;
use veil_crypto::{generate_keypair, sign_message};
use veil_identity::network_cert::{
    canonical_cert_body, decode_cert_blob, encode_cert_blob, verify_membership_cert,
};
use veil_types::{MEMBERSHIP_CERT_VERSION, MembershipCert, SignatureAlgorithm};

use veil_cfg;
use veil_node_runtime::admin as node;

use super::{
    cli::{NetworkArgs, NetworkCommand},
    handlers::CommandContext,
    output::{CommandIo, OutputEvent},
    util::map_node_error,
};

pub fn handle_network_command<I: CommandIo>(
    context: &mut CommandContext<'_, I, impl super::handlers::ConfigOps>,
    args: NetworkArgs,
) -> veil_cfg::Result<()> {
    match args.command {
        NetworkCommand::GenOwner {
            pub_out,
            priv_out,
            algo,
        } => gen_owner(context, &pub_out, &priv_out, algo.into()),
        NetworkCommand::GenNetworkId => gen_network_id(context),
        NetworkCommand::SignMember {
            owner_pub,
            owner_priv,
            algo,
            network_id,
            member_node_id,
            admin,
            valid_days,
            no_expiry,
            out,
        } => sign_member(
            context,
            &owner_pub,
            &owner_priv,
            algo.into(),
            &network_id,
            &member_node_id,
            admin,
            valid_days,
            no_expiry,
            &out,
        ),
        NetworkCommand::InspectCert { path } => inspect_cert(context, &path),
        NetworkCommand::VerifyCert {
            cert,
            owner_pub,
            algo,
            network_id,
        } => verify_cert(context, &cert, &owner_pub, algo.into(), &network_id),
        NetworkCommand::Ban { node_id, reason } => ban(context, node_id, reason),
    }
}

fn ban<I: CommandIo>(
    context: &mut CommandContext<'_, I, impl super::handlers::ConfigOps>,
    node_id: String,
    reason: Option<String>,
) -> veil_cfg::Result<()> {
    let (config_path, config) = context.config().load_existing()?;
    let socket = node::admin_socket_path(&config, config_path.parent()).map_err(map_node_error)?;
    if !node::admin_anchor_reachable_sync(&socket) {
        return Err(veil_cfg::ConfigError::CommandFailed(format!(
            "admin socket `{}` not found; is the node running?",
            socket.display()
        )));
    }
    let command = node::AdminCommand::PNetBan {
        node_id: node_id.clone(),
        reason: reason.clone(),
    };
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(veil_cfg::ConfigError::Io)?;
    let response = runtime
        .block_on(node::send_request(&socket, command))
        .map_err(map_node_error)?;
    if let Some(error) = response.error {
        return Err(veil_cfg::ConfigError::ValidationFailed(error));
    }
    if let Some(node::AdminResult::Ack { message }) = response.result {
        context.io.emit(OutputEvent::message(message));
    }
    Ok(())
}

fn gen_owner<I: CommandIo>(
    context: &mut CommandContext<'_, I, impl super::handlers::ConfigOps>,
    pub_out: &Path,
    priv_out: &Path,
    algo: SignatureAlgorithm,
) -> veil_cfg::Result<()> {
    let kp = generate_keypair(algo);
    fs::write(pub_out, format!("{}\n", kp.public_key))
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("write pub: {e}")))?;
    write_secret(priv_out, &kp.private_key)?;
    context.io.emit(OutputEvent::message(format!(
        "Wrote owner pubkey → {}\nWrote owner privkey → {} (mode 0600)\nAlgo: {algo}\n\n\
         ⚠ Keep the private key OFFLINE / encrypted backup. Anyone с it can issue admin certs.",
        pub_out.display(),
        priv_out.display(),
    )));
    Ok(())
}

fn gen_network_id<I: CommandIo>(
    context: &mut CommandContext<'_, I, impl super::handlers::ConfigOps>,
) -> veil_cfg::Result<()> {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let hex = bytes_to_hex(&bytes);
    context.io.emit(OutputEvent::message(format!(
        "network_id = {hex}\n\nCopy this к `[network].network_id` в every member's node.toml.",
    )));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign_member<I: CommandIo>(
    context: &mut CommandContext<'_, I, impl super::handlers::ConfigOps>,
    owner_pub: &Path,
    owner_priv: &Path,
    algo: SignatureAlgorithm,
    network_id_hex: &str,
    member_node_id_hex: &str,
    admin: bool,
    valid_days: u32,
    no_expiry: bool,
    out: &Path,
) -> veil_cfg::Result<()> {
    let network_id = decode_hex_32(network_id_hex)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("network_id: {e}")))?;
    let member_node_id = decode_hex_32(member_node_id_hex)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("member_node_id: {e}")))?;
    let pub_b64 = fs::read_to_string(owner_pub)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("read owner_pub: {e}")))?;
    let pub_b64 = pub_b64.trim();
    let priv_b64 = fs::read_to_string(owner_priv)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("read owner_priv: {e}")))?;
    let priv_b64 = priv_b64.trim();

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // `valid_until_unix == 0` ⇒ no-expiry sentinel (verify_membership_cert
    // skips the expiry check for this value).  Owner-side opt-in only.
    let valid_until_unix = if no_expiry {
        0
    } else {
        now_unix.saturating_add(u64::from(valid_days) * 86_400)
    };

    let mut cert = MembershipCert {
        version: MEMBERSHIP_CERT_VERSION,
        network_id,
        member_node_id,
        issued_at_unix: now_unix,
        valid_until_unix,
        admin,
        algo,
        owner_signature: Vec::new(),
    };
    let body = canonical_cert_body(&cert);
    cert.owner_signature = sign_message(algo, pub_b64, priv_b64, &body)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("sign: {e}")))?;

    let blob = encode_cert_blob(&cert);
    fs::write(out, &blob)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("write cert: {e}")))?;

    let expiry_descr = if no_expiry {
        "NEVER (sentinel 0 — revoke via DHT ban or owner-key rotation)".to_owned()
    } else {
        format!("{valid_until_unix} ({valid_days} days)")
    };
    context.io.emit(OutputEvent::message(format!(
        "Issued membership cert:\n  network_id      = {}\n  member_node_id  = {}\n  admin           = {}\n  issued_at_unix  = {}\n  valid_until_unix= {}\n  algo            = {}\n  signature_bytes = {}\nWrote {} bytes → {}",
        network_id_hex,
        member_node_id_hex,
        admin,
        now_unix,
        expiry_descr,
        algo,
        cert.owner_signature.len(),
        blob.len(),
        out.display(),
    )));
    Ok(())
}

fn inspect_cert<I: CommandIo>(
    context: &mut CommandContext<'_, I, impl super::handlers::ConfigOps>,
    path: &Path,
) -> veil_cfg::Result<()> {
    let blob = fs::read(path)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("read cert: {e}")))?;
    let cert = decode_cert_blob(&blob)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("decode cert: {e}")))?;
    let valid_until_descr = if cert.valid_until_unix == 0 {
        "0 (NEVER — sentinel `no expiry`)".to_owned()
    } else {
        cert.valid_until_unix.to_string()
    };
    context.io.emit(OutputEvent::message(format!(
        "Cert at {} ({} bytes):\n  version          = {}\n  network_id       = {}\n  member_node_id   = {}\n  issued_at_unix   = {}\n  valid_until_unix = {}\n  admin            = {}\n  algo             = {}\n  signature_bytes  = {}",
        path.display(),
        blob.len(),
        cert.version,
        bytes_to_hex(&cert.network_id),
        bytes_to_hex(&cert.member_node_id),
        cert.issued_at_unix,
        valid_until_descr,
        cert.admin,
        cert.algo,
        cert.owner_signature.len(),
    )));
    Ok(())
}

fn verify_cert<I: CommandIo>(
    context: &mut CommandContext<'_, I, impl super::handlers::ConfigOps>,
    cert_path: &Path,
    owner_pub_path: &Path,
    algo: SignatureAlgorithm,
    network_id_hex: &str,
) -> veil_cfg::Result<()> {
    let blob = fs::read(cert_path)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("read cert: {e}")))?;
    let cert = decode_cert_blob(&blob)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("decode cert: {e}")))?;
    let owner_pub_b64 = fs::read_to_string(owner_pub_path)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("read owner_pub: {e}")))?;
    let owner_pubkey_bytes = B64
        .decode(owner_pub_b64.trim())
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("decode owner_pub: {e}")))?;
    let network_id = decode_hex_32(network_id_hex)
        .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("network_id: {e}")))?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match verify_membership_cert(&cert, &network_id, algo, &owner_pubkey_bytes, now_unix) {
        Ok(()) => {
            let valid_until_descr = if cert.valid_until_unix == 0 {
                "NEVER (sentinel — revoke via DHT ban or owner-key rotation)".to_owned()
            } else {
                format!(
                    "{} (in {} days)",
                    cert.valid_until_unix,
                    cert.valid_until_unix.saturating_sub(now_unix) / 86_400
                )
            };
            context.io.emit(OutputEvent::message(format!(
                "✓ Cert verified:\n  member_node_id   = {}\n  admin            = {}\n  valid_until_unix = {}\n  algo             = {}",
                bytes_to_hex(&cert.member_node_id),
                cert.admin,
                valid_until_descr,
                cert.algo,
            )));
            Ok(())
        }
        Err(e) => Err(veil_cfg::ConfigError::ValidationFailed(format!(
            "✗ Cert verification failed: {e}"
        ))),
    }
}

fn write_secret(path: &Path, contents: &str) -> veil_cfg::Result<()> {
    // На Unix: create с mode 0600 so the privkey не world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("create priv: {e}")))?;
        f.write_all(contents.as_bytes())
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("write priv: {e}")))?;
        f.write_all(b"\n")
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("write priv: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, format!("{contents}\n"))
            .map_err(|e| veil_cfg::ConfigError::ValidationFailed(format!("write priv: {e}")))?;
    }
    Ok(())
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], String> {
    // HexError::Display reproduces the prior messages ("expected 64 hex chars,
    // got N" / "non-hex character"); the dead non-ascii branch dropped (input
    // is already a &str).
    veil_util::hex_to_array::<32>(hex).map_err(|e| e.to_string())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::cli::SignatureAlgorithmArg;
    use crate::cmd::test_support::{BufferIo, MockConfigOps};
    use tempfile::tempdir;

    fn ctx() -> CommandContext<'static, BufferIo, MockConfigOps> {
        CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops: MockConfigOps::default(),
        }
    }

    #[test]
    fn gen_owner_writes_pub_and_priv() {
        let dir = tempdir().expect("tempdir");
        let pub_path = dir.path().join("owner.pub");
        let priv_path = dir.path().join("owner.priv");
        let mut c = ctx();
        gen_owner(&mut c, &pub_path, &priv_path, SignatureAlgorithm::Ed25519).expect("gen_owner");
        assert!(pub_path.exists());
        assert!(priv_path.exists());
        let pub_b64 = fs::read_to_string(&pub_path).unwrap();
        let priv_b64 = fs::read_to_string(&priv_path).unwrap();
        assert!(!pub_b64.trim().is_empty());
        assert!(!priv_b64.trim().is_empty());
        assert!(c.io.output.contains("Wrote owner pubkey"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&priv_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "priv key must be 0600 на Unix");
        }
    }

    #[test]
    fn gen_network_id_emits_hex64() {
        let mut c = ctx();
        gen_network_id(&mut c).expect("gen_network_id");
        let out = &c.io.output;
        let line = out
            .lines()
            .find(|l| l.starts_with("network_id ="))
            .expect("network_id line");
        let hex = line.trim_start_matches("network_id =").trim();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn round_trip_sign_inspect_verify() {
        let dir = tempdir().expect("tempdir");
        let pub_path = dir.path().join("owner.pub");
        let priv_path = dir.path().join("owner.priv");
        let cert_path = dir.path().join("member.cert");

        // 1. generate the owner key
        gen_owner(
            &mut ctx(),
            &pub_path,
            &priv_path,
            SignatureAlgorithm::Ed25519,
        )
        .expect("gen_owner");

        // 2. sign а member cert
        let nid = "11".repeat(32);
        let mid = "22".repeat(32);
        let mut c_sign = ctx();
        sign_member(
            &mut c_sign,
            &pub_path,
            &priv_path,
            SignatureAlgorithm::Ed25519,
            &nid,
            &mid,
            true,
            30,
            false, // no_expiry
            &cert_path,
        )
        .expect("sign_member");
        assert!(cert_path.exists());
        assert!(c_sign.io.output.contains("Issued membership cert"));

        // 3. inspect
        let mut c_insp = ctx();
        inspect_cert(&mut c_insp, &cert_path).expect("inspect");
        assert!(c_insp.io.output.contains("admin            = true"));
        assert!(c_insp.io.output.contains(&nid));
        assert!(c_insp.io.output.contains(&mid));

        // 4. verify against the matching pub
        let mut c_ver = ctx();
        verify_cert(
            &mut c_ver,
            &cert_path,
            &pub_path,
            SignatureAlgorithm::Ed25519,
            &nid,
        )
        .expect("verify ok");
        assert!(c_ver.io.output.contains("Cert verified"));
    }

    #[test]
    fn verify_rejects_wrong_network_id() {
        let dir = tempdir().expect("tempdir");
        let pub_path = dir.path().join("owner.pub");
        let priv_path = dir.path().join("owner.priv");
        let cert_path = dir.path().join("member.cert");
        gen_owner(
            &mut ctx(),
            &pub_path,
            &priv_path,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let real_nid = "aa".repeat(32);
        let wrong_nid = "bb".repeat(32);
        let mid = "cc".repeat(32);
        sign_member(
            &mut ctx(),
            &pub_path,
            &priv_path,
            SignatureAlgorithm::Ed25519,
            &real_nid,
            &mid,
            false,
            10,
            false, // no_expiry
            &cert_path,
        )
        .unwrap();

        let err = verify_cert(
            &mut ctx(),
            &cert_path,
            &pub_path,
            SignatureAlgorithm::Ed25519,
            &wrong_nid,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Cert verification failed"),
            "expected verification failure, got: {msg}"
        );
    }

    #[test]
    fn sign_member_rejects_short_hex() {
        let dir = tempdir().expect("tempdir");
        let pub_path = dir.path().join("owner.pub");
        let priv_path = dir.path().join("owner.priv");
        gen_owner(
            &mut ctx(),
            &pub_path,
            &priv_path,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let err = sign_member(
            &mut ctx(),
            &pub_path,
            &priv_path,
            SignatureAlgorithm::Ed25519,
            "deadbeef", // too short
            &"11".repeat(32),
            false,
            1,
            false, // no_expiry
            &dir.path().join("out.cert"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("network_id"),
            "expected network_id error, got: {err}"
        );
    }

    #[test]
    fn signature_algorithm_arg_round_trips() {
        assert_eq!(
            SignatureAlgorithm::from(SignatureAlgorithmArg::Ed25519),
            SignatureAlgorithm::Ed25519
        );
        assert_eq!(
            SignatureAlgorithm::from(SignatureAlgorithmArg::Falcon512),
            SignatureAlgorithm::Falcon512
        );
    }
}
