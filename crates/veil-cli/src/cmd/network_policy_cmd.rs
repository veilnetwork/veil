use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::Path;

use veil_cfg::{ConfigError, Result};
use veil_identity::network_policy::{
    MAX_SIGNED_ROUTE_POLICY_BYTES, RoutePolicy, RoutePolicyAuthority, sign_route_policy,
    verify_route_policy,
};
#[cfg(unix)]
use veil_identity::network_policy_store::RoutePolicyStore;
use veil_identity::network_recovery::sign_owner_recovery;
#[cfg(unix)]
use veil_identity::network_recovery::{MAX_OWNER_RECOVERY_BYTES, OwnerRecovery};
use veil_types::SignatureAlgorithm;
use zeroize::Zeroizing;

use super::{
    cli::RoutePolicyCommand,
    handlers::{CommandContext, ConfigOps},
    output::{CommandIo, OutputEvent},
};

const MAX_POLICY_TOML_BYTES: usize = 1024 * 1024;
const MAX_OWNER_KEY_BYTES: usize = 16 * 1024;

pub(super) fn run<I: CommandIo>(
    context: &mut CommandContext<'_, I, impl ConfigOps>,
    command: RoutePolicyCommand,
) -> Result<()> {
    let trust = match &command {
        RoutePolicyCommand::Sign { trust, .. }
        | RoutePolicyCommand::Verify { trust, .. }
        | RoutePolicyCommand::SignRecovery { trust, .. } => trust,
        #[cfg(unix)]
        RoutePolicyCommand::Install { trust, .. }
        | RoutePolicyCommand::RotateOwner { trust, .. }
        | RoutePolicyCommand::PinRecovery { trust, .. }
        | RoutePolicyCommand::RecoverOwner { trust, .. }
        | RoutePolicyCommand::Status { trust, .. } => trust,
    };
    let owner_key = read_bounded(&trust.owner_pub, MAX_OWNER_KEY_BYTES)?;
    let public_key = read_text(&trust.owner_pub, &owner_key)?.trim();
    let authority = RoutePolicyAuthority {
        network_id: veil_util::hex_to_array(&trust.network_id)
            .map_err(|_| invalid("network ID must be 64 hexadecimal digits"))?,
        algorithm: trust.algo.into(),
        public_key,
    };
    match command {
        RoutePolicyCommand::Sign {
            input,
            owner_priv,
            out,
            ..
        } => {
            let spec = read_bounded(&input, MAX_POLICY_TOML_BYTES)?;
            let policy: RoutePolicy = toml::from_str(read_text(&input, &spec)?).map_err(invalid)?;
            if policy.network_id != authority.network_id {
                return Err(invalid("policy network ID differs from --network-id"));
            }
            let private_key = read_bounded(&owner_priv, MAX_OWNER_KEY_BYTES)?;
            let blob = sign_route_policy(
                policy,
                authority.algorithm,
                public_key,
                read_text(&owner_priv, &private_key)?.trim(),
            )
            .map_err(invalid)?;
            veil_util::write_new_owner_only(&out, &blob)
                .map_err(|error| invalid(format!("write {}: {error}", out.display())))?;
            context.io.emit(OutputEvent::message(format!(
                "Signed route policy written to {}",
                out.display()
            )));
        }
        RoutePolicyCommand::Verify { policy, .. } => {
            let blob = read_bounded(&policy, MAX_SIGNED_ROUTE_POLICY_BYTES)?;
            let verified = verify_route_policy(&blob, &authority).map_err(invalid)?;
            verified
                .check_current(veil_util::unix_secs_now_u64())
                .map_err(invalid)?;
            context
                .io
                .emit(OutputEvent::message(summary("Verified", &verified)));
        }
        #[cfg(unix)]
        RoutePolicyCommand::Install {
            policy,
            state_dir,
            initialize,
            ..
        } => {
            let blob = read_bounded(&policy, MAX_SIGNED_ROUTE_POLICY_BYTES)?;
            let accepted = open_store(&state_dir)?
                .accept(&blob, &authority, initialize)
                .map_err(invalid)?;
            context
                .io
                .emit(OutputEvent::message(summary("Stored", &accepted)));
        }
        #[cfg(unix)]
        RoutePolicyCommand::RotateOwner {
            policy,
            state_dir,
            next,
            check,
            ..
        } => {
            let next_key = PublicKeyFile::next(&next, &authority)?;
            let blob = read_bounded(&policy, MAX_SIGNED_ROUTE_POLICY_BYTES)?;
            let replacement = open_store(&state_dir)?
                .replace_owner(
                    &blob,
                    &authority,
                    &next_key.authority(authority.network_id),
                    check,
                )
                .map_err(invalid)?;
            let action = if check {
                "Checked successor"
            } else {
                "Stored successor"
            };
            context
                .io
                .emit(OutputEvent::message(summary(action, &replacement)));
        }
        #[cfg(unix)]
        RoutePolicyCommand::PinRecovery {
            state_dir,
            recovery,
            ..
        } => {
            let recovery_key = PublicKeyFile::recovery(&recovery)?;
            open_store(&state_dir)?
                .pin_recovery(&authority, &recovery_key.authority(authority.network_id))
                .map_err(invalid)?;
            context
                .io
                .emit(OutputEvent::message("Pinned P-Net recovery key"));
        }
        RoutePolicyCommand::SignRecovery {
            policy,
            recovery_priv,
            out,
            next,
            recovery,
            ..
        } => {
            let next_key = PublicKeyFile::next(&next, &authority)?;
            let recovery_key = PublicKeyFile::recovery(&recovery)?;
            let private_key = read_bounded(&recovery_priv, MAX_OWNER_KEY_BYTES)?;
            let blob = read_bounded(&policy, MAX_SIGNED_ROUTE_POLICY_BYTES)?;
            let signature = sign_owner_recovery(
                &blob,
                &authority,
                &next_key.authority(authority.network_id),
                &recovery_key.authority(authority.network_id),
                read_text(&recovery_priv, &private_key)?.trim(),
            )
            .map_err(invalid)?;
            veil_util::write_new_owner_only(&out, &signature)
                .map_err(|error| invalid(format!("write {}: {error}", out.display())))?;
            context.io.emit(OutputEvent::message(format!(
                "Signed owner recovery authorization written to {}",
                out.display()
            )));
        }
        #[cfg(unix)]
        RoutePolicyCommand::RecoverOwner {
            policy,
            authorization,
            state_dir,
            check,
            next,
            recovery,
            ..
        } => {
            let next_key = PublicKeyFile::next(&next, &authority)?;
            let recovery_key = PublicKeyFile::recovery(&recovery)?;
            let blob = read_bounded(&policy, MAX_SIGNED_ROUTE_POLICY_BYTES)?;
            let signature = read_bounded(&authorization, MAX_OWNER_RECOVERY_BYTES)?;
            let replacement = open_store(&state_dir)?
                .recover_owner(
                    &blob,
                    &authority,
                    &next_key.authority(authority.network_id),
                    &OwnerRecovery {
                        authority: &recovery_key.authority(authority.network_id),
                        signature: &signature,
                    },
                    check,
                )
                .map_err(invalid)?;
            let action = if check {
                "Checked recovery"
            } else {
                "Recovered"
            };
            context
                .io
                .emit(OutputEvent::message(summary(action, &replacement)));
        }
        #[cfg(unix)]
        RoutePolicyCommand::Status { state_dir, .. } => {
            let saved = open_store(&state_dir)?.load(&authority).map_err(invalid)?;
            let state = match saved.check_current(veil_util::unix_secs_now_u64()) {
                Ok(()) => "Current".to_owned(),
                Err(error) => error.to_string(),
            };
            context.io.emit(OutputEvent::message(format!(
                "{}\nStatus: {state}",
                summary("Stored", &saved)
            )));
        }
    }
    Ok(())
}

struct PublicKeyFile {
    algorithm: SignatureAlgorithm,
    text: String,
}

impl PublicKeyFile {
    fn read(path: &Path, algorithm: SignatureAlgorithm) -> Result<Self> {
        let bytes = read_bounded(path, MAX_OWNER_KEY_BYTES)?;
        Ok(Self {
            algorithm,
            text: read_text(path, &bytes)?.trim().to_owned(),
        })
    }

    fn next(
        args: &super::cli::RoutePolicySuccessor,
        current: &RoutePolicyAuthority<'_>,
    ) -> Result<Self> {
        Self::read(
            &args.next_owner_pub,
            args.next_algo.map_or(current.algorithm, Into::into),
        )
    }

    fn recovery(args: &super::cli::RoutePolicyRecoveryKey) -> Result<Self> {
        Self::read(&args.recovery_pub, args.recovery_algo.into())
    }

    fn authority(&self, network_id: [u8; 32]) -> RoutePolicyAuthority<'_> {
        RoutePolicyAuthority {
            network_id,
            algorithm: self.algorithm,
            public_key: &self.text,
        }
    }
}

#[cfg(unix)]
fn open_store(path: &Path) -> Result<RoutePolicyStore> {
    RoutePolicyStore::open(path)
        .map_err(|error| invalid(format!("open {}: {error}", path.display())))
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| invalid(format!("open {}: {error}", path.display())))?;
    if !file.metadata()?.is_file() {
        return Err(invalid(format!(
            "expected a regular file at {}",
            path.display()
        )));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid(format!(
            "{} exceeds {maximum} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_text<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str> {
    std::str::from_utf8(contents)
        .map_err(|_| invalid(format!("{} must contain UTF-8 text", path.display())))
}

fn summary(action: &str, policy: &RoutePolicy) -> String {
    format!(
        "{action} route policy for {}\nRevision: {}\nMembers: {}\nValid from: {}\nValid until: {}",
        veil_util::bytes_to_hex(&policy.network_id),
        policy.revision,
        policy.members.len(),
        policy.valid_from_unix,
        policy.valid_until_unix,
    )
}

fn invalid(error: impl std::fmt::Display) -> ConfigError {
    ConfigError::ValidationFailed(error.to_string())
}
