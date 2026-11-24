//! Offline authorization to replace a P-Net owner after compromise.
//! The authorization binds the exact initial snapshot of a fresh owner.

use crate::network_policy::{RoutePolicyAuthority, RoutePolicyError, verify_route_policy};
use veil_types::SignatureAlgorithm;

const DOMAIN: &[u8] = b"veil/p-net/owner-recovery/v1\0";
pub const MAX_OWNER_RECOVERY_BYTES: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum OwnerRecoveryError {
    #[error("current owner, successor and recovery key must belong to the same P-Net")]
    WrongNetwork,
    #[error("current owner, successor and recovery key must be distinct")]
    RepeatedKey,
    #[error("recovery authorization has an invalid signature length")]
    InvalidLength,
    #[error("invalid owner or recovery public key: {0}")]
    InvalidPublicKey(#[source] veil_error::ConfigError),
    #[error("an owner or recovery key contains a weak or invalid Ed25519 public key")]
    WeakEd25519Key,
    #[error("recovery authorization signature: {0}")]
    Signature(#[source] veil_error::ConfigError),
    #[error("replacement policy did not verify against the successor: {0}")]
    Policy(#[source] RoutePolicyError),
}

pub struct OwnerRecovery<'a> {
    pub authority: &'a RoutePolicyAuthority<'a>,
    pub signature: &'a [u8],
}

pub fn sign_owner_recovery(
    policy: &[u8],
    current: &RoutePolicyAuthority<'_>,
    successor: &RoutePolicyAuthority<'_>,
    recovery: &RoutePolicyAuthority<'_>,
    recovery_private_key: &str,
) -> Result<Vec<u8>, OwnerRecoveryError> {
    verify_route_policy(policy, successor).map_err(OwnerRecoveryError::Policy)?;
    let body = authorization_body(policy, current, successor, recovery)?;
    let signature = veil_crypto::sign_message(
        recovery.algorithm,
        recovery.public_key,
        recovery_private_key,
        &body,
    )
    .map_err(OwnerRecoveryError::Signature)?;
    verify_signature(recovery, &body, &signature)?;
    Ok(signature)
}

#[cfg(unix)]
pub(super) fn verify_owner_recovery(
    policy: &[u8],
    current: &RoutePolicyAuthority<'_>,
    successor: &RoutePolicyAuthority<'_>,
    recovery: &OwnerRecovery<'_>,
) -> Result<(), OwnerRecoveryError> {
    let body = authorization_body(policy, current, successor, recovery.authority)?;
    verify_signature(recovery.authority, &body, recovery.signature)
}

pub(super) fn owner_key_id(
    authority: &RoutePolicyAuthority<'_>,
) -> Result<[u8; 32], OwnerRecoveryError> {
    let key = veil_crypto::signature::decode_public_key(authority.algorithm, authority.public_key)
        .map_err(OwnerRecoveryError::InvalidPublicKey)?;
    if matches!(
        authority.algorithm,
        SignatureAlgorithm::Ed25519 | SignatureAlgorithm::Ed25519Falcon512Hybrid
    ) {
        // Both formats put the Ed25519 point in the first 32 bytes.
        let point = key
            .first_chunk()
            .ok_or(OwnerRecoveryError::WeakEd25519Key)?;
        let public = ed25519_dalek::VerifyingKey::from_bytes(point)
            .map_err(|_| OwnerRecoveryError::WeakEd25519Key)?;
        if public.is_weak() {
            return Err(OwnerRecoveryError::WeakEd25519Key);
        }
    }
    let mut hasher = blake3::Hasher::new_derive_key("veil/p-net/owner-recovery/key-id/v1");
    hasher.update(&[authority.algorithm.wire_byte()]);
    hasher.update(&key);
    Ok(*hasher.finalize().as_bytes())
}

fn authorization_body(
    policy: &[u8],
    current: &RoutePolicyAuthority<'_>,
    successor: &RoutePolicyAuthority<'_>,
    recovery: &RoutePolicyAuthority<'_>,
) -> Result<Vec<u8>, OwnerRecoveryError> {
    if current.network_id != successor.network_id || current.network_id != recovery.network_id {
        return Err(OwnerRecoveryError::WrongNetwork);
    }
    let current_key = owner_key_id(current)?;
    let next_key = owner_key_id(successor)?;
    let recovery_key = owner_key_id(recovery)?;
    if current_key == next_key || current_key == recovery_key || next_key == recovery_key {
        return Err(OwnerRecoveryError::RepeatedKey);
    }
    let mut body = Vec::with_capacity(DOMAIN.len() + 32 * 5);
    body.extend_from_slice(DOMAIN);
    body.extend_from_slice(&current.network_id);
    body.extend_from_slice(&current_key);
    body.extend_from_slice(&next_key);
    body.extend_from_slice(&recovery_key);
    body.extend_from_slice(blake3::hash(policy).as_bytes());
    Ok(body)
}

fn verify_signature(
    recovery: &RoutePolicyAuthority<'_>,
    body: &[u8],
    signature: &[u8],
) -> Result<(), OwnerRecoveryError> {
    if signature.is_empty() || signature.len() > MAX_OWNER_RECOVERY_BYTES {
        return Err(OwnerRecoveryError::InvalidLength);
    }
    veil_crypto::verify_message(recovery.algorithm, recovery.public_key, body, signature)
        .map_err(OwnerRecoveryError::Signature)
}
