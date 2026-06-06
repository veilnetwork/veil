//! S2.B: per-app cert verifier (independent from daemon's P-Net authority).
//!
//! ogate operators wanting their OWN trust domain (different from daemon's
//! `[network]`) configure a triple in `ogate.toml`:
//! ```toml
//! app_cert_trusted_owner_pubkey = "<base64 ed25519 owner pubkey>"
//! app_cert_owner_algo = "ed25519"
//! app_cert_network_id = "948b97b51b...ea87"
//! ```
//!
//! Each peer presents a `MembershipCert` (output of
//! `veil-cli network sign-member`) once via a cert message
//! (see. [`crate::cert_message`]).  Verified peers go into a cache;
//! subsequent IP packets from cached peers pass through.  Unverified
//! sources have their packets dropped.

use anyhow::{Result, anyhow};
use veil_identity::network_cert::{decode_cert_blob, verify_membership_cert};
use veil_types::SignatureAlgorithm;

pub struct AppCertGate {
    expected_network_id: [u8; 32],
    owner_algo: SignatureAlgorithm,
    owner_pubkey_bytes: Vec<u8>,
}

impl AppCertGate {
    pub fn from_config(
        owner_pubkey_b64: &str,
        owner_algo: SignatureAlgorithm,
        network_id_hex: &str,
    ) -> Result<Self> {
        let network_id_bytes =
            hex::decode(network_id_hex).map_err(|e| anyhow!("network_id hex: {e}"))?;
        if network_id_bytes.len() != 32 {
            return Err(anyhow!(
                "network_id must be 64 hex chars (got {})",
                network_id_hex.len()
            ));
        }
        let mut expected_network_id = [0u8; 32];
        expected_network_id.copy_from_slice(&network_id_bytes);
        let owner_pubkey_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, owner_pubkey_b64)
                .map_err(|e| anyhow!("owner_pubkey base64: {e}"))?;
        Ok(Self {
            expected_network_id,
            owner_algo,
            owner_pubkey_bytes,
        })
    }

    /// Verify cert blob against the configured authority and that
    /// cert.member_node_id matches the source's authenticated node_id.
    /// Returns the cert's `valid_until_unix` on success (0 sentinel
    /// kept verbatim) so the caller can stamp the cache entry.
    pub fn verify(&self, cert_blob: &[u8], src_node_id: &[u8; 32]) -> Result<u64> {
        let cert = decode_cert_blob(cert_blob).map_err(|e| anyhow!("cert decode: {e}"))?;
        if &cert.member_node_id != src_node_id {
            return Err(anyhow!(
                "cert.member_node_id != src_node_id ({:02x}{:02x}.. vs {:02x}{:02x}..)",
                cert.member_node_id[0],
                cert.member_node_id[1],
                src_node_id[0],
                src_node_id[1],
            ));
        }
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| anyhow!("system clock before UNIX_EPOCH"))?;
        verify_membership_cert(
            &cert,
            &self.expected_network_id,
            self.owner_algo,
            &self.owner_pubkey_bytes,
            now_unix,
        )
        .map_err(|e| anyhow!("cert verify: {e}"))?;
        Ok(cert.valid_until_unix)
    }
}
