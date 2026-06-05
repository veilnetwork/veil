//! S2.B: server-side app-layer cert verifier.
//!
//! When operator configures `app_cert_trusted_owner_pubkey` +
//! `app_cert_owner_algo` + `app_cert_network_id` в server.toml,
//! oproxy-server builds an [`AppCertGate`] at startup which holds the
//! parsed authority parameters.  Per-stream: server reads the wire
//! preamble (см. `wire::read_stream_prefix`), passes the cert blob к
//! [`AppCertGate::verify`], и admits / rejects.

use anyhow::{Result, anyhow};
use veil_identity::network_cert::{decode_cert_blob, verify_membership_cert};
use veil_types::SignatureAlgorithm;

/// Parsed server-side authority parameters.  Built once at startup.
pub struct AppCertGate {
    expected_network_id: [u8; 32],
    owner_algo: SignatureAlgorithm,
    owner_pubkey_bytes: Vec<u8>,
}

impl AppCertGate {
    /// Build от config fields.  Fails если any field is missing,
    /// network_id is malformed, или owner pubkey can't be base64-decoded.
    pub fn from_config(
        owner_pubkey_b64: &str,
        owner_algo: SignatureAlgorithm,
        network_id_hex: &str,
    ) -> Result<Self> {
        let network_id_bytes =
            hex::decode(network_id_hex).map_err(|e| anyhow!("app_cert_network_id hex: {e}"))?;
        if network_id_bytes.len() != 32 {
            return Err(anyhow!(
                "app_cert_network_id must be 64 hex chars (got {})",
                network_id_hex.len()
            ));
        }
        let mut expected_network_id = [0u8; 32];
        expected_network_id.copy_from_slice(&network_id_bytes);
        let owner_pubkey_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, owner_pubkey_b64)
                .map_err(|e| anyhow!("app_cert_trusted_owner_pubkey base64: {e}"))?;
        Ok(Self {
            expected_network_id,
            owner_algo,
            owner_pubkey_bytes,
        })
    }

    /// Verify cert blob against the configured authority.  Also enforces
    /// that the cert's `member_node_id` matches the stream's authenticated
    /// source `node_id` (peer can't forward someone else's cert).
    pub fn verify(&self, cert_blob: &[u8], src_node_id: &[u8; 32]) -> Result<()> {
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
        Ok(())
    }
}

// Needed for base64 decode in `from_config`.
use base64;
