//! Publishing a sovereign identity to the DHT — the records a REMOTE peer
//! resolves before it can seal anything for this node.
//!
//! Extracted from the one-shot at startup because startup is not the only
//! moment this has to happen. A deniably-booted node starts under a
//! placeholder identity and is promoted to the real one later; the promotion
//! swapped the document held in memory and left the DHT holding the
//! placeholder's records, because the only publish had already run. Peers
//! then resolved a certificate for an identity this node no longer used, the
//! PQXDH agreement behind every direct frame failed, and the whole live path
//! went silent while the mailbox — which resolves different records — kept
//! working and hid it.
//!
//! Measured before the fix: 0 of 86 single-shot frames delivered in either
//! direction between two devices on the same LAN, and four publish records in
//! the node's log, every one of them under the placeholder id.

use std::sync::Arc;

use veil_cfg::Config;
use veil_dht::KademliaService;
use veil_observability::NodeLogger;

use veil_identity::sovereign::SovereignIdentity;

/// Publish [`sov`]'s document, instance registry, ML-KEM certificate and any
/// persisted name claims.
///
/// Idempotent: republishing the same version is benign, so this is safe to
/// call again whenever the identity in force changes.
pub(crate) async fn publish_sovereign_identity(
    sov: &SovereignIdentity,
    dht: &Arc<KademliaService>,
    mlkem_keys: &Arc<veil_e2e::MlKemSeedRing>,
    config: &Config,
    veil_dir_path: &std::path::Path,
    logger: &Arc<NodeLogger>,
) {
        let publisher =
            crate::identity_local::publisher_dht::DhtBackedPublisher::new(Arc::clone(&dht));
        match veil_identity::publish::publish_identity_document(
            &sov.document, &publisher,
        ).await {
            Ok(()) => logger.info(
                "node.sovereign_identity.published",
                format!(
                    "node_id={} valid_until_unix={}",
                    veil_util::bytes_to_hex(sov.node_id()),
                    sov.document.valid_until_unix,
                ),
            ),
            Err(e) => logger.warn(
                "node.sovereign_identity.publish_failed",
                format!(
                    "node_id={} — DHT publish failed: {e} (peers may not find this identity until republish)",
                    veil_util::bytes_to_hex(sov.node_id()),
                ),
            ),
        }

        // InstanceRegistry publish: advertise this node's single
        // instance so peers can locate it by (node_id
        // instance_id). For MVP, `reg_version = 1` on every
        // fresh startup — peers tie-break on (version, sig) so
        // republishing the same version is benign. Future:
        // persist + monotonically bump reg_version across
        // restarts, and extend the entry list when paired
        // devices (462.30) join the identity.
        let instance_entry = veil_identity::publish::build_instance_entry(
            sov.active_instance_id(),
            sov.sig_key_idx,
            String::new(), // label empty for MVP; CLI flag to set it is follow-up
            0,             // last_seen_unix_ms — populated by subsequent republishes
        );
        let registry = sov.build_and_sign_registry(1, vec![instance_entry]);
        match veil_identity::publish::publish_instance_registry(&registry, &publisher).await {
            Ok(()) => logger.info(
                "node.sovereign_identity.registry_published",
                format!(
                    "node_id={} reg_version={} instances={}",
                    veil_util::bytes_to_hex(sov.node_id()),
                    registry.reg_version,
                    registry.instances.len(),
                ),
            ),
            Err(e) => logger.warn(
                "node.sovereign_identity.registry_publish_failed",
                format!(
                    "node_id={} — registry DHT publish failed: {e}",
                    veil_util::bytes_to_hex(sov.node_id()),
                ),
            ),
        }

        // per-instance ML-KEM cert — binds this node's
        // ML-KEM-768 encapsulation key (already loaded or generated
        // at startup into `mlkem_ek`) to the active identity subkey.
        // Peers resolving this identity can E2E-encrypt toward
        // `(node_id, instance_id)` without a separate X3DH-style
        // prekey fetch. `cert_version = 1` for MVP (parallels
        // `reg_version` above — future persist + bump). Validity
        // window: 30 days from startup, per spec.
        let cert_valid_from = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cert_valid_until = cert_valid_from + 30 * 86_400;
        match sov.sign_mlkem_cert(
            mlkem_keys.current_ek().to_vec(),
            mlkem_keys.current_ratchet_pk(),
            cert_valid_from,
            cert_valid_until,
            1,
        ) {
            Ok(cert) => {
                match veil_identity::publish::publish_mlkem_cert(&cert, &publisher).await {
                    Ok(()) => logger.info(
                        "node.sovereign_identity.mlkem_cert_published",
                        format!(
                            "node_id={} instance_id={} cert_version={}",
                            veil_util::bytes_to_hex(sov.node_id()),
                            veil_util::bytes_to_hex(&sov.active_instance_id()),
                            cert.cert_version,
                        ),
                    ),
                    Err(e) => logger.warn(
                        "node.sovereign_identity.mlkem_cert_publish_failed",
                        format!(
                            "node_id={} — ML-KEM cert DHT publish failed: {e}",
                            veil_util::bytes_to_hex(sov.node_id()),
                        ),
                    ),
                }
            }
            Err(e) => logger.warn(
                "node.sovereign_identity.mlkem_cert_sign_failed",
                format!(
                    "node_id={} — ML-KEM cert signing failed: {e}",
                    veil_util::bytes_to_hex(sov.node_id()),
                ),
            ),
        }

        // publish any persisted NameClaim files the user
        // has claimed via `veil-cli identity claim-name`. Scan is
        // tolerant — a corrupt file doesn't block the rest. Empty
        // directory (fresh node, no names) is a clean no-op.
        match veil_identity::sovereign::load_persisted_name_claims(&veil_dir_path) {
            Ok(claims) if !claims.is_empty() => {
                for claim in &claims {
                    match veil_identity::publish::publish_name_claim(claim, &publisher).await {
                        Ok(()) => logger.info(
                            "node.sovereign_identity.name_claim_published",
                            format!(
                                "node_id={} name=\"{}\"",
                                veil_util::bytes_to_hex(sov.node_id()),
                                claim.name,
                            ),
                        ),
                        Err(e) => logger.warn(
                            "node.sovereign_identity.name_claim_publish_failed",
                            format!(
                                "node_id={} name=\"{}\" — publish failed: {e}",
                                veil_util::bytes_to_hex(sov.node_id()),
                                claim.name,
                            ),
                        ),
                    }
                }
            }
            Ok(_) => {
                // No claims persisted — normal on a fresh node.
            }
            Err(e) => logger.warn(
                "node.sovereign_identity.name_claims_scan_failed",
                format!(
                    "node_id={} — name_claims scan failed: {e}",
                    veil_util::bytes_to_hex(sov.node_id()),
                ),
            ),
        }
}
