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

use std::sync::{Arc, RwLock};

use veil_session::SessionTxRegistry;

use veil_dht::KademliaService;
use veil_observability::NodeLogger;

use veil_identity::sovereign::SovereignIdentity;

impl crate::runtime::NodeRuntime {
    /// Re-read the identity document from disk and tell the network about it.
    ///
    /// The small operation that used to have no spelling. A host that merges a
    /// sibling's document — the moment two devices of one identity become one
    /// identity with two devices — changes a file the running node had already
    /// read, and the only way to make the node read it again was to apply a
    /// config: a full stop-and-restart of every service. That works and costs
    /// far too much. It tears down the IPC server, so every client connection
    /// dies with it; measured on a two-device stand, the merge succeeded and
    /// then every mailbox deposit failed with `connection closed` for as long as
    /// the app kept running.
    ///
    /// So: load, install into the shared cell, publish. Nothing is stopped.
    ///
    /// Refuses a document for a DIFFERENT IDENTITY — compared against the
    /// identity currently in force, never against this node's transport key.
    /// Those two are the same value only on a device that boots on the master
    /// key; a device restored into an existing identity has a transport key of
    /// its own, which is the entire point of the arrangement, and checking
    /// against it refuses every legitimate re-read on exactly the devices this
    /// exists for. What must not change is WHICH IDENTITY this node answers
    /// for. Returns how many devices the document names.
    pub async fn reload_sovereign_identity(&self) -> crate::error::Result<usize> {
        use crate::error::NodeError;

        let dir = self.identity_dir.clone();
        let sov =
            veil_identity::sovereign::SovereignIdentity::load_from_dir(&dir).map_err(|e| {
                NodeError::Identity(format!("identity re-read from {}: {e}", dir.display()))
            })?;
        // `load_from_dir` has already checked that the document still names the
        // key on this disk, so a merge that dropped this device cannot get here.
        if let Some(current) = self.identity.sovereign_identity.get()
            && !identity_reload_allowed(*current.node_id(), *sov.node_id())
        {
            return Err(NodeError::Identity(format!(
                "identity re-read refused: {} names identity {} but this node answers for {}",
                dir.display(),
                veil_util::bytes_to_hex(sov.node_id()),
                veil_util::bytes_to_hex(current.node_id()),
            )));
        }
        let devices = sov.document.identity_keys.len();
        let identity = *sov.node_id();
        let sov = Arc::new(sov);
        self.identity.sovereign_identity.set(Arc::clone(&sov));
        super::identity_publish::publish_sovereign_identity(
            &sov,
            &self.dht,
            &self.identity.mlkem_keys,
            &dir,
            // Sessions exist by the time a host merges anything, so replicate —
            // a local-only publish is a record no peer can resolve.
            Some((
                &self.session_tx_registry,
                *self.identity.local_identity.node_id.as_bytes(),
            )),
            &self.logger,
        )
        .await;
        self.logger.info(
            "node.sovereign_identity.reloaded",
            format!(
                "identity={} devices={} — re-read from {} without a runtime reload",
                veil_util::bytes_to_hex(&identity),
                devices,
                dir.display(),
            ),
        );
        Ok(devices)
    }
}

/// May a document just read from disk replace the identity in force?
///
/// Two parameters, and the node's TRANSPORT key is deliberately not one of
/// them. It is the same value as the identity only on a device that boots on
/// the master key; a device restored into an existing identity has a transport
/// key of its own — that is the whole arrangement — so comparing against it
/// refuses every legitimate re-read on exactly the devices this exists for.
/// Measured on a two-device stand: the restored one refused its own merge,
/// naming its transport id as the reason.
///
/// What must hold is that the identity this node answers for does not change
/// underneath it.
pub(crate) fn identity_reload_allowed(in_force: [u8; 32], incoming: [u8; 32]) -> bool {
    in_force == incoming
}

/// The registry to publish for `sov` — every device the document names, under
/// the document's own issue time.
///
/// One function because there are three publishers (startup, the periodic
/// republish task, the sim-only debug republish) and they disagreed. Two of them
/// built a set of ONE — this device — under a constant `reg_version = 1`, which
/// is the shape the startup path was deliberately moved away from: every device
/// publishes under the same node_id, so a one-device registry overwrites the
/// registry naming both, and an equal version gives the network nothing to
/// prefer the fuller record by. A second device linked, worked, and vanished
/// from the map at the next republish tick.
pub(crate) fn full_registry(
    sov: &SovereignIdentity,
) -> veil_proto::instance_registry::InstanceRegistry {
    sov.build_and_sign_registry(sov.registry_version(), sov.all_instance_entries())
}

/// Publish [`sov`]'s document, instance registry, ML-KEM certificate and any
/// persisted name claims.
///
/// Idempotent: republishing the same version is benign, so this is safe to
/// call again whenever the identity in force changes.
pub(crate) async fn publish_sovereign_identity(
    sov: &SovereignIdentity,
    dht: &Arc<KademliaService>,
    mlkem_keys: &Arc<veil_e2e::MlKemSeedRing>,
    veil_dir_path: &std::path::Path,
    // Present once sessions exist: without it the records are written to THIS
    // node's shard only and no peer ever sees them. The boot-time call passes
    // `None` because there are no peers yet; every later call must not.
    replication: Option<(&Arc<RwLock<SessionTxRegistry>>, [u8; 32])>,
    logger: &Arc<NodeLogger>,
) {
    let publisher = match replication {
        Some((registry, local_node_id)) => {
            crate::identity_local::publisher_dht::DhtBackedPublisher::with_replication(
                Arc::clone(dht),
                Arc::clone(registry),
                local_node_id,
            )
        }
        None => crate::identity_local::publisher_dht::DhtBackedPublisher::new(Arc::clone(dht)),
    };
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

    // InstanceRegistry publish: advertise EVERY device this identity names, so
    // a peer resolving node_id can seal one envelope per device.
    //
    // It used to advertise only this node's own instance, under a constant
    // `reg_version = 1`. Both halves were wrong once an identity had a second
    // device: every device publishes under the same node_id, so each in turn
    // replaced the registry with a set of one — itself — and the equal version
    // left peers tie-breaking on a signature. Whichever device wrote last was
    // the only one anyone could reach, and the others stayed online believing
    // they were reachable.
    //
    // Both now come from the document, which already names every device and is
    // the same document on all of them: identical registries instead of
    // contradicting ones, and a version that a device carrying an older
    // document loses rather than wins.
    let registry = full_registry(sov);
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
                        "node_id={} instance_id={} cert_version={} \
                             advertises ratchet_pk={} ek={}",
                        veil_util::bytes_to_hex(sov.node_id()),
                        veil_util::bytes_to_hex(&sov.active_instance_id()),
                        cert.cert_version,
                        // What a peer will seal to. Printed so it can be
                        // compared against what this node still HOLDS: if
                        // they differ, every peer working from this record
                        // is sealing to a key we cannot answer.
                        veil_util::bytes_to_hex(&mlkem_keys.current_ratchet_pk()[..4]),
                        veil_util::bytes_to_hex(&mlkem_keys.current_ek()[..4]),
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
    match veil_identity::sovereign::load_persisted_name_claims(veil_dir_path) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn standalone(dir: &std::path::Path) -> SovereignIdentity {
        let seed = veil_util::sensitive_bytes::SensitiveBytesN::<32>::from_bytes([0x42u8; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        veil_identity::sovereign_flow::save_standalone_identity_to_dir(
            dir,
            &seed,
            now - 3600,
            now + 3 * 86_400,
        )
        .expect("persist standalone identity");
        veil_identity::sovereign::SovereignIdentity::load_from_dir(dir)
            .expect("load standalone identity")
    }

    /// A merge that adds a device keeps the identity, so it is allowed; a
    /// document naming somebody else is not. The device's own transport key
    /// cannot appear here at all, which is the point — see the function.
    #[test]
    fn a_re_read_may_add_devices_but_not_change_who_we_are() {
        let identity = [0x11u8; 32];
        assert!(identity_reload_allowed(identity, identity));
        assert!(!identity_reload_allowed(identity, [0x22u8; 32]));
    }

    /// THE ONE THE SECOND DEVICE DISAPPEARED THROUGH.
    ///
    /// Every device of an identity publishes its registry under the SAME
    /// node_id, so a registry naming only the publisher does not sit beside the
    /// one naming both — it replaces it. Two of the three publishers built
    /// exactly that, under a constant version that could not lose the
    /// tie-break, so a linked second device stayed reachable only until the
    /// next republish tick.
    #[test]
    fn the_registry_names_every_device_the_document_does() {
        let tmp = tempfile::tempdir().unwrap();
        let mut sov = standalone(tmp.path());
        assert_eq!(full_registry(&sov).instances.len(), 1, "one device so far");

        // What linking does: the sibling's subkey joins the document.
        let mut sibling = sov.document.identity_keys[0].clone();
        sibling.device_id = [0xEEu8; 32];
        sov.document.identity_keys.push(sibling);

        let reg = full_registry(&sov);
        assert_eq!(
            reg.instances.len(),
            2,
            "a registry naming one device HIDES the other — it overwrites, it does not coexist",
        );
        assert!(
            reg.instances.iter().any(|i| i.instance_id == [0xEEu8; 16]),
            "the device that joined has to be in it",
        );
        assert_eq!(
            reg.reg_version, sov.document.issued_at_unix,
            "a constant version cannot lose to a fuller record",
        );
    }
}
