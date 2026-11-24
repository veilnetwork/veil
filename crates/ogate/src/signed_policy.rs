use std::sync::{Arc, Mutex};

use base64::Engine as _;
use tokio::sync::watch;
use veil_identity::network_policy::{
    RoutePolicyAuthority, VerifiedRoutePolicy, verify_route_policy,
};
use veil_identity::network_policy_store::{RoutePolicyStore, StoreError};
use veil_util::unix_secs_now_u64;
use veilclient::{PnetAuthority, PnetTrustRoot};

use crate::config::{OgateConfig, PeerEntry, SignedPolicyConfig};
use crate::routing::NodeId;

/// Parsed trust pin and the highest authenticated snapshot seen by this
/// bridge instance. The revision floor survives IPC reconnects.
pub(crate) struct SignedRoutes {
    config: SignedPolicyConfig,
    last: Mutex<Option<Arc<VerifiedRoutePolicy>>>,
    updates: watch::Sender<u64>,
    pub mirrors: Vec<NodeId>,
    pub publish: bool,
    pub root: PnetTrustRoot,
}

impl SignedRoutes {
    pub fn open(config: SignedPolicyConfig) -> anyhow::Result<Self> {
        let id = veil_util::hex_to_array(&config.network_id).map_err(|_| {
            anyhow::anyhow!("signed_policy.network_id must be 64 hexadecimal digits")
        })?;
        let key = base64::engine::general_purpose::STANDARD.decode(&config.owner_pubkey)?;
        let routes = Self {
            root: PnetTrustRoot::from_owner(id, config.owner_algo, &key),
            mirrors: config.mirror_ids()?,
            publish: config.publish,
            config,
            last: Mutex::new(None),
            updates: watch::channel(0).0,
        };
        routes.refresh()?;
        Ok(routes)
    }

    fn policy_authority(&self) -> RoutePolicyAuthority<'_> {
        RoutePolicyAuthority {
            network_id: self.root.network_id,
            algorithm: self.root.owner_algorithm,
            public_key: &self.config.owner_pubkey,
        }
    }

    pub fn refresh(&self) -> anyhow::Result<Arc<VerifiedRoutePolicy>> {
        let mut last = self
            .last
            .lock()
            .map_err(|_| anyhow::anyhow!("signed policy state lock failed"))?;
        let store = RoutePolicyStore::open(&self.config.state_dir)?;
        match store.try_load(&self.policy_authority()) {
            Ok(offered) => self.observe(&mut last, offered),
            Err(StoreError::Busy) => last.clone().ok_or_else(|| StoreError::Busy.into()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn installed_bytes(&self) -> anyhow::Result<(Arc<VerifiedRoutePolicy>, Vec<u8>)> {
        let mut last = self
            .last
            .lock()
            .map_err(|_| anyhow::anyhow!("signed policy state lock failed"))?;
        let store = RoutePolicyStore::open(&self.config.state_dir)?;
        let (offered, bytes) = store.try_load_signed(&self.policy_authority())?;
        Ok((self.observe(&mut last, offered)?, bytes))
    }

    pub fn verify_offer(&self, bytes: &[u8]) -> anyhow::Result<VerifiedRoutePolicy> {
        let offered = verify_route_policy(bytes, &self.policy_authority())?;
        offered.check_current(unix_secs_now_u64())?;
        Ok(offered)
    }

    pub fn install_offer(&self, bytes: &[u8]) -> anyhow::Result<u64> {
        let verified = self.verify_offer(bytes)?;
        let mut last = self
            .last
            .lock()
            .map_err(|_| anyhow::anyhow!("signed policy state lock failed"))?;
        if let Some(accepted) = last.as_ref() {
            require_monotonic(accepted, &verified)?;
        }
        let store = RoutePolicyStore::open(&self.config.state_dir)?;
        let accepted = store.try_accept(bytes, &self.policy_authority())?;
        Ok(self.observe(&mut last, accepted)?.revision)
    }

    pub fn updates(&self) -> watch::Receiver<u64> {
        self.updates.subscribe()
    }

    fn observe(
        &self,
        last: &mut Option<Arc<VerifiedRoutePolicy>>,
        offered: VerifiedRoutePolicy,
    ) -> anyhow::Result<Arc<VerifiedRoutePolicy>> {
        if let Some(accepted) = last.as_ref() {
            require_monotonic(accepted, &offered)?;
            if offered.revision == accepted.revision {
                return Ok(Arc::clone(accepted));
            }
        }
        let offered = Arc::new(offered);
        *last = Some(Arc::clone(&offered));
        // This notification carries only the expiry of a verified, durable
        // snapshot. The route task still reloads the protected store.
        self.updates.send_replace(offered.valid_until_unix);
        Ok(offered)
    }

    pub fn authenticate(
        &self,
        authority: Option<PnetAuthority>,
        now: u64,
    ) -> anyhow::Result<PnetAuthority> {
        let authority = authority.ok_or_else(|| anyhow::anyhow!(
            "signed policy requires a daemon with a verified local membership and P-Net authority support"
        ))?;
        anyhow::ensure!(
            authority.root == self.root,
            "daemon P-Net network or owner does not match signed_policy"
        );
        anyhow::ensure!(
            authority.is_current(now),
            "daemon local P-Net membership has expired"
        );
        Ok(authority)
    }
}

fn require_monotonic(
    accepted: &VerifiedRoutePolicy,
    offered: &VerifiedRoutePolicy,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        offered.revision >= accepted.revision,
        "signed policy revision went backwards"
    );
    anyhow::ensure!(
        offered.revision != accepted.revision || offered == accepted,
        "signed policy revision has conflicting contents"
    );
    Ok(())
}

pub(crate) fn assigned_peers(
    snapshot: &VerifiedRoutePolicy,
    cfg: &OgateConfig,
    node: &NodeId,
) -> anyhow::Result<Vec<PeerEntry>> {
    let Ok(index) = snapshot
        .members
        .binary_search_by_key(node, |member| member.node_id)
    else {
        return Ok(Vec::new());
    };
    let local = &snapshot.members[index];
    anyhow::ensure!(
        cfg.local_addr_v4 == local.addr_v4 && cfg.local_addr_v6 == local.addr_v6,
        "signed policy changes the local TUN addresses; update ogate config and restart"
    );
    anyhow::ensure!(
        snapshot
            .ipv4_range
            .is_some_and(|range| range.prefix_len() == cfg.prefix_v4)
            && (cfg.local_addr_v6.is_none()
                || snapshot
                    .ipv6_range
                    .is_some_and(|range| range.prefix_len() == cfg.prefix_v6)),
        "signed policy changes the local TUN prefixes; update ogate config and restart"
    );
    Ok(snapshot
        .members
        .iter()
        .filter_map(|member| {
            if &member.node_id == node {
                return None;
            }
            let addr_v4 = member.addr_v4;
            let addr_v6 = member.addr_v6.filter(|_| cfg.local_addr_v6.is_some());
            (addr_v4.is_some() || addr_v6.is_some()).then(|| PeerEntry {
                node_id: hex::encode(member.node_id),
                addr_v4,
                addr_v6,
                name: None,
            })
        })
        .collect())
}
