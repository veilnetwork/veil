//! Read-only deployment and admission checks for the ogate command line.

use anyhow::{Context as _, ensure};
use veil_util::unix_secs_now_u64;
use veilclient::VeilClient;
use veilclient::client::PnetStatus;

use crate::config::OgateConfig;
use crate::routing::{NodeId, RoutingTable, decode_node_id};
use crate::signed_policy::{SignedRoutes, assigned_peers};

pub(crate) async fn run(mut cfg: OgateConfig, peer: Option<&str>) -> anyhow::Result<()> {
    ensure!(
        cfg.pnet_required,
        "ogate check requires pnet_required = true"
    );
    let peer = peer
        .map(|value| {
            decode_node_id(value)
                .filter(|id| *id != [0; 32])
                .context("--peer must be a nonzero 64-digit hexadecimal Node ID")
        })
        .transpose()?;
    let mut routes = RoutingTable::from_config(&cfg).map_err(anyhow::Error::msg)?;
    let policy = cfg
        .signed_policy
        .as_ref()
        .map(|config| {
            SignedRoutes::open(config.clone()).with_context(|| {
                format!(
                    "cannot open signed policy in {}",
                    config.state_dir.display()
                )
            })
        })
        .transpose()?;

    let client = VeilClient::connect_with_pnet_authority(&cfg.socket_path)
        .await
        .with_context(|| {
            format!(
                "cannot reach the local Veil daemon at {}; check socket_path and service status",
                cfg.socket_path.display()
            )
        })?;
    let authority = client.pnet_authority();
    let node = client
        .node_identity()
        .await
        .context("cannot read the local Veil daemon identity")?
        .node_id;
    let now = unix_secs_now_u64();
    let mut revision = None;
    if let Some(policy) = &policy {
        policy.authenticate(authority, now)?;
        ensure!(
            client.supports_pnet_admission_batch(),
            "the local daemon does not support signed P-Net admission batches; upgrade the Veil daemon"
        );
        let snapshot = policy.refresh().context("cannot read the signed policy")?;
        snapshot.check_current(unix_secs_now_u64())?;
        ensure!(
            snapshot
                .members
                .binary_search_by_key(&node, |member| member.node_id)
                .is_ok(),
            "the local device has no virtual address assignment in signed policy revision {}",
            snapshot.revision
        );
        cfg.peers = assigned_peers(&snapshot, &cfg, &node)?;
        routes = RoutingTable::from_config(&cfg).map_err(anyhow::Error::msg)?;
        revision = Some((snapshot.revision, snapshot.valid_until_unix));
    } else if let Some(authority) = authority {
        ensure!(
            authority.is_current(now),
            "the local P-Net membership is expired or the clock is unavailable"
        );
    }

    if let Some(peer) = peer {
        ensure!(peer != node, "--peer identifies the local device");
        let route_peer = routes.peer_node_ids().any(|id| id == &peer);
        let mirror = policy
            .as_ref()
            .is_some_and(|policy| policy.mirrors.contains(&peer));
        let role = match (route_peer, mirror) {
            (true, true) => "route peer and configured mirror",
            (true, false) => "route peer",
            (false, true) => "configured mirror",
            (false, false) => anyhow::bail!(
                "the selected device has no configured route and is not a configured mirror"
            ),
        };
        let status = client
            .peer_pnet_status(&peer)
            .await
            .context("cannot query P-Net admission for the selected peer")?;
        check_admission(
            &peer,
            authority.map(|authority| authority.root.network_id),
            &status,
            unix_secs_now_u64(),
        )?;
        println!("{role} has current P-Net admission");
    }

    if let Some((revision, expires)) = revision {
        println!("signed policy revision {revision} is current until {expires} (Unix seconds)");
    }
    println!(
        "local Veil daemon reachable; {} configured route peers",
        routes.peer_count()
    );
    Ok(())
}

fn check_admission(
    peer: &NodeId,
    network: Option<[u8; 32]>,
    status: &PnetStatus,
    now: u64,
) -> anyhow::Result<()> {
    ensure!(
        status.peer_node_id == *peer,
        "daemon replied for a different peer"
    );
    ensure!(
        status.has_cert,
        "the daemon has no verified P-Net certificate for the peer; check its connection and membership configuration"
    );
    ensure!(
        network.is_none_or(|network| status.network_id == network),
        "the peer's certificate belongs to a different P-Net"
    );
    if status.valid_until_unix != 0 {
        ensure!(
            now != 0,
            "cannot check peer certificate expiry without a working clock"
        );
        ensure!(
            now < status.valid_until_unix,
            "the peer's P-Net certificate expired at {} (Unix seconds)",
            status.valid_until_unix
        );
    }
    ensure!(
        status.admitted,
        "the daemon has no current P-Net admission for the peer; check its session and network revocations"
    );
    Ok(())
}
